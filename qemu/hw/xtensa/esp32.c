/*
 * ESP32 SoC and machine
 *
 * Copyright (c) 2019 Espressif Systems (Shanghai) Co. Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 or
 * (at your option) any later version.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "hw/hw.h"
#include "hw/boards.h"
#include "hw/loader.h"
#include "hw/sysbus.h"
#include "target/xtensa/cpu.h"
#include "hw/misc/esp32_reg.h"
#include "hw/char/esp32_uart.h"
#include "hw/gpio/esp32_gpio.h"
#include "hw/misc/esp32_dport.h"
#include "hw/misc/esp32_rtc_cntl.h"
#include "hw/misc/esp32_rng.h"
#include "hw/misc/esp32_sha.h"
#include "hw/misc/esp32_aes.h"
#include "hw/timer/esp32_frc_timer.h"
#include "hw/timer/esp32_timg.h"
#include "hw/ssi/esp32_spi.h"
#include "hw/nvram/esp32_efuse.h"
#include "hw/xtensa/xtensa_memory.h"
#include "hw/misc/unimp.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "sysemu/sysemu.h"
#include "sysemu/reset.h"
#include "sysemu/runstate.h"
#include "sysemu/blockdev.h"
#include "sysemu/block-backend.h"
#include "exec/exec-all.h"
#include "net/net.h"
#include "elf.h"
#include "fuzz/hfuzz.h"

#define TYPE_ESP32_SOC "xtensa.esp32"
#define ESP32_SOC(obj) OBJECT_CHECK(Esp32SocState, (obj), TYPE_ESP32_SOC)

#define TYPE_ESP32_CPU XTENSA_CPU_TYPE_NAME("esp32")

typedef struct XtensaCPU XtensaCPU;

/**
 * Start and end of instrumentation address range
 */
const target_ulong hfuzz_qemu_start_code = 0x400C2000;
const target_ulong hfuzz_qemu_end_code = 0x40BFFFFF;

/**
 * Flag wheater process is a child process.
 */
bool childProcess = false;

enum {
    ESP32_MEMREGION_IROM,
    ESP32_MEMREGION_DROM,
    ESP32_MEMREGION_DRAM,
    ESP32_MEMREGION_IRAM,
    ESP32_MEMREGION_ICACHE0,
    ESP32_MEMREGION_ICACHE1,
    ESP32_MEMREGION_RTCSLOW,
    ESP32_MEMREGION_RTCFAST_D,
    ESP32_MEMREGION_RTCFAST_I,
};

static const struct MemmapEntry {
    hwaddr base;
    hwaddr size;
} esp32_memmap[] = {
    [ESP32_MEMREGION_DROM] = { 0x3ff90000, 0x10000 },
    [ESP32_MEMREGION_IROM] = { 0x40000000, 0x70000 },
    [ESP32_MEMREGION_DRAM] = { 0x3ffae000, 0x52000 },
    [ESP32_MEMREGION_IRAM] = { 0x40080000, 0x20000 },
    [ESP32_MEMREGION_ICACHE0] = { 0x40070000, 0x8000 },
    [ESP32_MEMREGION_ICACHE1] = { 0x40078000, 0x8000 },
    [ESP32_MEMREGION_RTCSLOW] = { 0x50000000, 0x2000 },
    [ESP32_MEMREGION_RTCFAST_I] = { 0x400C0000, 0x2000 },
    [ESP32_MEMREGION_RTCFAST_D] = { 0x3ff80000, 0x2000 },
};


#define ESP32_SOC_RESET_PROCPU    0x1
#define ESP32_SOC_RESET_APPCPU    0x2
#define ESP32_SOC_RESET_PERIPH    0x4
#define ESP32_SOC_RESET_DIG       (ESP32_SOC_RESET_PROCPU | ESP32_SOC_RESET_APPCPU | ESP32_SOC_RESET_PERIPH)
#define ESP32_SOC_RESET_RTC       0x8
#define ESP32_SOC_RESET_ALL       (ESP32_SOC_RESET_RTC | ESP32_SOC_RESET_DIG)


typedef struct Esp32SocState {
    /*< private >*/
    SysBusDevice parent_obj;

    /*< public >*/
    XtensaCPU cpu[ESP32_CPU_COUNT];
    Esp32DportState dport;
    ESP32UARTState uart[ESP32_UART_COUNT];
    Esp32GpioState gpio;
    Esp32RngState rng;
    Esp32RtcCntlState rtc_cntl;
    Esp32FrcTimerState frc_timer[ESP32_FRC_COUNT];
    Esp32TimgState timg[ESP32_TIMG_COUNT];
    Esp32SpiState spi[ESP32_SPI_COUNT];
    Esp32ShaState sha;
    Esp32AesState aes;
    Esp32EfuseState efuse;
    DeviceState *eth;

    MemoryRegion cpu_specific_mem[ESP32_CPU_COUNT];

    uint32_t requested_reset;
} Esp32SocState;


static void esp32_dig_reset(void *opaque, int n, int level)
{
    Esp32SocState *s = ESP32_SOC(opaque);
    if (level) {
        esp32_dport_clear_ill_trap_state(&s->dport);
        s->requested_reset = ESP32_SOC_RESET_DIG;
        qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
    }
}

static void esp32_cpu_reset(void* opaque, int n, int level)
{
    Esp32SocState *s = ESP32_SOC(opaque);
    if (level) {
        s->requested_reset = (n == 0) ? ESP32_SOC_RESET_PROCPU : ESP32_SOC_RESET_APPCPU;
        /* Use different cause for APP CPU so that its reset doesn't cause QEMU to exit,
         * when -no-reboot option is given.
         */
        ShutdownCause cause = (n == 0) ? SHUTDOWN_CAUSE_GUEST_RESET : SHUTDOWN_CAUSE_SUBSYSTEM_RESET;
        qemu_system_reset_request(cause);
    }

}

static void esp32_timg_cpu_reset(void* opaque, int n, int level)
{
    Esp32SocState *s = ESP32_SOC(opaque);
    if (level) {
        s->requested_reset = (n == 0) ? ESP32_SOC_RESET_PROCPU : ESP32_SOC_RESET_APPCPU;
        /* Use different cause for APP CPU so that its reset doesn't cause QEMU to exit,
         * when -no-reboot option is given.
         */
        ShutdownCause cause = (n == 0) ? SHUTDOWN_CAUSE_GUEST_RESET : SHUTDOWN_CAUSE_SUBSYSTEM_RESET;
        s->rtc_cntl.reset_cause[n] = ESP32_TGWDT_CPU_RESET;
        qemu_system_reset_request(cause);
    }
}

static void esp32_timg_sys_reset(void* opaque, int n, int level)
{
    Esp32SocState *s = ESP32_SOC(opaque);
    if (level) {
        esp32_dport_clear_ill_trap_state(&s->dport);
        s->requested_reset = ESP32_SOC_RESET_DIG;
        for (int i = 0; i < ESP32_CPU_COUNT; ++i) {
            s->rtc_cntl.reset_cause[i] = ESP32_TG0WDT_SYS_RESET + n;
        }
        qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
    }
}

static void remove_cpu_watchpoints(XtensaCPU* xcs)
{
    for (int i = 0; i < MAX_NDBREAK; ++i) {
        if (xcs->env.cpu_watchpoint[i]) {
            cpu_watchpoint_remove_by_ref(CPU(xcs), xcs->env.cpu_watchpoint[i]);
            xcs->env.cpu_watchpoint[i] = NULL;
        }
    }
}

static void esp32_soc_reset(DeviceState *dev)
{
    Esp32SocState *s = ESP32_SOC(dev);

    uint32_t strap_mode = s->gpio.strap_mode;

    bool flash_boot_mode = ((strap_mode & 0x10) || (strap_mode & 0x1f) == 0x0c);

    if (s->requested_reset == 0) {
        s->requested_reset = ESP32_SOC_RESET_ALL;
    }
    if (s->requested_reset & ESP32_SOC_RESET_RTC) {
        device_reset(DEVICE(&s->rtc_cntl));
    }
    if (s->requested_reset & ESP32_SOC_RESET_PERIPH) {
        device_reset(DEVICE(&s->dport));
        device_reset(DEVICE(&s->sha));
        device_reset(DEVICE(&s->aes));
        device_reset(DEVICE(&s->gpio));
        for (int i = 0; i < ESP32_UART_COUNT; ++i) {
            device_reset(DEVICE(&s->uart));
        }
        for (int i = 0; i < ESP32_FRC_COUNT; ++i) {
            device_reset(DEVICE(&s->frc_timer[i]));
        }
        for (int i = 0; i < ESP32_TIMG_COUNT; ++i) {
            device_reset(DEVICE(&s->timg[i]));
        }
        s->timg[0].flash_boot_mode = flash_boot_mode;
        for (int i = 0; i < ESP32_SPI_COUNT; ++i) {
            device_reset(DEVICE(&s->spi[i]));
        }
        device_reset(DEVICE(&s->efuse));
        if (s->eth) {
            device_reset(s->eth);
        }
    }
    if (s->requested_reset & ESP32_SOC_RESET_PROCPU) {
        xtensa_select_static_vectors(&s->cpu[0].env, s->rtc_cntl.stat_vector_sel[0]);
        remove_cpu_watchpoints(&s->cpu[0]);
        cpu_reset(CPU(&s->cpu[0]));
    }
    if (s->requested_reset & ESP32_SOC_RESET_APPCPU) {
        xtensa_select_static_vectors(&s->cpu[1].env, s->rtc_cntl.stat_vector_sel[1]);
        remove_cpu_watchpoints(&s->cpu[1]);
        cpu_reset(CPU(&s->cpu[1]));
    }
    s->requested_reset = 0;

        // CPUXtensaState *env = &s->cpu[0].env;

        // env->pc = 0x400f55bc;
        // env->regs[0] = 0x800f5693;
        // env->regs[1] = 0x3ffbd2d0;
        // env->regs[2] = 0x3ffbb59c;
        // env->regs[3] = 0x0;
        // env->regs[4] = 0x3ffbb5f4;
        // env->regs[5] = 0x0;
        // env->regs[6] = 0x0;
        // env->regs[7] = 0x0;
        // env->regs[8] = 0x5c;
        // env->regs[9] = 0x3ffbd2b0;
        // env->regs[10] = 0x5c;
        // env->regs[11] = 0x5c;
        // env->regs[12] = 0x80;
        // env->regs[13] = 0x3ffbbfd4;
        // env->regs[14] = 0x1;
        // env->regs[15] = 0x4;


        // char *rom_binary = qemu_find_file(QEMU_FILE_TYPE_BIOS, "/home/max/thesis/esp32_http_server/dump.bin");
        // if (rom_binary == NULL) {
        //     error_report("Error: -bios argument not set, and ROM code binary not found");
        //     exit(1);
        // }

        // //address_space_rw(env->address_space_er, 0x3FF80000, MEMTXATTRS_UNSPECIFIED, (uint8_t *)rom_binary, 0x80000, true);

        // g_free(rom_binary);
}

static void esp32_cpu_stall(void* opaque, int n, int level)
{
    Esp32SocState *s = ESP32_SOC(opaque);

    bool stall;
    if (n == 0) {
        stall = s->rtc_cntl.cpu_stall_state[0];
    } else {
        stall = s->rtc_cntl.cpu_stall_state[1] || s->dport.appcpu_stall_state;
    }

    if (stall != s->cpu[n].env.runstall) {
        xtensa_runstall(&s->cpu[n].env, stall);
    }
}

static void esp32_clk_update(void* opaque, int n, int level)
{
    Esp32SocState *s = ESP32_SOC(opaque);
    if (!level) {
        return;
    }

    /* APB clock */
    uint32_t apb_clk_freq, cpu_clk_freq;
    if (s->rtc_cntl.soc_clk == ESP32_SOC_CLK_PLL) {
        const uint32_t cpu_clk_mul[] = {1, 2, 3};
        apb_clk_freq = s->rtc_cntl.pll_apb_freq;
        cpu_clk_freq = cpu_clk_mul[s->dport.cpuperiod_sel] * apb_clk_freq;
    } else {
        apb_clk_freq = s->rtc_cntl.xtal_apb_freq;
        cpu_clk_freq = apb_clk_freq;
    }
    qdev_prop_set_int32(DEVICE(&s->frc_timer), "apb_freq", apb_clk_freq);
    qdev_prop_set_int32(DEVICE(&s->timg[0]), "apb_freq", apb_clk_freq);
    qdev_prop_set_int32(DEVICE(&s->timg[1]), "apb_freq", apb_clk_freq);
    *(uint32_t*)(&s->cpu[0].env.config->clock_freq_khz) = cpu_clk_freq / 1000;
}

static void esp32_soc_add_periph_device(MemoryRegion *dest, void* dev, hwaddr dport_base_addr)
{
    MemoryRegion *mr = sysbus_mmio_get_region(SYS_BUS_DEVICE(dev), 0);
    memory_region_add_subregion_overlap(dest, dport_base_addr, mr, 0);
    MemoryRegion *mr_apb = g_new(MemoryRegion, 1);
    char *name = g_strdup_printf("mr-apb-0x%08x", (uint32_t) dport_base_addr);
    memory_region_init_alias(mr_apb, OBJECT(dev), name, mr, 0, memory_region_size(mr));
    memory_region_add_subregion_overlap(dest, dport_base_addr - DR_REG_DPORT_APB_BASE + APB_REG_BASE, mr_apb, 0);
    g_free(name);
}

static void esp32_soc_add_unimp_device(MemoryRegion *dest, const char* name, hwaddr dport_base_addr, size_t size)
{
    create_unimplemented_device(name, dport_base_addr, size);
    char * name_apb = g_strdup_printf("%s-apb", name);
    create_unimplemented_device(name_apb, dport_base_addr - DR_REG_DPORT_APB_BASE + APB_REG_BASE, size);
    g_free(name_apb);
}

static void esp32_soc_realize(DeviceState *dev, Error **errp)
{
    Esp32SocState *s = ESP32_SOC(dev);
    MachineState *ms = MACHINE(qdev_get_machine());

    const struct MemmapEntry *memmap = esp32_memmap;
    MemoryRegion *sys_mem = get_system_memory();

    MemoryRegion *dram = g_new(MemoryRegion, 1);
    MemoryRegion *iram = g_new(MemoryRegion, 1);
    MemoryRegion *drom = g_new(MemoryRegion, 1);
    MemoryRegion *irom = g_new(MemoryRegion, 1);
    MemoryRegion *icache0 = g_new(MemoryRegion, 1);
    MemoryRegion *icache1 = g_new(MemoryRegion, 1);
    MemoryRegion *rtcslow = g_new(MemoryRegion, 1);
    MemoryRegion *rtcfast_i = g_new(MemoryRegion, 1);
    MemoryRegion *rtcfast_d = g_new(MemoryRegion, 1);

    memory_region_init_rom(irom, NULL, "esp32.irom",
                           memmap[ESP32_MEMREGION_IROM].size, &error_fatal);
    memory_region_add_subregion(sys_mem, memmap[ESP32_MEMREGION_IROM].base, irom);

    memory_region_init_alias(drom, NULL, "esp32.drom", irom, 0x60000, memmap[ESP32_MEMREGION_DROM].size);
    memory_region_add_subregion(sys_mem, memmap[ESP32_MEMREGION_DROM].base, drom);

    memory_region_init_ram(dram, NULL, "esp32.dram",
                           memmap[ESP32_MEMREGION_DRAM].size, &error_fatal);
    memory_region_add_subregion(sys_mem, memmap[ESP32_MEMREGION_DRAM].base, dram);

    memory_region_init_ram(iram, NULL, "esp32.iram",
                           memmap[ESP32_MEMREGION_IRAM].size, &error_fatal);
    memory_region_add_subregion(sys_mem, memmap[ESP32_MEMREGION_IRAM].base, iram);

    memory_region_init_ram(icache0, NULL, "esp32.icache0",
                           memmap[ESP32_MEMREGION_ICACHE0].size, &error_fatal);
    memory_region_add_subregion(sys_mem, memmap[ESP32_MEMREGION_ICACHE0].base, icache0);

    memory_region_init_ram(icache1, NULL, "esp32.icache1",
                           memmap[ESP32_MEMREGION_ICACHE1].size, &error_fatal);
    memory_region_add_subregion(sys_mem, memmap[ESP32_MEMREGION_ICACHE1].base, icache1);

    memory_region_init_ram(rtcslow, NULL, "esp32.rtcslow",
                           memmap[ESP32_MEMREGION_RTCSLOW].size, &error_fatal);
    memory_region_add_subregion(sys_mem, memmap[ESP32_MEMREGION_RTCSLOW].base, rtcslow);

    /* RTC Fast memory is only accessible by the PRO CPU */

    memory_region_init_ram(rtcfast_i, NULL, "esp32.rtcfast_i",
                           memmap[ESP32_MEMREGION_RTCSLOW].size, &error_fatal);
    memory_region_add_subregion(&s->cpu_specific_mem[0], memmap[ESP32_MEMREGION_RTCFAST_I].base, rtcfast_i);

    memory_region_init_alias(rtcfast_d, NULL, "esp32.rtcfast_d", rtcfast_i, 0, memmap[ESP32_MEMREGION_RTCFAST_D].size);
    memory_region_add_subregion(&s->cpu_specific_mem[0], memmap[ESP32_MEMREGION_RTCFAST_D].base, rtcfast_d);

    for (int i = 0; i < ms->smp.cpus; ++i) {
        object_property_set_bool(OBJECT(&s->cpu[i]), true, "realized", &error_abort);
    }

    object_property_set_bool(OBJECT(&s->dport), true, "realized", &error_abort);

    memory_region_add_subregion(sys_mem, DR_REG_DPORT_BASE,
                                sysbus_mmio_get_region(SYS_BUS_DEVICE(&s->dport), 0));
    qdev_connect_gpio_out_named(DEVICE(&s->dport), ESP32_DPORT_APPCPU_RESET_GPIO, 0,
                                qdev_get_gpio_in_named(dev, ESP32_RTC_CPU_RESET_GPIO, 1));
    qdev_connect_gpio_out_named(DEVICE(&s->dport), ESP32_DPORT_APPCPU_STALL_GPIO, 0,
                                qdev_get_gpio_in_named(dev, ESP32_RTC_CPU_STALL_GPIO, 1));
    qdev_connect_gpio_out_named(DEVICE(&s->rtc_cntl), ESP32_DPORT_CLK_UPDATE_GPIO, 0,
                                qdev_get_gpio_in_named(dev, ESP32_RTC_CLK_UPDATE_GPIO, 0));
    DeviceState* intmatrix_dev = DEVICE(&s->dport.intmatrix);

    if (s->dport.flash_blk) {
        for (int i = 0; i < ESP32_CPU_COUNT; ++i) {
            Esp32CacheRegionState *drom0 = &s->dport.cache_state[i].drom0;
            memory_region_add_subregion_overlap(&s->cpu_specific_mem[i], drom0->base, &drom0->illegal_access_trap_mem, -2);
            memory_region_add_subregion_overlap(&s->cpu_specific_mem[i], drom0->base, &drom0->mem, -1);
            Esp32CacheRegionState *iram0 = &s->dport.cache_state[i].iram0;
            memory_region_add_subregion_overlap(&s->cpu_specific_mem[i], iram0->base, &iram0->illegal_access_trap_mem, -2);
            memory_region_add_subregion_overlap(&s->cpu_specific_mem[i], iram0->base, &iram0->mem, -1);
        }
    }

    object_property_set_bool(OBJECT(&s->sha), true, "realized", &error_abort);
    esp32_soc_add_periph_device(sys_mem, &s->sha, DR_REG_SHA_BASE);

    object_property_set_bool(OBJECT(&s->aes), true, "realized", &error_abort);
    esp32_soc_add_periph_device(sys_mem, &s->aes, DR_REG_AES_BASE);

    object_property_set_bool(OBJECT(&s->rtc_cntl), true, "realized", &error_abort);
    esp32_soc_add_periph_device(sys_mem, &s->rtc_cntl, DR_REG_RTCCNTL_BASE);

    qdev_connect_gpio_out_named(DEVICE(&s->rtc_cntl), ESP32_RTC_DIG_RESET_GPIO, 0,
                                qdev_get_gpio_in_named(dev, ESP32_RTC_DIG_RESET_GPIO, 0));
    qdev_connect_gpio_out_named(DEVICE(&s->rtc_cntl), ESP32_RTC_CLK_UPDATE_GPIO, 0,
                                qdev_get_gpio_in_named(dev, ESP32_RTC_CLK_UPDATE_GPIO, 0));
    for (int i = 0; i < ms->smp.cpus; ++i) {
        qdev_connect_gpio_out_named(DEVICE(&s->rtc_cntl), ESP32_RTC_CPU_RESET_GPIO, i,
                                    qdev_get_gpio_in_named(dev, ESP32_RTC_CPU_RESET_GPIO, i));
        qdev_connect_gpio_out_named(DEVICE(&s->rtc_cntl), ESP32_RTC_CPU_STALL_GPIO, i,
                                    qdev_get_gpio_in_named(dev, ESP32_RTC_CPU_STALL_GPIO, i));
    }

    object_property_set_bool(OBJECT(&s->gpio), true, "realized", &error_abort);
    esp32_soc_add_periph_device(sys_mem, &s->gpio, DR_REG_GPIO_BASE);

    for (int i = 0; i < ESP32_UART_COUNT; ++i) {
        const hwaddr uart_base[] = {DR_REG_UART_BASE, DR_REG_UART1_BASE, DR_REG_UART2_BASE};
        object_property_set_bool(OBJECT(&s->uart[i]), true, "realized", &error_abort);
        esp32_soc_add_periph_device(sys_mem, &s->uart[i], uart_base[i]);
        sysbus_connect_irq(SYS_BUS_DEVICE(&s->uart[i]), 0,
                           qdev_get_gpio_in(intmatrix_dev, ETS_UART0_INTR_SOURCE + i));
    }

    for (int i = 0; i < ESP32_FRC_COUNT; ++i) {
        object_property_set_bool(OBJECT(&s->frc_timer[i]), true, "realized", &error_abort);

        esp32_soc_add_periph_device(sys_mem, &s->frc_timer[i], DR_REG_FRC_TIMER_BASE + i * ESP32_FRC_TIMER_STRIDE);

        sysbus_connect_irq(SYS_BUS_DEVICE(&s->frc_timer[i]), 0,
                           qdev_get_gpio_in(intmatrix_dev, ETS_TIMER1_INTR_SOURCE + i));
    }

    for (int i = 0; i < ESP32_TIMG_COUNT; ++i) {
        s->timg[i].id = i;

        const hwaddr timg_base[] = {DR_REG_TIMERGROUP0_BASE, DR_REG_TIMERGROUP1_BASE};
        object_property_set_bool(OBJECT(&s->timg[i]), true, "realized", &error_abort);

        esp32_soc_add_periph_device(sys_mem, &s->timg[i], timg_base[i]);

        int timg_level_int[] = { ETS_TG0_T0_LEVEL_INTR_SOURCE, ETS_TG1_T0_LEVEL_INTR_SOURCE };
        int timg_edge_int[] = { ETS_TG0_T0_EDGE_INTR_SOURCE, ETS_TG1_T0_EDGE_INTR_SOURCE };
        for (Esp32TimgInterruptType it = TIMG_T0_INT; it < TIMG_INT_MAX; ++it) {
            sysbus_connect_irq(SYS_BUS_DEVICE(&s->timg[i]), it, qdev_get_gpio_in(intmatrix_dev, timg_level_int[i] + it));
            sysbus_connect_irq(SYS_BUS_DEVICE(&s->timg[i]), TIMG_INT_MAX + it, qdev_get_gpio_in(intmatrix_dev, timg_edge_int[i] + it));
        }

        qdev_connect_gpio_out_named(DEVICE(&s->timg[i]), ESP32_TIMG_WDT_CPU_RESET_GPIO, 0,
                                    qdev_get_gpio_in_named(dev, ESP32_TIMG_WDT_CPU_RESET_GPIO, i));
        qdev_connect_gpio_out_named(DEVICE(&s->timg[i]), ESP32_TIMG_WDT_SYS_RESET_GPIO, 0,
                                    qdev_get_gpio_in_named(dev, ESP32_TIMG_WDT_SYS_RESET_GPIO, i));
    }
    s->timg[0].wdt_en_at_reset = true;

    for (int i = 0; i < ESP32_SPI_COUNT; ++i) {
        const hwaddr spi_base[] = {
            DR_REG_SPI0_BASE, DR_REG_SPI1_BASE, DR_REG_SPI2_BASE, DR_REG_SPI3_BASE
        };
        object_property_set_bool(OBJECT(&s->spi[i]), true, "realized", &error_abort);

        esp32_soc_add_periph_device(sys_mem, &s->spi[i], spi_base[i]);

        sysbus_connect_irq(SYS_BUS_DEVICE(&s->spi[i]), 0,
                           qdev_get_gpio_in(intmatrix_dev, ETS_SPI0_INTR_SOURCE + i));
    }

    object_property_set_bool(OBJECT(&s->rng), true, "realized", &error_abort);
    esp32_soc_add_periph_device(sys_mem, &s->rng, ESP32_RNG_BASE);

    object_property_set_bool(OBJECT(&s->efuse), true, "realized", &error_abort);
    esp32_soc_add_periph_device(sys_mem, &s->efuse, DR_REG_EFUSE_BASE);
    sysbus_connect_irq(SYS_BUS_DEVICE(&s->efuse), 0,
                       qdev_get_gpio_in(intmatrix_dev, ETS_EFUSE_INTR_SOURCE));


    //esp32_soc_add_unimp_device(sys_mem, "esp32.aes", DR_REG_AES_BASE, 0x1000);
    esp32_soc_add_unimp_device(sys_mem, "esp32.rsa", DR_REG_RSA_BASE, 0x1000);
    esp32_soc_add_unimp_device(sys_mem, "esp32.analog", DR_REG_ANA_BASE, 0x1000);
    esp32_soc_add_unimp_device(sys_mem, "esp32.rtcio", DR_REG_RTCIO_BASE, 0x400);
    esp32_soc_add_unimp_device(sys_mem, "esp32.rtcio", DR_REG_SENS_BASE, 0x400);
    esp32_soc_add_unimp_device(sys_mem, "esp32.iomux", DR_REG_IO_MUX_BASE, 0x2000);
    esp32_soc_add_unimp_device(sys_mem, "esp32.hinf", DR_REG_HINF_BASE, 0x1000);
    esp32_soc_add_unimp_device(sys_mem, "esp32.slc", DR_REG_SLC_BASE, 0x1000);
    esp32_soc_add_unimp_device(sys_mem, "esp32.slchost", DR_REG_SLCHOST_BASE, 0x1000);
    esp32_soc_add_unimp_device(sys_mem, "esp32.apbctrl", DR_REG_APB_CTRL_BASE, 0x1000);
    esp32_soc_add_unimp_device(sys_mem, "esp32.i2s0", DR_REG_I2S_BASE, 0x1000);
    esp32_soc_add_unimp_device(sys_mem, "esp32.bt", DR_REG_BT_BASE, 0x2000);
    esp32_soc_add_unimp_device(sys_mem, "esp32.i2s1", DR_REG_I2S1_BASE, 0x1000);
    esp32_soc_add_unimp_device(sys_mem, "esp32.i2c0", DR_REG_I2C_EXT_BASE, 0x1000);
    esp32_soc_add_unimp_device(sys_mem, "esp32.i2c1", DR_REG_I2C1_EXT_BASE, 0x1000);
    esp32_soc_add_unimp_device(sys_mem, "esp32.pwm1", DR_REG_PWM1_BASE, 0x1000);
    esp32_soc_add_unimp_device(sys_mem, "esp32.pwm2", DR_REG_PWM2_BASE, 0x1000);
    esp32_soc_add_unimp_device(sys_mem, "esp32.pwm3", DR_REG_PWM3_BASE, 0x4000);

    esp32_soc_add_unimp_device(sys_mem, "esp32.ledc", DR_REG_LEDC_BASE, 0x1000);

    qemu_register_reset((QEMUResetHandler*) esp32_soc_reset, dev);
}

static void esp32_soc_init(Object *obj)
{
    Esp32SocState *s = ESP32_SOC(obj);
    MachineState *ms = MACHINE(qdev_get_machine());
    char name[16];

    MemoryRegion *system_memory = get_system_memory();

    for (int i = 0; i < ms->smp.cpus; ++i) {
        snprintf(name, sizeof(name), "cpu%d", i);
        object_initialize_child(obj, name, &s->cpu[i], sizeof(s->cpu[i]), TYPE_ESP32_CPU, &error_abort, NULL);

        const uint32_t cpuid[ESP32_CPU_COUNT] = { 0xcdcd, 0xabab };
        s->cpu[i].env.sregs[PRID] = cpuid[i];

        snprintf(name, sizeof(name), "cpu%d-mem", i);
        memory_region_init(&s->cpu_specific_mem[i], NULL, name, UINT32_MAX);

        CPUState* cs = CPU(&s->cpu[i]);
        cs->num_ases = 1;
        cpu_address_space_init(cs, 0, "cpu-memory", &s->cpu_specific_mem[i]);

        MemoryRegion *cpu_view_sysmem = g_new(MemoryRegion, 1);
        snprintf(name, sizeof(name), "cpu%d-sysmem", i);
        memory_region_init_alias(cpu_view_sysmem, NULL, name, system_memory, 0, UINT32_MAX);
        memory_region_add_subregion_overlap(&s->cpu_specific_mem[i], 0, cpu_view_sysmem, 0);
        cs->memory = &s->cpu_specific_mem[i];
    }

    for (int i = 0; i < ESP32_UART_COUNT; ++i) {
        snprintf(name, sizeof(name), "uart%d", i);
        object_initialize_child(obj, name, &s->uart[i], sizeof(s->uart[i]),
                                TYPE_ESP32_UART, &error_abort, NULL);
    }

    object_property_add_alias(obj, "serial0", OBJECT(&s->uart[0]), "chardev",
                              &error_abort);

    object_initialize_child(obj, "gpio", &s->gpio, sizeof(s->gpio),
                                TYPE_ESP32_GPIO, &error_abort, NULL);

    object_initialize_child(obj, "dport", &s->dport, sizeof(s->dport),
                            TYPE_ESP32_DPORT, &error_abort, NULL);

    object_initialize_child(obj, "rtc_cntl", &s->rtc_cntl, sizeof(s->rtc_cntl),
                            TYPE_ESP32_RTC_CNTL, &error_abort, NULL);

    for (int i = 0; i < ESP32_FRC_COUNT; ++i) {
        snprintf(name, sizeof(name), "frc%d", i);
        object_initialize_child(obj, name, &s->frc_timer[i], sizeof(s->frc_timer[i]),
                                TYPE_ESP32_FRC_TIMER, &error_abort, NULL);
    }

    for (int i = 0; i < ESP32_TIMG_COUNT; ++i) {
        snprintf(name, sizeof(name), "timg%d", i);
        object_initialize_child(obj, name, &s->timg[i], sizeof(s->timg[i]),
                                TYPE_ESP32_TIMG, &error_abort, NULL);
    }

    for (int i = 0; i < ESP32_SPI_COUNT; ++i) {
        snprintf(name, sizeof(name), "spi%d", i);
        object_initialize_child(obj, name, &s->spi[i], sizeof(s->spi[i]),
                                TYPE_ESP32_SPI, &error_abort, NULL);
    }

    object_initialize_child(obj, "rng", &s->rng, sizeof(s->rng),
                            TYPE_ESP32_RNG, &error_abort, NULL);

    object_initialize_child(obj, "sha", &s->sha, sizeof(s->sha),
                                TYPE_ESP32_SHA, &error_abort, NULL);

    object_initialize_child(obj, "aes", &s->aes, sizeof(s->aes),
                                TYPE_ESP32_AES, &error_abort, NULL);

    object_initialize_child(obj, "efuse", &s->efuse, sizeof(s->efuse),
                                    TYPE_ESP32_EFUSE, &error_abort, NULL);


    qdev_init_gpio_in_named(DEVICE(s), esp32_dig_reset, ESP32_RTC_DIG_RESET_GPIO, 1);
    qdev_init_gpio_in_named(DEVICE(s), esp32_cpu_reset, ESP32_RTC_CPU_RESET_GPIO, ESP32_CPU_COUNT);
    qdev_init_gpio_in_named(DEVICE(s), esp32_cpu_stall, ESP32_RTC_CPU_STALL_GPIO, ESP32_CPU_COUNT);
    qdev_init_gpio_in_named(DEVICE(s), esp32_clk_update, ESP32_RTC_CLK_UPDATE_GPIO, 1);
    qdev_init_gpio_in_named(DEVICE(s), esp32_timg_cpu_reset, ESP32_TIMG_WDT_CPU_RESET_GPIO, 2);
    qdev_init_gpio_in_named(DEVICE(s), esp32_timg_sys_reset, ESP32_TIMG_WDT_SYS_RESET_GPIO, 2);
}

static Property esp32_soc_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static void esp32_soc_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->reset = esp32_soc_reset;
    dc->realize = esp32_soc_realize;
    dc->props = esp32_soc_properties;
}

static const TypeInfo esp32_soc_info = {
    .name = TYPE_ESP32_SOC,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(Esp32SocState),
    .instance_init = esp32_soc_init,
    .class_init = esp32_soc_class_init
};

static void esp32_soc_register_types(void)
{
    type_register_static(&esp32_soc_info);
}

type_init(esp32_soc_register_types)


static uint64_t translate_phys_addr(void *opaque, uint64_t addr)
{
    XtensaCPU *cpu = opaque;

    return cpu_get_phys_page_debug(CPU(cpu), addr);
}

static void esp32_machine_init_spi_flash(MachineState *machine, Esp32SocState *s, BlockBackend* blk)
{
    /* "main" flash chip is attached to SPI1 */
    DeviceState *spi_master = DEVICE(&s->spi[1]);
    SSIBus* spi_bus = (SSIBus *)qdev_get_child_bus(spi_master, "spi");
    DeviceState *flash_dev = ssi_create_slave_no_init(spi_bus, "gd25q32");
    qdev_prop_set_drive(flash_dev, "drive", blk, &error_fatal);
    qdev_init_nofail(flash_dev);
    qdev_connect_gpio_out_named(spi_master, SSI_GPIO_CS, 0,
                                qdev_get_gpio_in_named(flash_dev, SSI_GPIO_CS, 0));
}

static void esp32_machine_init_openeth(Esp32SocState *ss)
{
    SysBusDevice *sbd;
    NICInfo *nd = &nd_table[0];
    MemoryRegion* sys_mem = get_system_memory();
    hwaddr reg_base = DR_REG_EMAC_BASE;
    hwaddr desc_base = reg_base + 0x400;
    qemu_irq irq = qdev_get_gpio_in(DEVICE(&ss->dport.intmatrix), ETS_ETH_MAC_INTR_SOURCE);

    const char* type_openeth = "open_eth";
    if (nd->used && nd->model && strcmp(nd->model, type_openeth) == 0) {
        DeviceState* open_eth_dev = qdev_create(NULL, type_openeth);
        ss->eth = open_eth_dev;
        qdev_set_nic_properties(open_eth_dev, nd);
        qdev_init_nofail(open_eth_dev);

        sbd = SYS_BUS_DEVICE(open_eth_dev);
        sysbus_connect_irq(sbd, 0, irq);
        memory_region_add_subregion(sys_mem, reg_base, sysbus_mmio_get_region(sbd, 0));
        memory_region_add_subregion(sys_mem, desc_base, sysbus_mmio_get_region(sbd, 1));
    }
}

typedef struct Esp32WifiState {

    uint32_t reg[0x100000];
    int i2c_block;
    int i2c_reg;
} Esp32WifiState;

typedef struct Esp32PhyState {

    uint32_t reg[0x10000];
    int i2c_block;
    int i2c_reg;
} Esp32PhyState;

static unsigned char guess=0x98;


__attribute__((unused)) static uint64_t esp_wifi_read(void *opaque, hwaddr addr,
        unsigned size)
{

    Esp32WifiState *s=opaque;

    //printf("wifi read %" PRIx64 " \n",addr);


        // WDEV_RND_REG

        if (addr==0x35144) {
            static int rr=47;
             rr=rr*735%65535;
             //printf("WDEV_RND_REG\n");
            return (rr);
        }
    
    // e004   rom i2c 
    // e044   rom i2c
/*
    uint8_t rom_i2c_readReg(uint8_t block, uint8_t host_id, uint8_t reg_add);
    uint8_t rom_i2c_readReg_Mask(uint8_t block, uint8_t host_id, uint8_t reg_add, uint8_t msb, uint8_t lsb);
    void rom_i2c_writeReg(uint8_t block, uint8_t host_id, uint8_t reg_add, uint8_t pData);
    void rom_i2c_writeReg_Mask(uint8_t block, uint8_t host_id, uint8_t reg_add, uint8_t msb, uint8_t lsb, uint8_t indata);
stack 0x3ffe3cc0,
p/x $a2-7
0x62,0x01,0x06,  0x03,0x00, -256 (0xffffff00)
#0  0x400041c3 in rom_i2c_readReg_Mask ()
(gdb) p/x $a2
$35 = 0x62
(gdb) p/x $a3
$36 = 0x1
(gdb) p/x $a4
$37 = 0x6
wifi read e044 
wifi write e044,fffff0ff 
wifi read e044 
wifi write e044,fffff7ff 
wifi read e004 
wifi write e004,662 
wifi read e004 
wifi read e004 
get_rf_freq_init
#-1 #0  0x40004148 in rom_i2c_readReg ()
#0  0x400041c3 in rom_i2c_readReg_Mask ()
#1  0x40085b3c in get_rf_freq_cap (freq=<optimized out>, freq_offset=0, x_reg=<optimized out>,
    cap_array=0x3ffe3d0f "") at phy_chip_v7_ana.c:810
#2  0x40085cd9 in get_rf_freq_init () at phy_chip_v7_ana.c:900
#3  0x40086aae in set_chan_freq_hw_init (tx_freq_offset=2 '\002', rx_freq_offset=4 '\004') at phy_chip_v7_ana.c:1492
#4  0x40086d01 in rf_init () at phy_chip_v7_ana.c:795
#5  0x40089b6a in register_chipv7_phy (init_param=<optimized out>, rf_cal_data=0x3ffb79e8 "", rf_cal_level=2 '\002')
#6  0x400d13f0 in esp_phy_init (init_data=0x3f401828 <phy_init_data>, mode=PHY_RF_CAL_FULL,
    calibration_data=0x3ffb79e8) at /home/olas/esp/esp-idf/components/esp32/./phy_init.c:50
#7  0x400d0e43 in do_phy_init () at /home/olas/esp/esp-idf/components/esp32/./cpu_start.c:295
rom_i2c_reg block 0x62 reg 0x6 02
bf
4f
88
77
b4
00
02
00
00
07
b0
08
00
00
00
00
rom_i2c_reg block 0x67 reg 0x6 57
00
b5
bf
41
43
55
57
55
57
71
10
71
10
00
ea
ec
*/


/*    
rom_i2c_reg block 0x67 reg 0x6 57
*/

    if (addr==0xe004) {
        //fprintf(stderr,"(qemu ret) internal i2c block 0x62 %02x %d\n",s->i2c_reg,guess );
    }

    if (s->i2c_block==0x67) {
        if (addr==0xe004) {
            //fprintf(stderr,"(qemu ret) internal i2c block 0x67 %02x\n",s->i2c_reg );            
            switch (s->i2c_reg) {
                case 0: return 0x00;
                case 1: return 0xb5;
                case 2: return 0xbf;
                case 3: return 0x41;
                case 4: return 0x43;
                case 5: return 0x55;
                case 6: return 0x57;
                case 7: return 0x55;
                case 8: return 0x57;
                case 9: return 0x71;
                case 10: return 0x10;
                case 11: return 0x71;
                case 12: return 0x10;
                case 13: return 0x00;
                case 14: return 0xea;
                case 15: return 0xec;   
                default: return 0xff;
            }
        }
    }



    if (s->i2c_block==0x62) {
        if (addr==0xe004) {

            //fprintf(stderr,"(qemu ret) internal i2c block 0x62 %02x %d\n",s->i2c_reg,guess );
            
            switch (s->i2c_reg) {
                case 0: return 0xbf;
                case 1: return 0x4f;
                case 2: return 0x88;
                case 3: return 0x77;
                case 4: return 0xb4;
                case 5: return 0x00;
                case 6: return 0x02;
                case 7: return (100*guess++);
                case 8: return 0x00;
                case 9: return 0x07;
                case 10: return 0xb0;
                case 11: return 0x08;

                default: return 0xff;
            }
        }
    }

    switch(addr) {
    case 0x0:
        printf("0x0000000000000000\n");
        break;
    case 0x40:
        return 0x00A40100;
        break;
    case 0x10000:
        printf("0x10000 UART 1 AHB FIFO ???\n");
        break;
    case 0xe04c:
        return 0xffffffff;
        break;
    case 0xe0c4:
        return 0xffffffff;
        break;
    case 0x607c:
        return 0xffffffff;
        break;
    case 0x1c018:
        //return 0;
        return 0x11E15054;
        //return 0x80000000;
        // Some difference should land between these values
              // 0x980020c0;
              // 0x980020b0;
        //return   0x800000;
        break;
    case 0x33c00:
        return 0x0002BBED;
        break;
        //return 0x01000000;
        {
         //static int test=0x0002BBED;
         //printf("(qemu) %d\n",test);
         //return (test--);
        }
        //return 0;
        //return 
    case 0x33d24:
        return 1;
    // case 0xe008:
    //     return 1;
    // case 0xe168:
    //     return 1;
    // case 0x1d008:
    //     return 1;
    }
    if(addr < 0x100000) {
        return(s->reg[addr]);
    } else {
        return 0x0;
    }
}

extern void esp32_i2c_fifo_dataSet(int offset,unsigned int data);

extern void esp32_i2c_interruptSet(qemu_irq new_irq);


pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

__attribute__((unused)) static void esp_wifi_write(void *opaque, hwaddr addr,
        uint64_t val, unsigned size)
{
    Esp32WifiState *s=opaque;

    //printf("wifi write %" PRIx64 ",%" PRIx64 " \n",addr,val);


    // 0x01301c
    if (addr>=0x01301c && addr<=0x01311c) {        
        fprintf(stdout,"i2c apb write %" PRIx64 ",%" PRIx64 " \n",addr,val);
        //esp32_i2c_fifo_dataSet((addr-0x01301c)/4,val);
    }



    pthread_mutex_lock(&mutex);


    if (addr==0xe004) {
      s->i2c_block= val & 0xff;
      s->i2c_reg= (val>>8) & 0xff;
      //if (s->i2c_block!=0x62 && s->i2c_block!=0x67) 
      {
         //fprintf(stderr,"(qemu) internal i2c %02x %d\n",s->i2c_block,s->i2c_reg );
      }
    }


    if (addr==0x0) {
        // FIFO UART NUM 0 --  UART_FIFO_AHB_REG
        // if (gdb_serial[0]->gdb_serial_connected) {
        //     gdb_serial[0]->gdb_serial_data[gdb_serial[0]->gdb_serial_buff_tx%MAX_GDB_BUFF]=(char)val;
        //     gdb_serial[0]->gdb_serial_buff_tx++;
        // }
        fprintf(stdout,"ZZZ %ld",val);
        //uint8_t buf[1] = { val };
        //qemu_chr_fe_write(silly_serial, buf, 1);

    } else if (addr==0x10000) {
        // FIFO UART NUM 1 --  UART_FIFO_AHB_REG
        // if (gdb_serial[1]->gdb_serial_connected) {
        //     gdb_serial[1]->gdb_serial_data[gdb_serial[1]->gdb_serial_buff_tx%MAX_GDB_BUFF]=(char)val;
        //     gdb_serial[1]->gdb_serial_buff_tx++;
        // }

        fprintf(stdout,"YY %ld",val);
    } else if (addr==0x2e000) {
        // FIFO UART NUM 2  -- UART_FIFO_AHB_REG
        // if (gdb_serial[2]->gdb_serial_connected) {
        //     gdb_serial[2]->gdb_serial_data[gdb_serial[2]->gdb_serial_buff_tx%MAX_GDB_BUFF]=(char)val;
        //     gdb_serial[2]->gdb_serial_buff_tx++;
        // }
        fprintf(stdout,"XX %ld",val);
    }

    pthread_mutex_unlock(&mutex);
    if(addr < 0x100000) {
        s->reg[addr]=val;
    }
}

__attribute__((unused)) static uint64_t esp_phy_read(void *opaque, hwaddr addr,
        unsigned size) 
{

    //Esp32PhyState *s=opaque;

    printf("phy read %" PRIx64 " \n",addr);

    return 1;
}

__attribute__((unused))static void esp_phy_write(void *opaque, hwaddr addr,
        uint64_t val, unsigned size) 
{
    //Esp32PhyState *s=opaque;
    printf("phy write %" PRIx64 ",%" PRIx64 " \n",addr,val);
}
__attribute__((unused))static void esp32_machine_init_wifi(Esp32SocState *ss) 
{
    static const MemoryRegionOps esp_wifi_ops = {
    .read = esp_wifi_read,
    .write = esp_wifi_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    };

    Esp32WifiState *ws = g_malloc(sizeof(Esp32WifiState));


    MemoryRegion* sys_mem = get_system_memory();

    static MemoryRegion *wifi_io;
    wifi_io = g_malloc(sizeof(*wifi_io));
    memory_region_init_io(wifi_io, NULL, &esp_wifi_ops, ws, "esp32.wifi",
                          0x80000);

    memory_region_add_subregion(sys_mem, 0x60000000, wifi_io);



    static const MemoryRegionOps esp_phy_ops = {
    .read = esp_phy_read,
    .write = esp_phy_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    };

    Esp32PhyState *ps = g_malloc(sizeof(Esp32PhyState));

    static MemoryRegion *phy_io;
    phy_io = g_malloc(sizeof(*phy_io));
    memory_region_init_io(phy_io, NULL, &esp_phy_ops, ps, "esp32.phy",
                          0x1FFF);

    memory_region_add_subregion(sys_mem, DR_REG_PHY_BASE, phy_io);


}

static void esp32_machine_inst_init(MachineState *machine)
{
    Esp32SocState *s = g_new0(Esp32SocState, 1);

    BlockBackend* blk = NULL;
    DriveInfo *dinfo = drive_get_next(IF_MTD);
    if (dinfo) {
        qemu_log("Adding SPI flash device\n");
        blk = blk_by_legacy_dinfo(dinfo);
    } else {
        qemu_log("Not initializing SPI Flash\n");
    }

    object_initialize_child(OBJECT(machine), "soc", s, sizeof(*s),
                            TYPE_ESP32_SOC, &error_abort, NULL);

    if (blk) {
        s->dport.flash_blk = blk;
    }
    qdev_prop_set_chr(DEVICE(s), "serial0", serial_hd(0));

    object_property_set_bool(OBJECT(s), true, "realized", &error_abort);

    if (blk) {
        esp32_machine_init_spi_flash(machine, s, blk);
    }

    esp32_machine_init_openeth(s);

    esp32_machine_init_wifi(s);


    /* Need MMU initialized prior to ELF loading,
     * so that ELF gets loaded into virtual addresses
     */
    cpu_reset(CPU(&s->cpu[0]));

    const char *load_elf_filename = NULL;
    if (machine->firmware) {
        load_elf_filename = machine->firmware;
    }
    if (machine->kernel_filename) {
        qemu_log("Warning: both -bios and -kernel arguments specified. Only loading the the -kernel file.\n");
        load_elf_filename = machine->kernel_filename;
    }

    if (load_elf_filename) {
        uint64_t elf_entry;
        uint64_t elf_lowaddr;
        int success = load_elf(load_elf_filename, NULL,
                               translate_phys_addr, &s->cpu[0],
                               &elf_entry, &elf_lowaddr,
                               NULL, 0, EM_XTENSA, 0, 0);
        if (success > 0) {
            s->cpu[0].env.pc = elf_entry;
        }
    } else {
        char *rom_binary = qemu_find_file(QEMU_FILE_TYPE_BIOS, "esp32-r0-rom.bin");
        if (rom_binary == NULL) {
            error_report("Error: -bios argument not set, and ROM code binary not found");
            exit(1);
        }

        int size = load_image_targphys(rom_binary, esp32_memmap[ESP32_MEMREGION_IROM].base, esp32_memmap[ESP32_MEMREGION_IROM].size);
        if (size < 0) {
            error_report("Error: could not load ROM binary '%s'", rom_binary);
            exit(1);
        }
        g_free(rom_binary);
    }



        // CPUXtensaState *env = &s->cpu[0].env;

        // env->pc = 0x400f55bc;
        // env->regs[0] = 0x800f5693;
        // env->regs[1] = 0x3ffbd2d0;
        // env->regs[2] = 0x3ffbb59c;
        // env->regs[3] = 0x0;
        // env->regs[4] = 0x3ffbb5f4;
        // env->regs[5] = 0x0;
        // env->regs[6] = 0x0;
        // env->regs[7] = 0x0;
        // env->regs[8] = 0x5c;
        // env->regs[9] = 0x3ffbd2b0;
        // env->regs[10] = 0x5c;
        // env->regs[11] = 0x5c;
        // env->regs[12] = 0x80;
        // env->regs[13] = 0x3ffbbfd4;
        // env->regs[14] = 0x1;
        // env->regs[15] = 0x4;


        // char *rom_binary = qemu_find_file(QEMU_FILE_TYPE_BIOS, "/home/max/thesis/esp32_http_server/dump.bin");
        // if (rom_binary == NULL) {
        //     error_report("Error: -bios argument not set, and ROM code binary not found");
        //     exit(1);
        // }

        // address_space_rw(env->address_space_er, 0x3FF80000, MEMTXATTRS_UNSPECIFIED, (uint8_t *)rom_binary, 0x80000, true);

        // g_free(rom_binary);

}

/* Initialize machine type */
static void esp32_machine_init(MachineClass *mc)
{
    mc->desc = "Espressif ESP32 machine";
    mc->init = esp32_machine_inst_init;
    mc->max_cpus = 2;
    mc->default_cpus = 2;
}

DEFINE_MACHINE("esp32", esp32_machine_init)

