/*
 * ESP32 AES accelerator
 *
 * Copyright (c) 2019 Espressif Systems (Aesnghai) Co. Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 or
 * (at your option) any later version.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/error-report.h"
#include "crypto/hash.h"
#include "qapi/error.h"
#include "hw/hw.h"
#include "hw/sysbus.h"
#include "hw/registerfields.h"
#include "hw/boards.h"
#include "hw/misc/esp32_aes.h"

#define ESP32_AES_REGS_SIZE 0x1000

/* QEMU hash API includes only the "qcrypto_hash_bytes" function which takes
 * bytes as input, and calculates the digest. It doesn't allow "updating"
 * the state multiple times with blocks of input. Therefore we collect all
 * the input in an array (s->full_text) and when AES_X_LOAD_REG is set,
 * we call "qcrypto_hash_bytes" to get the digest.
 */



static uint64_t esp32_aes_read(void *opaque, hwaddr addr, unsigned int size)
{
    Esp32AesState *s = ESP32_AES(opaque);
    uint64_t r = 0;
    switch (addr) {
    case 4:
        r = 1;
        s->text[0] = r;
        break;
    }
    return r;
}

static void esp32_aes_write(void *opaque, hwaddr addr,
                       uint64_t value, unsigned int size)
{
    Esp32AesState *s = ESP32_AES(opaque);
    switch (addr) {
    case 0 :
        s->text[0] = value;
        break;
    case 0x10 ... 0x2C: 
        s->key[(addr - 0x10) / sizeof(uint32_t)] = value;
        break;
    
    case 0x30 ... 0x3C: 
        s->text[(addr - 0x30) / sizeof(uint32_t)] = value;
        break;
    
    case 0x08:
        s->mode = value & 0x8;
        break;
    }
}

static const MemoryRegionOps esp32_aes_ops = {
    .read =  esp32_aes_read,
    .write = esp32_aes_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static void esp32_aes_reset(DeviceState *dev)
{
    Esp32AesState *s = ESP32_AES(dev);
    s->mode = 0;
}

static void esp32_aes_init(Object *obj)
{
    Esp32AesState *s = ESP32_AES(obj);
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);

    memory_region_init_io(&s->iomem, obj, &esp32_aes_ops, s,
                          TYPE_ESP32_AES, ESP32_AES_REGS_SIZE);
    sysbus_init_mmio(sbd, &s->iomem);
}

static void esp32_aes_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->reset = esp32_aes_reset;
}

static const TypeInfo esp32_aes_info = {
    .name = TYPE_ESP32_AES,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(Esp32AesState),
    .instance_init = esp32_aes_init,
    .class_init = esp32_aes_class_init
};

static void esp32_aes_register_types(void)
{
    type_register_static(&esp32_aes_info);
}

type_init(esp32_aes_register_types)
