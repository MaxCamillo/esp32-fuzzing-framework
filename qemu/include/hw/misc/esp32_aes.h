#pragma once

#include "hw/hw.h"
#include "hw/sysbus.h"
#include "hw/registerfields.h"
#include "hw/misc/esp32_reg.h"

#define TYPE_ESP32_AES "misc.esp32.aes"
#define ESP32_AES(obj) OBJECT_CHECK(Esp32AesState, (obj), TYPE_ESP32_AES)

#define ESP32_AES_TEXT_REG_CNT    4
#define ESP32_AES_KEY_REG_CNT    8

typedef struct Esp32AESState {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    uint32_t text[ESP32_AES_TEXT_REG_CNT];
    uint32_t key[ESP32_AES_KEY_REG_CNT];
    uint8_t mode;
} Esp32AesState;

