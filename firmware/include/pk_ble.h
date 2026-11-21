// FIDO BLE transport (GATT service 0xFFFD) on top of Bluedroid.
#pragma once

#include <stdint.h>
#include <stddef.h>

namespace ble {
void begin(const char* name = "TechXPassKey");
void poll();
void keepalive();
bool connected();
}  // namespace ble
