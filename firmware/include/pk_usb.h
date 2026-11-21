// USB composite device: HID (CTAPHID) + CDC (management/recovery).
#pragma once

#include <stdint.h>
#include <stddef.h>

class USBCDC;

namespace usb {

USBCDC& cdc();
bool begin(const char* serial);
bool hid_ready();
bool send_report(const uint8_t* data, size_t len, uint32_t timeout_ms = 50);
// Blocks up to timeout_ms for a 64-byte HID OUT report from the host.
bool pop_report(uint8_t out[64], uint32_t timeout_ms);

}  // namespace usb
