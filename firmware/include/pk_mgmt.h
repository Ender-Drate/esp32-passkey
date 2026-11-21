// Binary management protocol over USB CDC (the COM port).
//
// Frame: A5 5A | ver(1) | cmd(1) | seq(1) | len(2 LE) | payload | crc16(2 LE)
// CRC16-CCITT (init 0xFFFF) over ver..payload.
#pragma once

#include <stdint.h>
#include <stddef.h>

namespace mgmt {

void begin();
void poll();
void log(const char* fmt, ...);

}  // namespace mgmt
