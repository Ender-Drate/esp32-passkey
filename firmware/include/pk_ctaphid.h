// CTAPHID transport (FIDO HID framing) over the USB HID interface.
#pragma once

#include <stdint.h>
#include <stddef.h>

namespace ctaphid {

bool init();
void poll();
void keepalive();
bool cancelled();
uint32_t active_cid();
// Called from the USB task for every OUT report, before queueing.
void note_output_report(const uint8_t* pkt);
bool send_raw(uint32_t cid, uint8_t cmd, const uint8_t* data, size_t len);

}  // namespace ctaphid
