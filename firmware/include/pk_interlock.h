// Second-board interlock: challenge/response over UART (GPIO16/17).
#pragma once

#include <stdint.h>

namespace pk {
namespace interlock {

void begin();
void poll();

// True only while the second board has proven possession of the link key
// within the last PK_IL_PROOF_TIMEOUT_MS.
bool ready();

// Erase the link key on this board and start pairing a new second board.
void forget();

// "ok" | "waiting" | "mismatch" | "pairing"
const char* state();

uint32_t lastProofAgeMs();

}  // namespace interlock
}  // namespace pk
