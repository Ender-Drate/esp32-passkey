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

// True once a second board has ever completed pairing.  After this the main
// board never hands out the link key again; replacing the second board
// requires the explicit replace flow (old board verified first).
bool paired();

// "Replace second board" flow.  beginReplace() only succeeds while the old
// board is currently proving presence.  The old key is kept until a new board
// proves the pending key, so a timeout/cancel leaves the old board working
// and never touches credentials.
bool beginReplace();
void cancelReplace();
bool replaceMode();

// Erase the link key on this board and start pairing a new second board.
void forget();

// "ok" | "waiting" | "mismatch" | "pairing"
const char* state();

uint32_t lastProofAgeMs();

}  // namespace interlock
}  // namespace pk
