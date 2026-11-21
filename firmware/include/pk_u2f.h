// CTAP1 / U2F raw message handler (over CTAPHID MSG).
#pragma once

#include <stdint.h>
#include <stddef.h>

namespace pk {
namespace u2f {
size_t handle(const uint8_t* req, size_t len, uint8_t* resp, size_t cap, uint8_t* status);
}
}  // namespace pk
