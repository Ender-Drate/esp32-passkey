// CTAP2.1 command dispatcher.
#pragma once

#include <stdint.h>
#include <stddef.h>

namespace pk {
namespace ctap {

void init();
// Returns the CBOR payload length written to resp (status is set separately).
size_t handle(uint8_t cmd, const uint8_t* req, size_t len, uint8_t* resp, size_t cap, uint8_t* status);
void wink();
bool pin_is_set();
uint8_t pin_retries();
void factory_reset();
void poll();
bool user_presence(uint32_t timeout_ms);
bool check_pin_string(const char* pin, size_t len);

}  // namespace ctap
}  // namespace pk
