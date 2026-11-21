#pragma once

#include <stdint.h>

namespace led {
void init();
void set(uint8_t r, uint8_t g, uint8_t b);
void idle();
void wait_touch();
void success();
void error();
void wink();
void poll();
}  // namespace led
