#include "pk_led.h"

#include <Arduino.h>

#include "pk_config.h"

namespace led {

static uint32_t g_until = 0;
static uint8_t g_idleR = 0, g_idleG = 0, g_idleB = 10;

void set(uint8_t r, uint8_t g, uint8_t b) {
    neopixelWrite(PK_LED_PIN, r, g, b);
}

void init() {
    set(0, 0, 0);
}

void idle() {
    g_until = 0;
    set(g_idleR, g_idleG, g_idleB);
}

void wait_touch() {
    g_until = 0;
    set(0, 0, 40);
}

void success() {
    set(0, 60, 0);
    g_until = millis() + 400;
}

void error() {
    set(80, 0, 0);
    g_until = millis() + 800;
}

void wink() {
    set(0, 60, 30);
    g_until = millis() + 600;
}

void poll() {
    static bool lastPressed = false;
    if (g_until && (int32_t)(millis() - g_until) >= 0) {
        g_until = 0;
        idle();
    }
    // Breathing / heartbeat while waiting for a touch.
    (void)lastPressed;
}

}  // namespace led
