#include "pk_led.h"

#include <Arduino.h>

#include "pk_config.h"

namespace led {

static uint32_t g_until = 0;
static bool g_locked = false;
static uint8_t g_idleR = 0, g_idleG = 0, g_idleB = 10;

void set(uint8_t r, uint8_t g, uint8_t b) {
    neopixelWrite(PK_LED_PIN, r, g, b);
}

void init() {
    g_locked = false;
    set(0, 0, 0);
}

void idle() {
    g_until = 0;
    if (g_locked) {
        set(90, 0, 0);
        return;
    }
    set(g_idleR, g_idleG, g_idleB);
}

void wait_touch() {
    if (g_locked) {
        set(90, 0, 0);
        return;
    }
    g_until = 0;
    set(0, 0, 40);
}

void success() {
    if (g_locked) {
        set(90, 0, 0);
        return;
    }
    set(0, 60, 0);
    g_until = millis() + 400;
}

void error() {
    if (g_locked) {
        set(90, 0, 0);
        return;
    }
    set(80, 0, 0);
    g_until = millis() + 800;
}

void wink() {
    if (g_locked) {
        set(90, 0, 0);
        return;
    }
    set(0, 60, 30);
    g_until = millis() + 600;
}

void locked(bool on) {
    g_locked = on;
    g_until = 0;
    if (on) {
        set(90, 0, 0);
    } else {
        set(g_idleR, g_idleG, g_idleB);
    }
}

bool locked() { return g_locked; }

void poll() {
    if (g_locked) {
        set(90, 0, 0);
        return;
    }
    if (g_until && (int32_t)(millis() - g_until) >= 0) {
        g_until = 0;
        idle();
    }
}

}  // namespace led
