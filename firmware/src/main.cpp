// ESP32 Passkey - FIDO2 / CTAP2.1 / U2F authenticator with USB HID + CDC.
#include <Arduino.h>
#include <esp_system.h>

#include "pk_config.h"
#include "pk_ble.h"
#include "pk_ctap2.h"
#include "pk_ctaphid.h"
#include "pk_interlock.h"
#include "pk_led.h"
#include "pk_mgmt.h"
#include "pk_store.h"
#include "pk_usb.h"

using namespace pk;

void setup() {
    Serial.begin(115200);
    Serial.printf("\n[boot] %s %s\n", PK_PRODUCT_NAME, PK_VERSION);

    led::init();
    if (!store::begin()) {
        Serial.println("[boot] storage init failed");
        led::error();
    }
    ctap::init();

    char serial[24];
    uint64_t id = ESP.getEfuseMac();
    snprintf(serial, sizeof(serial), "PK%04X%04X", (unsigned)(id >> 32), (unsigned)id);

    if (!usb::begin(serial)) {
        Serial.println("[boot] usb init failed");
    }
    mgmt::begin();
    interlock::begin();
    ctaphid::init();
    ble::begin(PK_PRODUCT_NAME);

    led::idle();
    mgmt::log("boot: %d creds, pin=%d, reset=%d, stack=%u", store::credential_count(),
              ctap::pin_is_set() ? 1 : 0, (int)esp_reset_reason(),
              (unsigned)uxTaskGetStackHighWaterMark(nullptr));
    Serial.printf("[boot] ready, %d credentials, PSRAM %u\n", store::credential_count(),
                  (unsigned)ESP.getFreePsram());
}

void loop() {
    ctaphid::poll();
    mgmt::poll();
    ble::poll();
    ctap::poll();
    store::flush_if_dirty();
    led::poll();
    delay(1);
}
