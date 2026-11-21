// Second-board interlock.
//
// Main board (this firmware)          Second board (passkey-key)
//   GPIO16  TX  --------------------->  GPIO42 RX
//   GPIO17  RX  <---------------------  GPIO41 TX
//   GND     --------------------------  GND
//
// The main board stores a 32-byte link key in NVS.  The second board gets the
// same key during pairing and stores it in its own NVS.  At runtime the main
// board sends a random 16-byte nonce every ~700 ms; the second board answers
// with HMAC-SHA256(link_key, nonce || "TECHX-IL").  If no valid proof arrives
// within PK_IL_PROOF_TIMEOUT_MS the interlock is closed: the LED turns red and
// CTAP makeCredential/getAssertion (and U2F) are denied.
//
// The device PIN is NOT moved: it stays on the main board and is still entered
// on the computer.  The second board is an additional physical factor.

#include "pk_interlock.h"

#include "pk_config.h"

#if PK_INTERLOCK

#include <Arduino.h>
#include <Preferences.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <string.h>

#include "pk_crypto.h"
#include "pk_led.h"

namespace pk {
namespace interlock {
namespace {

HardwareSerial g_serial(1);
Preferences g_prefs;

uint8_t g_key[32];
volatile bool g_haveKey = false;
volatile bool g_ready = false;
volatile uint8_t g_state = 0;  // 0 pairing, 1 waiting, 2 ok, 3 mismatch

uint8_t g_nonce[16];
volatile uint32_t g_lastProof = 0;
uint32_t g_lastChallenge = 0;
uint32_t g_lastPair = 0;
bool g_awaiting = false;
bool g_keyAnnounced = false;
bool g_swapped = false;
uint32_t g_lastSwap = 0;

char g_line[160];
size_t g_lineLen = 0;

TaskHandle_t g_task = nullptr;

int hexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool parseHex(const char* s, uint8_t* out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        int hi = hexNibble(s[2 * i]);
        int lo = hexNibble(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return s[2 * n] == 0;
}

void toHex(const uint8_t* in, size_t n, char* out) {
    static const char* digits = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 0x0F];
    }
    out[2 * n] = 0;
}

void saveKey() {
    g_prefs.putBytes("key", g_key, sizeof(g_key));
}

void loadOrCreateKey() {
    size_t len = g_prefs.getBytesLength("key");
    if (len == sizeof(g_key) && g_prefs.getBytes("key", g_key, sizeof(g_key)) == sizeof(g_key)) {
        g_haveKey = true;
        Serial.println("[interlock] loaded link key");
        return;
    }
    if (!random_bytes(g_key, sizeof(g_key))) {
        Serial.println("[interlock] RNG failed");
        return;
    }
    saveKey();
    g_haveKey = true;
    Serial.println("[interlock] generated new link key, pairing...");
}

void proof(const uint8_t nonce[16], uint8_t out[32]) {
    uint8_t msg[16 + 8];
    memcpy(msg, nonce, 16);
    memcpy(msg + 16, "TECHX-IL", 8);
    hmac_sha256(g_key, sizeof(g_key), msg, sizeof(msg), out);
}

void sendPair() {
    char hex[65];
    toHex(g_key, sizeof(g_key), hex);
    g_serial.printf("K %s\n", hex);
    g_lastPair = millis();
}

void sendChallenge() {
    if (!random_bytes(g_nonce, sizeof(g_nonce))) return;
    char hex[33];
    toHex(g_nonce, sizeof(g_nonce), hex);
    g_serial.printf("C %s\n", hex);
    g_lastChallenge = millis();
    g_awaiting = true;
}

void handleLine(char* line) {
    if (strncmp(line, "P ", 2) == 0) {
        uint8_t got[32], want[32];
        if (!parseHex(line + 2, got, sizeof(got))) return;
        proof(g_nonce, want);
        if (ct_equal(got, want, sizeof(want))) {
            g_lastProof = millis();
            g_awaiting = false;
            if (!g_ready) {
                g_ready = true;
                g_state = 2;
                led::locked(false);
                Serial.println("[interlock] second board OK");
            }
        } else {
            g_ready = false;
            g_state = 3;
            g_awaiting = false;
            led::locked(true);
            if (!g_keyAnnounced) {
                Serial.println("[interlock] proof mismatch (different key?)");
                g_keyAnnounced = true;
            }
        }
        return;
    }
    if (strncmp(line, "OK K", 4) == 0) {
        Serial.println("[interlock] second board stored the link key");
        return;
    }
    if (strncmp(line, "ERR", 3) == 0) {
        Serial.printf("[interlock] peer: %s\n", line);
        return;
    }
    if (strncmp(line, "S ", 2) == 0) {
        Serial.printf("[interlock] peer status: %s\n", line + 2);
    }
}

void readLines() {
    while (g_serial.available() > 0) {
        char c = (char)g_serial.read();
        if (c == '\n' || c == '\r') {
            if (g_lineLen > 0) {
                g_line[g_lineLen] = 0;
                handleLine(g_line);
                g_lineLen = 0;
            }
        } else if (g_lineLen < sizeof(g_line) - 1) {
            g_line[g_lineLen++] = c;
        }
    }
}

void task(void*) {
    for (;;) {
        readLines();

        if (!g_haveKey) {
            loadOrCreateKey();
        }

        uint32_t now = millis();

        // Support both common wirings:
        //   crossed: main 16 -> peer 42, main 17 <- peer 41  (RX=17, TX=16)
        //   straight: main 16 -> peer 41, main 17 -> peer 42 (RX=16, TX=17)
        // Try one mapping, and if no proof arrives, flip the pins.
        if (!g_ready && (uint32_t)(now - g_lastSwap) > 6000) {
            g_swapped = !g_swapped;
            g_serial.end();
            g_serial.begin(PK_IL_BAUD, SERIAL_8N1,
                           g_swapped ? PK_IL_TX_PIN : PK_IL_RX_PIN,
                           g_swapped ? PK_IL_RX_PIN : PK_IL_TX_PIN);
            g_lastSwap = now;
            g_awaiting = false;
            g_lastChallenge = 0;
            g_lastPair = 0;
            Serial.printf("[interlock] uart pins -> rx=%d tx=%d\n",
                          g_swapped ? PK_IL_TX_PIN : PK_IL_RX_PIN,
                          g_swapped ? PK_IL_RX_PIN : PK_IL_TX_PIN);
        }

        // Challenge every ~700 ms; this is both the presence heartbeat and
        // the recovery path when the second board appears later.
        if (g_haveKey && (uint32_t)(now - g_lastChallenge) > 700) {
            sendChallenge();
        }

        // Pairing: keep offering the key until the peer proves it has it.
        if (g_haveKey && !g_ready && (uint32_t)(now - g_lastPair) > 3000) {
            sendPair();
        }

        if (g_awaiting && (uint32_t)(now - g_lastChallenge) > PK_IL_PROOF_TIMEOUT_MS) {
            g_awaiting = false;
        }

        if (g_ready && (uint32_t)(now - g_lastProof) > PK_IL_PROOF_TIMEOUT_MS) {
            g_ready = false;
            g_state = 1;
            led::locked(true);
            Serial.println("[interlock] proof timeout, locked");
        }

        delay(10);
    }
}

}  // namespace

void begin() {
    g_prefs.begin("pk-il", false);
    loadOrCreateKey();

    g_serial.begin(PK_IL_BAUD, SERIAL_8N1, PK_IL_RX_PIN, PK_IL_TX_PIN);
    g_serial.setTimeout(50);

    led::locked(true);
    g_lastPair = millis() - 3000;  // offer pairing immediately
    g_lastSwap = millis();
    xTaskCreatePinnedToCore(task, "interlock", 4096, nullptr, 1, &g_task, 0);
    Serial.printf("[interlock] uart1 rx=%d tx=%d baud=%d\n", PK_IL_RX_PIN, PK_IL_TX_PIN,
                  PK_IL_BAUD);
}

void poll() {}

bool ready() { return g_ready; }

void forget() {
    g_ready = false;
    g_haveKey = false;
    g_state = 0;
    g_keyAnnounced = false;
    g_awaiting = false;
    g_lastProof = 0;
    g_prefs.remove("key");
    led::locked(true);
    Serial.println("[interlock] link key forgotten, re-pairing");
}

const char* state() {
    if (g_ready) return "ok";
    if (g_state == 3) return "mismatch";
    if (g_state == 0) return "pairing";
    return "waiting";
}

uint32_t lastProofAgeMs() {
    if (g_lastProof == 0) return 0xFFFFFFFFu;
    return millis() - g_lastProof;
}

}  // namespace interlock
}  // namespace pk

#else  // !PK_INTERLOCK

namespace pk {
namespace interlock {
void begin() {}
void poll() {}
bool ready() { return true; }
void forget() {}
const char* state() { return "disabled"; }
uint32_t lastProofAgeMs() { return 0; }
}  // namespace interlock
}  // namespace pk

#endif
