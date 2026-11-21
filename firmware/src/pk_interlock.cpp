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
#include "pk_store.h"

namespace pk {
namespace interlock {
namespace {

HardwareSerial g_serial(1);
Preferences g_prefs;

uint8_t g_key[32];
uint8_t g_pendingKey[32];
uint8_t g_pendingKek[32];
uint8_t g_kekNonce[12];
volatile bool g_haveKey = false;
volatile bool g_ready = false;
volatile bool g_paired = false;
volatile bool g_replaceMode = false;
volatile bool g_replaceRequest = false;
volatile bool g_hasPending = false;
volatile bool g_awaitingKek = false;
volatile bool g_pendingVerified = false;
volatile bool g_proofValid = false;
uint8_t g_kekTarget = 0;  // 1 = active key, 2 = pending key
uint32_t g_lastKek = 0;
uint32_t g_replaceDeadline = 0;
uint32_t g_lastPendingPair = 0;
bool g_pairedLoaded = false;
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
volatile uint32_t g_rxBytes = 0;
volatile uint32_t g_rxLines = 0;
char g_lastRx[48] = {0};
uint32_t g_proofOk = 0;
uint32_t g_proofBad = 0;
uint32_t g_kekTries = 0;
uint32_t g_kekFails = 0;
uint32_t g_unlockFails = 0;
char g_dbgText[96] = {0};

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
        if (!g_pairedLoaded) {
            // Devices upgraded from the first interlock build have a key but
            // no flag.  Treat them as already paired so an attacker cannot
            // pair a blank board during the upgrade.
            g_paired = g_prefs.getBool("paired", true);
            g_pairedLoaded = true;
        }
        Serial.printf("[interlock] loaded link key (paired=%d)\n", g_paired ? 1 : 0);
        return;
    }
    if (!random_bytes(g_key, sizeof(g_key))) {
        Serial.println("[interlock] RNG failed");
        return;
    }
    saveKey();
    g_haveKey = true;
    g_paired = false;
    g_pairedLoaded = true;
    g_prefs.putBool("paired", false);
    Serial.println("[interlock] generated new link key, pairing...");
}

void proofWithKey(const uint8_t key[32], const uint8_t nonce[16], uint8_t out[32]) {
    uint8_t msg[16 + 8];
    memcpy(msg, nonce, 16);
    memcpy(msg + 16, "TECHX-IL", 8);
    hmac_sha256(key, 32, msg, sizeof(msg), out);
}

void proof(const uint8_t nonce[16], uint8_t out[32]) {
    proofWithKey(g_key, nonce, out);
}

void sendKey(const uint8_t key[32]) {
    char hex[65];
    toHex(key, 32, hex);
    g_serial.printf("K %s\n", hex);
}

void sendPair() {
    sendKey(g_key);
    g_lastPair = millis();
}

void sendPending() {
    sendKey(g_pendingKey);
    g_lastPendingPair = millis();
}

void sendKekRequest(const uint8_t key[32], uint8_t target) {
    (void)key;
    if (!random_bytes(g_kekNonce, sizeof(g_kekNonce))) return;
    char hex[25];
    toHex(g_kekNonce, sizeof(g_kekNonce), hex);
    g_serial.printf("E %s\n", hex);
    g_kekTarget = target;
    g_awaitingKek = true;
    g_lastKek = millis();
    g_kekTries++;
}

void sendChallenge() {
    if (!random_bytes(g_nonce, sizeof(g_nonce))) return;
    char hex[33];
    toHex(g_nonce, sizeof(g_nonce), hex);
    g_serial.printf("C %s\n", hex);
    g_lastChallenge = millis();
    g_awaiting = true;
}

void promotePending() {
    memcpy(g_key, g_pendingKey, sizeof(g_key));
    saveKey();
    g_hasPending = false;
    g_replaceMode = false;
    g_pendingVerified = false;
    g_paired = true;
    g_pairedLoaded = true;
    g_prefs.putBool("paired", true);
    g_ready = true;
    g_lastProof = millis();
    g_state = 2;
    led::locked(false);
    Serial.println("[interlock] replacement complete; new board active");
}

void handleLine(char* line) {
    if (strncmp(line, "P ", 2) == 0) {
        uint8_t got[32], active[32];
        if (!parseHex(line + 2, got, sizeof(got))) return;
        proof(g_nonce, active);

        if (g_replaceMode && g_hasPending) {
            uint8_t pending[32];
            proofWithKey(g_pendingKey, g_nonce, pending);
            if (ct_equal(got, pending, sizeof(pending))) {
                g_proofOk++;
                g_lastProof = millis();
                g_awaiting = false;
                g_pendingVerified = true;
                if (!g_awaitingKek) {
                    sendKekRequest(g_pendingKey, 2);
                }
                return;
            }
            if (ct_equal(got, active, sizeof(active))) {
                // The old board is still connected; it stays verified for
                // the mode but must not unlock while we wait for the new one.
                return;
            }
        } else if (ct_equal(got, active, sizeof(active))) {
            g_proofOk++;
            g_lastProof = millis();
            g_awaiting = false;
            g_proofValid = true;
            if (!g_paired) {
                // First successful pairing: from now on the key is never
                // offered again.  A replacement requires the explicit
                // "replace key board" flow.
                g_paired = true;
                g_pairedLoaded = true;
                g_prefs.putBool("paired", true);
                Serial.println("[interlock] first pairing complete; locked to this board");
            }
            if (store::credentials_unlocked()) {
                if (!g_ready) {
                    g_ready = true;
                    g_state = 2;
                    led::locked(false);
                    Serial.println("[interlock] second board OK");
                }
            } else if (!g_awaitingKek) {
                sendKekRequest(g_key, 1);
            }
            return;
        }

        // Unknown/mismatched key.
        if (!g_replaceMode) {
            g_proofBad++;
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
    if (strncmp(line, "E ", 2) == 0) {
        uint8_t blob[48];
        uint8_t kek[32];
        if (!parseHex(line + 2, blob, sizeof(blob))) return;
        const uint8_t* key = (g_kekTarget == 2) ? g_pendingKey : g_key;
        if (!aes256_gcm_decrypt(key, g_kekNonce, sizeof(g_kekNonce),
                                blob, sizeof(blob), kek)) {
            g_kekFails++;
            Serial.println("[interlock] KEK decrypt failed");
            g_awaitingKek = false;
            return;
        }
        g_awaitingKek = false;
        if (g_kekTarget == 2) {
            memcpy(g_pendingKek, kek, sizeof(g_pendingKek));
            if (store::rewrap_dek(kek)) {
                promotePending();
            } else {
                Serial.println("[interlock] DEK rewrap failed; replacement aborted");
            }
        } else {
            if (store::unlock_credentials(kek)) {
                g_ready = true;
                g_state = 2;
                led::locked(false);
                Serial.println("[interlock] store unlocked with second-board KEK");
            } else {
                g_unlockFails++;
                Serial.println("[interlock] credential store unlock failed");
            }
        }
        return;
    }
    if (strncmp(line, "OK K", 4) == 0) {
        Serial.println("[interlock] second board stored the link key");
        return;
    }
    if (strncmp(line, "ERR", 3) == 0) {
        if (strncmp(line, "ERR HASKEY", 10) == 0) {
            g_state = 3;
            Serial.println("[interlock] peer already has a different key; wipe this board to re-pair");
        } else {
            Serial.printf("[interlock] peer: %s\n", line);
        }
        return;
    }
    if (strncmp(line, "S ", 2) == 0) {
        Serial.printf("[interlock] peer status: %s\n", line + 2);
    }
}

void readLines() {
    while (g_serial.available() > 0) {
        char c = (char)g_serial.read();
        g_rxBytes++;
        if (c == '\n' || c == '\r') {
            if (g_lineLen > 0) {
                g_line[g_lineLen] = 0;
                g_rxLines++;
                strncpy(g_lastRx, g_line, sizeof(g_lastRx) - 1);
                g_lastRx[sizeof(g_lastRx) - 1] = 0;
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

        if (g_replaceRequest) {
            g_replaceRequest = false;
            if (!random_bytes(g_pendingKey, sizeof(g_pendingKey))) {
                Serial.println("[interlock] RNG failed for replacement key");
            } else {
                g_hasPending = true;
                g_replaceMode = true;
                g_replaceDeadline = now + 120000;
                g_lastPendingPair = 0;
                g_lastChallenge = 0;
                g_ready = false;
                g_lastProof = 0;
                g_state = 1;
                led::locked(true);
                Serial.println("[interlock] replace mode: old board verified, waiting for new board");
            }
        }

        // Support both common wirings:
        //   crossed: main 16 -> peer 42, main 17 <- peer 41  (RX=17, TX=16)
        //   straight: main 16 -> peer 41, main 17 -> peer 42 (RX=16, TX=17)
        // Try one mapping, and if no proof arrives, flip the pins.
        if (!g_ready && !g_replaceMode && (uint32_t)(now - g_lastSwap) > 6000) {
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

        // Pairing is one-shot: only an unpaired main board hands out the key.
        // In replace mode the pending key is offered instead; the old key is
        // only swapped in after the new board proves it.
        if (g_replaceMode && g_hasPending && (uint32_t)(now - g_lastPendingPair) > 3000) {
            sendPending();
        } else if (g_haveKey && !g_paired && (uint32_t)(now - g_lastPair) > 3000) {
            sendPair();
        }

        // A valid proof is not enough: the store stays ciphertext until the
        // second board releases the KEK.  Retry the KEK request until it works.
        if (g_proofValid && !store::credentials_unlocked() && !g_awaitingKek &&
            (uint32_t)(now - g_lastKek) > 1500) {
            sendKekRequest(g_key, 1);
        }
        if (g_pendingVerified && g_replaceMode && !g_awaitingKek &&
            (uint32_t)(now - g_lastKek) > 1500) {
            sendKekRequest(g_pendingKey, 2);
        }

        if (g_replaceMode && (int32_t)(now - g_replaceDeadline) >= 0) {
            g_replaceMode = false;
            g_hasPending = false;
            g_pendingVerified = false;
            g_ready = false;
            g_lastProof = 0;
            Serial.println("[interlock] replace timeout; old key kept");
        }

        if (g_awaiting && (uint32_t)(now - g_lastChallenge) > PK_IL_PROOF_TIMEOUT_MS) {
            g_awaiting = false;
        }

        if (g_ready && (uint32_t)(now - g_lastProof) > PK_IL_PROOF_TIMEOUT_MS) {
            g_ready = false;
            g_proofValid = false;
            g_state = 1;
            led::locked(true);
            Serial.println("[interlock] proof timeout, locked");
        }
        if (g_proofValid && (uint32_t)(now - g_lastProof) > PK_IL_PROOF_TIMEOUT_MS) {
            g_proofValid = false;
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

bool beginReplace() {
    if (g_replaceMode || g_replaceRequest) return false;
    if (!g_ready || !store::credentials_unlocked()) return false;
    g_replaceRequest = true;
    return true;
}

void cancelReplace() {
    if (!g_replaceMode && !g_replaceRequest) return;
    g_replaceRequest = false;
    g_replaceMode = false;
    g_hasPending = false;
    g_pendingVerified = false;
    g_awaitingKek = false;
    g_ready = false;
    g_lastProof = 0;
    Serial.println("[interlock] replace cancelled");
}

bool replaceMode() { return g_replaceMode || g_replaceRequest; }

void forget() {
    g_ready = false;
    g_haveKey = false;
    g_paired = false;
    g_replaceMode = false;
    g_replaceRequest = false;
    g_hasPending = false;
    g_pendingVerified = false;
    g_awaitingKek = false;
    g_proofValid = false;
    g_pairedLoaded = true;
    g_state = 0;
    g_keyAnnounced = false;
    g_awaiting = false;
    g_lastProof = 0;
    g_prefs.remove("key");
    g_prefs.putBool("paired", false);
    led::locked(true);
    Serial.println("[interlock] link key forgotten, re-pairing");
}

bool paired() { return g_paired; }

const char* state() {
    if (g_replaceMode) return "replace";
    if (g_ready) return "ok";
    if (!g_paired) return "pairing";
    if (g_state == 3) return "mismatch";
    return "waiting";
}

uint32_t lastProofAgeMs() {
    if (g_lastProof == 0) return 0xFFFFFFFFu;
    return millis() - g_lastProof;
}

uint32_t rxBytes() { return g_rxBytes; }
uint32_t rxLines() { return g_rxLines; }
const char* lastLine() { return g_lastRx; }

const char* debugText() {
    snprintf(g_dbgText, sizeof(g_dbgText), "ok%u bad%u e%u/%u uf%u",
             (unsigned)g_proofOk, (unsigned)g_proofBad, (unsigned)g_kekTries,
             (unsigned)g_kekFails, (unsigned)g_unlockFails);
    return g_dbgText;
}

}  // namespace interlock
}  // namespace pk

#else  // !PK_INTERLOCK

namespace pk {
namespace interlock {
void begin() {}
void poll() {}
bool ready() { return true; }
bool paired() { return true; }
bool beginReplace() { return false; }
void cancelReplace() {}
bool replaceMode() { return false; }
void forget() {}
const char* state() { return "disabled"; }
uint32_t lastProofAgeMs() { return 0; }
uint32_t rxBytes() { return 0; }
uint32_t rxLines() { return 0; }
const char* lastLine() { return ""; }
const char* debugText() { return ""; }
}  // namespace interlock
}  // namespace pk

#endif
