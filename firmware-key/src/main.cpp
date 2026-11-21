// TechXPassKey second board: stores the link key and answers HMAC challenges.
//
// Protocol (newline terminated ASCII, 115200 8N1):
//   K <64 hex>   store key if empty           -> "OK K" / "ERR HASKEY"
//   C <32 hex>   16-byte nonce                -> "P <64 hex>" / "ERR NOKEY"
//   S            status                       -> "S 1" / "S 0"
//   PING                                      -> "PONG"
//
// Hold BOOT (GPIO0) for 3 s while powering up to erase the stored key, e.g.
// when moving this board to a different main board.

#include <Arduino.h>
#include <Preferences.h>
#include <mbedtls/md.h>
#include <mbedtls/gcm.h>
#include <string.h>

#ifndef KEY_RX_PIN
#define KEY_RX_PIN 42
#endif
#ifndef KEY_TX_PIN
#define KEY_TX_PIN 41
#endif
#ifndef KEY_LED_PIN
#define KEY_LED_PIN 48
#endif
#ifndef KEY_BUTTON_PIN
#define KEY_BUTTON_PIN 0
#endif

namespace {

HardwareSerial g_link(1);
Preferences prefs;
uint8_t g_key[32];
uint8_t g_kek[32];
bool g_haveKey = false;

char g_line[160];
size_t g_lineLen = 0;
uint32_t g_lastBlink = 0;
bool g_blinkOn = false;

void led(uint8_t r, uint8_t g, uint8_t b) {
#if KEY_LED_PIN >= 0
    neopixelWrite(KEY_LED_PIN, r, g, b);
#else
    (void)r; (void)g; (void)b;
#endif
}

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

void proof(const uint8_t nonce[16], uint8_t out[32]) {
    uint8_t msg[16 + 8];
    memcpy(msg, nonce, 16);
    memcpy(msg + 16, "TECHX-IL", 8);
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, info, 1);
    mbedtls_md_hmac_starts(&ctx, g_key, sizeof(g_key));
    mbedtls_md_hmac_update(&ctx, msg, sizeof(msg));
    mbedtls_md_hmac_finish(&ctx, out);
    mbedtls_md_free(&ctx);
}

void handleLine(char* line) {
    if (strncmp(line, "PING", 4) == 0) {
        g_link.println("PONG");
        return;
    }
    if (strncmp(line, "S", 1) == 0 && (line[1] == 0 || line[1] == ' ')) {
        g_link.printf("S %d\n", g_haveKey ? 1 : 0);
        return;
    }
    if (strncmp(line, "K ", 2) == 0) {
        uint8_t incoming[32];
        if (!parseHex(line + 2, incoming, sizeof(incoming))) {
            g_link.println("ERR BADHEX");
            return;
        }
        if (g_haveKey) {
            g_link.println("ERR HASKEY");
            return;
        }
        memcpy(g_key, incoming, sizeof(g_key));
        prefs.putBytes("key", g_key, sizeof(g_key));
        g_haveKey = true;
        led(0, 40, 0);
        g_link.println("OK K");
        Serial.println("[key] link key stored");
        return;
    }
    if (strncmp(line, "C ", 2) == 0) {
        uint8_t nonce[16], mac[32];
        char hex[65];
        if (!parseHex(line + 2, nonce, sizeof(nonce))) {
            g_link.println("ERR BADHEX");
            return;
        }
        if (!g_haveKey) {
            g_link.println("ERR NOKEY");
            return;
        }
        proof(nonce, mac);
        toHex(mac, sizeof(mac), hex);
        g_link.printf("P %s\n", hex);
        return;
    }
    if (strncmp(line, "E ", 2) == 0) {
        uint8_t nonce[12];
        uint8_t out[48];
        char hex[97];
        if (!parseHex(line + 2, nonce, sizeof(nonce))) {
            g_link.println("ERR BADHEX");
            return;
        }
        if (!g_haveKey) {
            g_link.println("ERR NOKEY");
            return;
        }
        mbedtls_gcm_context ctx;
        mbedtls_gcm_init(&ctx);
        int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, g_key, 256);
        if (rc == 0) {
            rc = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, sizeof(g_kek),
                                           nonce, sizeof(nonce), nullptr, 0,
                                           g_kek, out, 16, out + sizeof(g_kek));
        }
        mbedtls_gcm_free(&ctx);
        if (rc != 0) {
            g_link.println("ERR CRYPTO");
            return;
        }
        toHex(out, sizeof(out), hex);
        g_link.printf("E %s\n", hex);
        return;
    }
    g_link.println("ERR CMD");
}

void readLines() {
    while (g_link.available() > 0) {
        char c = (char)g_link.read();
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

}  // namespace

void setup() {
    Serial.begin(115200);
    Serial.println("\n[boot] TechXPassKey key board");

    pinMode(KEY_BUTTON_PIN, INPUT_PULLUP);
    prefs.begin("pk-key", false);

    // Erase key when BOOT is held during power-up (recovery / re-pairing).
    if (digitalRead(KEY_BUTTON_PIN) == LOW) {
        uint32_t start = millis();
        led(40, 0, 0);
        while (digitalRead(KEY_BUTTON_PIN) == LOW && millis() - start < 5000) {
            delay(20);
        }
        if (millis() - start >= 3000) {
            prefs.remove("key");
            prefs.remove("kek");
            Serial.println("[key] erased by BOOT hold");
        }
    }

    if (prefs.getBytesLength("key") == sizeof(g_key) &&
        prefs.getBytes("key", g_key, sizeof(g_key)) == sizeof(g_key)) {
        g_haveKey = true;
    }
    if (prefs.getBytesLength("kek") == sizeof(g_kek) &&
        prefs.getBytes("kek", g_kek, sizeof(g_kek)) == sizeof(g_kek)) {
        Serial.println("[key] KEK loaded");
    } else {
        for (int i = 0; i < (int)sizeof(g_kek); i++) g_kek[i] = (uint8_t)esp_random();
        prefs.putBytes("kek", g_kek, sizeof(g_kek));
        Serial.println("[key] new KEK generated");
    }

    g_link.begin(115200, SERIAL_8N1, KEY_RX_PIN, KEY_TX_PIN);
    g_link.setTimeout(50);

    if (g_haveKey) {
        led(0, 30, 0);
        Serial.println("[key] ready (key stored)");
    } else {
        led(40, 0, 0);
        Serial.println("[key] waiting for pairing (no key)");
    }
}

void loop() {
    readLines();

    if (!g_haveKey) {
        if (millis() - g_lastBlink > 600) {
            g_lastBlink = millis();
            g_blinkOn = !g_blinkOn;
            led(g_blinkOn ? 50 : 0, 0, 0);
        }
    } else {
        led(0, 30, 0);
    }
    delay(5);
}
