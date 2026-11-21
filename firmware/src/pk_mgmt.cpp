#include "pk_mgmt.h"

#include <Arduino.h>
#include <LittleFS.h>
#include <Update.h>
#include <esp_system.h>
#include <stdarg.h>
#include <string.h>

#include "esp32-hal-tinyusb.h"

#include "pk_config.h"
#include "pk_crypto.h"
#include "pk_ctap2.h"
#include "pk_interlock.h"
#include "pk_store.h"
#include "pk_u2f.h"
#include "pk_usb.h"

namespace mgmt {

using namespace pk;

static inline USBCDC& C() { return usb::cdc(); }

enum : uint8_t {
    CMD_PING = 0x01,
    CMD_INFO = 0x02,
    CMD_LOG = 0x03,
    CMD_SET_TIME = 0x10,
    CMD_SET_UP_MODE = 0x11,
    CMD_OTA_BEGIN = 0x20,
    CMD_OTA_DATA = 0x21,
    CMD_OTA_END = 0x22,
    CMD_REBOOT = 0x30,
    CMD_BOOTLOADER = 0x31,
    CMD_FACTORY_RESET = 0x32,
    CMD_REPLACE_KEY = 0x33,
    CMD_REPLACE_CANCEL = 0x34,
    CMD_LIST_CREDS = 0x40,
    CMD_DELETE_CRED = 0x41,
    CMD_DELETE_ALL = 0x42,
    CMD_GET_TIME = 0x12,
    CMD_DEVICE_ID = 0x13,
    CMD_CTAP = 0x50,
    CMD_U2F = 0x51,
};

enum : uint8_t {
    ST_OK = 0,
    ST_ERROR = 1,
    ST_BAD_FRAME = 2,
    ST_AUTH = 3,
    ST_BUSY = 4,
    ST_NOTSUP = 5,
};

static const uint8_t SOF1 = 0xA5;
static const uint8_t SOF2 = 0x5A;
static const size_t MAX_PAYLOAD = 4096;

enum RxState { RX_SOF1, RX_SOF2, RX_HDR, RX_PAYLOAD, RX_CRC1, RX_CRC2 };
static RxState g_state = RX_SOF1;
static uint8_t g_hdr[5];
static size_t g_hdrOff = 0;
static uint8_t g_payload[MAX_PAYLOAD];
static size_t g_payloadLen = 0;
static size_t g_payloadOff = 0;
static uint16_t g_crc = 0;
static uint16_t g_crcRecv = 0;

static char g_logs[64][160];
static int g_logHead = 0;
static int g_logCount = 0;

static bool g_otaActive = false;
static uint32_t g_otaSize = 0;
static uint32_t g_otaWritten = 0;
static uint32_t g_otaCrcExpected = 0;
static uint32_t g_otaCrc = 0xFFFFFFFF;

// ---------------------------------------------------------------------------
static uint16_t crc16(const uint8_t* data, size_t len, uint16_t crc = 0xFFFF) {
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int b = 0; b < 8; b++) {
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
        }
    }
    return crc;
}

static uint32_t crc32_update(uint32_t crc, const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++) crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1)));
    }
    return crc;
}

static void send_frame(uint8_t cmd, const uint8_t* payload, size_t len) {
    if (len > MAX_PAYLOAD) return;
    uint8_t hdr[5];
    hdr[0] = 1;
    hdr[1] = (uint8_t)(cmd | 0x80);
    hdr[2] = 0;
    hdr[3] = (uint8_t)(len & 0xFF);
    hdr[4] = (uint8_t)(len >> 8);
    uint16_t crc = crc16(hdr, sizeof(hdr));
    crc = crc16(payload, len, crc);
    uint8_t sof[2] = {SOF1, SOF2};
    uint8_t tail[2] = {(uint8_t)(crc & 0xFF), (uint8_t)(crc >> 8)};
    C().write(sof, 2);
    C().write(hdr, sizeof(hdr));
    if (len) C().write(payload, len);
    C().write(tail, 2);
    C().flush();
}

static void send_status(uint8_t cmd, uint8_t status, const uint8_t* data = nullptr, size_t len = 0) {
    static uint8_t buf[MAX_PAYLOAD];
    if (len + 1 > sizeof(buf)) return;
    buf[0] = status;
    if (len) memcpy(buf + 1, data, len);
    send_frame(cmd, buf, len + 1);
}

// Status + payload without an extra copy (CTAP responses can be ~1 KB).
static void send_status_data(uint8_t cmd, uint8_t status, const uint8_t* data, size_t len) {
    if (len + 1 > MAX_PAYLOAD) return;
    uint8_t hdr[5];
    hdr[0] = 1;
    hdr[1] = (uint8_t)(cmd | 0x80);
    hdr[2] = 0;
    hdr[3] = (uint8_t)((len + 1) & 0xFF);
    hdr[4] = (uint8_t)((len + 1) >> 8);
    uint16_t crc = crc16(hdr, sizeof(hdr));
    crc = crc16(&status, 1, crc);
    crc = crc16(data, len, crc);
    uint8_t sof[2] = {SOF1, SOF2};
    uint8_t tail[2] = {(uint8_t)(crc & 0xFF), (uint8_t)(crc >> 8)};
    C().write(sof, 2);
    C().write(hdr, sizeof(hdr));
    C().write(&status, 1);
    if (len) C().write(data, len);
    C().write(tail, 2);
    C().flush();
}

// ---------------------------------------------------------------------------
static const char* B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static void b64url(const uint8_t* in, size_t len, char* out) {
    size_t o = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < len) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < len) v |= in[i + 2];
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = (i + 1 < len) ? B64[(v >> 6) & 63] : '=';
        out[o++] = (i + 2 < len) ? B64[v & 63] : '=';
    }
    out[o] = 0;
}

static int json_escape(char* out, size_t cap, const uint8_t* s, size_t n) {
    size_t o = 0;
    for (size_t i = 0; i < n && o + 2 < cap; i++) {
        uint8_t c = s[i];
        if (c == '"' || c == '\\') {
            out[o++] = '\\';
            out[o++] = (char)c;
        } else if (c == '\n') {
            out[o++] = '\\'; out[o++] = 'n';
        } else if (c < 0x20) {
            o += snprintf(out + o, cap - o, "\\u%04x", c);
        } else {
            out[o++] = (char)c;
        }
    }
    out[o] = 0;
    return (int)o;
}

static void cmd_info() {
    char rp[PK_MAX_RP_ID_LEN * 2 + 1];
    (void)rp;
    char idB64[PK_MAX_CRED_ID_LEN * 2];
    (void)idB64;
    char buf[1400];
    int n = snprintf(buf, sizeof(buf),
                     "{\"name\":\"%s\",\"version\":\"%s\",\"aaguid\":\"54 45 43 48 58 50 41 53 53 4b 45 59 30 30 30 31\","
                     "\"pin\":%s,\"retries\":%u,\"creds\":%d,\"maxCreds\":%d,\"upMode\":%u,"
                     "\"il\":%s,\"ilState\":\"%s\",\"ilPaired\":%s,\"ilReplace\":%s,"
                     "\"fsUsed\":%u,\"fsTotal\":%u,\"epoch\":%llu,\"ota\":%s,"
                     "\"boot\":%u,\"reset\":%d}",
                     PK_PRODUCT_NAME, PK_VERSION, ctap::pin_is_set() ? "true" : "false",
                     (unsigned)ctap::pin_retries(), store::credential_count(), PK_MAX_CREDENTIALS,
                     (unsigned)store::settings().upMode,
                     interlock::ready() ? "true" : "false", interlock::state(),
                     interlock::paired() ? "true" : "false",
                     interlock::replaceMode() ? "true" : "false",
                     (unsigned)LittleFS.usedBytes(),
                     (unsigned)LittleFS.totalBytes(), (unsigned long long)store::now_epoch(),
                     g_otaActive ? "true" : "false",
                     (unsigned)store::settings().bootCount, (int)esp_reset_reason());
    if (n > 0) send_status(CMD_INFO, ST_OK, (const uint8_t*)buf, (size_t)n);
}

static void cmd_list_creds() {
    static char buf[4096];
    size_t o = 0;
    o += snprintf(buf + o, sizeof(buf) - o, "[");
    bool first = true;
    for (int i = 0; i < store::credential_count(); i++) {
        const Credential& c = store::credentials()[i];
        if (!(c.flags & 0x01)) continue;
        char idb64[PK_MAX_CRED_ID_LEN * 2 + 8];
        char uidb64[PK_MAX_USER_ID_LEN * 2 + 8];
        char rp[PK_MAX_RP_ID_LEN * 2 + 1];
        char rpn[PK_MAX_TEXT_FIELD * 2 + 1];
        char un[PK_MAX_TEXT_FIELD * 2 + 1];
        char dn[PK_MAX_TEXT_FIELD * 2 + 1];
        b64url(c.credId, c.credIdLen, idb64);
        b64url(c.userId, c.userIdLen, uidb64);
        json_escape(rp, sizeof(rp), c.rpId, c.rpIdLen);
        json_escape(rpn, sizeof(rpn), c.rpName, c.rpNameLen);
        json_escape(un, sizeof(un), c.userName, c.userNameLen);
        json_escape(dn, sizeof(dn), c.displayName, c.displayNameLen);
        int w = snprintf(buf + o, sizeof(buf) - o,
                         "%s{\"id\":\"%s\",\"rpId\":\"%s\",\"rpName\":\"%s\",\"userId\":\"%s\","
                         "\"userName\":\"%s\",\"displayName\":\"%s\",\"created\":%llu,\"lastUsed\":%llu,"
                         "\"credProtect\":%u,\"signCount\":%u}",
                         first ? "" : ",", idb64, rp, rpn, uidb64, un, dn,
                         (unsigned long long)c.createdAt, (unsigned long long)c.lastUsed,
                         (unsigned)c.credProtect, (unsigned)c.signCount);
        if (w <= 0 || (size_t)w >= sizeof(buf) - o) break;
        o += (size_t)w;
        first = false;
    }
    o += snprintf(buf + o, sizeof(buf) - o, "]");
    send_status(CMD_LIST_CREDS, ST_OK, (const uint8_t*)buf, o);
}

static bool auth_payload(const uint8_t* p, size_t len, size_t& off) {
    if (len < 1) return false;
    uint8_t pinLen = p[0];
    if (len < 1u + pinLen) return false;
    off = 1 + pinLen;
    if (!ctap::pin_is_set()) return true;
    return ctap::check_pin_string((const char*)p + 1, pinLen);
}

// ---------------------------------------------------------------------------
static void dispatch(uint8_t cmd, const uint8_t* p, size_t len) {
    switch (cmd) {
        case CMD_PING:
            send_status(CMD_PING, ST_OK, p, len);
            break;
        case CMD_INFO:
            cmd_info();
            break;
        case CMD_LIST_CREDS:
            cmd_list_creds();
            break;
        case CMD_LOG: {
            static char buf[2400];
            size_t o = 0;
            int start = (g_logHead - g_logCount + 64) % 64;
            for (int i = 0; i < g_logCount && o < sizeof(buf) - 200; i++) {
                const char* line = g_logs[(start + i) % 64];
                o += snprintf(buf + o, sizeof(buf) - o, "%s\n", line);
            }
            send_status(CMD_LOG, ST_OK, (const uint8_t*)buf, o);
            break;
        }
        case CMD_SET_TIME:
            if (len != 8) { send_status(cmd, ST_ERROR); break; }
            {
                uint64_t t = 0;
                for (int i = 7; i >= 0; i--) t = (t << 8) | p[i];
                store::sync_epoch(t);
            }
            send_status(cmd, ST_OK);
            break;
        case CMD_GET_TIME: {
            uint64_t t = store::now_epoch();
            send_status(cmd, ST_OK, (const uint8_t*)&t, 8);
            break;
        }
        case CMD_SET_UP_MODE:
            if (len != 1 || p[0] > 1) { send_status(cmd, ST_ERROR); break; }
            store::settings().upMode = p[0];
            store::save_settings();
            send_status(cmd, ST_OK);
            break;
        case CMD_DEVICE_ID: {
            uint64_t id = ESP.getEfuseMac();
            uint8_t mac[6];
            memcpy(mac, &id, 6);
            send_status(cmd, ST_OK, mac, 6);
            break;
        }
        case CMD_CTAP: {
            static uint8_t out[PK_MAX_MSG_SIZE];
            if (len < 1) { send_status(cmd, ST_ERROR); break; }
            uint8_t status = 0;
            size_t n = ctap::handle(p[0], p + 1, len - 1, out, sizeof(out), &status);
            send_status_data(cmd, status, out, n);
            break;
        }
        case CMD_U2F: {
            static uint8_t out[PK_MAX_MSG_SIZE];
            uint8_t status = 0;
            size_t n = u2f::handle(p, len, out, sizeof(out), &status);
            send_status_data(cmd, 0, out, n);
            break;
        }
        case CMD_OTA_BEGIN:
            if (len != 8) { send_status(cmd, ST_ERROR); break; }
            g_otaSize = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
            g_otaCrcExpected = (uint32_t)p[4] | ((uint32_t)p[5] << 8) | ((uint32_t)p[6] << 16) |
                               ((uint32_t)p[7] << 24);
            g_otaWritten = 0;
            g_otaCrc = 0xFFFFFFFF;
            if (!Update.begin(g_otaSize)) {
                send_status(cmd, ST_ERROR);
                break;
            }
            g_otaActive = true;
            log("OTA begin: %u bytes", (unsigned)g_otaSize);
            send_status(cmd, ST_OK);
            break;
        case CMD_OTA_DATA: {
            if (!g_otaActive || len < 5) { send_status(cmd, ST_ERROR); break; }
            uint32_t off = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
                           ((uint32_t)p[3] << 24);
            if (off != g_otaWritten) { send_status(cmd, ST_ERROR); break; }
            size_t n = len - 4;
            if (Update.write((uint8_t*)p + 4, n) != n) {
                send_status(cmd, ST_ERROR);
                g_otaActive = false;
                break;
            }
            g_otaCrc = crc32_update(g_otaCrc, p + 4, n);
            g_otaWritten += n;
            send_status(cmd, ST_OK);
            break;
        }
        case CMD_OTA_END: {
            if (!g_otaActive) { send_status(cmd, ST_ERROR); break; }
            uint32_t got = ~g_otaCrc;
            bool crcOk = (g_otaCrcExpected == 0) || (got == g_otaCrcExpected);
            if (!crcOk || g_otaWritten != g_otaSize) {
                Update.abort();
                g_otaActive = false;
                send_status(cmd, ST_ERROR);
                break;
            }
            if (!Update.end(true)) {
                Update.abort();
                g_otaActive = false;
                send_status(cmd, ST_ERROR);
                break;
            }
            g_otaActive = false;
            send_status(cmd, ST_OK);
            log("OTA ok, rebooting");
            delay(200);
            ESP.restart();
            break;
        }
        case CMD_REBOOT:
            send_status(cmd, ST_OK);
            delay(100);
            ESP.restart();
            break;
        case CMD_BOOTLOADER:
            send_status(cmd, ST_OK);
            delay(100);
            usb_persist_restart(RESTART_BOOTLOADER);
            break;
        case CMD_FACTORY_RESET: {
            size_t off = 0;
            if (!auth_payload(p, len, off)) { send_status(cmd, ST_AUTH); break; }
            ctap::factory_reset();
            send_status(cmd, ST_OK);
            break;
        }
        case CMD_REPLACE_KEY: {
            if (!interlock::beginReplace()) { send_status(cmd, ST_AUTH); break; }
            send_status(cmd, ST_OK);
            break;
        }
        case CMD_REPLACE_CANCEL: {
            interlock::cancelReplace();
            send_status(cmd, ST_OK);
            break;
        }
        case CMD_DELETE_CRED: {
            size_t off = 0;
            if (!auth_payload(p, len, off)) { send_status(cmd, ST_AUTH); break; }
            const uint8_t* id = p + off;
            size_t idLen = len - off;
            if (idLen == 0) { send_status(cmd, ST_ERROR); break; }
            bool ok = store::delete_credential(id, idLen);
            send_status(cmd, ok ? ST_OK : ST_ERROR);
            break;
        }
        case CMD_DELETE_ALL: {
            size_t off = 0;
            if (!auth_payload(p, len, off)) { send_status(cmd, ST_AUTH); break; }
            store::delete_all_credentials();
            send_status(cmd, ST_OK);
            break;
        }
        default:
            send_status(cmd, ST_NOTSUP);
            break;
    }
}

void log(const char* fmt, ...) {
    char line[160];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    strncpy(g_logs[g_logHead], line, sizeof(g_logs[0]) - 1);
    g_logs[g_logHead][sizeof(g_logs[0]) - 1] = 0;
    g_logHead = (g_logHead + 1) % 64;
    if (g_logCount < 64) g_logCount++;
    Serial.printf("[mgmt] %s\n", line);
}

// ---------------------------------------------------------------------------
static void feed(uint8_t b) {
    switch (g_state) {
        case RX_SOF1:
            if (b == SOF1) g_state = RX_SOF2;
            break;
        case RX_SOF2:
            if (b == SOF2) {
                g_state = RX_HDR;
                g_hdrOff = 0;
            } else {
                g_state = (b == SOF1) ? RX_SOF2 : RX_SOF1;
            }
            break;
        case RX_HDR:
            g_hdr[g_hdrOff++] = b;
            if (g_hdrOff == sizeof(g_hdr)) {
                g_payloadLen = (size_t)g_hdr[3] | ((size_t)g_hdr[4] << 8);
                if (g_payloadLen > MAX_PAYLOAD) {
                    g_state = RX_SOF1;
                    break;
                }
                g_payloadOff = 0;
                g_state = g_payloadLen ? RX_PAYLOAD : RX_CRC1;
            }
            break;
        case RX_PAYLOAD:
            g_payload[g_payloadOff++] = b;
            if (g_payloadOff == g_payloadLen) g_state = RX_CRC1;
            break;
        case RX_CRC1:
            g_crcRecv = b;
            g_state = RX_CRC2;
            break;
        case RX_CRC2: {
            g_crcRecv |= (uint16_t)b << 8;
            uint16_t crc = crc16(g_hdr, sizeof(g_hdr));
            crc = crc16(g_payload, g_payloadLen, crc);
            if (crc == g_crcRecv && g_hdr[0] == 1) {
                dispatch(g_hdr[1], g_payload, g_payloadLen);
            }
            g_state = RX_SOF1;
            break;
        }
    }
}

void begin() {
    C().setRxBufferSize(8192);
    C().setTxTimeoutMs(100);
    log("mgmt ready");
}

void poll() {
    int budget = 512;
    while (C().available() > 0 && budget-- > 0) {
        feed((uint8_t)C().read());
    }
}

}  // namespace mgmt
