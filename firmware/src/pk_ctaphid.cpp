#include "pk_ctaphid.h"

#include <Arduino.h>
#include <string.h>

#include "esp_system.h"

#include "pk_config.h"
#include "pk_ctap2.h"
#include "pk_mgmt.h"
#include "pk_u2f.h"
#include "pk_usb.h"

#if PK_DEBUG
#define DBG(...) mgmt::log(__VA_ARGS__)
#else
#define DBG(...) do {} while (0)
#endif

namespace ctaphid {

static uint32_t g_channels[PK_CTAPHID_CHANNEL_COUNT];
static int g_channelCount = 0;
static uint32_t g_activeCid = 0;
static bool g_rxActive = false;
static uint8_t g_rxCmd = 0;
static uint32_t g_rxTotal = 0;
static uint32_t g_rxGot = 0;
static uint8_t g_rxSeq = 0;
static uint8_t g_rxBuf[PK_MAX_MSG_SIZE];
static uint8_t g_txBuf[PK_MAX_MSG_SIZE];
static volatile bool g_cancel = false;
static volatile bool g_processing = false;
static uint32_t g_lastKeepalive = 0;

static uint32_t rd32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static void wr32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}
static uint16_t rd16(const uint8_t* p) { return (uint16_t)((p[0] << 8) | p[1]); }
static void wr16(uint8_t* p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

static bool channel_exists(uint32_t cid) {
    for (int i = 0; i < g_channelCount; i++) if (g_channels[i] == cid) return true;
    return false;
}

static uint32_t allocate_channel() {
    uint32_t cid = 0;
    do {
        cid = esp_random() & 0x7FFFFFFF;
    } while (cid == 0 || channel_exists(cid));
    if (g_channelCount < PK_CTAPHID_CHANNEL_COUNT) {
        g_channels[g_channelCount++] = cid;
    } else {
        g_channels[0] = cid;
    }
    return cid;
}

bool send_raw(uint32_t cid, uint8_t cmd, const uint8_t* data, size_t len) {
    if (len > 0xFFFF) return false;
    uint8_t pkt[64];
    memset(pkt, 0, sizeof(pkt));
    wr32(pkt, cid);
    pkt[4] = cmd;
    wr16(pkt + 5, (uint16_t)len);
    size_t first = len > 57 ? 57 : len;
    if (first) memcpy(pkt + 7, data, first);
    if (!usb::send_report(pkt, 64)) return false;

    size_t sent = first;
    uint8_t seq = 0;
    while (sent < len) {
        memset(pkt, 0, sizeof(pkt));
        wr32(pkt, cid);
        pkt[4] = seq++;
        size_t n = (len - sent) > 59 ? 59 : (len - sent);
        memcpy(pkt + 5, data + sent, n);
        sent += n;
        if (!usb::send_report(pkt, 64)) return false;
    }
    return true;
}

void keepalive() {
    if (!g_processing) return;
    uint32_t now = millis();
    if (now - g_lastKeepalive < 90) return;
    g_lastKeepalive = now;
    uint8_t status = 1;
    send_raw(g_activeCid, CTAPHID_CMD_KEEPALIVE, &status, 1);
}

bool cancelled() { return g_cancel; }
uint32_t active_cid() { return g_activeCid; }

void note_output_report(const uint8_t* pkt) {
    if (pkt[4] == CTAPHID_CMD_CANCEL && pkt[5] == 0 && pkt[6] == 0) g_cancel = true;
}

static void error(uint32_t cid, uint8_t code) { send_raw(cid, CTAPHID_CMD_ERROR, &code, 1); }

static void dispatch(uint32_t cid, uint8_t cmd, const uint8_t* data, size_t len) {
    uint8_t status = 0;
    size_t outLen = 0;
    DBG("DISP cmd=%02x len=%u", cmd, (unsigned)len);
    if (cmd == CTAPHID_CMD_PING) {
        send_raw(cid, CTAPHID_CMD_PING, data, len);
        return;
    }
    g_processing = true;
    g_lastKeepalive = 0;
    if (cmd == CTAPHID_CMD_CBOR) {
        if (len < 1) {
            error(cid, CTAPHID_ERR_INVALID_LEN);
        } else {
            g_txBuf[0] = 0;
            outLen = pk::ctap::handle(data[0], data + 1, len - 1, g_txBuf + 1,
                                      sizeof(g_txBuf) - 1, &status);
            g_txBuf[0] = status;
            send_raw(cid, CTAPHID_CMD_CBOR, g_txBuf, outLen + 1);
        }
    } else if (cmd == CTAPHID_CMD_MSG) {
        outLen = pk::u2f::handle(data, len, g_txBuf, sizeof(g_txBuf), &status);
        send_raw(cid, CTAPHID_CMD_MSG, g_txBuf, outLen);
    } else {
        error(cid, CTAPHID_ERR_INVALID_CMD);
    }
    g_processing = false;
}

static void handle_packet(const uint8_t* pkt) {
    uint32_t cid = rd32(pkt);
    uint8_t b0 = pkt[4];
    uint16_t bcnt = rd16(pkt + 5);
    static int logged = 0;
    if (logged < 8) {
        logged++;
        DBG("PKT cid=%08x b0=%02x bcnt=%u", cid, b0, bcnt);
    }

    // CANCEL is special: its command byte (0x11) has no 0x80 bit.
    if (b0 == CTAPHID_CMD_CANCEL && bcnt == 0) {
        g_cancel = true;
        return;
    }

    if (b0 & 0x80) {  // init packet
        if (b0 == CTAPHID_CMD_INIT) {
            // 8-byte nonce + 1-byte CTAPHID protocol version
            if (bcnt != 9 && bcnt != 8) { error(cid, CTAPHID_ERR_INVALID_LEN); return; }
            uint32_t newCid = channel_exists(cid) ? cid : allocate_channel();
            uint8_t resp[17];
            memcpy(resp, pkt + 7, 8);
            wr32(resp + 8, newCid);
            resp[12] = 2;
            resp[13] = PK_VERSION_MAJOR;
            resp[14] = PK_VERSION_MINOR;
            resp[15] = PK_VERSION_PATCH;
            resp[16] = 0x05;  // wink + cbor
            g_rxActive = false;
            // The reply to a broadcast INIT goes out on the broadcast channel;
            // the newly allocated CID is carried inside the payload.
            bool ok = send_raw(cid, CTAPHID_CMD_INIT, resp, sizeof(resp));
            DBG("INIT cid=%08x -> %08x %s", cid, newCid, ok ? "ok" : "SENDFAIL");
            return;
        }
        if (!channel_exists(cid)) { error(cid, CTAPHID_ERR_INVALID_CHANNEL); return; }
        if (b0 == CTAPHID_CMD_WINK) {
            g_activeCid = cid;
            pk::ctap::wink();
            send_raw(cid, CTAPHID_CMD_WINK, nullptr, 0);
            return;
        }
        if (b0 == CTAPHID_CMD_LOCK) {
            send_raw(cid, CTAPHID_CMD_LOCK, nullptr, 0);
            return;
        }
        if (b0 != CTAPHID_CMD_PING && b0 != CTAPHID_CMD_MSG && b0 != CTAPHID_CMD_CBOR) {
            error(cid, CTAPHID_ERR_INVALID_CMD);
            return;
        }
        if (g_rxActive) {
            if (cid != g_activeCid || b0 != g_rxCmd) { error(cid, CTAPHID_ERR_CHANNEL_BUSY); return; }
        }
        if (bcnt > sizeof(g_rxBuf)) { error(cid, CTAPHID_ERR_INVALID_LEN); return; }
        g_activeCid = cid;
        g_rxCmd = b0;
        g_rxTotal = bcnt;
        g_rxGot = 0;
        g_rxSeq = 0;
        g_rxActive = true;
        g_cancel = false;
        size_t n = bcnt > 57 ? 57 : bcnt;
        if (n) memcpy(g_rxBuf, pkt + 7, n);
        g_rxGot = n;
    } else {
        // continuation packet, byte 4 is the sequence number
        if (!g_rxActive || cid != g_activeCid) { error(cid, CTAPHID_ERR_INVALID_SEQ); return; }
        if (pkt[4] != g_rxSeq) { error(cid, CTAPHID_ERR_INVALID_SEQ); return; }
        size_t n = g_rxTotal - g_rxGot;
        if (n > 59) n = 59;
        memcpy(g_rxBuf + g_rxGot, pkt + 5, n);
        g_rxGot += n;
        g_rxSeq++;
    }

    if (g_rxGot >= g_rxTotal) {
        g_rxActive = false;
        dispatch(g_activeCid, g_rxCmd, g_rxBuf, g_rxTotal);
    }
}

void poll() {
    uint8_t pkt[64];
    if (!usb::pop_report(pkt, 5)) return;
    handle_packet(pkt);
}

bool init() { return true; }

}  // namespace ctaphid
