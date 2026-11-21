#include "pk_ble.h"

#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include "esp_gap_ble_api.h"
#include <string.h>

#include "esp_system.h"

#include "pk_config.h"
#include "pk_ctap2.h"
#include "pk_mgmt.h"
#include "pk_u2f.h"

#if PK_DEBUG
#define DBG(...) mgmt::log(__VA_ARGS__)
#else
#define DBG(...) do {} while (0)
#endif

namespace ble {

// FIDO U2F over BLE service
#ifndef PK_BLE_ALIAS
#define PK_BLE_ALIAS 0
#endif
#if PK_BLE_ALIAS
// Windows reserves 0xFFFD for its own FIDO stack, so a test build can expose
// the identical GATT layout on 0xFFF0 to exercise the transport end to end.
static const char* SERVICE_UUID = "0000FFF0-0000-1000-8000-00805F9B34FB";
#else
static const char* SERVICE_UUID = "0000FFFD-0000-1000-8000-00805F9B34FB";
#endif
static const char* CP_UUID = "F1D0FFF1-DEAA-ECEE-B42F-C9BA7ED623BB";
static const char* STATUS_UUID = "F1D0FFF2-DEAA-ECEE-B42F-C9BA7ED623BB";
static const char* CP_LEN_UUID = "F1D0FFF3-DEAA-ECEE-B42F-C9BA7ED623BB";
static const char* REV_BITS_UUID = "F1D0FFF4-DEAA-ECEE-B42F-C9BA7ED623BB";
static const char* REV_UUID = "00002A28-0000-1000-8000-00805F9B34FB";

// Conservative fragment size: works with the default ATT MTU (23).
static const size_t FRAG = 20;

struct Request {
    uint8_t cmd;
    uint16_t len;
    uint8_t* data;
};

static QueueHandle_t g_queue = nullptr;
static BLECharacteristic* g_status = nullptr;
static BLEServer* g_server = nullptr;
static volatile bool g_connected = false;
static volatile bool g_inflight = false;

// reassembly state
static uint8_t g_rxBuf[PK_MAX_MSG_SIZE];
static size_t g_rxTotal = 0;
static size_t g_rxGot = 0;
static uint8_t g_rxCmd = 0;
static uint8_t g_rxSeq = 0;

static void resetRx() {
    g_rxTotal = 0;
    g_rxGot = 0;
    g_rxSeq = 0;
}

static void notifyFrame(uint8_t stat, const uint8_t* data, size_t len) {
    if (!g_status || !g_connected) return;
    DBG("BLE notify stat=%02x len=%u", stat, (unsigned)len);
    uint8_t frag[FRAG];
    frag[0] = stat;
    frag[1] = (uint8_t)(len >> 8);
    frag[2] = (uint8_t)len;
    size_t first = len > FRAG - 3 ? FRAG - 3 : len;
    if (first) memcpy(frag + 3, data, first);
    g_status->setValue(frag, 3 + first);
    g_status->notify();
    size_t sent = first;
    uint8_t seq = 0;
    while (sent < len) {
        size_t n = len - sent;
        if (n > FRAG - 1) n = FRAG - 1;
        frag[0] = seq++;
        memcpy(frag + 1, data + sent, n);
        g_status->setValue(frag, 1 + n);
        g_status->notify();
        sent += n;
        delay(6);
    }
}

void keepalive() {
    if (!g_connected || !g_inflight) return;
    static uint32_t last = 0;
    if (millis() - last < 90) return;
    last = millis();
    uint8_t st = 0x01;  // TUP_NEEDED
    notifyFrame(0x82, &st, 1);
}

bool connected() { return g_connected; }

class ServerCallbacks : public BLEServerCallbacks {
    void onConnect(BLEServer* server) override {
        (void)server;
        g_connected = true;
        resetRx();
        mgmt::log("BLE connected");
    }
    void onDisconnect(BLEServer* server) override {
        (void)server;
        g_connected = false;
        g_inflight = false;
        resetRx();
        mgmt::log("BLE disconnected");
        BLEDevice::startAdvertising();
    }
};

class ControlCallbacks : public BLECharacteristicCallbacks {
    void onWrite(BLECharacteristic* c) override {
        const uint8_t* p = c->getData();
        size_t n = c->getLength();
        if (!p || n < 1) return;
        DBG("BLE write len=%u b0=%02x", (unsigned)n, p[0]);

        if (p[0] & 0x80) {  // initialization fragment
            if (n < 3) return;
            g_rxCmd = p[0];
            g_rxTotal = ((size_t)p[1] << 8) | p[2];
            g_rxGot = 0;
            g_rxSeq = 0;
            if (g_rxTotal > sizeof(g_rxBuf)) {
                g_rxTotal = 0;
                uint8_t err03[2] = {0x01, 0x03}; notifyFrame(0xBF, err03, 2);  // INVALID_LEN
                return;
            }
            size_t take = n - 3;
            if (take > g_rxTotal) take = g_rxTotal;
            memcpy(g_rxBuf, p + 3, take);
            g_rxGot = take;
        } else {
            if (g_rxTotal == 0) return;
            if (p[0] != g_rxSeq) {
                resetRx();
                uint8_t err04[2] = {0x01, 0x04}; notifyFrame(0xBF, err04, 2);  // INVALID_SEQ
                return;
            }
            g_rxSeq++;
            size_t take = n - 1;
            if (take > g_rxTotal - g_rxGot) take = g_rxTotal - g_rxGot;
            memcpy(g_rxBuf + g_rxGot, p + 1, take);
            g_rxGot += take;
        }

        if (g_rxTotal && g_rxGot >= g_rxTotal) {
            uint8_t* copy = (uint8_t*)malloc(g_rxTotal);
            if (!copy) { resetRx(); return; }
            memcpy(copy, g_rxBuf, g_rxTotal);
            Request req{g_rxCmd, (uint16_t)g_rxTotal, copy};
            if (xQueueSend(g_queue, &req, 0) != pdTRUE) {
                free(copy);
                uint8_t err06[2] = {0x01, 0x06}; notifyFrame(0xBF, err06, 2);  // CHANNEL_BUSY
            }
            resetRx();
        }
    }
};

class RevCallbacks : public BLECharacteristicCallbacks {
    void onWrite(BLECharacteristic* c) override {
        (void)c;  // version negotiation is accepted but we always speak 1.2
    }
};

void begin(const char* name) {
    g_queue = xQueueCreate(2, sizeof(Request));
    BLEDevice::init(name);
    g_server = BLEDevice::createServer();
    g_server->setCallbacks(new ServerCallbacks());

    BLEService* svc = g_server->createService(SERVICE_UUID);

    BLECharacteristic* cp = svc->createCharacteristic(
        CP_UUID, BLECharacteristic::PROPERTY_WRITE | BLECharacteristic::PROPERTY_WRITE_NR);
    cp->setCallbacks(new ControlCallbacks());

    g_status = svc->createCharacteristic(STATUS_UUID, BLECharacteristic::PROPERTY_NOTIFY);
    g_status->addDescriptor(new BLE2902());

    BLECharacteristic* lenChar = svc->createCharacteristic(CP_LEN_UUID, BLECharacteristic::PROPERTY_READ);
    uint8_t lenVal[2] = {FRAG, 0};
    lenChar->setValue(lenVal, 2);

    BLECharacteristic* rev = svc->createCharacteristic(
        BLEUUID(REV_UUID), BLECharacteristic::PROPERTY_READ);
    rev->setValue("1.0");

    BLECharacteristic* bits = svc->createCharacteristic(
        REV_BITS_UUID, BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_WRITE);
    uint8_t bitVal[1] = {0xC0};  // 1.1 + 1.2
    bits->setValue(bitVal, 1);
    bits->setCallbacks(new RevCallbacks());

    svc->start();

    // Advertise from a random static address: Windows caches GATT per
    // (address, service UUID), and a public MAC keeps the stale "no FIDO
    // service" entry forever.
    esp_bd_addr_t randAddr = {0xDA, 0x7E, 0x51, 0xA3, 0x2C, 0x48};
    esp_ble_gap_set_rand_addr(randAddr);

    esp_ble_adv_data_t advData = {};
    advData.set_scan_rsp = false;
    advData.include_name = false;
    advData.include_txpower = false;
    advData.flag = (ESP_BLE_ADV_FLAG_GEN_DISC | ESP_BLE_ADV_FLAG_BREDR_NOT_SPT);
    static uint8_t fidoUuid[2] = {0xFD, 0xFF};  // 0xFFFD little-endian
    advData.p_service_uuid = fidoUuid;
    advData.service_uuid_len = sizeof(fidoUuid);
    esp_ble_gap_config_adv_data(&advData);

    esp_ble_adv_data_t scanRsp = {};
    scanRsp.set_scan_rsp = true;
    scanRsp.include_name = true;
    scanRsp.include_txpower = false;
    scanRsp.flag = 0;
    esp_ble_gap_config_adv_data(&scanRsp);

    esp_ble_adv_params_t advParams = {};
    advParams.adv_int_min = 0x20;
    advParams.adv_int_max = 0x40;
    advParams.adv_type = ADV_TYPE_IND;
    advParams.own_addr_type = BLE_ADDR_TYPE_RANDOM;
    advParams.channel_map = ADV_CHNL_ALL;
    advParams.adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY;
    esp_err_t advErr = esp_ble_gap_start_advertising(&advParams);
    mgmt::log("BLE advertising as %s, svc handle=%u adv=%d", name,
              (unsigned)svc->getHandle(), (int)advErr);
}

static void sendError(uint16_t code) {
    uint8_t e[2] = {(uint8_t)(code >> 8), (uint8_t)code};
    notifyFrame(0xBF, e, 2);
}

void poll() {
    if (!g_queue || !g_connected) return;
    Request req;
    if (xQueueReceive(g_queue, &req, 0) != pdTRUE) return;

    static uint8_t out[PK_MAX_MSG_SIZE];
    size_t outLen = 0;
    g_inflight = true;
    DBG("BLE req cmd=%02x len=%u", req.cmd, (unsigned)req.len);

    if (req.cmd == 0x81) {  // PING
        memcpy(out, req.data, req.len);
        outLen = req.len;
        notifyFrame(0x81, out, outLen);
    } else if (req.cmd == 0x83) {  // U2F MSG (extended APDU)
        uint8_t st = 0;
        outLen = pk::u2f::handle(req.data, req.len, out, sizeof(out), &st);
        notifyFrame(0x83, out, outLen);
    } else if (req.cmd == 0x90) {  // CTAP2 CBOR
        if (req.len < 1) {
            sendError(0x03);
        } else {
            uint8_t st = 0;
            out[0] = 0;
            size_t n = pk::ctap::handle(req.data[0], req.data + 1, req.len - 1, out + 1,
                                        sizeof(out) - 1, &st);
            out[0] = st;
            notifyFrame(0x90, out, n + 1);
        }
    } else {
        sendError(0x01);  // INVALID_CMD
    }

    g_inflight = false;
    free(req.data);
}

}  // namespace ble
