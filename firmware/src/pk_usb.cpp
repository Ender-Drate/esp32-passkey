#include "pk_usb.h"

#include <Arduino.h>
#include <USB.h>
#include <USBCDC.h>
#include <USBHID.h>
#include <string.h>

#include "pk_config.h"
#include "pk_ctaphid.h"
#include "pk_mgmt.h"

#if PK_DEBUG
#define DBG(...) mgmt::log(__VA_ARGS__)
#else
#define DBG(...) do {} while (0)
#endif

namespace usb {

static const uint8_t FIDO_REPORT_DESC[] = {
    0x06, 0xD0, 0xF1,  // Usage Page (FIDO Alliance)
    0x09, 0x01,        // Usage (FIDO Authenticator)
    0xA1, 0x01,        // Collection (Application)
    0x09, 0x20,        //   Usage (Input Report Data)
    0x15, 0x00,        //   Logical Minimum (0)
    0x26, 0xFF, 0x00,  //   Logical Maximum (255)
    0x75, 0x08,        //   Report Size (8)
    0x95, 0x40,        //   Report Count (64)
    0x81, 0x02,        //   Input (Data,Var,Abs)
    0x09, 0x21,        //   Usage (Output Report Data)
    0x15, 0x00,
    0x26, 0xFF, 0x00,
    0x75, 0x08,
    0x95, 0x40,
    0x91, 0x02,        //   Output (Data,Var,Abs)
    0xC0,              // End Collection
};

struct HidPacket {
    uint8_t data[64];
};

static QueueHandle_t g_rxQueue = nullptr;
static USBHID g_hid;
static USBCDC g_cdc(0);
static bool g_started = false;

USBCDC& cdc() { return g_cdc; }

class FidoHidDevice : public USBHIDDevice {
public:
    uint16_t _onGetDescriptor(uint8_t* buffer) override {
        memcpy(buffer, FIDO_REPORT_DESC, sizeof(FIDO_REPORT_DESC));
        return sizeof(FIDO_REPORT_DESC);
    }

    void _onOutput(uint8_t report_id, const uint8_t* buffer, uint16_t len) override {
        (void)report_id;
        static int logged = 0;
        if (logged < 6) {
            logged++;
            uint32_t cid = ((uint32_t)buffer[0] << 24) | ((uint32_t)buffer[1] << 16) |
                           ((uint32_t)buffer[2] << 8) | buffer[3];
            (void)cid;
            DBG("HID OUT cid=%08x cmd=%02x len=%u", cid, buffer[4], len);
        }
        if (len != 64 || !g_rxQueue) return;
        ctaphid::note_output_report(buffer);
        HidPacket pkt;
        memcpy(pkt.data, buffer, 64);
        // Never block the USB task; drop if the firmware is not keeping up.
        xQueueSend(g_rxQueue, &pkt, 0);
    }
};

static FidoHidDevice g_fido;

bool begin(const char* serial) {
    g_rxQueue = xQueueCreate(12, sizeof(HidPacket));
    if (!g_rxQueue) return false;

    // USB must be initialised by us, not by the core: the HID report
    // descriptor has to exist before USB.begin() builds the configuration.
    USB.manufacturerName(PK_MANUFACTURER);
    USB.productName(PK_PRODUCT_NAME);
    if (serial && serial[0]) USB.serialNumber(serial);
    USB.VID(0x303A);
    USB.PID(0x82F1);
    USB.usbPower(100);

    if (!g_hid.addDevice(&g_fido, sizeof(FIDO_REPORT_DESC))) {
        Serial.println("[usb] HID addDevice failed");
        return false;
    }
    g_hid.begin();
    g_cdc.setRxBufferSize(8192);
    g_cdc.setTxTimeoutMs(100);
    if (!USB.begin()) {
        Serial.println("[usb] USB.begin failed");
        return false;
    }
    g_cdc.begin(115200);
    g_started = true;
    return true;
}

bool hid_ready() { return g_started && g_hid.ready(); }

bool send_report(const uint8_t* data, size_t len, uint32_t timeout_ms) {
    if (!g_started || len != 64) return false;
    if (!g_hid.ready()) return false;
    return g_hid.SendReport(0, data, 64, timeout_ms);
}

bool pop_report(uint8_t out[64], uint32_t timeout_ms) {
    if (!g_rxQueue) return false;
    HidPacket pkt;
    if (xQueueReceive(g_rxQueue, &pkt, pdMS_TO_TICKS(timeout_ms)) != pdTRUE) return false;
    memcpy(out, pkt.data, 64);
    return true;
}

}  // namespace usb
