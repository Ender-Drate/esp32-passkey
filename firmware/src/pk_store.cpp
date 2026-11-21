#include "pk_store.h"

#include <Arduino.h>
#include <LittleFS.h>
#include <Preferences.h>
#include <esp_heap_caps.h>
#include <string.h>

#include "pk_crypto.h"

namespace pk {
namespace store {

static const char* NVS_NS = "pk";
static Preferences g_prefs;
static uint8_t g_master[32];
static Settings g_settings;
static Credential* g_creds = nullptr;
static int g_credCount = 0;
static bool g_dirty = false;
static uint32_t g_dirtyAt = 0;

static const char* CRED_FILE = "/creds.bin";
static const char* CRED_TMP = "/creds.tmp";
static const char* BLOB_FILE = "/blob.bin";

// --- serialization helpers ---------------------------------------------------
struct Writer {
    uint8_t* p;
    size_t cap;
    size_t n = 0;
    bool ok = true;
    Writer(uint8_t* buf, size_t capacity) : p(buf), cap(capacity) {}
    void u8(uint8_t v) { if (n + 1 > cap) { ok = false; return; } p[n++] = v; }
    void u16(uint16_t v) { u8(v & 0xFF); u8(v >> 8); }
    void u32(uint32_t v) { u16(v & 0xFFFF); u16(v >> 16); }
    void u64(uint64_t v) { u32((uint32_t)v); u32((uint32_t)(v >> 32)); }
    void raw(const void* d, size_t l) {
        if (n + l > cap) { ok = false; return; }
        memcpy(p + n, d, l);
        n += l;
    }
};

struct Reader {
    const uint8_t* p;
    size_t cap;
    size_t n = 0;
    bool ok = true;
    Reader(const uint8_t* buf, size_t capacity) : p(buf), cap(capacity) {}
    uint8_t u8() { if (n + 1 > cap) { ok = false; return 0; } return p[n++]; }
    uint16_t u16() { uint16_t a = u8(); uint16_t b = u8(); return a | (b << 8); }
    uint32_t u32() { uint32_t a = u16(); uint32_t b = u16(); return a | (b << 16); }
    uint64_t u64() { uint64_t a = u32(); uint64_t b = u32(); return a | (b << 32); }
    void raw(void* d, size_t l) {
        if (n + l > cap) { ok = false; memset(d, 0, l); return; }
        memcpy(d, p + n, l);
        n += l;
    }
};

static void serialize_cred(Writer& w, const Credential& c) {
    w.u8(c.credIdLen);
    w.raw(c.credId, c.credIdLen);
    w.raw(c.rpIdHash, 32);
    w.u8(c.rpIdLen); w.raw(c.rpId, c.rpIdLen);
    w.u8(c.rpNameLen); w.raw(c.rpName, c.rpNameLen);
    w.u8(c.userIdLen); w.raw(c.userId, c.userIdLen);
    w.u8(c.userNameLen); w.raw(c.userName, c.userNameLen);
    w.u8(c.displayNameLen); w.raw(c.displayName, c.displayNameLen);
    w.raw(c.priv, 32);
    w.raw(c.credRandom, 32);
    w.u32(c.signCount);
    w.u8(c.credProtect);
    w.u8(c.flags);
    w.u64(c.createdAt);
    w.u64(c.lastUsed);
}

static bool deserialize_cred(Reader& r, Credential& c) {
    memset(&c, 0, sizeof(c));
    c.credIdLen = r.u8();
    if (c.credIdLen > PK_MAX_CRED_ID_LEN) return false;
    r.raw(c.credId, c.credIdLen);
    r.raw(c.rpIdHash, 32);
    c.rpIdLen = r.u8();
    if (c.rpIdLen > PK_MAX_RP_ID_LEN) return false;
    r.raw(c.rpId, c.rpIdLen);
    c.rpNameLen = r.u8();
    if (c.rpNameLen > PK_MAX_TEXT_FIELD) return false;
    r.raw(c.rpName, c.rpNameLen);
    c.userIdLen = r.u8();
    if (c.userIdLen > PK_MAX_USER_ID_LEN) return false;
    r.raw(c.userId, c.userIdLen);
    c.userNameLen = r.u8();
    if (c.userNameLen > PK_MAX_TEXT_FIELD) return false;
    r.raw(c.userName, c.userNameLen);
    c.displayNameLen = r.u8();
    if (c.displayNameLen > PK_MAX_TEXT_FIELD) return false;
    r.raw(c.displayName, c.displayNameLen);
    r.raw(c.priv, 32);
    r.raw(c.credRandom, 32);
    c.signCount = r.u32();
    c.credProtect = r.u8();
    c.flags = r.u8();
    c.createdAt = r.u64();
    c.lastUsed = r.u64();
    return r.ok;
}

// --- init --------------------------------------------------------------------
bool begin() {
    if (!LittleFS.begin(true)) {
        Serial.println("[store] LittleFS mount failed");
        return false;
    }
    g_prefs.begin(NVS_NS, false);

    size_t mkLen = g_prefs.getBytesLength("mk");
    if (mkLen == 32) {
        g_prefs.getBytes("mk", g_master, 32);
    } else {
        if (!random_bytes(g_master, 32)) return false;
        g_prefs.putBytes("mk", g_master, 32);
    }

    size_t slen = g_prefs.getBytesLength("cfg");
    if (slen == sizeof(Settings)) {
        g_prefs.getBytes("cfg", &g_settings, sizeof(Settings));
    } else {
        memset(&g_settings, 0, sizeof(Settings));
        g_settings.version = 1;
        g_settings.pinRetries = PK_PIN_RETRIES;
        g_settings.minPinLen = PK_PIN_MIN_LEN;
        g_settings.upMode = 0;
        save_settings();
    }
    if (g_settings.pinRetries > PK_PIN_RETRIES) g_settings.pinRetries = PK_PIN_RETRIES;
    if (g_settings.minPinLen < PK_PIN_MIN_LEN) g_settings.minPinLen = PK_PIN_MIN_LEN;

    g_creds = (Credential*)heap_caps_malloc(sizeof(Credential) * PK_MAX_CREDENTIALS,
                                            MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!g_creds) g_creds = (Credential*)malloc(sizeof(Credential) * PK_MAX_CREDENTIALS);
    if (!g_creds) return false;

    g_credCount = 0;
    File f = LittleFS.open(CRED_FILE, "r");
    if (f) {
        uint8_t hdr[8];
        if (f.read(hdr, 8) == 8 && memcmp(hdr, "PKC1", 4) == 0) {
            uint16_t count = (uint16_t)(hdr[6] | (hdr[7] << 8));
            for (uint16_t i = 0; i < count && g_credCount < PK_MAX_CREDENTIALS; i++) {
                uint8_t buf[1024];
                uint16_t len = 0;
                if (f.read((uint8_t*)&len, 2) != 2) break;
                if (len > sizeof(buf) || f.read(buf, len) != len) break;
                Reader r{buf, len};
                if (!deserialize_cred(r, g_creds[g_credCount])) break;
                g_credCount++;
            }
        }
        f.close();
    }
    g_settings.bootCount++;
    save_settings();
    return true;
}

const uint8_t* master_key() { return g_master; }
Settings& settings() { return g_settings; }

void save_settings() {
    g_prefs.putBytes("cfg", &g_settings, sizeof(Settings));
}

int credential_count() { return g_credCount; }
Credential* credentials() { return g_creds; }

Credential* find_by_cred_id(const uint8_t* id, size_t len) {
    for (int i = 0; i < g_credCount; i++) {
        if (g_creds[i].credIdLen == len && ct_equal(g_creds[i].credId, id, len)) return &g_creds[i];
    }
    return nullptr;
}

Credential* find_by_rp(const uint8_t rpIdHash[32], const uint8_t* credId, size_t credIdLen) {
    for (int i = 0; i < g_credCount; i++) {
        if (!(g_creds[i].flags & 1)) continue;
        if (memcmp(g_creds[i].rpIdHash, rpIdHash, 32) != 0) continue;
        if (credId && credIdLen && (g_creds[i].credIdLen != credIdLen ||
                                    !ct_equal(g_creds[i].credId, credId, credIdLen))) continue;
        return &g_creds[i];
    }
    return nullptr;
}

bool add_credential(const Credential& c) {
    if (g_credCount >= PK_MAX_CREDENTIALS) return false;
    g_creds[g_credCount++] = c;
    return save_credentials();
}

bool update_credential(const Credential& c) {
    for (int i = 0; i < g_credCount; i++) {
        if (g_creds[i].credIdLen == c.credIdLen &&
            ct_equal(g_creds[i].credId, c.credId, c.credIdLen)) {
            g_creds[i] = c;
            return save_credentials();
        }
    }
    return false;
}

bool delete_credential(const uint8_t* credId, size_t len) {
    for (int i = 0; i < g_credCount; i++) {
        if (g_creds[i].credIdLen == len && ct_equal(g_creds[i].credId, credId, len)) {
            for (int j = i; j < g_credCount - 1; j++) g_creds[j] = g_creds[j + 1];
            g_credCount--;
            return save_credentials();
        }
    }
    return false;
}

void delete_all_credentials() {
    g_credCount = 0;
    save_credentials();
}

void mark_dirty() {
    g_dirty = true;
    if (!g_dirtyAt) g_dirtyAt = millis();
}

void flush_if_dirty() {
    if (g_dirty && millis() - g_dirtyAt > 2000) {
        save_credentials();
        g_dirty = false;
        g_dirtyAt = 0;
    }
}

void factory_reset() {
    delete_all_credentials();
    large_blob_reset();
    memset(&g_settings, 0, sizeof(g_settings));
    g_settings.version = 1;
    g_settings.pinRetries = PK_PIN_RETRIES;
    g_settings.minPinLen = PK_PIN_MIN_LEN;
    g_settings.upMode = 0;
    g_settings.bootCount = 1;
    if (!random_bytes(g_master, 32)) {
        for (int i = 0; i < 32; i++) g_master[i] = (uint8_t)esp_random();
    }
    g_prefs.putBytes("mk", g_master, 32);
    save_settings();
}

bool save_credentials() {
    File f = LittleFS.open(CRED_TMP, "w");
    if (!f) return false;
    uint8_t hdr[8] = {'P', 'K', 'C', '1', 1, 0, (uint8_t)(g_credCount & 0xFF),
                      (uint8_t)(g_credCount >> 8)};
    f.write(hdr, 8);
    for (int i = 0; i < g_credCount; i++) {
        uint8_t buf[1024];
        Writer w{buf, sizeof(buf)};
        serialize_cred(w, g_creds[i]);
        if (!w.ok) { f.close(); LittleFS.remove(CRED_TMP); return false; }
        uint16_t len = (uint16_t)w.n;
        f.write((const uint8_t*)&len, 2);
        f.write(buf, len);
    }
    f.close();
    LittleFS.remove(CRED_FILE);
    bool ok = LittleFS.rename(CRED_TMP, CRED_FILE);
    g_dirty = false;
    return ok;
}

bool wrap_key_handle(const KeyHandle& kh, uint8_t* out, size_t& outLen) {
    uint8_t plain[128];
    Writer w{plain, sizeof(plain)};
    w.u8(1);
    w.raw(kh.rpIdHash, 32);
    w.raw(kh.priv, 32);
    w.u32(kh.signCount);
    w.u8(kh.flags);
    w.raw(kh.credRandom, 32);
    if (!w.ok) return false;
    uint8_t iv[12];
    random_bytes(iv, sizeof(iv));
    out[0] = 1;
    memcpy(out + 1, iv, 12);
    if (!aes256_gcm_encrypt(g_master, iv, 12, plain, w.n, out + 13)) return false;
    outLen = 13 + w.n + 16;
    return true;
}

bool unwrap_key_handle(const uint8_t* in, size_t inLen, KeyHandle& kh) {
    if (inLen < 13 + 1 + 16 || in[0] != 1) return false;
    uint8_t plain[128];
    size_t ctLen = inLen - 13;
    if (ctLen > sizeof(plain)) return false;
    if (!aes256_gcm_decrypt(g_master, in + 1, 12, in + 13, ctLen, plain)) return false;
    if (plain[0] != 1) return false;
    Reader r{plain + 1, ctLen - 16 - 1};
    r.raw(kh.rpIdHash, 32);
    r.raw(kh.priv, 32);
    kh.signCount = r.u32();
    kh.flags = r.u8();
    r.raw(kh.credRandom, 32);
    return r.ok;
}

// --- large blobs -------------------------------------------------------------
static size_t g_blobSize = 0;
static bool g_blobLoaded = false;

static void load_blob_meta() {
    if (g_blobLoaded) return;
    g_blobSize = 0;
    File f = LittleFS.open(BLOB_FILE, "r");
    if (f) {
        g_blobSize = f.size();
        f.close();
    }
    g_blobLoaded = true;
}

size_t large_blob_size() {
    load_blob_meta();
    return g_blobSize;
}

bool large_blob_read(uint8_t* out, size_t offset, size_t len) {
    load_blob_meta();
    if (offset > g_blobSize) return false;
    size_t n = len;
    if (offset + n > g_blobSize) n = g_blobSize - offset;
    File f = LittleFS.open(BLOB_FILE, "r");
    if (!f) return n == 0;
    f.seek(offset);
    size_t got = f.read(out, n);
    f.close();
    return got == n;
}

bool large_blob_write(const uint8_t* data, size_t len) {
    if (len > PK_MAX_LARGE_BLOB) return false;
    File f = LittleFS.open(BLOB_FILE, "w");
    if (!f) return false;
    bool ok = f.write(data, len) == len;
    f.close();
    if (ok) { g_blobSize = len; g_blobLoaded = true; }
    return ok;
}

void large_blob_reset() {
    LittleFS.remove(BLOB_FILE);
    g_blobSize = 0;
    g_blobLoaded = true;
}

uint64_t now_epoch() {
    uint32_t up = (millis() - g_settings.uptimeAtSync) / 1000;
    return g_settings.epochAtSync + up;
}

void sync_epoch(uint64_t epoch) {
    g_settings.epochAtSync = epoch;
    g_settings.uptimeAtSync = millis();
    save_settings();
}

}  // namespace store
}  // namespace pk
