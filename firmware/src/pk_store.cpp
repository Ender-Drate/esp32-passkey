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

// Credentials are encrypted with a random DEK.  The DEK is wrapped by the
// second board's KEK and stored in NVS; the KEK itself never touches main
// flash.  At boot the interlock task obtains the KEK, unwraps the DEK and
// decrypts /creds.bin into PSRAM.
static uint8_t g_dek[32];
static uint8_t g_kek[32];
static bool g_unlocked = false;
static bool g_legacyPlain = false;
static uint8_t* g_plain = nullptr;
static uint8_t* g_cipher = nullptr;
static const size_t SCRATCH_CAP = 32768;
static char g_err[48] = {0};

static void set_err(const char* e) {
    strncpy(g_err, e, sizeof(g_err) - 1);
    g_err[sizeof(g_err) - 1] = 0;
}

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

// --- encrypted store helpers -------------------------------------------------
static bool build_plain(size_t& outLen) {
    Writer w{g_plain, SCRATCH_CAP};
    w.raw("PKC1", 4);
    w.u8(1);
    w.u8(0);
    w.u16((uint16_t)g_credCount);
    for (int i = 0; i < g_credCount; i++) {
        uint8_t rec[1024];
        Writer rw{rec, sizeof(rec)};
        serialize_cred(rw, g_creds[i]);
        if (!rw.ok || rw.n > 0xFFFF) return false;
        w.u16((uint16_t)rw.n);
        w.raw(rec, rw.n);
        if (!w.ok) return false;
    }
    outLen = w.n;
    return w.ok;
}

static bool parse_plain(const uint8_t* buf, size_t len) {
    if (len < 8 || memcmp(buf, "PKC1", 4) != 0) return false;
    uint16_t count = (uint16_t)(buf[6] | (buf[7] << 8));
    Reader r{buf + 8, len - 8};
    g_credCount = 0;
    for (uint16_t i = 0; i < count && g_credCount < PK_MAX_CREDENTIALS; i++) {
        uint16_t n = r.u16();
        if (!r.ok || n == 0 || r.n + n > r.cap) return false;
        Reader cr{r.p + r.n, n};
        if (!deserialize_cred(cr, g_creds[g_credCount])) return false;
        r.n += n;
        g_credCount++;
    }
    return true;
}

static bool load_legacy_file() {
    File f = LittleFS.open(CRED_FILE, "r");
    if (!f) return false;
    size_t n = f.size();
    if (n < 8 || n > SCRATCH_CAP) {
        f.close();
        return false;
    }
    size_t got = 0;
    while (got < n) {
        size_t r = f.read(g_plain + got, n - got);
        if (r == 0) break;
        got += r;
    }
    f.close();
    if (got != n) return false;
    return parse_plain(g_plain, n);
}

static bool save_wrap() {
    uint8_t iv[12];
    if (!random_bytes(iv, sizeof(iv))) return false;
    uint8_t wrap[12 + 32 + 16];
    memcpy(wrap, iv, 12);
    if (!aes256_gcm_encrypt(g_kek, iv, 12, g_dek, 32, wrap + 12)) return false;
    return g_prefs.putBytes("dek", wrap, sizeof(wrap)) == sizeof(wrap);
}

static bool load_wrap(const uint8_t kek[32]) {
    size_t len = g_prefs.getBytesLength("dek");
    if (len != 12 + 32 + 16) return false;
    uint8_t wrap[12 + 32 + 16];
    if (g_prefs.getBytes("dek", wrap, sizeof(wrap)) != sizeof(wrap)) return false;
    return aes256_gcm_decrypt(kek, wrap, 12, wrap + 12, 32 + 16, g_dek);
}

static bool load_encrypted() {
    File f = LittleFS.open(CRED_FILE, "r");
    if (!f) {
        g_credCount = 0;
        return true;
    }
    uint8_t hdr[8];
    if (f.read(hdr, 8) != 8 || memcmp(hdr, "PKC2", 4) != 0) {
        f.close();
        return false;
    }
    size_t total = f.size() - 8;
    if (total < 12 + 16 || total > SCRATCH_CAP) {
        f.close();
        return false;
    }
    if (f.read(g_cipher, total) != total) {
        f.close();
        return false;
    }
    f.close();
    size_t ctLen = total - 12;
    if (!aes256_gcm_decrypt(g_dek, g_cipher, 12, g_cipher + 12, ctLen, g_plain)) return false;
    return parse_plain(g_plain, ctLen - 16);
}

static bool save_encrypted() {
    size_t n = 0;
    if (!build_plain(n)) { set_err("build"); return false; }
    uint8_t iv[12];
    if (!random_bytes(iv, sizeof(iv))) { set_err("rng"); return false; }
    memcpy(g_cipher, iv, 12);
    if (!aes256_gcm_encrypt(g_dek, iv, 12, g_plain, n, g_cipher + 12)) {
        set_err("gcm");
        return false;
    }

    File f = LittleFS.open(CRED_TMP, "w");
    if (!f) { set_err("open"); return false; }
    uint8_t hdr[8] = {'P', 'K', 'C', '2', 1, 0, (uint8_t)(g_credCount & 0xFF),
                      (uint8_t)(g_credCount >> 8)};
    bool ok = f.write(hdr, 8) == 8;
    if (ok) ok = f.write(g_cipher, 12 + n + 16) == (12 + n + 16);
    f.close();
    if (!ok) {
        set_err("write");
        LittleFS.remove(CRED_TMP);
        return false;
    }
    LittleFS.remove(CRED_FILE);
    ok = LittleFS.rename(CRED_TMP, CRED_FILE);
    if (!ok) { set_err("rename"); return false; }
    g_dirty = false;
    g_dirtyAt = 0;
    return true;
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
    g_plain = (uint8_t*)heap_caps_malloc(SCRATCH_CAP, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!g_plain) g_plain = (uint8_t*)malloc(SCRATCH_CAP);
    g_cipher = (uint8_t*)heap_caps_malloc(SCRATCH_CAP + 64, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!g_cipher) g_cipher = (uint8_t*)malloc(SCRATCH_CAP + 64);
    if (!g_creds || !g_plain || !g_cipher) return false;

    g_credCount = 0;
    g_unlocked = false;
    g_legacyPlain = false;

    File f = LittleFS.open(CRED_FILE, "r");
    if (f) {
        uint8_t hdr[8];
        if (f.read(hdr, 8) == 8 && memcmp(hdr, "PKC1", 4) == 0) {
            g_legacyPlain = load_legacy_file();
        }
        f.close();
    }
    g_settings.bootCount++;
    save_settings();
    return true;
}

bool unlock_credentials(const uint8_t kek[32]) {
    if (g_unlocked) return true;
    memcpy(g_kek, kek, 32);

    bool haveWrap = load_wrap(kek);
    if (haveWrap) {
        if (!load_encrypted()) {
            // A wrapped DEK exists but the file is still the legacy plaintext
            // (e.g. the first migration was interrupted).  Recover it with the
            // existing DEK instead of generating a new one.
            if (LittleFS.exists(CRED_FILE) && load_legacy_file()) {
                g_legacyPlain = true;
                g_unlocked = true;
                if (!save_encrypted()) {
                    g_unlocked = false;
                    set_err("recover-enc");
                    return false;
                }
                g_legacyPlain = false;
            } else {
                set_err("load-enc");
                memset(g_dek, 0, sizeof(g_dek));
                return false;
            }
        }
    } else {
        // No wrapped DEK yet.  If a file exists it must be the legacy plaintext
        // store; parse it before generating a new DEK, otherwise a parse error
        // would silently replace real credentials with an empty store.
        if (LittleFS.exists(CRED_FILE)) {
            if (!g_legacyPlain) g_legacyPlain = load_legacy_file();
            if (!g_legacyPlain) {
                set_err("legacy-parse");
                Serial.println("[store] legacy store parse failed; refusing to overwrite");
                return false;
            }
        }
        if (!random_bytes(g_dek, sizeof(g_dek))) { set_err("rng"); return false; }
        g_unlocked = true;
        if (g_legacyPlain) {
            if (!save_encrypted()) {
                g_unlocked = false;
                return false;
            }
            g_legacyPlain = false;
        } else {
            g_credCount = 0;
        }
        if (!save_wrap()) {
            set_err("save-wrap");
            g_unlocked = false;
            return false;
        }
    }
    g_unlocked = true;
    set_err("ok");
    return true;
}

bool rewrap_dek(const uint8_t newKek[32]) {
    if (!g_unlocked) return false;
    memcpy(g_kek, newKek, 32);
    return save_wrap();
}

bool credentials_unlocked() { return g_unlocked; }

const char* lastError() { return g_err; }

bool encrypted_at_rest() {
    File f = LittleFS.open(CRED_FILE, "r");
    if (!f) return true;
    uint8_t hdr[4];
    bool enc = f.read(hdr, 4) == 4 && memcmp(hdr, "PKC2", 4) == 0;
    f.close();
    return enc;
}

const uint8_t* master_key() { return g_master; }
Settings& settings() { return g_settings; }

void save_settings() {
    g_prefs.putBytes("cfg", &g_settings, sizeof(g_settings));
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
    if (!g_unlocked || g_credCount >= PK_MAX_CREDENTIALS) return false;
    g_creds[g_credCount++] = c;
    return save_credentials();
}

bool update_credential(const Credential& c) {
    if (!g_unlocked) return false;
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
    if (!g_unlocked) return false;
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
    if (g_unlocked) {
        save_credentials();
    } else {
        LittleFS.remove(CRED_FILE);
    }
}

void mark_dirty() {
    g_dirty = true;
    if (!g_dirtyAt) g_dirtyAt = millis();
}

void flush_if_dirty() {
    if (g_dirty && g_unlocked && millis() - g_dirtyAt > 2000) {
        save_credentials();
        g_dirty = false;
        g_dirtyAt = 0;
    }
}

void factory_reset() {
    LittleFS.remove(CRED_FILE);
    LittleFS.remove(CRED_TMP);
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
    g_prefs.remove("dek");
    memset(g_dek, 0, sizeof(g_dek));
    memset(g_kek, 0, sizeof(g_kek));
    g_unlocked = false;
    g_legacyPlain = false;
    g_credCount = 0;
    save_settings();
}

bool save_credentials() {
    if (!g_unlocked) return false;
    return save_encrypted();
}

bool wrap_key_handle(const KeyHandle& kh, uint8_t* out, size_t& outLen) {
    if (!g_unlocked) return false;
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
    if (!aes256_gcm_encrypt(g_dek, iv, 12, plain, w.n, out + 13)) return false;
    outLen = 13 + w.n + 16;
    return true;
}

bool unwrap_key_handle(const uint8_t* in, size_t inLen, KeyHandle& kh) {
    if (!g_unlocked || inLen < 13 + 1 + 16 || in[0] != 1) return false;
    uint8_t plain[128];
    size_t ctLen = inLen - 13;
    if (ctLen > sizeof(plain)) return false;
    if (!aes256_gcm_decrypt(g_dek, in + 1, 12, in + 13, ctLen, plain)) {
        // Key handles created before the DEK migration were wrapped with the
        // old master key.  Accept those, then re-wrap on the next use.
        if (!aes256_gcm_decrypt(g_master, in + 1, 12, in + 13, ctLen, plain)) return false;
    }
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
