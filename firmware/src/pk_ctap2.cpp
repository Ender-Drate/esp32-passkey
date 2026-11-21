#include "pk_ctap2.h"

#include <Arduino.h>
#include <string.h>

#include "pk_cbor.h"
#include "pk_config.h"
#include "pk_crypto.h"
#include "pk_ctaphid.h"
#include "pk_ble.h"
#include "pk_led.h"
#include "pk_mgmt.h"
#include "pk_store.h"

#if PK_DEBUG
#define DBG(...) mgmt::log(__VA_ARGS__)
#else
#define DBG(...) do {} while (0)
#endif

namespace pk {
namespace ctap {

using cbor::Value;

// ---------------------------------------------------------------------------
// PIN / UV session
// ---------------------------------------------------------------------------
struct PinCtx {
    bool     kaValid = false;
    uint8_t  kaPriv[32];
    uint8_t  shared[64];
    size_t   sharedLen = 0;
    uint8_t  proto = 1;
    uint8_t  token[32];
    bool     tokenValid = false;
    uint32_t tokenBorn = 0;
    uint8_t  tokenProto = 1;
    uint32_t perms = 0;
    bool     permRpSet = false;
    uint8_t  permRp[32];
};

static PinCtx g_pin;

static uint8_t AAGUID[16] = PK_AAGUID;

bool pin_is_set() { return (store::settings().flags & 0x01) != 0; }
uint8_t pin_retries() { return store::settings().pinRetries; }

static void save_settings() { store::save_settings(); }

// --- user presence ----------------------------------------------------------
static bool button_down() { return digitalRead(PK_BUTTON_PIN) == LOW; }

static bool wait_touch(uint32_t timeout_ms) {
    if (store::settings().upMode == 1) {
        led::success();
        return true;
    }
    uint32_t start = millis();
    uint32_t lowSince = 0;
    led::wait_touch();
    while (millis() - start < timeout_ms) {
        if (ctaphid::cancelled()) {
            led::error();
            return false;
        }
        if (button_down()) {
            if (!lowSince) lowSince = millis();
            if (millis() - lowSince >= 40) {
                led::success();
                return true;
            }
        } else {
            lowSince = 0;
            led::wait_touch();
        }
        ctaphid::keepalive();
        ble::keepalive();
        led::poll();
        delay(5);
    }
    led::error();
    return false;
}

void wink() { led::wink(); }

// --- PIN crypto helpers -----------------------------------------------------
static bool pin_store_hash(const uint8_t h[16]) {
    uint8_t iv[12];
    if (!random_bytes(iv, sizeof(iv))) return false;
    uint8_t enc[44];
    memcpy(enc, iv, 12);
    if (!aes256_gcm_encrypt(store::master_key(), iv, 12, h, 16, enc + 12)) return false;
    Settings& s = store::settings();
    memcpy(s.pinHashEnc, enc, 44);
    s.pinHashLen = 44;
    s.flags |= 0x01;
    save_settings();
    return true;
}

static bool pin_load_hash(uint8_t h[16]) {
    Settings& s = store::settings();
    if (!(s.flags & 0x01) || s.pinHashLen != 44) return false;
    return aes256_gcm_decrypt(store::master_key(), s.pinHashEnc, 12, s.pinHashEnc + 12, 32, h);
}

static size_t utf8_count(const uint8_t* s, size_t n) {
    size_t c = 0;
    for (size_t i = 0; i < n; i++) if ((s[i] & 0xC0) != 0x80) c++;
    return c;
}

static bool pin_blocked() {
    Settings& s = store::settings();
    if (s.pinRetries > 0) return false;
    uint32_t elapsed = (millis() - s.lockoutStartMs) / 1000;
    if (elapsed < s.lockoutSeconds) return true;
    s.pinRetries = 1;
    s.lockoutSeconds = 0;
    s.lockoutStartMs = 0;
    save_settings();
    return false;
}

static void pin_fail() {
    Settings& s = store::settings();
    if (s.pinRetries) s.pinRetries--;
    if (s.pinRetries == 0) {
        s.lockoutStartMs = millis();
        s.lockoutSeconds = 30;
    }
    save_settings();
}

static void pin_success() {
    Settings& s = store::settings();
    s.pinRetries = PK_PIN_RETRIES;
    s.lockoutSeconds = 0;
    s.lockoutStartMs = 0;
    save_settings();
}

static void write_cose_pub(cbor::Writer& w, const uint8_t x[32], const uint8_t y[32]) {
    w.map(5);
    w.uint(1); w.uint(2);          // kty: EC2
    w.uint(3); w.integer(COSE_ALG_ES256);
    w.uint(-1); w.uint(1);         // crv: P-256
    w.uint(-2); w.bytes(x, 32);
    w.uint(-3); w.bytes(y, 32);
}

static bool pin_encrypt(const uint8_t* plain, size_t len, uint8_t* out, size_t& outLen) {
    if (g_pin.proto == 2) {
        uint8_t iv[16];
        if (!random_bytes(iv, sizeof(iv))) return false;
        memcpy(out, iv, 16);
        if (!aes256_cbc(true, g_pin.shared + 32, iv, plain, len, out + 16)) return false;
        outLen = 16 + len;
        return true;
    }
    uint8_t zero[16] = {0};
    if (!aes256_cbc(true, g_pin.shared, zero, plain, len, out)) return false;
    outLen = len;
    return true;
}

static bool pin_decrypt(const uint8_t* in, size_t len, uint8_t* out, size_t expectLen) {
    if (g_pin.proto == 2) {
        if (len < 16 || (len - 16) != expectLen) return false;
        uint8_t zero[16] = {0};
        (void)zero;
        return aes256_cbc(false, g_pin.shared + 32, in, in + 16, len - 16, out);
    }
    if (len != expectLen) return false;
    uint8_t zero[16] = {0};
    return aes256_cbc(false, g_pin.shared, zero, in, len, out);
}

static bool verify_shared_auth(const uint8_t* param, size_t paramLen, const uint8_t* msg, size_t msgLen) {
    uint8_t mac[32];
    hmac_sha256(g_pin.shared, 32, msg, msgLen, mac);
    size_t want = (g_pin.proto == 2) ? 32 : 16;
    if (paramLen != want) return false;
    return ct_equal(param, mac, want);
}

static bool verify_token_auth(const uint8_t* param, size_t paramLen, const uint8_t* msg, size_t msgLen,
                              uint32_t perm, const uint8_t* rpIdHash) {
    if (!g_pin.tokenValid) return false;
    if (millis() - g_pin.tokenBorn > 600000) return false;
    if ((g_pin.perms & perm) == 0) return false;
    if (g_pin.permRpSet && rpIdHash && memcmp(g_pin.permRp, rpIdHash, 32) != 0) return false;
    size_t want = (g_pin.tokenProto == 2) ? 32 : 16;
    if (paramLen != want) return false;
    uint8_t mac[32];
    hmac_sha256(g_pin.token, 32, msg, msgLen, mac);
    return ct_equal(param, mac, want);
}

// --- CBOR helpers -----------------------------------------------------------
static bool as_bytes(const Value* v, const uint8_t*& p, size_t& n) {
    if (!v || v->type != cbor::T_BYTES) return false;
    p = v->data;
    n = v->len;
    return true;
}

static bool copy_text(const Value* v, uint8_t* dst, uint8_t& len, size_t max) {
    if (!v) { len = 0; return true; }
    if (v->type != cbor::T_TEXT || v->len > max) return false;
    memcpy(dst, v->data, v->len);
    len = (uint8_t)v->len;
    return true;
}

static void put_cred_descriptor(cbor::Writer& w, const uint8_t* id, size_t idLen) {
    w.map(2);
    w.text("type"); w.text("public-key");
    w.text("id"); w.bytes(id, idLen);
}

static void put_user(cbor::Writer& w, const Credential& c) {
    w.map(3);
    w.text("id"); w.bytes(c.userId, c.userIdLen);
    w.text("name"); w.text((const char*)c.userName, c.userNameLen);
    w.text("displayName"); w.text((const char*)c.displayName, c.displayNameLen);
}

// ---------------------------------------------------------------------------
// authenticatorGetInfo
// ---------------------------------------------------------------------------
static size_t do_get_info(cbor::Writer& w) {
    Settings& s = store::settings();
    int remaining = PK_MAX_CREDENTIALS - store::credential_count();
    if (remaining < 0) remaining = 0;

    w.map(16);
    w.uint(1);
    w.array(3);
    w.text("FIDO_2_0");
    w.text("FIDO_2_1");
    w.text("U2F_V2");

    w.uint(2);
    w.array(0);

    w.uint(3);
    w.bytes(AAGUID, 16);

    w.uint(4);
    w.map(8);
    w.text("rk"); w.boolean(true);
    w.text("up"); w.boolean(true);
    w.text("plat"); w.boolean(false);
    w.text("clientPin"); w.boolean(pin_is_set());
    w.text("alwaysUv"); w.boolean((s.flags & 0x02) != 0);
    w.text("credMgmt"); w.boolean(true);
    w.text("largeBlobs"); w.boolean(true);
    w.text("pinUvAuthToken"); w.boolean(true);

    w.uint(5); w.uint(7609);
    w.uint(6); w.array(2); w.uint(2); w.uint(1);
    w.uint(7); w.uint(PK_MAX_CBOR_CRED_LIST);
    w.uint(8); w.uint(160);
    w.uint(9); w.array(2); w.text("usb"); w.text("ble");
    w.uint(0x0A);
    w.array(1);
    w.map(2);
    w.text("type"); w.text("public-key");
    w.text("alg"); w.integer(COSE_ALG_ES256);
    w.uint(0x0B); w.uint(PK_MAX_LARGE_BLOB);
    w.uint(0x0C); w.boolean(false);
    w.uint(0x0D); w.uint(s.minPinLen);
    w.uint(0x0E); w.uint(((uint32_t)PK_VERSION_MAJOR << 16) | ((uint32_t)PK_VERSION_MINOR << 8) | PK_VERSION_PATCH);
    w.uint(0x10); w.uint(0);
    w.uint(0x14); w.uint((uint32_t)remaining);
    return w.size();
}

// ---------------------------------------------------------------------------
// authenticatorMakeCredential
// ---------------------------------------------------------------------------
static uint8_t do_make_credential(const Value& req, cbor::Writer& w) {
    const Value* cdh = req.get(1);
    if (!cdh || cdh->type != cbor::T_BYTES || cdh->len != 32) return CTAP2_ERR_MISSING_PARAMETER;

    const Value* rp = req.get(2);
    if (!rp || rp->type != cbor::T_MAP) return CTAP2_ERR_MISSING_PARAMETER;
    const Value* rpIdV = rp->get("id");
    if (!rpIdV || rpIdV->type != cbor::T_TEXT || rpIdV->len == 0 || rpIdV->len > PK_MAX_RP_ID_LEN)
        return CTAP2_ERR_MISSING_PARAMETER;

    const Value* user = req.get(3);
    if (!user || user->type != cbor::T_MAP) return CTAP2_ERR_MISSING_PARAMETER;
    const Value* userIdV = user->get("id");
    if (!userIdV || userIdV->type != cbor::T_BYTES || userIdV->len == 0 || userIdV->len > PK_MAX_USER_ID_LEN)
        return CTAP2_ERR_MISSING_PARAMETER;

    uint8_t rpIdHash[32];
    sha256(rpIdV->data, rpIdV->len, rpIdHash);

    const Value* params = req.get(4);
    bool es256 = false;
    if (params && params->type == cbor::T_ARRAY) {
        for (const Value& p : params->items) {
            const Value* alg = p.get("alg");
            const Value* type = p.get("type");
            if (alg && alg->is_int() && alg->i == COSE_ALG_ES256 && type && type->type == cbor::T_TEXT &&
                type->len == 10 && memcmp(type->data, "public-key", 10) == 0) {
                es256 = true;
            }
        }
    }
    if (!es256) return CTAP2_ERR_UNSUPPORTED_ALGORITHM;

    // options
    bool rk = false, up = true;
    const Value* opts = req.get(7);
    if (opts && opts->type == cbor::T_MAP) {
        const Value* v = opts->get("rk");
        if (v && v->type == cbor::T_BOOL) rk = v->b;
        v = opts->get("up");
        if (v && v->type == cbor::T_BOOL) up = v->b;
    }

    // excludeList
    const Value* excl = req.get(5);
    if (excl && excl->type == cbor::T_ARRAY) {
        for (const Value& d : excl->items) {
            const Value* id = d.get("id");
            if (!id || id->type != cbor::T_BYTES || id->len == 0) continue;
            Credential* c = store::find_by_cred_id(id->data, id->len);
            if (c && memcmp(c->rpIdHash, rpIdHash, 32) == 0) return CTAP2_ERR_CREDENTIAL_EXCLUDED;
            KeyHandle kh;
            if (store::unwrap_key_handle(id->data, id->len, kh) &&
                memcmp(kh.rpIdHash, rpIdHash, 32) == 0) {
                return CTAP2_ERR_CREDENTIAL_EXCLUDED;
            }
        }
    }

    // credProtect extension: Windows/browsers handle the output poorly when it
    // is echoed, so we accept the input but do not advertise/emit the output.
    uint8_t credProtect = 0;
    const Value* exts = req.get(6);
    (void)exts;

    // PIN / UV
    bool uv = false;
    if (pin_is_set()) {
        const Value* pp = req.get(8);
        if (!pp || pp->type != cbor::T_BYTES) return CTAP2_ERR_PIN_REQUIRED;
        if (!verify_token_auth(pp->data, pp->len, cdh->data, 32, PK_PERM_MC, rpIdHash))
            return CTAP2_ERR_PIN_AUTH_INVALID;
        uv = true;
    }
    if ((credProtect == 2 || credProtect == 3) && !uv) return CTAP2_ERR_PIN_REQUIRED;

    if (up && !wait_touch(PK_DEFAULT_UP_TIMEOUT_MS)) {
        return ctaphid::cancelled() ? CTAP2_ERR_KEEPALIVE_CANCEL : CTAP2_ERR_USER_ACTION_TIMEOUT;
    }

    uint8_t priv[32], x[32], y[32];
    if (!ec_generate(priv, x, y)) return CTAP2_ERR_OTHER;

    uint8_t credId[256];  // may hold a wrapped (non-resident) key handle
    uint8_t credIdLen = 0;
    uint8_t credRandom[32];
    if (!random_bytes(credRandom, 32)) return CTAP2_ERR_OTHER;

    if (rk) {
        if (store::credential_count() >= PK_MAX_CREDENTIALS) return CTAP2_ERR_KEY_STORE_FULL;
        credIdLen = 32;
        if (!random_bytes(credId, credIdLen)) return CTAP2_ERR_OTHER;
    } else {
        KeyHandle kh;
        memcpy(kh.rpIdHash, rpIdHash, 32);
        memcpy(kh.priv, priv, 32);
        kh.signCount = 0;
        kh.flags = 0;
        memcpy(kh.credRandom, credRandom, 32);
        size_t khLen = 0;
        if (!store::wrap_key_handle(kh, credId, khLen)) return CTAP2_ERR_OTHER;
        credIdLen = (uint8_t)khLen;
    }

    // authData
    uint8_t auth[512];
    size_t alen = 0;
    memcpy(auth, rpIdHash, 32);
    alen = 32;
    uint8_t flags = AUTH_FLAG_UP | (uv ? AUTH_FLAG_UV : 0) | AUTH_FLAG_AT;
    if (credProtect) flags |= AUTH_FLAG_ED;
    auth[alen++] = flags;
    auth[alen++] = 0;
    auth[alen++] = 0;
    auth[alen++] = 0;
    auth[alen++] = 0;
    memcpy(auth + alen, AAGUID, 16);
    alen += 16;
    auth[alen++] = (uint8_t)(credIdLen >> 8);
    auth[alen++] = (uint8_t)credIdLen;
    memcpy(auth + alen, credId, credIdLen);
    alen += credIdLen;
    // COSE_Key ES256
    auth[alen++] = 0xA5;
    auth[alen++] = 0x01; auth[alen++] = 0x02;
    auth[alen++] = 0x03; auth[alen++] = 0x26;
    auth[alen++] = 0x20; auth[alen++] = 0x01;
    auth[alen++] = 0x21; auth[alen++] = 0x58; auth[alen++] = 0x20;
    memcpy(auth + alen, x, 32); alen += 32;
    auth[alen++] = 0x22; auth[alen++] = 0x58; auth[alen++] = 0x20;
    memcpy(auth + alen, y, 32); alen += 32;

    if (credProtect) {
        auth[alen++] = 0xA1;
        auth[alen++] = 0x6B;
        const char* key = "credProtect";
        memcpy(auth + alen, key, 11); alen += 11;
        auth[alen++] = credProtect;
    }

    uint8_t msg[512 + 32];
    memcpy(msg, auth, alen);
    memcpy(msg + alen, cdh->data, 32);

    uint8_t sig[80];
    size_t sigLen = 0;
    if (!ecdsa_sign_sha256(priv, msg, alen + 32, sig, sizeof(sig), sigLen)) return CTAP2_ERR_OTHER;

    if (rk) {
        Credential c;
        memset(&c, 0, sizeof(c));
        memcpy(c.credId, credId, credIdLen);
        c.credIdLen = credIdLen;
        memcpy(c.rpIdHash, rpIdHash, 32);
        if (!copy_text(rpIdV, c.rpId, c.rpIdLen, sizeof(c.rpId))) return CTAP2_ERR_OTHER;
        if (!copy_text(rp->get("name"), c.rpName, c.rpNameLen, sizeof(c.rpName))) c.rpNameLen = 0;
        memcpy(c.userId, userIdV->data, userIdV->len);
        c.userIdLen = (uint8_t)userIdV->len;
        if (!copy_text(user->get("name"), c.userName, c.userNameLen, sizeof(c.userName))) c.userNameLen = 0;
        if (!copy_text(user->get("displayName"), c.displayName, c.displayNameLen, sizeof(c.displayName)))
            c.displayNameLen = 0;
        memcpy(c.priv, priv, 32);
        memcpy(c.credRandom, credRandom, 32);
        c.signCount = 0;
        c.credProtect = credProtect;
        c.flags = 0x01;
        c.createdAt = store::now_epoch();
        c.lastUsed = c.createdAt;
        if (!store::add_credential(c)) return CTAP2_ERR_KEY_STORE_FULL;
    }

    w.map(3);
    w.uint(1); w.text("packed");
    w.uint(2); w.bytes(auth, alen);
    w.uint(3);
    w.map(2);
    w.text("alg"); w.integer(COSE_ALG_ES256);
    w.text("sig"); w.bytes(sig, sigLen);
    return CTAP2_OK;
}

// ---------------------------------------------------------------------------
// authenticatorGetAssertion
// ---------------------------------------------------------------------------
struct Cand {
    bool resident;
    Credential* c;
    KeyHandle kh;
    uint8_t id[256];
    uint8_t idLen;
};

static Cand g_cands[PK_MAX_CBOR_CRED_LIST];
static int g_candCount = 0;
static int g_candNext = 0;
static bool g_gaActive = false;
static bool g_gaUv = false;

static uint8_t g_gaCdh[32];
static uint8_t g_gaRpH[32];

static uint8_t emit_assertion(int idx, cbor::Writer& w, bool first) {
    Cand& cand = g_cands[idx];
    uint32_t counter;
    if (cand.resident) {
        cand.c->signCount++;
        cand.c->lastUsed = store::now_epoch();
        store::mark_dirty();
        counter = cand.c->signCount;
    } else {
        counter = ++store::settings().globalSignCount;
        store::save_settings();
    }
    uint8_t auth[37];
    memcpy(auth, g_gaRpH, 32);
    auth[32] = AUTH_FLAG_UP | (g_gaUv ? AUTH_FLAG_UV : 0);
    auth[33] = (uint8_t)(counter >> 24);
    auth[34] = (uint8_t)(counter >> 16);
    auth[35] = (uint8_t)(counter >> 8);
    auth[36] = (uint8_t)counter;
    uint8_t msg[69];
    memcpy(msg, auth, 37);
    memcpy(msg + 37, g_gaCdh, 32);

    const uint8_t* priv = cand.resident ? cand.c->priv : cand.kh.priv;
    uint8_t sig[80];
    size_t sigLen = 0;
    if (!ecdsa_sign_sha256(priv, msg, 69, sig, sizeof(sig), sigLen)) return CTAP2_ERR_OTHER;

    int pairs = 3 + (cand.resident ? 1 : 0) + (first ? 1 : 0);
    w.map(pairs);
    w.uint(1);
    put_cred_descriptor(w, cand.id, cand.idLen);
    w.uint(2); w.bytes(auth, 37);
    w.uint(3); w.bytes(sig, sigLen);
    if (cand.resident) {
        w.uint(4);
        put_user(w, *cand.c);
    }
    if (first) {
        w.uint(5); w.uint((uint32_t)g_candCount);
    }
    return CTAP2_OK;
}

static uint8_t do_get_assertion(const Value& req, cbor::Writer& w) {
    const Value* rpIdV = req.get(1);
    if (!rpIdV || rpIdV->type != cbor::T_TEXT || rpIdV->len == 0 || rpIdV->len > PK_MAX_RP_ID_LEN)
        return CTAP2_ERR_MISSING_PARAMETER;
    const Value* cdh = req.get(2);
    if (!cdh || cdh->type != cbor::T_BYTES || cdh->len != 32) return CTAP2_ERR_MISSING_PARAMETER;

    uint8_t rpIdHash[32];
    sha256(rpIdV->data, rpIdV->len, rpIdHash);

    // options
    bool up = true;
    const Value* opts = req.get(5);
    if (opts && opts->type == cbor::T_MAP) {
        const Value* v = opts->get("up");
        if (v && v->type == cbor::T_BOOL) up = v->b;
    }

    // authorization
    bool uv = false;
    if (pin_is_set()) {
        const Value* pp = req.get(6);
        if (!pp || pp->type != cbor::T_BYTES) return CTAP2_ERR_PIN_REQUIRED;
        if (!verify_token_auth(pp->data, pp->len, cdh->data, 32, PK_PERM_GA, rpIdHash))
            return CTAP2_ERR_PIN_AUTH_INVALID;
        uv = true;
    }

    // candidates
    g_candCount = 0;
    const Value* allow = req.get(3);
    if (allow && allow->type == cbor::T_ARRAY) {
        for (const Value& d : allow->items) {
            if (g_candCount >= PK_MAX_CBOR_CRED_LIST) break;
            const Value* id = d.get("id");
            if (!id || id->type != cbor::T_BYTES || id->len == 0) continue;
            Credential* c = store::find_by_cred_id(id->data, id->len);
            if (c && memcmp(c->rpIdHash, rpIdHash, 32) == 0) {
                Cand& cand = g_cands[g_candCount++];
                cand.resident = true;
                cand.c = c;
                memcpy(cand.id, c->credId, c->credIdLen);
                cand.idLen = c->credIdLen;
                memset(&cand.kh, 0, sizeof(cand.kh));
                continue;
            }
            KeyHandle kh;
            if (store::unwrap_key_handle(id->data, id->len, kh) &&
                memcmp(kh.rpIdHash, rpIdHash, 32) == 0) {
                Cand& cand = g_cands[g_candCount++];
                cand.resident = false;
                cand.c = nullptr;
                cand.kh = kh;
                memcpy(cand.id, id->data, id->len);
                cand.idLen = (uint8_t)id->len;
            }
        }
    } else {
        for (int i = 0; i < store::credential_count() && g_candCount < PK_MAX_CBOR_CRED_LIST; i++) {
            Credential* c = &store::credentials()[i];
            if (!(c->flags & 0x01)) continue;
            if (memcmp(c->rpIdHash, rpIdHash, 32) != 0) continue;
            Cand& cand = g_cands[g_candCount++];
            cand.resident = true;
            cand.c = c;
            memcpy(cand.id, c->credId, c->credIdLen);
            cand.idLen = c->credIdLen;
            memset(&cand.kh, 0, sizeof(cand.kh));
        }
    }
    if (g_candCount == 0) return CTAP2_ERR_NO_CREDENTIALS;

    // credProtect enforcement
    for (int i = 0; i < g_candCount; i++) {
        if (g_cands[i].resident && g_cands[i].c->credProtect >= 2 && !uv) return CTAP2_ERR_PIN_REQUIRED;
    }

    if (up && !wait_touch(PK_DEFAULT_UP_TIMEOUT_MS)) {
        return ctaphid::cancelled() ? CTAP2_ERR_KEEPALIVE_CANCEL : CTAP2_ERR_USER_ACTION_TIMEOUT;
    }

    memcpy(g_gaCdh, cdh->data, 32);
    memcpy(g_gaRpH, rpIdHash, 32);
    g_gaUv = uv;
    g_candNext = 0;
    uint8_t st = emit_assertion(0, w, true);
    if (st == CTAP2_OK) {
        g_gaActive = true;
        g_candNext = 1;
    }
    return st;
}

static uint8_t do_get_next_assertion(cbor::Writer& w) {
    if (!g_gaActive || g_candNext >= g_candCount) return CTAP2_ERR_NOT_ALLOWED;
    int idx = g_candNext++;
    return emit_assertion(idx, w, false);
}

// ---------------------------------------------------------------------------
// clientPIN
// ---------------------------------------------------------------------------
static void write_key_agreement(cbor::Writer& w) {
    uint8_t x[32], y[32];
    ec_generate(g_pin.kaPriv, x, y);
    g_pin.kaValid = true;
    random_bytes(g_pin.token, 32);
    g_pin.tokenValid = true;
    g_pin.tokenBorn = millis();
    g_pin.perms = 0;
    g_pin.permRpSet = false;
    write_cose_pub(w, x, y);
}

static bool prepare_shared(const Value* ka, uint8_t proto) {
    if (!ka || ka->type != cbor::T_MAP) return false;
    uint8_t x[32], y[32];
    if (!cbor::cose_key_p256(*ka, x, y)) return false;
    uint8_t z[32];
    if (!ecdh_p256(g_pin.kaPriv, x, y, z)) return false;
    g_pin.proto = proto;
    if (proto == 2) {
        static const uint8_t zero32[32] = {0};
        if (!hkdf_sha256(zero32, 32, z, 32, "CTAP2 HMAC key", g_pin.shared, 32)) return false;
        if (!hkdf_sha256(zero32, 32, z, 32, "CTAP2 AES key", g_pin.shared + 32, 32)) return false;
        g_pin.sharedLen = 64;
    } else {
        memcpy(g_pin.shared, z, 32);
        g_pin.sharedLen = 32;
    }
    return true;
}

static uint8_t do_client_pin(const Value& req, cbor::Writer& w) {
    const Value* subV = req.get(2);
    if (!subV || !subV->is_int()) return CTAP1_ERR_INVALID_PARAMETER;
    uint8_t sub = (uint8_t)subV->i;
    uint8_t proto = 1;
    const Value* protoV = req.get(1);
    if (protoV && protoV->is_int()) proto = (uint8_t)protoV->i;
    if (proto != 1 && proto != 2) return CTAP1_ERR_INVALID_PARAMETER;
    DBG("clientPIN sub=%02x proto=%u", sub, proto);

    if (sub == PIN_GET_RETRIES) {
        w.map(1);
        w.uint(3);
        w.uint(pin_retries());
        return CTAP2_OK;
    }
    if (sub == PIN_GET_KEY_AGREEMENT) {
        if (pin_blocked()) return CTAP2_ERR_PIN_AUTH_BLOCKED;
        w.map(1);
        w.uint(1);
        write_key_agreement(w);
        return CTAP2_OK;
    }
    if (sub == PIN_GET_UV_RETRIES) {
        w.map(1);
        w.uint(5);
        w.uint(0);
        return CTAP2_OK;
    }

    const Value* ka = req.get(3);
    if (!g_pin.kaValid || !prepare_shared(ka, proto)) return CTAP1_ERR_INVALID_PARAMETER;

    if (sub == PIN_SET_PIN) {
        if (pin_is_set()) return CTAP2_ERR_PIN_AUTH_INVALID;
        const Value* enc = req.get(5);
        const Value* auth = req.get(4);
        if (!enc || enc->type != cbor::T_BYTES || !auth || auth->type != cbor::T_BYTES)
            return CTAP2_ERR_MISSING_PARAMETER;
        if (!verify_shared_auth(auth->data, auth->len, enc->data, enc->len)) {
            DBG("setPIN: shared auth failed");
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }
        uint8_t padded[64];
        if (!pin_decrypt(enc->data, enc->len, padded, 64)) {
            DBG("setPIN: decrypt failed (%u bytes)", (unsigned)enc->len);
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }
        size_t n = 0;
        while (n < 64 && padded[n]) n++;
        if (n < store::settings().minPinLen || n > 63) return CTAP2_ERR_PIN_POLICY_VIOLATION;
        if (utf8_count(padded, n) < store::settings().minPinLen) return CTAP2_ERR_PIN_POLICY_VIOLATION;
        uint8_t h[32];
        sha256(padded, n, h);
        if (!pin_store_hash(h)) {
            DBG("setPIN: pin_store_hash failed");
            return CTAP2_ERR_OTHER;
        }
        pin_success();
        DBG("setPIN: ok (%u chars)", (unsigned)n);
        return CTAP2_OK;
    }

    if (sub == PIN_CHANGE_PIN) {
        const Value* enc = req.get(5);
        const Value* hashEnc = req.get(6);
        const Value* auth = req.get(4);
        if (!enc || enc->type != cbor::T_BYTES || !hashEnc || hashEnc->type != cbor::T_BYTES ||
            !auth || auth->type != cbor::T_BYTES)
            return CTAP2_ERR_MISSING_PARAMETER;
        uint8_t msg[256];
        size_t mlen = 0;
        memcpy(msg, enc->data, enc->len); mlen = enc->len;
        memcpy(msg + mlen, hashEnc->data, hashEnc->len); mlen += hashEnc->len;
        if (!verify_shared_auth(auth->data, auth->len, msg, mlen)) return CTAP2_ERR_PIN_AUTH_INVALID;
        uint8_t cur[16], ref[16];
        if (!pin_decrypt(hashEnc->data, hashEnc->len, cur, 16)) return CTAP2_ERR_PIN_AUTH_INVALID;
        if (!pin_load_hash(ref)) return CTAP2_ERR_PIN_AUTH_INVALID;
        if (!ct_equal(cur, ref, 16)) {
            pin_fail();
            return CTAP2_ERR_PIN_INVALID;
        }
        uint8_t padded[64];
        if (!pin_decrypt(enc->data, enc->len, padded, 64)) return CTAP2_ERR_PIN_AUTH_INVALID;
        size_t n = 0;
        while (n < 64 && padded[n]) n++;
        if (n < store::settings().minPinLen || n > 63) return CTAP2_ERR_PIN_POLICY_VIOLATION;
        uint8_t h[32];
        sha256(padded, n, h);
        if (!pin_store_hash(h)) return CTAP2_ERR_OTHER;
        pin_success();
        return CTAP2_OK;
    }

    if (sub == PIN_GET_TOKEN || sub == PIN_GET_TOKEN_PIN_PERMS) {
        if (pin_blocked()) return CTAP2_ERR_PIN_AUTH_BLOCKED;
        const Value* hashEnc = req.get(6);
        if (!hashEnc || hashEnc->type != cbor::T_BYTES) return CTAP2_ERR_MISSING_PARAMETER;
        uint8_t cur[16], ref[16];
        if (!pin_decrypt(hashEnc->data, hashEnc->len, cur, 16)) return CTAP2_ERR_PIN_AUTH_INVALID;
        if (!pin_load_hash(ref)) return CTAP2_ERR_PIN_INVALID;
        if (!ct_equal(cur, ref, 16)) {
            pin_fail();
            return CTAP2_ERR_PIN_INVALID;
        }
        pin_success();
        uint32_t perms = 0x03;
        if (sub == PIN_GET_TOKEN_PIN_PERMS) {
            const Value* pv = req.get(9);
            if (!pv || !pv->is_int() || pv->i == 0) return CTAP2_ERR_MISSING_PARAMETER;
            perms = (uint32_t)pv->i;
        }
        g_pin.perms = perms;
        g_pin.tokenProto = proto;
        g_pin.tokenValid = true;
        g_pin.tokenBorn = millis();
        g_pin.permRpSet = false;
        const Value* rp = req.get(0x0A);
        if (rp && rp->type == cbor::T_TEXT) {
            sha256(rp->data, rp->len, g_pin.permRp);
            g_pin.permRpSet = true;
        }
        uint8_t enc[64];
        size_t encLen = 0;
        if (!pin_encrypt(g_pin.token, 32, enc, encLen)) return CTAP2_ERR_OTHER;
        w.map(1);
        w.uint(2);
        w.bytes(enc, encLen);
        return CTAP2_OK;
    }

    return CTAP1_ERR_INVALID_PARAMETER;
}

// ---------------------------------------------------------------------------
// credential management
// ---------------------------------------------------------------------------
static int g_rpIdx[PK_MAX_CREDENTIALS];
static int g_rpCount = 0;
static int g_rpNext = 0;
static int g_credIdx[PK_MAX_CREDENTIALS];
static int g_credCount = 0;
static int g_credNext = 0;

static bool cred_mgmt_auth(const Value& req, uint8_t sub, const uint8_t* rpIdHash) {
    const Value* p = req.get(4);
    if (!p || p->type != cbor::T_BYTES) return false;
    size_t want = (g_pin.tokenProto == 2) ? 32 : 16;
    if (p->len != want) return false;
    if (!g_pin.tokenValid || (g_pin.perms & PK_PERM_CM) == 0) return false;
    if (g_pin.permRpSet && rpIdHash && memcmp(g_pin.permRp, rpIdHash, 32) != 0) return false;

    uint8_t msg[512];
    msg[0] = sub;
    size_t mlen = 1;
    const Value* params = req.get(2);
    if (params && params->type == cbor::T_MAP) {
        cbor::Writer pw;
        cbor::encode_canonical(*params, pw);
        if (pw.size() + 1 > sizeof(msg)) return false;
        memcpy(msg + 1, pw.data(), pw.size());
        mlen += pw.size();
    }
    uint8_t mac[32];
    hmac_sha256(g_pin.token, 32, msg, mlen, mac);
    if (ct_equal(p->data, mac, want)) return true;
    if (mlen > 1) {
        hmac_sha256(g_pin.token, 32, msg, 1, mac);
        if (ct_equal(p->data, mac, want)) return true;
    }
    DBG("cmAuth fail sub=%02x mlen=%u", sub, (unsigned)mlen);
    return false;
}

static bool same_rp_exists(int idx) {
    for (int i = 0; i < g_rpCount; i++) {
        if (memcmp(store::credentials()[g_rpIdx[i]].rpIdHash, store::credentials()[idx].rpIdHash, 32) == 0)
            return true;
    }
    return false;
}

static uint8_t do_cred_mgmt(const Value& req, cbor::Writer& w) {
    const Value* subV = req.get(1);
    if (!subV || !subV->is_int()) return CTAP1_ERR_INVALID_PARAMETER;
    uint8_t sub = (uint8_t)subV->i;

    switch (sub) {
        case CREDMGMT_GET_METADATA: {
            if (pin_is_set() && !cred_mgmt_auth(req, sub, nullptr)) return CTAP2_ERR_PIN_AUTH_INVALID;
            int used = 0;
            for (int i = 0; i < store::credential_count(); i++)
                if (store::credentials()[i].flags & 0x01) used++;
            w.map(2);
            w.uint(1); w.uint((uint32_t)used);
            w.uint(2); w.uint((uint32_t)(PK_MAX_CREDENTIALS - used));
            return CTAP2_OK;
        }
        case CREDMGMT_ENUM_RPS_BEGIN: {
            if (pin_is_set() && !cred_mgmt_auth(req, sub, nullptr)) return CTAP2_ERR_PIN_AUTH_INVALID;
            g_rpCount = 0;
            g_rpNext = 0;
            for (int i = 0; i < store::credential_count(); i++) {
                if (!(store::credentials()[i].flags & 0x01)) continue;
                if (!same_rp_exists(i) && g_rpCount < PK_MAX_CREDENTIALS) g_rpIdx[g_rpCount++] = i;
            }
            if (g_rpCount == 0) return CTAP2_ERR_NO_CREDENTIALS;
            const Credential& c = store::credentials()[g_rpIdx[0]];
            w.map(3);
            w.uint(3);
            w.map(2);
            w.text("id"); w.text((const char*)c.rpId, c.rpIdLen);
            w.text("name"); w.text((const char*)c.rpName, c.rpNameLen);
            w.uint(4); w.bytes(c.rpIdHash, 32);
            w.uint(5); w.uint((uint32_t)g_rpCount);
            g_rpNext = 1;
            return CTAP2_OK;
        }
        case CREDMGMT_ENUM_RPS_NEXT: {
            if (g_rpNext >= g_rpCount) return CTAP2_ERR_NOT_ALLOWED;
            const Credential& c = store::credentials()[g_rpIdx[g_rpNext++]];
            w.map(2);
            w.uint(3);
            w.map(2);
            w.text("id"); w.text((const char*)c.rpId, c.rpIdLen);
            w.text("name"); w.text((const char*)c.rpName, c.rpNameLen);
            w.uint(4); w.bytes(c.rpIdHash, 32);
            return CTAP2_OK;
        }
        case CREDMGMT_ENUM_CREDS_BEGIN: {
            const Value* params = req.get(2);
            const Value* rpHash = (params && params->type == cbor::T_MAP) ? params->get(1) : nullptr;
            if (!rpHash || rpHash->type != cbor::T_BYTES || rpHash->len != 32)
                return CTAP2_ERR_MISSING_PARAMETER;
            if (pin_is_set() && !cred_mgmt_auth(req, sub, rpHash->data)) return CTAP2_ERR_PIN_AUTH_INVALID;
            g_credCount = 0;
            g_credNext = 0;
            for (int i = 0; i < store::credential_count(); i++) {
                const Credential& c = store::credentials()[i];
                if (!(c.flags & 0x01)) continue;
                if (memcmp(c.rpIdHash, rpHash->data, 32) != 0) continue;
                if (g_credCount < PK_MAX_CREDENTIALS) g_credIdx[g_credCount++] = i;
            }
            if (g_credCount == 0) return CTAP2_ERR_NO_CREDENTIALS;
            const Credential& c = store::credentials()[g_credIdx[0]];
            w.map(5);
            w.uint(6);
            put_user(w, c);
            w.uint(7);
            put_cred_descriptor(w, c.credId, c.credIdLen);
            w.uint(8);
            {
                uint8_t x[32], y[32];
                if (!ec_pub_from_priv(c.priv, x, y)) return CTAP2_ERR_OTHER;
                write_cose_pub(w, x, y);
            }
            w.uint(9); w.uint((uint32_t)g_credCount);
            w.uint(0x0A); w.uint(c.credProtect);
            g_credNext = 1;
            return CTAP2_OK;
        }
        case CREDMGMT_ENUM_CREDS_NEXT: {
            if (g_credNext >= g_credCount) return CTAP2_ERR_NOT_ALLOWED;
            const Credential& c = store::credentials()[g_credIdx[g_credNext++]];
            w.map(5);
            w.uint(6);
            put_user(w, c);
            w.uint(7);
            put_cred_descriptor(w, c.credId, c.credIdLen);
            w.uint(8);
            {
                uint8_t x[32], y[32];
                if (!ec_pub_from_priv(c.priv, x, y)) return CTAP2_ERR_OTHER;
                write_cose_pub(w, x, y);
            }
            w.uint(9); w.uint((uint32_t)g_credCount);
            w.uint(0x0A); w.uint(c.credProtect);
            return CTAP2_OK;
        }
        case CREDMGMT_DELETE_CREDENTIAL: {
            const Value* params = req.get(2);
            const Value* desc = (params && params->type == cbor::T_MAP) ? params->get(2) : nullptr;
            const Value* id = desc ? desc->get("id") : nullptr;
            if (!id || id->type != cbor::T_BYTES) return CTAP2_ERR_MISSING_PARAMETER;
            if (pin_is_set() && !cred_mgmt_auth(req, sub, nullptr)) return CTAP2_ERR_PIN_AUTH_INVALID;
            if (!store::delete_credential(id->data, id->len)) return CTAP2_ERR_NO_CREDENTIALS;
            return CTAP2_OK;
        }
        case CREDMGMT_UPDATE_USER_INFO: {
            const Value* params = req.get(2);
            const Value* desc = (params && params->type == cbor::T_MAP) ? params->get(2) : nullptr;
            const Value* user = (params && params->type == cbor::T_MAP) ? params->get(3) : nullptr;
            const Value* id = desc ? desc->get("id") : nullptr;
            if (!id || id->type != cbor::T_BYTES || !user || user->type != cbor::T_MAP)
                return CTAP2_ERR_MISSING_PARAMETER;
            if (pin_is_set() && !cred_mgmt_auth(req, sub, nullptr)) return CTAP2_ERR_PIN_AUTH_INVALID;
            Credential* c = store::find_by_cred_id(id->data, id->len);
            if (!c) return CTAP2_ERR_NO_CREDENTIALS;
            const Value* uid = user->get("id");
            if (uid && uid->type == cbor::T_BYTES && uid->len <= PK_MAX_USER_ID_LEN) {
                memcpy(c->userId, uid->data, uid->len);
                c->userIdLen = (uint8_t)uid->len;
            }
            copy_text(user->get("name"), c->userName, c->userNameLen, sizeof(c->userName));
            copy_text(user->get("displayName"), c->displayName, c->displayNameLen, sizeof(c->displayName));
            store::update_credential(*c);
            return CTAP2_OK;
        }
        default:
            return CTAP1_ERR_INVALID_PARAMETER;
    }
}

// ---------------------------------------------------------------------------
// large blobs
// ---------------------------------------------------------------------------
static const uint8_t LARGE_BLOB_INITIAL[17] = {0x80, 0x76, 0xbe, 0x8b, 0x52, 0x8d, 0x00, 0x75, 0xf7,
                                               0xaa, 0xe9, 0x8d, 0x6f, 0xa5, 0x7a, 0x6d, 0x3c};
static uint8_t* g_blobBuf = nullptr;
static size_t g_blobExpected = 0;
static size_t g_blobNext = 0;

static size_t blob_total_size() {
    size_t n = store::large_blob_size();
    return n ? n : sizeof(LARGE_BLOB_INITIAL);
}

static bool blob_read_at(uint8_t* out, size_t offset, size_t len, size_t& got) {
    size_t total = blob_total_size();
    if (offset > total) return false;
    if (offset + len > total) len = total - offset;
    got = len;
    if (store::large_blob_size() == 0) {
        memcpy(out, LARGE_BLOB_INITIAL + offset, len);
        return true;
    }
    return store::large_blob_read(out, offset, len);
}

static uint8_t do_large_blobs(const Value& req, cbor::Writer& w) {
    const Value* offsetV = req.get(3);
    if (!offsetV || !offsetV->is_int() || offsetV->i < 0) return CTAP1_ERR_INVALID_PARAMETER;
    size_t offset = (size_t)offsetV->i;
    const Value* getV = req.get(1);
    const Value* setV = req.get(2);
    if ((!getV && !setV) || (getV && setV)) return CTAP1_ERR_INVALID_PARAMETER;

    if (getV) {
        if (!getV->is_int() || getV->i <= 0) return CTAP1_ERR_INVALID_PARAMETER;
        if (req.get(4)) return CTAP1_ERR_INVALID_PARAMETER;
        if (req.get(5) || req.get(6)) return CTAP1_ERR_INVALID_PARAMETER;
        size_t want = (size_t)getV->i;
        if (want > 7609 - 64) return CTAP1_ERR_INVALID_LENGTH;
        uint8_t tmp[PK_MAX_LARGE_BLOB + 32];
        size_t got = 0;
        if (!blob_read_at(tmp, offset, want, got)) return CTAP1_ERR_INVALID_PARAMETER;
        w.map(1);
        w.uint(1);
        w.bytes(tmp, got);
        return CTAP2_OK;
    }

    if (setV->type != cbor::T_BYTES) return CTAP1_ERR_INVALID_PARAMETER;
    if (setV->len > 7609 - 64) return CTAP1_ERR_INVALID_LENGTH;

    if (offset == 0) {
        const Value* lenV = req.get(4);
        if (!lenV || !lenV->is_int() || lenV->i < 17) return CTAP1_ERR_INVALID_PARAMETER;
        if ((size_t)lenV->i > PK_MAX_LARGE_BLOB) return CTAP2_ERR_LARGE_BLOB_STORAGE_FULL;
        g_blobExpected = (size_t)lenV->i;
        g_blobNext = 0;
        if (!g_blobBuf) g_blobBuf = (uint8_t*)malloc(PK_MAX_LARGE_BLOB);
        if (!g_blobBuf) return CTAP2_ERR_OTHER;
    } else {
        if (req.get(4)) return CTAP1_ERR_INVALID_PARAMETER;
        if (offset != g_blobNext) return CTAP1_ERR_INVALID_SEQ;
    }

    if (pin_is_set()) {
        const Value* auth = req.get(5);
        const Value* protoV = req.get(6);
        if (!auth || auth->type != cbor::T_BYTES) return CTAP2_ERR_PIN_AUTH_INVALID;
        if (!protoV || !protoV->is_int()) return CTAP2_ERR_MISSING_PARAMETER;
        if ((g_pin.perms & PK_PERM_LBW) == 0) return CTAP2_ERR_PIN_AUTH_INVALID;
        uint8_t msg[64];
        memset(msg, 0xFF, 32);
        msg[32] = 0x0C;
        msg[33] = 0x00;
        msg[34] = (uint8_t)offset;
        msg[35] = (uint8_t)(offset >> 8);
        msg[36] = (uint8_t)(offset >> 16);
        msg[37] = (uint8_t)(offset >> 24);
        uint8_t h[32];
        sha256(setV->data, setV->len, h);
        memcpy(msg + 38, h, 32);
        size_t want = (g_pin.tokenProto == 2) ? 32 : 16;
        if (auth->len != want) return CTAP2_ERR_PIN_AUTH_INVALID;
        uint8_t mac[32];
        hmac_sha256(g_pin.token, 32, msg, 70, mac);
        if (!ct_equal(auth->data, mac, want)) return CTAP2_ERR_PIN_AUTH_INVALID;
    }

    if (offset + setV->len > g_blobExpected) return CTAP1_ERR_INVALID_PARAMETER;
    memcpy(g_blobBuf + offset, setV->data, setV->len);
    g_blobNext = offset + setV->len;
    if (g_blobNext == g_blobExpected) {
        uint8_t h[32];
        sha256(g_blobBuf, g_blobExpected - 16, h);
        if (!ct_equal(h, g_blobBuf + g_blobExpected - 16, 16)) return CTAP2_ERR_INTEGRITY_FAILURE;
        if (!store::large_blob_write(g_blobBuf, g_blobExpected)) return CTAP2_ERR_LARGE_BLOB_STORAGE_FULL;
        g_blobExpected = 0;
        g_blobNext = 0;
    }
    return CTAP2_OK;
}

// ---------------------------------------------------------------------------
// authenticatorConfig
// ---------------------------------------------------------------------------
static bool config_auth(const Value& req, uint8_t sub) {
    const Value* p = req.get(4);
    if (!p || p->type != cbor::T_BYTES) return false;
    uint8_t msg[64];
    memset(msg, 0xFF, 32);
    msg[32] = 0x0D;
    msg[33] = sub;
    size_t want = (g_pin.tokenProto == 2) ? 32 : 16;
    if (p->len != want) return false;
    uint8_t mac[32];
    hmac_sha256(g_pin.token, 32, msg, 34, mac);
    return ct_equal(p->data, mac, want);
}

static uint8_t do_config(const Value& req, cbor::Writer& w) {
    const Value* subV = req.get(1);
    if (!subV || !subV->is_int()) return CTAP1_ERR_INVALID_PARAMETER;
    uint8_t sub = (uint8_t)subV->i;
    if (pin_is_set() && !config_auth(req, sub)) return CTAP2_ERR_PIN_AUTH_INVALID;

    switch (sub) {
        case CONFIG_ENABLE_ENTERPRISE_ATT:
            store::settings().flags |= 0x04;
            store::save_settings();
            return CTAP2_OK;
        case CONFIG_TOGGLE_ALWAYS_UV: {
            const Value* v = req.get(2);
            if (!v || v->type != cbor::T_BOOL) return CTAP2_ERR_MISSING_PARAMETER;
            if (v->b) store::settings().flags |= 0x02;
            else store::settings().flags &= ~0x02;
            store::save_settings();
            return CTAP2_OK;
        }
        case CONFIG_SET_MIN_PIN_LENGTH: {
            const Value* v = req.get(2);
            if (!v || !v->is_int()) return CTAP2_ERR_MISSING_PARAMETER;
            if (v->i < 4 || v->i > 63) return CTAP2_ERR_PIN_POLICY_VIOLATION;
            store::settings().minPinLen = (uint8_t)v->i;
            store::save_settings();
            return CTAP2_OK;
        }
        default:
            return CTAP2_ERR_UNSUPPORTED_OPTION;
    }
}

// ---------------------------------------------------------------------------
// reset
// ---------------------------------------------------------------------------
void factory_reset() {
    store::factory_reset();
    memset(&g_pin, 0, sizeof(g_pin));
    g_candCount = 0;
    g_gaActive = false;
}

static uint8_t do_reset() {
    if (!wait_touch(10000)) {
        return ctaphid::cancelled() ? CTAP2_ERR_KEEPALIVE_CANCEL : CTAP2_ERR_OPERATION_DENIED;
    }
    factory_reset();
    return CTAP2_OK;
}

// ---------------------------------------------------------------------------
// dispatcher
// ---------------------------------------------------------------------------
void init() {
    pinMode(PK_BUTTON_PIN, INPUT_PULLUP);
    g_pin.tokenValid = false;
}

static size_t finish(cbor::Writer& w, uint8_t* resp, size_t cap, uint8_t* status) {
    cbor::Value v;
    if (!cbor::parse(w.data(), w.size(), v)) {
        *status = CTAP2_ERR_OTHER;
        return 0;
    }
    cbor::Writer out;
    out.reserve(w.size() + 64);
    cbor::encode_canonical(v, out);
    if (out.size() > cap) {
        *status = CTAP2_ERR_OTHER;
        return 0;
    }
    memcpy(resp, out.data(), out.size());
    if (out.size() >= 8) {
        char hex[3 * 24 + 1];
        size_t n = out.size() < 24 ? out.size() : 24;
        for (size_t i = 0; i < n; i++) snprintf(hex + i * 3, 4, "%02x ", out.data()[i]);
        DBG("resp len=%u %s", (unsigned)out.size(), hex);
    }
    return out.size();
}

size_t handle(uint8_t cmd, const uint8_t* req, size_t len, uint8_t* resp, size_t cap, uint8_t* status) {
    cbor::Writer w;
    w.reserve(1024);
    *status = CTAP2_OK;
    DBG("CTAP cmd=%02x len=%u", cmd, (unsigned)len);
    if ((cmd == CTAP2_CMD_MAKE_CREDENTIAL || cmd == CTAP2_CMD_CLIENT_PIN) && len >= 8) {
        char hex[3 * 24 + 1];
        size_t n = len < 24 ? len : 24;
        for (size_t i = 0; i < n; i++) snprintf(hex + i * 3, 4, "%02x ", req[i]);
        DBG("req %s", hex);
    }

    if (cmd == CTAP2_CMD_GET_INFO) {
        *status = CTAP2_OK;
        do_get_info(w);
        return finish(w, resp, cap, status);
    }
    if (cmd == CTAP2_CMD_RESET) {
        *status = do_reset();
        return 0;
    }
    if (cmd == CTAP2_CMD_SELECTION) {
        *status = CTAP2_OK;
        return 0;
    }

    if (len == 0) { *status = CTAP2_ERR_INVALID_CBOR; return 0; }
    Value v;
    if (!cbor::parse(req, len, v) || v.type != cbor::T_MAP) {
        *status = CTAP2_ERR_INVALID_CBOR;
        return 0;
    }

    switch (cmd) {
        case CTAP2_CMD_MAKE_CREDENTIAL:
            *status = do_make_credential(v, w);
            break;
        case CTAP2_CMD_GET_ASSERTION:
            *status = do_get_assertion(v, w);
            break;
        case CTAP2_CMD_GET_NEXT_ASSERTION:
            *status = do_get_next_assertion(w);
            break;
        case CTAP2_CMD_CLIENT_PIN:
            *status = do_client_pin(v, w);
            break;
        case CTAP2_CMD_CREDENTIAL_MGMT:
            *status = do_cred_mgmt(v, w);
            break;
        case CTAP2_CMD_LARGE_BLOBS:
            *status = do_large_blobs(v, w);
            break;
        case CTAP2_CMD_CONFIG:
            *status = do_config(v, w);
            break;
        default:
            *status = CTAP1_ERR_INVALID_COMMAND;
            break;
    }
    if (*status != CTAP2_OK) return 0;
    if (w.size() == 0) return 0;  // commands with an empty response payload
    return finish(w, resp, cap, status);
}

void poll() {}

bool user_presence(uint32_t timeout_ms) { return wait_touch(timeout_ms); }

bool check_pin_string(const char* pin, size_t len) {
    if (!pin_is_set()) return true;
    uint8_t h[32];
    sha256((const uint8_t*)pin, len, h);
    uint8_t ref[16];
    if (!pin_load_hash(ref)) return false;
    if (ct_equal(h, ref, 16)) {
        pin_success();
        return true;
    }
    pin_fail();
    return false;
}

}  // namespace ctap
}  // namespace pk
