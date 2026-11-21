#include "pk_u2f.h"

#include <Arduino.h>
#include <string.h>

#include "pk_config.h"
#include "pk_crypto.h"
#include "pk_ctap2.h"
#include "pk_store.h"
#include "pk_u2f_cert.h"

namespace pk {
namespace u2f {

// U2F raw messages are APDUs: 00 INS P1 P2 Lc [data]
static const uint8_t INS_REGISTER = 0x01;
static const uint8_t INS_AUTHENTICATE = 0x02;
static const uint8_t INS_VERSION = 0x03;

static void put_sw(uint8_t* resp, size_t& n, uint16_t sw) {
    resp[n++] = (uint8_t)(sw >> 8);
    resp[n++] = (uint8_t)sw;
}

static size_t error(uint8_t* resp, uint16_t sw, uint8_t* status) {
    size_t n = 0;
    put_sw(resp, n, sw);
    *status = 0;
    return n;
}

size_t handle(const uint8_t* req, size_t len, uint8_t* resp, size_t cap, uint8_t* status) {
    *status = 0;
    if (len < 5 || req[0] != 0x00) return error(resp, 0x6700, status);

    uint8_t ins = req[1];
    uint8_t p1 = req[2];
    size_t lc = req[4];
    const uint8_t* data = req + 5;
    if (lc == 0 && len > 5) {
        if (len < 7) return error(resp, 0x6700, status);
        lc = ((size_t)req[5] << 8) | req[6];
        data = req + 7;
    }
    if ((size_t)(data - req) + lc > len) return error(resp, 0x6700, status);

    if (ins == INS_VERSION) {
        static const char ver[] = "U2F_V2";
        size_t n = sizeof(ver) - 1;
        if (cap < n + 2) return error(resp, 0x6F00, status);
        memcpy(resp, ver, n);
        put_sw(resp, n, 0x9000);
        return n;
    }

    if (ins == INS_REGISTER) {
        if (lc != 64) return error(resp, 0x6700, status);
        const uint8_t* challenge = data;
        const uint8_t* appId = data + 32;

        if (!ctap::user_presence(PK_DEFAULT_UP_TIMEOUT_MS)) return error(resp, 0x6985, status);

        uint8_t priv[32], pub[65];
        uint8_t x[32], y[32];
        if (!ec_generate(priv, x, y)) return error(resp, 0x6F00, status);
        pub[0] = 0x04;
        memcpy(pub + 1, x, 32);
        memcpy(pub + 33, y, 32);

        uint8_t credRandom[32];
        random_bytes(credRandom, 32);
        KeyHandle kh;
        memcpy(kh.rpIdHash, appId, 32);
        memcpy(kh.priv, priv, 32);
        kh.signCount = 0;
        kh.flags = 0;
        memcpy(kh.credRandom, credRandom, 32);

        uint8_t khBuf[256];  // wrapped handles can exceed PK_MAX_CRED_ID_LEN
        size_t khLen = 0;
        if (!store::wrap_key_handle(kh, khBuf, khLen) || khLen > 255)
            return error(resp, 0x6F00, status);

        uint8_t signed_data[1 + 32 + 32 + 255 + 65];
        size_t sl = 0;
        signed_data[sl++] = 0x00;
        memcpy(signed_data + sl, appId, 32); sl += 32;
        memcpy(signed_data + sl, challenge, 32); sl += 32;
        memcpy(signed_data + sl, khBuf, khLen); sl += khLen;
        memcpy(signed_data + sl, pub, 65); sl += 65;

        uint8_t sig[80];
        size_t sigLen = 0;
        if (!ecdsa_sign_sha256(U2F_ATTEST_PRIV, signed_data, sl, sig, sizeof(sig), sigLen))
            return error(resp, 0x6F00, status);

        if (cap < 1 + 65 + 1 + khLen + U2F_ATTEST_CERT_LEN + sigLen + 2)
            return error(resp, 0x6F00, status);
        size_t n = 0;
        resp[n++] = 0x05;
        memcpy(resp + n, pub, 65); n += 65;
        resp[n++] = (uint8_t)khLen;
        memcpy(resp + n, khBuf, khLen); n += khLen;
        memcpy(resp + n, U2F_ATTEST_CERT, U2F_ATTEST_CERT_LEN); n += U2F_ATTEST_CERT_LEN;
        memcpy(resp + n, sig, sigLen); n += sigLen;
        put_sw(resp, n, 0x9000);
        return n;
    }

    if (ins == INS_AUTHENTICATE) {
        if (lc < 65) return error(resp, 0x6700, status);
        const uint8_t* challenge = data;
        const uint8_t* appId = data + 32;
        uint8_t khLen = data[64];
        if (lc != 65u + khLen) return error(resp, 0x6700, status);

        KeyHandle kh;
        if (!store::unwrap_key_handle(data + 65, khLen, kh)) return error(resp, 0x6A80, status);
        if (memcmp(kh.rpIdHash, appId, 32) != 0) return error(resp, 0x6A80, status);

        if (p1 == 0x07) return error(resp, 0x6985, status);  // check-only
        if (p1 != 0x03 && p1 != 0x08) return error(resp, 0x6B00, status);

        bool up = (p1 == 0x03);
        if (up && !ctap::user_presence(PK_DEFAULT_UP_TIMEOUT_MS)) return error(resp, 0x6985, status);

        uint32_t counter = ++store::settings().globalSignCount;
        store::save_settings();

        uint8_t sd[69];
        memcpy(sd, appId, 32);
        sd[32] = up ? 0x01 : 0x00;
        sd[33] = (uint8_t)(counter >> 24);
        sd[34] = (uint8_t)(counter >> 16);
        sd[35] = (uint8_t)(counter >> 8);
        sd[36] = (uint8_t)counter;
        memcpy(sd + 37, challenge, 32);

        uint8_t sig[80];
        size_t sigLen = 0;
        if (!ecdsa_sign_sha256(kh.priv, sd, sizeof(sd), sig, sizeof(sig), sigLen))
            return error(resp, 0x6F00, status);

        if (cap < 5 + sigLen + 2) return error(resp, 0x6F00, status);
        size_t n = 0;
        resp[n++] = up ? 0x01 : 0x00;
        resp[n++] = (uint8_t)(counter >> 24);
        resp[n++] = (uint8_t)(counter >> 16);
        resp[n++] = (uint8_t)(counter >> 8);
        resp[n++] = (uint8_t)counter;
        memcpy(resp + n, sig, sigLen); n += sigLen;
        put_sw(resp, n, 0x9000);
        return n;
    }

    return error(resp, 0x6D00, status);
}

}  // namespace u2f
}  // namespace pk
