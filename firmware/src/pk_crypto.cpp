#include "pk_crypto.h"

#include <string.h>

#include "mbedtls/aes.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"

namespace pk {

static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_drbg;
static bool g_rng_ready = false;

bool rng_init() {
    if (g_rng_ready) return true;
    mbedtls_entropy_init(&g_entropy);
    mbedtls_ctr_drbg_init(&g_drbg);
    static const char pers[] = "esp32-passkey";
    int rc = mbedtls_ctr_drbg_seed(&g_drbg, mbedtls_entropy_func, &g_entropy,
                                   (const unsigned char*)pers, sizeof(pers) - 1);
    g_rng_ready = (rc == 0);
    return g_rng_ready;
}

bool random_bytes(uint8_t* out, size_t len) {
    if (!rng_init()) return false;
    return mbedtls_ctr_drbg_random(&g_drbg, out, len) == 0;
}

void sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
    mbedtls_sha256_ret(data, len, out, 0);
}

void sha256_bits(const uint8_t* data, size_t len, uint32_t bitlen, uint8_t out[32]) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, data, len);
    // mbedtls has no bit-granular finish; CTAP only uses byte lengths. Kept for API parity.
    (void)bitlen;
    mbedtls_sha256_finish_ret(&ctx, out);
    mbedtls_sha256_free(&ctx);
}

void sha256_two(const uint8_t* a, size_t an, const uint8_t* b, size_t bn, uint8_t out[32]) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, a, an);
    mbedtls_sha256_update_ret(&ctx, b, bn);
    mbedtls_sha256_finish_ret(&ctx, out);
    mbedtls_sha256_free(&ctx);
}

void hmac_sha256(const uint8_t* key, size_t keyLen, const uint8_t* msg, size_t msgLen, uint8_t out[32]) {
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_hmac(md, key, keyLen, msg, msgLen, out);
}

bool hkdf_sha256(const uint8_t* salt, size_t saltLen, const uint8_t* ikm, size_t ikmLen,
                 const char* info, uint8_t* out, size_t outLen) {
    // RFC 5869 with HMAC-SHA256 (mbedTLS HKDF is not enabled in this build).
    uint8_t prk[32];
    if (!salt || saltLen == 0) {
        uint8_t zero[32] = {0};
        hmac_sha256(zero, 32, ikm, ikmLen, prk);
    } else {
        hmac_sha256(salt, saltLen, ikm, ikmLen, prk);
    }

    uint8_t t[32];
    size_t tLen = 0;
    size_t done = 0;
    uint8_t counter = 1;
    size_t infoLen = info ? strlen(info) : 0;
    while (done < outLen) {
        uint8_t buf[32 + 64 + 1];
        size_t n = 0;
        if (tLen) { memcpy(buf, t, tLen); n += tLen; }
        if (infoLen) { memcpy(buf + n, info, infoLen); n += infoLen; }
        buf[n++] = counter;
        hmac_sha256(prk, 32, buf, n, t);
        tLen = 32;
        size_t take = outLen - done;
        if (take > 32) take = 32;
        memcpy(out + done, t, take);
        done += take;
        counter++;
    }
    return true;
}

bool aes256_cbc(bool encrypt, const uint8_t key[32], const uint8_t iv[16],
                const uint8_t* in, size_t len, uint8_t* out) {
    if (len % 16 != 0) return false;
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    uint8_t ivCopy[16];
    memcpy(ivCopy, iv, 16);
    int rc;
    if (encrypt) {
        rc = mbedtls_aes_setkey_enc(&ctx, key, 256);
        if (rc == 0) rc = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, len, ivCopy, in, out);
    } else {
        rc = mbedtls_aes_setkey_dec(&ctx, key, 256);
        if (rc == 0) rc = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, len, ivCopy, in, out);
    }
    mbedtls_aes_free(&ctx);
    return rc == 0;
}

bool aes256_gcm_encrypt(const uint8_t key[32], const uint8_t* iv, size_t ivLen,
                        const uint8_t* pt, size_t len, uint8_t* out) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (rc == 0) {
        rc = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, len, iv, ivLen,
                                       nullptr, 0, pt, out, 16, out + len);
    }
    mbedtls_gcm_free(&ctx);
    return rc == 0;
}

bool aes256_gcm_decrypt(const uint8_t key[32], const uint8_t* iv, size_t ivLen,
                        const uint8_t* ctAndTag, size_t len, uint8_t* out) {
    if (len < 16) return false;
    size_t ctLen = len - 16;
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (rc == 0) {
        rc = mbedtls_gcm_auth_decrypt(&ctx, ctLen, iv, ivLen, nullptr, 0,
                                      ctAndTag + ctLen, 16, ctAndTag, out);
    }
    mbedtls_gcm_free(&ctx);
    return rc == 0;
}

static void load_group(mbedtls_ecp_group& grp) {
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
}

bool ec_generate(uint8_t priv[32], uint8_t x[32], uint8_t y[32]) {
    if (!rng_init()) return false;
    mbedtls_ecp_group grp;
    load_group(grp);
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);
    bool ok = mbedtls_ecp_gen_keypair(&grp, &d, &Q, mbedtls_ctr_drbg_random, &g_drbg) == 0;
    if (ok) {
        ok = mbedtls_mpi_write_binary(&d, priv, 32) == 0;
        uint8_t buf[65];
        size_t olen = 0;
        if (ok) ok = mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                    &olen, buf, sizeof(buf)) == 0 && olen == 65;
        if (ok) {
            memcpy(x, buf + 1, 32);
            memcpy(y, buf + 33, 32);
        }
    }
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&grp);
    return ok;
}

bool ec_pub_from_priv(const uint8_t priv[32], uint8_t x[32], uint8_t y[32]) {
    mbedtls_ecp_group grp;
    load_group(grp);
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);
    bool ok = mbedtls_mpi_read_binary(&d, priv, 32) == 0;
    if (ok) ok = mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, mbedtls_ctr_drbg_random, &g_drbg) == 0;
    if (ok) {
        uint8_t buf[65];
        size_t olen = 0;
        ok = mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                            &olen, buf, sizeof(buf)) == 0 && olen == 65;
        if (ok) {
            memcpy(x, buf + 1, 32);
            memcpy(y, buf + 33, 32);
        }
    }
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&grp);
    return ok;
}

bool ecdsa_sign_sha256(const uint8_t priv[32], const uint8_t* msg, size_t len,
                       uint8_t* der, size_t cap, size_t& derLen) {
    uint8_t hash[32];
    sha256(msg, len, hash);
    mbedtls_ecp_group grp;
    load_group(grp);
    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);
    ctx.grp = grp;
    bool ok = mbedtls_mpi_read_binary(&ctx.d, priv, 32) == 0;
    if (ok) {
        ok = mbedtls_ecdsa_write_signature(&ctx, MBEDTLS_MD_SHA256, hash, 32,
                                           der, &derLen, mbedtls_ctr_drbg_random, &g_drbg) == 0;
    }
    mbedtls_ecdsa_free(&ctx);  // frees ctx.grp as well
    return ok;
}

bool ecdsa_verify_sha256(const uint8_t x[32], const uint8_t y[32],
                         const uint8_t* data, size_t len,
                         const uint8_t* der, size_t derLen) {
    uint8_t hash[32];
    sha256(data, len, hash);
    mbedtls_ecp_group grp;
    load_group(grp);
    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);
    ctx.grp = grp;
    uint8_t pub[65];
    pub[0] = 0x04;
    memcpy(pub + 1, x, 32);
    memcpy(pub + 33, y, 32);
    bool ok = mbedtls_ecp_point_read_binary(&ctx.grp, &ctx.Q, pub, 65) == 0;
    if (ok) {
        ok = mbedtls_ecdsa_read_signature(&ctx, hash, 32, der, derLen) == 0;
    }
    mbedtls_ecdsa_free(&ctx);
    return ok;
}

bool ecdh_p256(const uint8_t priv[32], const uint8_t peerX[32], const uint8_t peerY[32], uint8_t out[32]) {
    mbedtls_ecp_group grp;
    load_group(grp);
    mbedtls_mpi d, z;
    mbedtls_ecp_point Q;
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);
    mbedtls_ecp_point_init(&Q);
    uint8_t pub[65];
    pub[0] = 0x04;
    memcpy(pub + 1, peerX, 32);
    memcpy(pub + 33, peerY, 32);
    bool ok = mbedtls_mpi_read_binary(&d, priv, 32) == 0;
    if (ok) ok = mbedtls_ecp_point_read_binary(&grp, &Q, pub, 65) == 0;
    if (ok) ok = mbedtls_ecp_check_pubkey(&grp, &Q) == 0;
    if (ok) ok = mbedtls_ecdh_compute_shared(&grp, &z, &Q, &d,
                                             mbedtls_ctr_drbg_random, &g_drbg) == 0;
    if (ok) ok = mbedtls_mpi_write_binary(&z, out, 32) == 0;
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&z);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&grp);
    return ok;
}

bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

uint32_t crc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++) {
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1)));
        }
    }
    return ~crc;
}

}  // namespace pk
