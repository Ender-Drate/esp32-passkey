// mbedTLS wrappers: hashes, HMAC, HKDF, AES, P-256 ECDSA/ECDH.
#pragma once

#include <stdint.h>
#include <stddef.h>

namespace pk {

bool rng_init();
bool random_bytes(uint8_t* out, size_t len);

void sha256(const uint8_t* data, size_t len, uint8_t out[32]);
void sha256_bits(const uint8_t* data, size_t len, uint32_t bitlen, uint8_t out[32]);
void sha256_two(const uint8_t* a, size_t an, const uint8_t* b, size_t bn, uint8_t out[32]);
void hmac_sha256(const uint8_t* key, size_t keyLen, const uint8_t* msg, size_t msgLen, uint8_t out[32]);
bool hkdf_sha256(const uint8_t* salt, size_t saltLen, const uint8_t* ikm, size_t ikmLen,
                 const char* info, uint8_t* out, size_t outLen);

bool aes256_cbc(bool encrypt, const uint8_t key[32], const uint8_t iv[16],
                const uint8_t* in, size_t len, uint8_t* out);
// iv(12) || ciphertext(len) || tag(16)
bool aes256_gcm_encrypt(const uint8_t key[32], const uint8_t* iv, size_t ivLen,
                        const uint8_t* pt, size_t len, uint8_t* out);
bool aes256_gcm_decrypt(const uint8_t key[32], const uint8_t* iv, size_t ivLen,
                        const uint8_t* ctAndTag, size_t len, uint8_t* out);

bool ec_generate(uint8_t priv[32], uint8_t x[32], uint8_t y[32]);
bool ec_pub_from_priv(const uint8_t priv[32], uint8_t x[32], uint8_t y[32]);
bool ecdsa_sign_sha256(const uint8_t priv[32], const uint8_t* msg, size_t len,
                       uint8_t* der, size_t cap, size_t& derLen);
bool ecdsa_verify_sha256(const uint8_t x[32], const uint8_t y[32],
                         const uint8_t* data, size_t len,
                         const uint8_t* der, size_t derLen);
bool ecdh_p256(const uint8_t priv[32], const uint8_t peerX[32], const uint8_t peerY[32], uint8_t out[32]);

bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n);
uint32_t crc32(const uint8_t* data, size_t len);

}  // namespace pk
