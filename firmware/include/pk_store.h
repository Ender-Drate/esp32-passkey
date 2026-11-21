// Persistent state: master key, settings, resident credentials, large blobs.
#pragma once

#include <stdint.h>
#include <stddef.h>

#include "pk_config.h"

namespace pk {

struct Credential {
    uint8_t  credId[PK_MAX_CRED_ID_LEN];
    uint8_t  credIdLen;
    uint8_t  rpIdHash[32];
    uint8_t  rpId[PK_MAX_RP_ID_LEN];
    uint8_t  rpIdLen;
    uint8_t  rpName[PK_MAX_TEXT_FIELD];
    uint8_t  rpNameLen;
    uint8_t  userId[PK_MAX_USER_ID_LEN];
    uint8_t  userIdLen;
    uint8_t  userName[PK_MAX_TEXT_FIELD];
    uint8_t  userNameLen;
    uint8_t  displayName[PK_MAX_TEXT_FIELD];
    uint8_t  displayNameLen;
    uint8_t  priv[32];
    uint8_t  credRandom[32];
    uint32_t signCount;
    uint8_t  credProtect;
    uint8_t  flags;        // bit0: discoverable (resident)
    uint64_t createdAt;
    uint64_t lastUsed;
};

struct KeyHandle {
    uint8_t  rpIdHash[32];
    uint8_t  priv[32];
    uint32_t signCount;
    uint8_t  flags;        // bit0: UV required at creation
    uint8_t  credRandom[32];
};

struct Settings {
    uint8_t  version;
    uint8_t  flags;          // bit0 pinSet, bit1 alwaysUv, bit2 enterpriseAtt
    uint8_t  pinRetries;
    uint8_t  minPinLen;
    uint8_t  upMode;         // 0 = button, 1 = auto (developer)
    uint8_t  pinHashLen;
    uint8_t  reserved[2];
    uint8_t  pinHashEnc[44]; // iv(12) || ct(16) || tag(16)
    uint32_t lockoutStartMs;
    uint32_t lockoutSeconds;
    uint32_t bootCount;
    uint32_t globalSignCount;
    uint64_t epochAtSync;
    uint32_t uptimeAtSync;
};

namespace store {

bool begin();

const uint8_t* master_key();

Settings& settings();
void save_settings();

// credentials
int credential_count();
Credential* credentials();
Credential* find_by_cred_id(const uint8_t* id, size_t len);
Credential* find_by_rp(const uint8_t rpIdHash[32], const uint8_t* credId, size_t credIdLen);
bool add_credential(const Credential& c);
bool update_credential(const Credential& c);
bool delete_credential(const uint8_t* credId, size_t len);
void delete_all_credentials();
bool save_credentials();
void mark_dirty();
void flush_if_dirty();
void factory_reset();

// non-resident key handles (U2F + rk=false)
bool wrap_key_handle(const KeyHandle& kh, uint8_t* out, size_t& outLen);
bool unwrap_key_handle(const uint8_t* in, size_t inLen, KeyHandle& kh);

// large blob array
size_t large_blob_size();
bool large_blob_read(uint8_t* out, size_t offset, size_t len);
bool large_blob_write(const uint8_t* data, size_t len);
void large_blob_reset();

uint64_t now_epoch();
void sync_epoch(uint64_t epoch);

}  // namespace store
}  // namespace pk
