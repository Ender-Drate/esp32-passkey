// ESP32 Passkey - global configuration and constants
#pragma once

#include <stdint.h>
#include <stddef.h>

#define PK_VERSION "0.1.0"
#define PK_PRODUCT_NAME "TechXPassKey"
#define PK_MANUFACTURER "TechX"

#ifndef PK_DEBUG
#define PK_DEBUG 0
#endif

// --- Hardware ---------------------------------------------------------------
#ifndef PK_LED_PIN
#define PK_LED_PIN 48          // onboard WS2812 on most ESP32-S3 devkits
#endif
#ifndef PK_BUTTON_PIN
#define PK_BUTTON_PIN 0        // BOOT button = user presence
#endif

// --- FIDO -------------------------------------------------------------------
#define PK_AAGUID { 0x54, 0x45, 0x43, 0x48, 0x58, 0x50, 0x41, 0x53, \
                    0x53, 0x4B, 0x45, 0x59, 0x30, 0x30, 0x30, 0x31 }
// "TECHXPASSKEY0001"

#define PK_MAX_CREDENTIALS          100
#define PK_MAX_CRED_ID_LEN          64
#define PK_MAX_RP_ID_LEN            96
#define PK_MAX_USER_ID_LEN          64
#define PK_MAX_TEXT_FIELD           64
#define PK_MAX_MSG_SIZE             8192
#define PK_MAX_LARGE_BLOB           8192
#define PK_MAX_CBOR_CRED_LIST       16
#define PK_PIN_MIN_LEN              4
#define PK_PIN_MAX_LEN              63
#define PK_PIN_RETRIES              8
#define PK_DEFAULT_UP_TIMEOUT_MS    30000
#define PK_CTAPHID_CHANNEL_COUNT    8

// CTAPHID commands (bit 7 set, except CANCEL)
enum : uint8_t {
    CTAPHID_CMD_PING        = 0x81,
    CTAPHID_CMD_MSG         = 0x83,
    CTAPHID_CMD_LOCK        = 0x84,
    CTAPHID_CMD_INIT        = 0x86,
    CTAPHID_CMD_WINK        = 0x88,
    CTAPHID_CMD_CBOR        = 0x90,
    CTAPHID_CMD_CANCEL      = 0x11,
    CTAPHID_CMD_KEEPALIVE   = 0xBB,
    CTAPHID_CMD_ERROR       = 0xBF,
};

enum : uint8_t {
    CTAPHID_ERR_INVALID_CMD     = 0x01,
    CTAPHID_ERR_INVALID_PAR     = 0x02,
    CTAPHID_ERR_INVALID_LEN     = 0x03,
    CTAPHID_ERR_INVALID_SEQ     = 0x04,
    CTAPHID_ERR_MSG_TIMEOUT     = 0x05,
    CTAPHID_ERR_CHANNEL_BUSY    = 0x06,
    CTAPHID_ERR_LOCK_REQUIRED   = 0x0A,
    CTAPHID_ERR_INVALID_CHANNEL = 0x0B,
    CTAPHID_ERR_OTHER           = 0x7F,
};

// CTAP2 commands
enum : uint8_t {
    CTAP2_CMD_MAKE_CREDENTIAL   = 0x01,
    CTAP2_CMD_GET_ASSERTION     = 0x02,
    CTAP2_CMD_GET_INFO          = 0x04,
    CTAP2_CMD_CLIENT_PIN        = 0x06,
    CTAP2_CMD_RESET             = 0x07,
    CTAP2_CMD_GET_NEXT_ASSERTION= 0x08,
    CTAP2_CMD_BIO_ENROLLMENT    = 0x09,
    CTAP2_CMD_CREDENTIAL_MGMT   = 0x0A,
    CTAP2_CMD_SELECTION         = 0x0B,
    CTAP2_CMD_LARGE_BLOBS       = 0x0C,
    CTAP2_CMD_CONFIG            = 0x0D,
};

// CTAP2 status codes
enum : uint8_t {
    CTAP2_OK                        = 0x00,
    CTAP1_ERR_INVALID_COMMAND       = 0x01,
    CTAP1_ERR_INVALID_PARAMETER     = 0x02,
    CTAP1_ERR_INVALID_LENGTH        = 0x03,
    CTAP1_ERR_INVALID_SEQ           = 0x04,
    CTAP1_ERR_TIMEOUT               = 0x05,
    CTAP1_ERR_CHANNEL_BUSY          = 0x06,
    CTAP1_ERR_LOCK_REQUIRED         = 0x0A,
    CTAP1_ERR_INVALID_CHANNEL       = 0x0B,
    CTAP2_ERR_CBOR_UNEXPECTED_TYPE  = 0x11,
    CTAP2_ERR_INVALID_CBOR          = 0x12,
    CTAP2_ERR_MISSING_PARAMETER     = 0x14,
    CTAP2_ERR_LIMIT_EXCEEDED        = 0x15,
    CTAP2_ERR_FP_DATABASE_FULL      = 0x16,
    CTAP2_ERR_INTEGRITY_FAILURE     = 0x17,
    CTAP2_ERR_LARGE_BLOB_STORAGE_FULL = 0x18,
    CTAP2_ERR_CREDENTIAL_EXCLUDED   = 0x19,
    CTAP2_ERR_PROCESSING            = 0x21,
    CTAP2_ERR_INVALID_CREDENTIAL    = 0x22,
    CTAP2_ERR_USER_ACTION_PENDING   = 0x23,
    CTAP2_ERR_OPERATION_PENDING     = 0x24,
    CTAP2_ERR_NO_OPERATIONS         = 0x25,
    CTAP2_ERR_UNSUPPORTED_ALGORITHM = 0x26,
    CTAP2_ERR_OPERATION_DENIED      = 0x27,
    CTAP2_ERR_KEY_STORE_FULL        = 0x28,
    CTAP2_ERR_NOT_BUSY              = 0x29,
    CTAP2_ERR_NO_OPERATION_PENDING  = 0x2A,
    CTAP2_ERR_UNSUPPORTED_OPTION    = 0x2B,
    CTAP2_ERR_INVALID_OPTION        = 0x2C,
    CTAP2_ERR_KEEPALIVE_CANCEL      = 0x2D,
    CTAP2_ERR_NO_CREDENTIALS        = 0x2E,
    CTAP2_ERR_USER_ACTION_TIMEOUT   = 0x2F,
    CTAP2_ERR_NOT_ALLOWED           = 0x30,
    CTAP2_ERR_PIN_INVALID           = 0x31,
    CTAP2_ERR_PIN_BLOCKED           = 0x32,
    CTAP2_ERR_PIN_AUTH_INVALID      = 0x33,
    CTAP2_ERR_PIN_AUTH_BLOCKED      = 0x34,
    CTAP2_ERR_PIN_NOT_SET           = 0x35,
    CTAP2_ERR_PIN_REQUIRED          = 0x36,
    CTAP2_ERR_PIN_POLICY_VIOLATION  = 0x37,
    CTAP2_ERR_PIN_TOKEN_EXPIRED     = 0x38,
    CTAP2_ERR_REQUEST_TOO_LARGE     = 0x39,
    CTAP2_ERR_ACTION_TIMEOUT        = 0x3A,
    CTAP2_ERR_OTHER                 = 0x7F,
};

// Credential management subcommands
enum : uint8_t {
    CREDMGMT_GET_METADATA           = 0x01,
    CREDMGMT_ENUM_RPS_BEGIN         = 0x02,
    CREDMGMT_ENUM_RPS_NEXT          = 0x03,
    CREDMGMT_ENUM_CREDS_BEGIN       = 0x04,
    CREDMGMT_ENUM_CREDS_NEXT        = 0x05,
    CREDMGMT_DELETE_CREDENTIAL      = 0x06,
    CREDMGMT_UPDATE_USER_INFO       = 0x07,
};

// clientPIN subcommands
enum : uint8_t {
    PIN_GET_RETRIES                 = 0x01,
    PIN_GET_KEY_AGREEMENT           = 0x02,
    PIN_SET_PIN                     = 0x03,
    PIN_CHANGE_PIN                  = 0x04,
    PIN_GET_TOKEN                   = 0x05,
    PIN_GET_TOKEN_UV                = 0x06,
    PIN_GET_UV_RETRIES              = 0x07,
    PIN_GET_TOKEN_PIN_PERMS         = 0x09,
};

// authentictorConfig subcommands
enum : uint8_t {
    CONFIG_ENABLE_ENTERPRISE_ATT    = 0x01,
    CONFIG_TOGGLE_ALWAYS_UV         = 0x02,
    CONFIG_SET_MIN_PIN_LENGTH       = 0x03,
    CONFIG_VENDOR_PROTOTYPE         = 0xFF,
};

// largeBlobs subcommands
enum : uint8_t {
    LARGEBLOB_READ                  = 0x01,
    LARGEBLOB_WRITE                 = 0x02,
};

// COSE algorithms
#define COSE_ALG_ES256              (-7)
#define COSE_ALG_EDDSA              (-8)
#define COSE_ALG_ECDH_ES_HKDF_256   (-25)

// CTAP2 pinUvAuthToken permissions
#define PK_PERM_MC  0x01
#define PK_PERM_GA  0x02
#define PK_PERM_CM  0x04
#define PK_PERM_BE  0x08
#define PK_PERM_LBW 0x10
#define PK_PERM_ACFG 0x20

// authData flags
#define AUTH_FLAG_UP        0x01
#define AUTH_FLAG_UV        0x04
#define AUTH_FLAG_BE        0x08
#define AUTH_FLAG_BS        0x10
#define AUTH_FLAG_AT        0x40
#define AUTH_FLAG_ED        0x80
