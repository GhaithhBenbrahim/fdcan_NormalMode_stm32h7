/**
 ******************************************************************************
 * @file    cal_types.h
 * @brief   Crypto Abstraction Layer (CAL) — Common Types
 *
 * This header defines all shared types, return codes, algorithm identifiers,
 * and buffer size constants for the CAL. All UDS code uses these types;
 * no mbedTLS or PQClean types leak above this layer.
 *
 * Algorithm indicator values (field in UDS 0x29 messages) are OEM-defined
 * per ISO 14229-1:2020 §10.4. We define our own mapping here.
 *
 * @author  Ghaith Ben Brahim
 * @date    2026-03-15
 ******************************************************************************
 */
#ifndef CAL_TYPES_H
#define CAL_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * ALGORITHM IDENTIFIERS
 * These values appear in the UDS 0x29 algorithmIndicator field.
 * ============================================================================
 */
typedef enum {
    CAL_ALG_NONE         = 0x00,
    CAL_ALG_ECDSA_P256   = 0x01,   /**< Classical: ECDSA-P256 / ECDH-P256 */
    /* PQC — stubbed, filled in Week 9 */
    CAL_ALG_ML_DSA_2     = 0x10,   /**< PQC: ML-DSA-2 (FIPS 204) */
    CAL_ALG_ML_KEM_512   = 0x11,   /**< PQC: ML-KEM-512 (FIPS 203) */
    CAL_ALG_HYBRID       = 0x20,   /**< Hybrid: classical + PQC */
} cal_algorithm_t;

/**
 * @brief  High-level crypto mode — selectable at runtime from the TouchGFX GUI.
 *         Maps directly to a backend vtable (cal_backend_classical / pqc / hybrid).
 */
typedef enum {
    CAL_MODE_CLASSICAL = 0,   /**< ECDSA-P256 + ECDH-P256 (today)     */
    CAL_MODE_PQC       = 1,   /**< ML-DSA-2 + ML-KEM-512 (Week 9)    */
    CAL_MODE_HYBRID    = 2,   /**< Classical + PQC combined (Week 11) */
    CAL_MODE_COUNT     = 3,
} cal_mode_t;

/* ============================================================================
 * RETURN CODES
 * ============================================================================
 */
typedef enum {
    CAL_OK                  = 0,
    CAL_ERR_INVALID_PARAM   = -1,
    CAL_ERR_VERIFY_FAILED   = -2,   /**< Signature or tag verification failed */
    CAL_ERR_CRYPTO          = -3,   /**< Generic mbedTLS / crypto error        */
    CAL_ERR_BUFFER_TOO_SMALL= -4,
    CAL_ERR_NOT_SUPPORTED   = -5,   /**< Algorithm not yet implemented          */
    CAL_ERR_NOT_INIT        = -6,   /**< cal_init() not called                  */
} cal_result_t;

/* ============================================================================
 * BUFFER SIZE CONSTANTS — classical crypto (ECDSA-P256 / ECDH-P256)
 * ============================================================================
 */

/** Raw private key scalar — 32 bytes for ECDSA-P256 */
#define CAL_ECDSA_PRIVKEY_SIZE      32U

/** Uncompressed public key: 0x04 || X(32) || Y(32) */
#define CAL_ECDSA_PUBKEY_SIZE       65U

/** DER-encoded ECDSA signature: max 72 bytes (r,s each 32 bytes + overhead) */
#define CAL_ECDSA_SIG_MAX_SIZE      72U

/** ECDH shared secret (X-coordinate) */
#define CAL_ECDH_SHARED_SECRET_SIZE 32U

/** AES-256 key = 32 bytes */
#define CAL_AES256_KEY_SIZE         32U

/** AES-GCM IV/nonce = 12 bytes (96-bit, standard for GCM) */
#define CAL_AES_GCM_IV_SIZE         12U

/** AES-GCM authentication tag = 16 bytes */
#define CAL_AES_GCM_TAG_SIZE        16U

/** SHA-256 digest = 32 bytes */
#define CAL_SHA256_SIZE             32U

/** HMAC-SHA256 output = 32 bytes */
#define CAL_HMAC_SHA256_SIZE        32U

/** HKDF-SHA256 max output key material */
#define CAL_HKDF_MAX_OKM            64U

/** Server challenge (random nonce) = 32 bytes */
#define CAL_CHALLENGE_SIZE          32U

/* Future-proofing maximums for PQC (sizing static CAL structs) */
#define CAL_MAX_PUBKEY_SIZE         CAL_ECDSA_PUBKEY_SIZE   /* 65B now, 1312B ML-DSA-2 later */
#define CAL_MAX_SIG_SIZE            CAL_ECDSA_SIG_MAX_SIZE  /* 72B now, 2420B ML-DSA-2 later */
#define CAL_MAX_PRIVKEY_SIZE        CAL_ECDSA_PRIVKEY_SIZE  /* 32B now */

/* ============================================================================
 * STRUCTURED TYPES
 * ============================================================================
 */

/**
 * @brief  Public key — algorithm-tagged, self-describing.
 */
typedef struct {
    uint8_t         bytes[CAL_MAX_PUBKEY_SIZE];
    uint16_t        length;     /**< Actual used bytes */
    cal_algorithm_t alg;
} cal_pubkey_t;

/**
 * @brief  Signature — DER-encoded for ECDSA, raw for ML-DSA.
 */
typedef struct {
    uint8_t  bytes[CAL_MAX_SIG_SIZE];
    uint16_t length;            /**< Actual used bytes */
} cal_signature_t;

/**
 * @brief  Ephemeral key pair produced by cal_keygen().
 */
typedef struct {
    cal_pubkey_t pub;
    uint8_t      priv[CAL_MAX_PRIVKEY_SIZE];
    uint16_t     priv_len;
} cal_keypair_t;

/**
 * @brief  Derived session key material.
 */
typedef struct {
    uint8_t  key[CAL_AES256_KEY_SIZE];   /**< AES-256 session key          */
    uint8_t  verify[CAL_HMAC_SHA256_SIZE];/**< HMAC proof for sessionKeyInfo */
    bool     valid;
} cal_session_t;

#ifdef __cplusplus
}
#endif

#endif /* CAL_TYPES_H */
