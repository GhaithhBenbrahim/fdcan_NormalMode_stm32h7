/**
 ******************************************************************************
 * @file    cal_api.h
 * @brief   Crypto Abstraction Layer (CAL) — Unified API
 *
 * All UDS logic calls ONLY these cal_* functions. The implementation
 * (cal_classical.c today, cal_pqc.c in Week 9) is swapped without touching
 * any UDS code.
 *
 * Usage:
 *   1. Call cal_init() once at startup (initialises RNG context).
 *   2. Call individual cal_* functions as needed.
 *   3. cal_deinit() on shutdown (frees mbedTLS contexts).
 *
 * @author  Ghaith Ben Brahim
 * @date    2026-03-15
 ******************************************************************************
 */
#ifndef CAL_API_H
#define CAL_API_H

#include "cal_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/**
 * @brief  Initialise the CAL — must be called once before any other cal_*
 *         call. Sets up the mbedTLS entropy + CTR-DRBG context backed by the
 *         STM32H7 hardware RNG.
 * @retval CAL_OK or CAL_ERR_CRYPTO
 */
cal_result_t cal_init(void);

/**
 * @brief  Release mbedTLS contexts. Call on shutdown or before deep-sleep.
 */
void cal_deinit(void);

/* ============================================================================
 * RANDOM NUMBER GENERATION
 * ============================================================================
 */

/**
 * @brief  Generate cryptographically-secure random bytes (HW RNG via mbedTLS).
 * @param  buf  Destination buffer
 * @param  len  Number of bytes to generate
 * @retval CAL_OK / CAL_ERR_CRYPTO
 */
cal_result_t cal_rng(uint8_t *buf, uint16_t len);

/* ============================================================================
 * RUNTIME BACKEND SELECTION
 * ============================================================================
 */

/**
 * @brief  Switch the active crypto backend at runtime.
 * @param  mode  CAL_MODE_CLASSICAL / CAL_MODE_PQC / CAL_MODE_HYBRID
 * @retval CAL_OK or CAL_ERR_NOT_SUPPORTED
 */
cal_result_t cal_select_mode(cal_mode_t mode);

/**
 * @brief  Get current mode enum.
 */
cal_mode_t cal_get_mode(void);

/**
 * @brief  Get the UDS algorithm indicator for the currently active backend.
 */
uint8_t cal_get_alg_indicator(void);

/* ============================================================================
 * KEY GENERATION
 * ============================================================================
 */

/**
 * @brief  Generate an ephemeral key pair for the given algorithm.
 *         For CAL_ALG_ECDSA_P256: generates an ECDSA-P256 keypair usable
 *         for both signing (ECDSA) and key exchange (ECDH).
 * @param  alg       Algorithm selector
 * @param  kp_out    Output keypair (public + private)
 * @retval CAL_OK / CAL_ERR_CRYPTO / CAL_ERR_NOT_SUPPORTED
 */
cal_result_t cal_keygen(cal_algorithm_t alg, cal_keypair_t *kp_out);

/* ============================================================================
 * DIGITAL SIGNATURE
 * ============================================================================
 */

/**
 * @brief  Sign a message. Internally computes SHA-256(msg) then ECDSA-signs.
 * @param  alg      Algorithm (CAL_ALG_ECDSA_P256)
 * @param  priv     Raw private key bytes
 * @param  priv_len Private key length (32 for P-256)
 * @param  msg      Message to sign (NOT a pre-hash)
 * @param  msg_len  Message length in bytes
 * @param  sig_out  Output signature (DER-encoded for ECDSA)
 * @retval CAL_OK / CAL_ERR_CRYPTO / CAL_ERR_NOT_SUPPORTED
 */
cal_result_t cal_sign(cal_algorithm_t     alg,
                      const uint8_t      *priv,     uint16_t priv_len,
                      const uint8_t      *msg,      uint16_t msg_len,
                      cal_signature_t    *sig_out);

/**
 * @brief  Verify a signature. Internally computes SHA-256(msg).
 * @param  alg     Algorithm
 * @param  pub     Public key (from certificate or raw)
 * @param  msg     Original message (NOT a pre-hash)
 * @param  msg_len Message length
 * @param  sig     Signature to verify
 * @retval CAL_OK on success, CAL_ERR_VERIFY_FAILED on mismatch,
 *         CAL_ERR_CRYPTO on other errors
 */
cal_result_t cal_verify(cal_algorithm_t        alg,
                        const cal_pubkey_t    *pub,
                        const uint8_t         *msg,     uint16_t msg_len,
                        const cal_signature_t *sig);

/* ============================================================================
 * KEY EXCHANGE
 * ============================================================================
 */

/**
 * @brief  Compute ECDH shared secret (X-coordinate of scalar multiplication).
 *         For ECDH: secret = [priv] * peer_pub_point  (X-coordinate only)
 * @param  priv       Our private key scalar (32 bytes for P-256)
 * @param  priv_len   Private key length
 * @param  peer_pub   Peer's public key (uncompressed, 65 bytes for P-256)
 * @param  secret_out Output buffer, must be >= CAL_ECDH_SHARED_SECRET_SIZE
 * @param  secret_len Actual output length
 * @retval CAL_OK / CAL_ERR_CRYPTO
 */
cal_result_t cal_ecdh_shared_secret(const uint8_t     *priv,     uint16_t priv_len,
                                    const cal_pubkey_t *peer_pub,
                                    uint8_t            *secret_out,
                                    uint16_t           *secret_len);

/* ============================================================================
 * KEY DERIVATION
 * ============================================================================
 */

/**
 * @brief  HKDF-SHA256: Extract-then-Expand (RFC 5869).
 * @param  ikm      Input Key Material (e.g. ECDH shared secret)
 * @param  ikm_len  IKM length
 * @param  salt     Optional salt (NULL = all-zeros)
 * @param  salt_len Salt length (0 if NULL)
 * @param  info     Context-specific label
 * @param  info_len Info length
 * @param  okm_out  Output Key Material
 * @param  okm_len  Desired output length (<= CAL_HKDF_MAX_OKM)
 * @retval CAL_OK / CAL_ERR_CRYPTO / CAL_ERR_INVALID_PARAM
 */
cal_result_t cal_hkdf(const uint8_t *ikm,  uint16_t ikm_len,
                      const uint8_t *salt, uint16_t salt_len,
                      const uint8_t *info, uint16_t info_len,
                      uint8_t       *okm_out, uint16_t okm_len);

/**
 * @brief  HMAC-SHA256.
 * @param  key     HMAC key
 * @param  key_len Key length
 * @param  msg     Message
 * @param  msg_len Message length
 * @param  mac_out 32-byte output MAC
 * @retval CAL_OK / CAL_ERR_CRYPTO
 */
cal_result_t cal_hmac_sha256(const uint8_t *key,  uint16_t key_len,
                              const uint8_t *msg,  uint16_t msg_len,
                              uint8_t        mac_out[CAL_HMAC_SHA256_SIZE]);

/* ============================================================================
 * X.509 CERTIFICATE
 * ============================================================================
 */

/**
 * @brief  Verify a DER-encoded X.509 certificate against a CA certificate
 *         and extract the subject public key.
 *
 *         Validation checks:
 *           - Signature verification (ECDSA-P256 with CA public key)
 *           - Validity period (NotBefore / NotAfter) — requires time source
 *             Set MBEDTLS_HAVE_TIME_DATE in mbedtls_config.h if available.
 *           - Basic Constraints: CA:FALSE on leaf cert
 *
 * @param  cert_der     DER-encoded leaf certificate
 * @param  cert_len     Certificate length
 * @param  ca_cert_der  DER-encoded CA certificate
 * @param  ca_len       CA certificate length
 * @param  pub_key_out  Extracted subject public key (caller-allocated)
 * @retval CAL_OK on success, CAL_ERR_VERIFY_FAILED if chain invalid,
 *         CAL_ERR_CRYPTO on parse errors
 */
cal_result_t cal_cert_verify_chain(const uint8_t *cert_der, uint16_t cert_len,
                                   const uint8_t *ca_cert_der, uint16_t ca_len,
                                   cal_pubkey_t  *pub_key_out);

/* ============================================================================
 * SYMMETRIC ENCRYPTION (AES-256-GCM)
 * ============================================================================
 */

/**
 * @brief  AES-256-GCM authenticated encryption (HW-accelerated via CRYP).
 * @param  key          32-byte AES key
 * @param  iv           12-byte IV/nonce (must be unique per (key, message) pair)
 * @param  aad          Additional authenticated data (may be NULL)
 * @param  aad_len      AAD length (0 if NULL)
 * @param  plaintext    Input plaintext
 * @param  pt_len       Plaintext length
 * @param  ct_out       Output ciphertext buffer (same length as plaintext)
 * @param  tag_out      16-byte authentication tag output
 * @retval CAL_OK / CAL_ERR_CRYPTO
 */
cal_result_t cal_aes256gcm_encrypt(const uint8_t  key[CAL_AES256_KEY_SIZE],
                                   const uint8_t  iv[CAL_AES_GCM_IV_SIZE],
                                   const uint8_t *aad,      uint16_t aad_len,
                                   const uint8_t *plaintext, uint16_t pt_len,
                                   uint8_t       *ct_out,
                                   uint8_t        tag_out[CAL_AES_GCM_TAG_SIZE]);

/**
 * @brief  AES-256-GCM authenticated decryption (HW-accelerated via CRYP).
 * @param  key          32-byte AES key
 * @param  iv           12-byte IV/nonce
 * @param  aad          Additional authenticated data
 * @param  aad_len      AAD length
 * @param  ciphertext   Input ciphertext
 * @param  ct_len       Ciphertext length
 * @param  tag          16-byte authentication tag to verify
 * @param  pt_out       Decrypted output buffer (same length as ciphertext)
 * @retval CAL_OK on success, CAL_ERR_VERIFY_FAILED if tag mismatch (tampering!)
 */
cal_result_t cal_aes256gcm_decrypt(const uint8_t  key[CAL_AES256_KEY_SIZE],
                                   const uint8_t  iv[CAL_AES_GCM_IV_SIZE],
                                   const uint8_t *aad,        uint16_t aad_len,
                                   const uint8_t *ciphertext, uint16_t ct_len,
                                   const uint8_t  tag[CAL_AES_GCM_TAG_SIZE],
                                   uint8_t       *pt_out);

#ifdef __cplusplus
}
#endif

#endif /* CAL_API_H */
