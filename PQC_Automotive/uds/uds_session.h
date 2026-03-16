/**
 ******************************************************************************
 * @file    uds_session.h
 * @brief   UDS Session Encryption — AES-256-GCM (post-authentication)
 *
 * After UDS 0x29 authentication completes, all subsequent diagnostic
 * messages are encrypted/decrypted with AES-256-GCM using the derived
 * session key.
 *
 * IV management: 96-bit IV = 32-bit counter (big-endian) || 64-bit zero-pad
 * The counter is incremented per message. ECU TX and VCI TX use separate
 * counters so there is never IV reuse for the same key direction.
 *
 * AAD (Additional Authenticated Data): UDS SID + SubFunction bytes
 * This authenticates the message type even without encrypting it.
 *
 * @author  Ghaith Ben Brahim
 * @date    2026-03-15
 ******************************************************************************
 */
#ifndef UDS_SESSION_H
#define UDS_SESSION_H

#include "uds_types.h"
#include "cal/cal_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * SESSION CONTEXT
 * ============================================================================
 */
typedef struct {
    uint8_t  key[CAL_AES256_KEY_SIZE];   /**< AES-256 session key (from 0x29)  */
    uint32_t tx_counter;                  /**< Our TX message counter (IV base) */
    uint32_t rx_counter;                  /**< Expected RX counter from peer     */
    bool     active;                      /**< True after key installed          */
} uds_session_ctx_t;

/*
 * Encrypted message wire format (prepended to each UDS payload):
 *
 *   [IV_counter 4B big-endian] [TAG 16B] [ciphertext N B]
 *
 * Total overhead per message: 20 bytes.
 */
#define UDS_SESSION_OVERHEAD    (4U + CAL_AES_GCM_TAG_SIZE)  /* 20 bytes */

/* ============================================================================
 * API
 * ============================================================================
 */

/**
 * @brief  Install a session key obtained from uds_0x29_server_get_session_key()
 *         or uds_0x29_client_get_session_key(). Resets counters.
 */
void uds_session_install_key(uds_session_ctx_t *ctx,
                              const uint8_t      key[CAL_AES256_KEY_SIZE]);

/**
 * @brief  Reset session (e.g. on deAuthenticate). Zeroes key and counters.
 */
void uds_session_reset(uds_session_ctx_t *ctx);

/**
 * @brief  Encrypt a plaintext UDS payload before sending.
 *
 *         Output format: [counter(4B)] [tag(16B)] [ciphertext]
 *         AAD = first aad_len bytes of plaintext (e.g. SID + SubFunction).
 *
 * @param  ctx         Session context
 * @param  plaintext   UDS payload to encrypt
 * @param  pt_len      Payload length
 * @param  aad_len     Number of leading bytes to treat as AAD (typically 2)
 * @param  out_buf     Output buffer (must hold pt_len + UDS_SESSION_OVERHEAD)
 * @param  out_len     [out] bytes written
 * @retval UDS_OK / UDS_ERR_CRYPTO_FAIL / UDS_ERR_BUFFER_OVERFLOW
 */
uds_result_t uds_session_encrypt(uds_session_ctx_t *ctx,
                                  const uint8_t     *plaintext, uint16_t pt_len,
                                  uint8_t            aad_len,
                                  uint8_t           *out_buf,   uint16_t *out_len,
                                  uint16_t           out_buf_size);

/**
 * @brief  Decrypt and authenticate a received encrypted payload.
 *
 *         Input format: [counter(4B)] [tag(16B)] [ciphertext]
 *         AAD = first aad_len bytes of decrypted plaintext.
 *
 * @param  ctx         Session context
 * @param  in_buf      Received encrypted payload
 * @param  in_len      Payload length (must be > UDS_SESSION_OVERHEAD)
 * @param  aad_len     Number of leading plaintext bytes treated as AAD
 * @param  out_buf     Decrypted output (must hold in_len - UDS_SESSION_OVERHEAD)
 * @param  out_len     [out] bytes written
 * @retval UDS_OK on success, UDS_ERR_CRYPTO_FAIL on tag mismatch or replay
 */
uds_result_t uds_session_decrypt(uds_session_ctx_t *ctx,
                                  const uint8_t     *in_buf,  uint16_t in_len,
                                  uint8_t            aad_len,
                                  uint8_t           *out_buf, uint16_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* UDS_SESSION_H */
