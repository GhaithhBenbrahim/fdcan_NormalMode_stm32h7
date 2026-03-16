/**
 ******************************************************************************
 * @file    uds_0x29_server.h
 * @brief   UDS 0x29 PKI APCE — ECU Server Side
 *
 * Implements the ECU (server) role of ISO 14229-1:2020 §10.4 PKI APCE
 * Unidirectional authentication:
 *
 *   1. Receive 0x29/0x01 (VCU) — verify client cert, generate challenge + ECDH key
 *   2. Send 0x69/0x01          — challenge + server ephemeral ECDH pubkey
 *   3. Receive 0x29/0x03 (POWN)— verify ECDSA proof-of-ownership
 *   4. Derive session key       — HKDF(ECDH_secret)
 *   5. Send 0x69/0x03          — HMAC session key proof (sessionKeyInfo)
 *
 * RTOS-ready: all functions are non-blocking. Plug into a task via
 * the callback or poll uds_0x29_server_process() from your ISO-TP RX handler.
 *
 * @author  Ghaith Ben Brahim
 * @date    2026-03-15
 ******************************************************************************
 */
#ifndef UDS_0x29_SERVER_H
#define UDS_0x29_SERVER_H

#include "uds_types.h"
#include "cal/cal_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * SERVER AUTHENTICATION STATE MACHINE
 * ============================================================================
 */

typedef enum {
    UDS_SRV_STATE_IDLE              = 0,  /**< No active auth, ready for VCU */
    UDS_SRV_STATE_VCU_PROCESSING    = 1,  /**< Async cert verify in progress */
    UDS_SRV_STATE_CHALLENGE_SENT    = 2,  /**< 0x01 response sent, await 0x03 */
    UDS_SRV_STATE_POWN_PROCESSING   = 3,  /**< Async signature verify in progress */
    UDS_SRV_STATE_AUTHENTICATED     = 4,  /**< Auth complete, session active   */
    UDS_SRV_STATE_FAILED            = 5,  /**< Terminal failure — reset needed */
} uds_srv_state_t;

/* ============================================================================
 * SERVER CONTEXT — one per ECU CAN channel
 * Holds all intermediate values across the two-message exchange.
 * ============================================================================
 */
typedef struct {
    uds_srv_state_t  state;

    /* Saved during VCU processing, used when POWN arrives */
    uint8_t          challenge_server[CAL_CHALLENGE_SIZE];  /**< 32 B nonce  */
    cal_keypair_t    eph_key_server;                        /**< Ephemeral ECDH keypair */
    cal_pubkey_t     client_pubkey;                         /**< From cert — used to verify POWN */
    
    /* Async state variables */
    uds_vcu_request_t  vcu_req;
    uds_pown_request_t pown_req;

    /* Derived after POWN verification */
    uint8_t          session_key[CAL_AES256_KEY_SIZE];      /**< AES-256 session key */
    uint8_t          session_key_info[CAL_HMAC_SHA256_SIZE];/**< HMAC proof sent to client */
    bool             session_valid;

    /* Debug / diagnostics */
    uint32_t         auth_attempt_count;
} uds_srv_ctx_t;

/* ============================================================================
 * CONFIGURATION — provide before calling uds_0x29_server_init()
 * ============================================================================
 */
typedef struct {
    const uint8_t  *ca_cert_der;        /**< DER-encoded CA certificate (const, in flash) */
    uint16_t        ca_cert_len;
} uds_srv_config_t;

/* ============================================================================
 * API
 * ============================================================================
 */

/**
 * @brief  Initialise server context. Call once before processing any messages.
 * @param  ctx    Server context (caller-allocated, statically or on task stack)
 * @param  cfg    CA certificate configuration
 * @retval UDS_OK or UDS_ERR_INVALID_MSG
 */
uds_result_t uds_0x29_server_init(uds_srv_ctx_t        *ctx,
                                   const uds_srv_config_t *cfg);

/**
 * @brief  Reset server state to IDLE (e.g. on timeout, session end, error).
 *         Zeroes all cryptographic material in the context.
 * @param  ctx  Server context
 */
void uds_0x29_server_reset(uds_srv_ctx_t *ctx);

/**
 * @brief  Process an incoming UDS 0x29 message (server/ECU role).
 *
 *         Call this from your ISO-TP RX callback whenever a complete UDS
 *         message is received with SID == 0x29.
 *
 *         On return:
 *           - UDS_OK:      *tx_len > 0, tx_buf contains the response to send.
 *           - UDS_PENDING: no response ready (should not occur in sync flow).
 *           - Negative:    *tx_len contains a NRC response.
 *
 * @param  ctx      Server context
 * @param  rx_buf   Raw ISO-TP payload (retained until function returns)
 * @param  rx_len   ISO-TP payload length
 * @param  tx_buf   Response buffer (caller-provided, >= 256 bytes)
 * @param  tx_len   [out] bytes written to tx_buf (0 = no response)
 * @retval UDS_OK / negative on error
 */
uds_result_t uds_0x29_server_process(uds_srv_ctx_t  *ctx,
                                      const uint8_t  *rx_buf,  uint16_t  rx_len,
                                      uint8_t        *tx_buf,  uint16_t *tx_len);

/**
 * @brief  Get the current server state.
 */
uds_srv_state_t uds_0x29_server_get_state(const uds_srv_ctx_t *ctx);

/**
 * @brief  Return the derived session key (valid only in AUTHENTICATED state).
 * @retval Pointer to 32-byte key, or NULL if not authenticated.
 */
const uint8_t *uds_0x29_server_get_session_key(const uds_srv_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* UDS_0x29_SERVER_H */
