/**
 ******************************************************************************
 * @file    uds_0x29_client.h
 * @brief   UDS 0x29 PKI APCE — VCI Client Side
 *
 * Implements the VCI / Tester (client) role:
 *   1. Send 0x29/0x01 (VCU): cert + algorithm indicator
 *   2. Receive 0x69/0x01:    parse challenge + server ephemeral pubkey
 *   3. Sign proof-of-ownership, generate ephemeral ECDH key
 *   4. Send 0x29/0x03 (POWN): signature + challenge echo + eph pubkey
 *   5. Receive 0x69/0x03:    verify sessionKeyInfo, derive same session key
 *
 * @author  Ghaith Ben Brahim
 * @date    2026-03-15
 ******************************************************************************
 */
#ifndef UDS_0x29_CLIENT_H
#define UDS_0x29_CLIENT_H

#include "uds_types.h"
#include "cal/cal_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CLIENT STATE MACHINE
 * ============================================================================
 */
typedef enum {
    UDS_CLI_STATE_IDLE           = 0,
    UDS_CLI_STATE_VCU_SENT       = 1, /**< Waiting for VCU response   */
    UDS_CLI_STATE_POWN_SENT      = 2, /**< Waiting for POWN response  */
    UDS_CLI_STATE_AUTHENTICATED  = 3, /**< Session key valid           */
    UDS_CLI_STATE_FAILED         = 4,
} uds_cli_state_t;

/* ============================================================================
 * CLIENT CONTEXT
 * ============================================================================
 */
typedef struct {
    uds_cli_state_t  state;

    /* Client ephemeral ECDH keypair generated before POWN */
    cal_keypair_t    eph_key_client;

    /* Server ephemeral pubkey — saved from VCU response, used for ECDH in POWN */
    cal_pubkey_t     eph_pub_server;

    /* Server challenge received in VCU response — echoed in POWN */
    uint8_t          challenge_server[CAL_CHALLENGE_SIZE];
    uint8_t          challenge_server_len;

    /* Derived session key */
    uint8_t          session_key[CAL_AES256_KEY_SIZE];
    bool             session_valid;
} uds_cli_ctx_t;

/* ============================================================================
 * CONFIGURATION
 * ============================================================================
 */
typedef struct {
    const uint8_t  *cert_der;           /**< Client DER certificate (in flash)  */
    uint16_t        cert_len;
    const uint8_t  *priv_key;           /**< Client ECDSA private key (32B)      */
    uint16_t        priv_key_len;
} uds_cli_config_t;

/* ============================================================================
 * API
 * ============================================================================
 */

/**
 * @brief  Initialise client context.
 */
uds_result_t uds_0x29_client_init(uds_cli_ctx_t          *ctx,
                                   const uds_cli_config_t *cfg);

/**
 * @brief  Reset client context and zero all key material.
 */
void uds_0x29_client_reset(uds_cli_ctx_t *ctx);

/**
 * @brief  Step 1: Build VCU request (0x29 0x01) to send via ISO-TP.
 *         Call this to start authentication. tx_buf receives the fully encoded
 *         request ready for isotp_send().
 * @param  ctx     Client context
 * @param  tx_buf  Output buffer for the ISO-TP payload
 * @param  tx_len  [out] bytes written
 * @retval UDS_OK or error
 */
uds_result_t uds_0x29_client_build_vcu(uds_cli_ctx_t  *ctx,
                                        uint8_t        *tx_buf,
                                        uint16_t       *tx_len,
                                        uint16_t        tx_buf_size);

/**
 * @brief  Step 2: Process VCU response (0x69 0x01) and build POWN request.
 *         Call this from your ISO-TP RX handler when the response arrives.
 *         - Saves server challenge
 *         - Generates client ephemeral ECDH keypair
 *         - Signs proof-of-ownership
 *         - Encodes POWN request into tx_buf
 * @param  ctx     Client context
 * @param  rx_buf  ISO-TP payload of server's VCU response
 * @param  rx_len  Response length
 * @param  tx_buf  Output buffer for POWN request
 * @param  tx_len  [out] bytes written
 * @retval UDS_OK or error
 */
uds_result_t uds_0x29_client_process_vcu_response(uds_cli_ctx_t  *ctx,
                                                    const uint8_t  *rx_buf,
                                                    uint16_t        rx_len,
                                                    uint8_t        *tx_buf,
                                                    uint16_t       *tx_len,
                                                    uint16_t        tx_buf_size);

/**
 * @brief  Step 3: Process POWN response (0x69 0x03).
 *         - Derives session key (same HKDF as server)
 *         - Verifies sessionKeyInfo HMAC from server
 *         - Sets state to AUTHENTICATED on success
 * @param  ctx     Client context
 * @param  rx_buf  ISO-TP payload of server's POWN response
 * @param  rx_len  Response length
 * @retval UDS_OK if session key matches, UDS_ERR_CRYPTO_FAIL if mismatch
 */
uds_result_t uds_0x29_client_process_pown_response(uds_cli_ctx_t  *ctx,
                                                     const uint8_t  *rx_buf,
                                                     uint16_t        rx_len);

/**
 * @brief  Get current client state.
 */
uds_cli_state_t uds_0x29_client_get_state(const uds_cli_ctx_t *ctx);

/**
 * @brief  Return the derived session key (valid only in AUTHENTICATED state).
 */
const uint8_t *uds_0x29_client_get_session_key(const uds_cli_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* UDS_0x29_CLIENT_H */
