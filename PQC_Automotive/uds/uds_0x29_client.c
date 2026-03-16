/**
 ******************************************************************************
 * @file    uds_0x29_client.c
 * @brief   UDS 0x29 PKI APCE — VCI Client Implementation
 *
 * Authentication sequence from the client perspective:
 *
 * build_vcu():
 *   → Encodes [0x29][0x01][commCfg][certLen][cert][0x00][algInd]
 *
 * process_vcu_response():
 *   1. Decode [0x69][0x01] → save challenge_server + eph_pub_server into ctx
 *   2. Generate client ephemeral ECDH keypair (saved in ctx.eph_key_client)
 *   3. Build proof-of-ownership token:
 *        auth_token = challenge_server || eph_pub_client_bytes
 *      (SHA-256 computed inside cal_sign)
 *   4. ECDSA-sign with long-term private key → DER signature
 *   5. Encode [0x29][0x03][algInd][proofLen][proof][challEchoLen][echo][keyLen][key]
 *
 * process_pown_response():
 *   1. Decode [0x69][0x03] → extract sessionKeyInfo (32B HMAC)
 *   2. Compute ECDH shared secret: ECDH(ctx.eph_key_client.priv, ctx.eph_pub_server)
 *   3. Derive session key: HKDF(shared_secret, salt=challenge_server, info=label)
 *   4. Compute expected sessionKeyInfo locally and compare (constant-time)
 *   5. If match → AUTHENTICATED
 *
 * @author  Ghaith Ben Brahim
 * @date    2026-03-15
 ******************************************************************************
 */

#include "uds_0x29_client.h"
#include "uds_0x29_codec.h"
#include "cal/cal_api.h"

#include <string.h>

/* ============================================================================
 * PRIVATE CONSTANTS — must match server exactly
 * ============================================================================
 */
static const uint8_t k_hkdf_info[]  = "UDS-0x29-SESSION-KEY";
static const uint8_t k_hmac_label[] = "ECU-SESSION-PROOF";

/* Saved config */
static uds_cli_config_t s_cli_cfg;

/* ============================================================================
 * PRIVATE: session key derivation (identical to server side)
 * ============================================================================
 */

static cal_result_t client_derive_session_key(
    const uint8_t *shared_secret,
    const uint8_t  challenge_server[CAL_CHALLENGE_SIZE],
    uint8_t        session_key_out[CAL_AES256_KEY_SIZE])
{
    return cal_hkdf(shared_secret,    CAL_ECDH_SHARED_SECRET_SIZE,
                    challenge_server, CAL_CHALLENGE_SIZE,
                    k_hkdf_info,      (uint16_t)(sizeof(k_hkdf_info) - 1U),
                    session_key_out,  CAL_AES256_KEY_SIZE);
}

static cal_result_t client_expected_session_info(
    const uint8_t session_key[CAL_AES256_KEY_SIZE],
    const uint8_t challenge_server[CAL_CHALLENGE_SIZE],
    uint8_t       out[CAL_HMAC_SHA256_SIZE])
{
    uint8_t  hmac_msg[sizeof(k_hmac_label) - 1U + CAL_CHALLENGE_SIZE];
    uint16_t label_len = (uint16_t)(sizeof(k_hmac_label) - 1U);
    memcpy(hmac_msg, k_hmac_label, label_len);
    memcpy(&hmac_msg[label_len], challenge_server, CAL_CHALLENGE_SIZE);

    return cal_hmac_sha256(session_key, CAL_AES256_KEY_SIZE,
                           hmac_msg, (uint16_t)sizeof(hmac_msg),
                           out);
}

/* ============================================================================
 * PUBLIC API
 * ============================================================================
 */

uds_result_t uds_0x29_client_init(uds_cli_ctx_t          *ctx,
                                   const uds_cli_config_t *cfg)
{
    if (ctx == NULL || cfg == NULL)   return UDS_ERR_INVALID_MSG;
    if (cfg->cert_der == NULL)        return UDS_ERR_INVALID_MSG;
    if (cfg->priv_key == NULL)        return UDS_ERR_INVALID_MSG;

    memset(ctx, 0, sizeof(uds_cli_ctx_t));
    ctx->state = UDS_CLI_STATE_IDLE;
    s_cli_cfg  = *cfg;
    return UDS_OK;
}

void uds_0x29_client_reset(uds_cli_ctx_t *ctx)
{
    if (ctx == NULL) return;
    /* Zero all ephemeral key material */
    memset(&ctx->eph_key_client,   0, sizeof(ctx->eph_key_client));
    memset(&ctx->eph_pub_server,   0, sizeof(ctx->eph_pub_server));
    memset(ctx->challenge_server,  0, sizeof(ctx->challenge_server));
    memset(ctx->session_key,       0, sizeof(ctx->session_key));
    ctx->state         = UDS_CLI_STATE_IDLE;
    ctx->session_valid = false;
}

/* --------------------------------------------------------------------------
 * STEP 1: Build and return the VCU request payload
 * -------------------------------------------------------------------------- */

uds_result_t uds_0x29_client_build_vcu(uds_cli_ctx_t  *ctx,
                                        uint8_t        *tx_buf,
                                        uint16_t       *tx_len,
                                        uint16_t        tx_buf_size)
{
    if (ctx == NULL || tx_buf == NULL || tx_len == NULL) return UDS_ERR_INVALID_MSG;

    *tx_len = 0U;

    if (ctx->state != UDS_CLI_STATE_IDLE) return UDS_ERR_WRONG_STATE;

    uint16_t len = uds_0x29_encode_vcu_request(
        tx_buf, tx_buf_size,
        UDS_COMM_CFG_SESSION_KEY_REQUEST,   /* bit 0 = request session key info */
        s_cli_cfg.cert_der, s_cli_cfg.cert_len,
        NULL, 0U,                            /* no optional client challenge     */
        cal_get_alg_indicator());

    if (len == 0U) return UDS_ERR_BUFFER_OVERFLOW;

    *tx_len    = len;
    ctx->state = UDS_CLI_STATE_VCU_SENT;
    return UDS_OK;
}

/* --------------------------------------------------------------------------
 * STEP 2: Parse VCU response → produce POWN request
 * -------------------------------------------------------------------------- */

uds_result_t uds_0x29_client_process_vcu_response(uds_cli_ctx_t  *ctx,
                                                    const uint8_t  *rx_buf,
                                                    uint16_t        rx_len,
                                                    uint8_t        *tx_buf,
                                                    uint16_t       *tx_len,
                                                    uint16_t        tx_buf_size)
{
    if (ctx == NULL || rx_buf == NULL || tx_buf == NULL || tx_len == NULL) {
        return UDS_ERR_INVALID_MSG;
    }

    *tx_len = 0U;

    if (ctx->state != UDS_CLI_STATE_VCU_SENT) return UDS_ERR_WRONG_STATE;

    /* 1. Decode VCU response */
    uds_vcu_response_t rsp = {0};
    if (uds_0x29_decode_vcu_response(rx_buf, rx_len, &rsp) != UDS_OK) {
        ctx->state = UDS_CLI_STATE_FAILED;
        return UDS_ERR_INVALID_MSG;
    }
    if (rsp.challenge_server_len != CAL_CHALLENGE_SIZE) {
        ctx->state = UDS_CLI_STATE_FAILED;
        return UDS_ERR_INVALID_MSG;
    }
    if (rsp.eph_pubkey_server_len != CAL_ECDSA_PUBKEY_SIZE) {
        ctx->state = UDS_CLI_STATE_FAILED;
        return UDS_ERR_INVALID_MSG;
    }

    /* 2. Copy pointers-to-rx_buf data into ctx before rx_buf may be recycled */
    memcpy(ctx->challenge_server, rsp.challenge_server, CAL_CHALLENGE_SIZE);
    ctx->challenge_server_len = rsp.challenge_server_len;

    memcpy(ctx->eph_pub_server.bytes, rsp.eph_pubkey_server, rsp.eph_pubkey_server_len);
    ctx->eph_pub_server.length = rsp.eph_pubkey_server_len;
    ctx->eph_pub_server.alg    = CAL_ALG_ECDSA_P256;

    /* 3. Generate our ephemeral ECDH keypair (private stays in ctx for step 3) */
    cal_result_t cal_ret = cal_keygen(CAL_ALG_ECDSA_P256, &ctx->eph_key_client);
    if (cal_ret != CAL_OK) {
        ctx->state = UDS_CLI_STATE_FAILED;
        return UDS_ERR_CRYPTO_FAIL;
    }

    /* 4. Build proof-of-ownership token:
     *       auth_token = challenge_server (32B) || eph_pub_client (65B)
     *    The server reconstructs this token and verifies our ECDSA signature.
     */
    uint8_t auth_token[CAL_CHALLENGE_SIZE + CAL_ECDSA_PUBKEY_SIZE];
    memcpy(auth_token, ctx->challenge_server, CAL_CHALLENGE_SIZE);
    memcpy(&auth_token[CAL_CHALLENGE_SIZE],
           ctx->eph_key_client.pub.bytes,
           ctx->eph_key_client.pub.length);

    /* 5. Sign with our long-term ECDSA private key */
    cal_signature_t sig = {0};
    cal_ret = cal_sign(CAL_ALG_ECDSA_P256,
                       s_cli_cfg.priv_key,  s_cli_cfg.priv_key_len,
                       auth_token,          (uint16_t)sizeof(auth_token),
                       &sig);
    if (cal_ret != CAL_OK) {
        ctx->state = UDS_CLI_STATE_FAILED;
        return UDS_ERR_CRYPTO_FAIL;
    }

    /* 6. Encode POWN request */
    uint16_t len = uds_0x29_encode_pown_request(
        tx_buf, tx_buf_size,
        cal_get_alg_indicator(),
        sig.bytes, sig.length,
        ctx->challenge_server, (uint8_t)CAL_CHALLENGE_SIZE,   /* echo challenge  */
        &ctx->eph_key_client.pub);

    if (len == 0U) {
        ctx->state = UDS_CLI_STATE_FAILED;
        return UDS_ERR_BUFFER_OVERFLOW;
    }

    *tx_len    = len;
    ctx->state = UDS_CLI_STATE_POWN_SENT;
    return UDS_OK;
}

/* --------------------------------------------------------------------------
 * STEP 3: Parse POWN response — derive key and verify server proof
 * -------------------------------------------------------------------------- */

uds_result_t uds_0x29_client_process_pown_response(uds_cli_ctx_t  *ctx,
                                                     const uint8_t  *rx_buf,
                                                     uint16_t        rx_len)
{
    if (ctx == NULL || rx_buf == NULL) return UDS_ERR_INVALID_MSG;

    if (ctx->state != UDS_CLI_STATE_POWN_SENT) return UDS_ERR_WRONG_STATE;

    /* 1. Validate POWN response header */
    if (rx_len < UDS_POWN_RSP_TOTAL_LEN)                      { goto auth_fail; }
    if (rx_buf[0] != UDS_SID_AUTH_RESPONSE)                    { goto auth_fail; }
    if (rx_buf[1] != UDS_0x29_SF_PROOF_OF_OWNERSHIP)           { goto auth_fail; }
    if (rx_buf[2] != (uint8_t)UDS_POWN_RSP_SESSION_INFO_LEN)  { goto auth_fail; }

    const uint8_t *received_info = &rx_buf[3];

    /* 2. Compute ECDH shared secret using our ephemeral private key + server's ephemeral pubkey
     *    Both stored in ctx — no statics, no externs needed.
     */
    uint8_t  shared_secret[CAL_ECDH_SHARED_SECRET_SIZE];
    uint16_t shared_len = 0U;

    cal_result_t cal_ret = cal_ecdh_shared_secret(
        ctx->eph_key_client.priv,
        ctx->eph_key_client.priv_len,
        &ctx->eph_pub_server,             /* saved in step 2 */
        shared_secret, &shared_len);

    /* Immediately zero our ephemeral private key */
    memset(ctx->eph_key_client.priv, 0, sizeof(ctx->eph_key_client.priv));

    if (cal_ret != CAL_OK) {
        memset(shared_secret, 0, sizeof(shared_secret));
        goto auth_fail;
    }

    /* 3. Derive session key: same HKDF as server */
    cal_ret = client_derive_session_key(shared_secret, ctx->challenge_server,
                                         ctx->session_key);
    memset(shared_secret, 0, sizeof(shared_secret));

    if (cal_ret != CAL_OK) goto auth_fail;

    /* 4. Compute expected sessionKeyInfo and compare (constant-time) */
    uint8_t expected_info[CAL_HMAC_SHA256_SIZE];
    cal_ret = client_expected_session_info(ctx->session_key, ctx->challenge_server,
                                            expected_info);
    if (cal_ret != CAL_OK) goto auth_fail;

    uint8_t diff = 0U;
    for (uint8_t i = 0U; i < CAL_HMAC_SHA256_SIZE; i++) {
        diff |= (received_info[i] ^ expected_info[i]);
    }

    if (diff != 0U) {
        /* Server sent different HMAC — session keys do not match */
        goto auth_fail;
    }

    ctx->session_valid = true;
    ctx->state         = UDS_CLI_STATE_AUTHENTICATED;
    return UDS_OK;

auth_fail:
    memset(ctx->session_key, 0, sizeof(ctx->session_key));
    ctx->state = UDS_CLI_STATE_FAILED;
    return UDS_ERR_CRYPTO_FAIL;
}

uds_cli_state_t uds_0x29_client_get_state(const uds_cli_ctx_t *ctx)
{
    return (ctx != NULL) ? ctx->state : UDS_CLI_STATE_IDLE;
}

const uint8_t *uds_0x29_client_get_session_key(const uds_cli_ctx_t *ctx)
{
    if (ctx == NULL || !ctx->session_valid) return NULL;
    return ctx->session_key;
}
