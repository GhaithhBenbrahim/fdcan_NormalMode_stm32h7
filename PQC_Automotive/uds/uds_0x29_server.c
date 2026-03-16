/**
 ******************************************************************************
 * @file    uds_0x29_server.c
 * @brief   UDS 0x29 PKI APCE — ECU Server Implementation
 *
 * Authentication flow (ISO 14229-1:2020 §10.4, Unidirectional):
 *
 * STEP 1 — Receive VCU (0x29 0x01):
 *   a) Decode request: cert, optional client challenge, alg indicator
 *   b) Verify certificate chain against CA cert → extract client public key
 *   c) Generate server challenge (32B random)
 *   d) Generate ephemeral ECDH key pair (private saved in ctx)
 *   e) Send VCU response: [0x69 0x01 | challenge_server | eph_pub_server]
 *   f) Transition to CHALLENGE_SENT
 *
 * STEP 2 — Receive POWN (0x29 0x03):
 *   a) Decode request: alg_ind, proof (ECDSA sig), challenge echo, eph_pub_client
 *   b) Validate challenge echo (must match saved challenge_server)
 *   c) Build proof-of-ownership token:
 *        auth_token = challenge_server || eph_pub_client_bytes
 *        (SHA-256 is computed inside cal_verify)
 *   d) Verify ECDSA signature: cal_verify(client_pubkey, auth_token, signature)
 *   e) Compute ECDH shared secret: ECDH(eph_priv_server, eph_pub_client)
 *   f) Derive session key via HKDF:
 *        IKM  = shared_secret (32B)
 *        Salt = challenge_server (32B)
 *        Info = "UDS-0x29-SESSION-KEY" (20B)
 *        OKM  = session_key (32B)
 *   g) Compute sessionKeyInfo (HMAC proof for client):
 *        sessionKeyInfo = HMAC-SHA256(session_key, "ECU-SESSION-PROOF" || challenge_server)
 *   h) Send POWN response: [0x69 0x03 | 32 | sessionKeyInfo]
 *   i) Transition to AUTHENTICATED
 *
 * @author  Ghaith Ben Brahim
 * @date    2026-03-15
 ******************************************************************************
 */

#include "uds_0x29_server.h"
#include "uds_0x29_codec.h"
#include "cal/cal_api.h"

#include <string.h>

/* ============================================================================
 * PRIVATE CONSTANTS
 * ============================================================================
 */

/** HKDF info label for session key derivation */
static const uint8_t k_hkdf_info[]  = "UDS-0x29-SESSION-KEY";
static const uint8_t k_hmac_label[] = "ECU-SESSION-PROOF";

/* TX buffer capacity for server responses (responses are small) */
#define SRV_TX_BUF_MIN   256U

/* ============================================================================
 * PRIVATE: session key derivation helpers
 * ============================================================================
 */

/**
 * @brief  Derive AES-256 session key from ECDH shared secret using HKDF-SHA256.
 *         IKM = shared_secret, Salt = challenge_server, Info = k_hkdf_info
 */
static cal_result_t derive_session_key(const uint8_t *shared_secret,
                                        const uint8_t  challenge_server[CAL_CHALLENGE_SIZE],
                                        uint8_t        session_key_out[CAL_AES256_KEY_SIZE])
{
    return cal_hkdf(shared_secret,      CAL_ECDH_SHARED_SECRET_SIZE,
                    challenge_server,   CAL_CHALLENGE_SIZE,
                    k_hkdf_info,        (uint16_t)(sizeof(k_hkdf_info) - 1U),
                    session_key_out,    CAL_AES256_KEY_SIZE);
}

/**
 * @brief  Compute sessionKeyInfo: HMAC-SHA256(session_key, label || challenge_server).
 *         This proves to the client that the ECU derived the correct session key.
 */
static cal_result_t compute_session_key_info(
    const uint8_t session_key[CAL_AES256_KEY_SIZE],
    const uint8_t challenge_server[CAL_CHALLENGE_SIZE],
    uint8_t       info_out[CAL_HMAC_SHA256_SIZE])
{
    /* Build HMAC message: label || challenge_server */
    uint8_t hmac_msg[sizeof(k_hmac_label) - 1U + CAL_CHALLENGE_SIZE];
    uint16_t label_len = (uint16_t)(sizeof(k_hmac_label) - 1U);

    memcpy(hmac_msg, k_hmac_label, label_len);
    memcpy(&hmac_msg[label_len], challenge_server, CAL_CHALLENGE_SIZE);

    return cal_hmac_sha256(session_key, CAL_AES256_KEY_SIZE,
                           hmac_msg, (uint16_t)sizeof(hmac_msg),
                           info_out);
}

/* ============================================================================
 * PRIVATE: process VCU (0x29 0x01)
 * ============================================================================
 */

static uds_result_t process_vcu(uds_srv_ctx_t  *ctx,
                                 const uds_srv_config_t *cfg,
                                 const uint8_t  *rx_buf, uint16_t rx_len,
                                 uint8_t        *tx_buf, uint16_t *tx_len)
{
    /* Only accept VCU from IDLE or VCU_PROCESSING state */
    if (ctx->state != UDS_SRV_STATE_IDLE && ctx->state != UDS_SRV_STATE_VCU_PROCESSING) {
        *tx_len = uds_0x29_encode_nrc(tx_buf, SRV_TX_BUF_MIN,
                                       UDS_SID_AUTHENTICATION,
                                       UDS_NRC_REQUEST_SEQUENCE_ERROR);
        return UDS_ERR_WRONG_STATE;
    }

    /* 1. If currently in IDLE, decode and start VCU processing */
    if (ctx->state == UDS_SRV_STATE_IDLE) {
        if (uds_0x29_decode_vcu_request(rx_buf, rx_len, &ctx->vcu_req) != UDS_OK) {
            *tx_len = uds_0x29_encode_nrc(tx_buf, SRV_TX_BUF_MIN,
                                           UDS_SID_AUTHENTICATION,
                                           UDS_NRC_CONDITIONS_NOT_CORRECT);
            return UDS_ERR_INVALID_MSG;
        }

        /* 2. Check algorithm indicator matches current backend */
        if (ctx->vcu_req.alg_indicator != cal_get_alg_indicator()) {
            *tx_len = uds_0x29_encode_nrc(tx_buf, SRV_TX_BUF_MIN,
                                           UDS_SID_AUTHENTICATION,
                                           UDS_NRC_REQUEST_OUT_OF_RANGE);
            return UDS_ERR_UNKNOWN_ALG;
        }

        /* Move to processing state and tell caller to send 0x78 Pending response */
        ctx->state = UDS_SRV_STATE_VCU_PROCESSING;
        *tx_len = uds_0x29_encode_nrc(tx_buf, SRV_TX_BUF_MIN,
                                       UDS_SID_AUTHENTICATION,
                                       UDS_NRC_RESPONSE_PENDING);
        return UDS_PENDING;
    }

    /* 3. Verify certificate chain → extract client public key */
    cal_result_t cal_ret = cal_cert_verify_chain(ctx->vcu_req.cert,        ctx->vcu_req.cert_len,
                                                  cfg->ca_cert_der, cfg->ca_cert_len,
                                                  &ctx->client_pubkey);
    if (cal_ret != CAL_OK) {
        *tx_len = uds_0x29_encode_nrc(tx_buf, SRV_TX_BUF_MIN,
                                       UDS_SID_AUTHENTICATION,
                                       UDS_NRC_INVALID_KEY);
        ctx->state = UDS_SRV_STATE_FAILED;
        return UDS_ERR_CERT_INVALID;
    }

    /* 4. Generate server challenge (32 random bytes) */
    cal_ret = cal_rng(ctx->challenge_server, CAL_CHALLENGE_SIZE);
    if (cal_ret != CAL_OK) {
        *tx_len = uds_0x29_encode_nrc(tx_buf, SRV_TX_BUF_MIN,
                                       UDS_SID_AUTHENTICATION,
                                       UDS_NRC_CONDITIONS_NOT_CORRECT);
        return UDS_ERR_CRYPTO_FAIL;
    }

    /* 5. Generate server ephemeral ECDH key pair (private key held in ctx) */
    cal_ret = cal_keygen(CAL_ALG_ECDSA_P256, &ctx->eph_key_server);
    if (cal_ret != CAL_OK) {
        *tx_len = uds_0x29_encode_nrc(tx_buf, SRV_TX_BUF_MIN,
                                       UDS_SID_AUTHENTICATION,
                                       UDS_NRC_CONDITIONS_NOT_CORRECT);
        return UDS_ERR_CRYPTO_FAIL;
    }

    /* 6. Encode and send VCU response */
    uint16_t rsp_len = uds_0x29_encode_vcu_response(tx_buf, SRV_TX_BUF_MIN,
                                                      ctx->challenge_server,
                                                      &ctx->eph_key_server.pub);
    if (rsp_len == 0U) {
        return UDS_ERR_BUFFER_OVERFLOW;
    }

    *tx_len    = rsp_len;
    ctx->state = UDS_SRV_STATE_CHALLENGE_SENT;

    return UDS_OK;
}

/* ============================================================================
 * PRIVATE: process POWN (0x29 0x03)
 * ============================================================================
 */

static uds_result_t process_pown(uds_srv_ctx_t  *ctx,
                                  const uint8_t  *rx_buf, uint16_t rx_len,
                                  uint8_t        *tx_buf, uint16_t *tx_len)
{
    /* Only accept POWN from CHALLENGE_SENT or POWN_PROCESSING state */
    if (ctx->state != UDS_SRV_STATE_CHALLENGE_SENT && ctx->state != UDS_SRV_STATE_POWN_PROCESSING) {
        *tx_len = uds_0x29_encode_nrc(tx_buf, SRV_TX_BUF_MIN,
                                       UDS_SID_AUTHENTICATION,
                                       UDS_NRC_REQUEST_SEQUENCE_ERROR);
        return UDS_ERR_WRONG_STATE;
    }

    /* 1. If currently in CHALLENGE_SENT, decode and start POWN processing */
    if (ctx->state == UDS_SRV_STATE_CHALLENGE_SENT) {
        if (uds_0x29_decode_pown_request(rx_buf, rx_len, &ctx->pown_req) != UDS_OK) {
            *tx_len = uds_0x29_encode_nrc(tx_buf, SRV_TX_BUF_MIN,
                                           UDS_SID_AUTHENTICATION,
                                           UDS_NRC_CONDITIONS_NOT_CORRECT);
            return UDS_ERR_INVALID_MSG;
        }

        /* 2. Validate algorithm indicator matches current backend */
        if (ctx->pown_req.alg_indicator != cal_get_alg_indicator()) {
            *tx_len = uds_0x29_encode_nrc(tx_buf, SRV_TX_BUF_MIN,
                                           UDS_SID_AUTHENTICATION,
                                           UDS_NRC_REQUEST_OUT_OF_RANGE);
            return UDS_ERR_UNKNOWN_ALG;
        }

        /* 3. Validate challenge echo (if present) — must match our saved challenge */
        if (ctx->pown_req.challenge_echo != NULL && ctx->pown_req.challenge_echo_len == CAL_CHALLENGE_SIZE) {
            if (memcmp(ctx->pown_req.challenge_echo, ctx->challenge_server, CAL_CHALLENGE_SIZE) != 0) {
                *tx_len = uds_0x29_encode_nrc(tx_buf, SRV_TX_BUF_MIN,
                                               UDS_SID_AUTHENTICATION,
                                               UDS_NRC_INVALID_KEY);
                ctx->state = UDS_SRV_STATE_FAILED;
                return UDS_ERR_CRYPTO_FAIL;
            }
        }

        /* 4. Validate ephemeral public key size */
        if (ctx->pown_req.eph_pubkey_client_len != CAL_ECDSA_PUBKEY_SIZE) {
            *tx_len = uds_0x29_encode_nrc(tx_buf, SRV_TX_BUF_MIN,
                                           UDS_SID_AUTHENTICATION,
                                           UDS_NRC_CONDITIONS_NOT_CORRECT);
            return UDS_ERR_INVALID_MSG;
        }

        /* Move to processing state and tell caller to send 0x78 Pending response */
        ctx->state = UDS_SRV_STATE_POWN_PROCESSING;
        *tx_len = uds_0x29_encode_nrc(tx_buf, SRV_TX_BUF_MIN,
                                       UDS_SID_AUTHENTICATION,
                                       UDS_NRC_RESPONSE_PENDING);
        return UDS_PENDING;
    }

    /* 5. Build the proof-of-ownership token that the client signed:
     *    auth_token = challenge_server (32B) || eph_pub_client_bytes (65B)
     *    cal_verify internally computes SHA-256(auth_token) before verifying.
     */
    uint8_t auth_token[CAL_CHALLENGE_SIZE + CAL_ECDSA_PUBKEY_SIZE];
    memcpy(auth_token,                      ctx->challenge_server,            CAL_CHALLENGE_SIZE);
    memcpy(&auth_token[CAL_CHALLENGE_SIZE], ctx->pown_req.eph_pubkey_client,  ctx->pown_req.eph_pubkey_client_len);

    /* 6. Verify ECDSA signature */
    cal_signature_t sig = {0};
    if (ctx->pown_req.proof_len > CAL_MAX_SIG_SIZE) {
        *tx_len = uds_0x29_encode_nrc(tx_buf, SRV_TX_BUF_MIN,
                                       UDS_SID_AUTHENTICATION,
                                       UDS_NRC_CONDITIONS_NOT_CORRECT);
        return UDS_ERR_INVALID_MSG;
    }
    memcpy(sig.bytes, ctx->pown_req.proof, ctx->pown_req.proof_len);
    sig.length = ctx->pown_req.proof_len;

    cal_result_t cal_ret = cal_verify(CAL_ALG_ECDSA_P256,
                                       &ctx->client_pubkey,
                                       auth_token, (uint16_t)sizeof(auth_token),
                                       &sig);
    if (cal_ret != CAL_OK) {
        *tx_len = uds_0x29_encode_nrc(tx_buf, SRV_TX_BUF_MIN,
                                       UDS_SID_AUTHENTICATION,
                                       UDS_NRC_INVALID_KEY);
        ctx->state = UDS_SRV_STATE_FAILED;
        return UDS_ERR_CRYPTO_FAIL;
    }

    /* 7. Compute ECDH shared secret using our ephemeral private key + client's ephemeral pub */
    cal_pubkey_t eph_client_pub = {0};
    memcpy(eph_client_pub.bytes, ctx->pown_req.eph_pubkey_client, ctx->pown_req.eph_pubkey_client_len);
    eph_client_pub.length = ctx->pown_req.eph_pubkey_client_len;
    eph_client_pub.alg    = CAL_ALG_ECDSA_P256;

    uint8_t  shared_secret[CAL_ECDH_SHARED_SECRET_SIZE];
    uint16_t shared_len = 0U;

    cal_ret = cal_ecdh_shared_secret(ctx->eph_key_server.priv,
                                      ctx->eph_key_server.priv_len,
                                      &eph_client_pub,
                                      shared_secret, &shared_len);
    if (cal_ret != CAL_OK) {
        *tx_len = uds_0x29_encode_nrc(tx_buf, SRV_TX_BUF_MIN,
                                       UDS_SID_AUTHENTICATION,
                                       UDS_NRC_CONDITIONS_NOT_CORRECT);
        ctx->state = UDS_SRV_STATE_FAILED;
        return UDS_ERR_CRYPTO_FAIL;
    }

    /* 8. Derive session key: HKDF(shared_secret, salt=challenge_server, info=label) */
    cal_ret = derive_session_key(shared_secret, ctx->challenge_server, ctx->session_key);

    /* Immediately zero the shared secret — not needed after key derivation */
    memset(shared_secret, 0, sizeof(shared_secret));

    if (cal_ret != CAL_OK) {
        *tx_len = uds_0x29_encode_nrc(tx_buf, SRV_TX_BUF_MIN,
                                       UDS_SID_AUTHENTICATION,
                                       UDS_NRC_CONDITIONS_NOT_CORRECT);
        ctx->state = UDS_SRV_STATE_FAILED;
        return UDS_ERR_CRYPTO_FAIL;
    }

    /* Also zero the ephemeral private key — not needed anymore */
    memset(ctx->eph_key_server.priv, 0, sizeof(ctx->eph_key_server.priv));

    /* 9. Compute sessionKeyInfo = HMAC(session_key, label || challenge_server)
     *    This is sent to the client so they can verify the server derived the right key.
     */
    cal_ret = compute_session_key_info(ctx->session_key,
                                        ctx->challenge_server,
                                        ctx->session_key_info);
    if (cal_ret != CAL_OK) {
        ctx->state = UDS_SRV_STATE_FAILED;
        return UDS_ERR_CRYPTO_FAIL;
    }

    /* 10. Encode POWN positive response */
    uint16_t rsp_len = uds_0x29_encode_pown_response(tx_buf, SRV_TX_BUF_MIN,
                                                       ctx->session_key_info);
    if (rsp_len == 0U) {
        return UDS_ERR_BUFFER_OVERFLOW;
    }

    *tx_len           = rsp_len;
    ctx->session_valid = true;
    ctx->state         = UDS_SRV_STATE_AUTHENTICATED;

    return UDS_OK;
}

/* ============================================================================
 * PUBLIC API
 * ============================================================================
 */

static uds_srv_config_t s_cfg;  /* saved config for use during VCU processing */

uds_result_t uds_0x29_server_init(uds_srv_ctx_t          *ctx,
                                   const uds_srv_config_t *cfg)
{
    if (ctx == NULL || cfg == NULL)            return UDS_ERR_INVALID_MSG;
    if (cfg->ca_cert_der == NULL)              return UDS_ERR_INVALID_MSG;
    if (cfg->ca_cert_len == 0U)                return UDS_ERR_INVALID_MSG;

    memset(ctx, 0, sizeof(uds_srv_ctx_t));
    ctx->state = UDS_SRV_STATE_IDLE;
    s_cfg      = *cfg;

    return UDS_OK;
}

void uds_0x29_server_reset(uds_srv_ctx_t *ctx)
{
    if (ctx == NULL) return;

    /* Zero all crypto material before resetting state */
    memset(ctx->challenge_server, 0, sizeof(ctx->challenge_server));
    memset(&ctx->eph_key_server,  0, sizeof(ctx->eph_key_server));
    memset(&ctx->client_pubkey,   0, sizeof(ctx->client_pubkey));
    memset(ctx->session_key,      0, sizeof(ctx->session_key));
    memset(ctx->session_key_info, 0, sizeof(ctx->session_key_info));

    ctx->state         = UDS_SRV_STATE_IDLE;
    ctx->session_valid = false;
}

uds_result_t uds_0x29_server_process(uds_srv_ctx_t  *ctx,
                                      const uint8_t  *rx_buf,  uint16_t  rx_len,
                                      uint8_t        *tx_buf,  uint16_t *tx_len)
{
    if (ctx == NULL || rx_buf == NULL || tx_buf == NULL || tx_len == NULL) {
        return UDS_ERR_INVALID_MSG;
    }

    *tx_len = 0U;

    /* Need at least SID + SubFunction */
    if (rx_len < 2U) {
        *tx_len = uds_0x29_encode_nrc(tx_buf, SRV_TX_BUF_MIN,
                                       UDS_SID_AUTHENTICATION,
                                       UDS_NRC_CONDITIONS_NOT_CORRECT);
        return UDS_ERR_INVALID_MSG;
    }

    uint8_t subfunction = rx_buf[1];

    switch (subfunction) {
        case UDS_0x29_SF_VERIFY_CERT_UNIDIRECTIONAL:
            if (ctx->state != UDS_SRV_STATE_IDLE && ctx->state != UDS_SRV_STATE_VCU_PROCESSING) {
                /* A new VCU request aborts any previous/stale auth attempt entirely */
                uds_0x29_server_reset(ctx);
            }
            return process_vcu(ctx, &s_cfg, rx_buf, rx_len, tx_buf, tx_len);

        case UDS_0x29_SF_PROOF_OF_OWNERSHIP:
            if (ctx->state != UDS_SRV_STATE_CHALLENGE_SENT && ctx->state != UDS_SRV_STATE_POWN_PROCESSING) {
                *tx_len = uds_0x29_encode_nrc(tx_buf, SRV_TX_BUF_MIN, UDS_SID_AUTHENTICATION, UDS_NRC_REQUEST_SEQUENCE_ERROR);
                return UDS_ERR_WRONG_STATE;
            }
            return process_pown(ctx, rx_buf, rx_len, tx_buf, tx_len);

        case UDS_0x29_SF_DEAUTHENTICATE:
            uds_0x29_server_reset(ctx);
            /* Send positive response [0x69 0x00] */
            if (tx_buf != NULL && SRV_TX_BUF_MIN >= 2U) {
                tx_buf[0] = UDS_SID_AUTH_RESPONSE;
                tx_buf[1] = UDS_0x29_SF_DEAUTHENTICATE;
                *tx_len   = 2U;
            }
            return UDS_OK;

        default:
            *tx_len = uds_0x29_encode_nrc(tx_buf, SRV_TX_BUF_MIN,
                                           UDS_SID_AUTHENTICATION,
                                           UDS_NRC_REQUEST_OUT_OF_RANGE);
            return UDS_ERR_UNKNOWN_SUBFUNCTION;
    }
}

uds_srv_state_t uds_0x29_server_get_state(const uds_srv_ctx_t *ctx)
{
    return (ctx != NULL) ? ctx->state : UDS_SRV_STATE_IDLE;
}

const uint8_t *uds_0x29_server_get_session_key(const uds_srv_ctx_t *ctx)
{
    if (ctx == NULL || !ctx->session_valid) return NULL;
    return ctx->session_key;
}
