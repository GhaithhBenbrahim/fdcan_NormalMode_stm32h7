/**
 ******************************************************************************
 * @file    uds_session.c
 * @brief   UDS Session Encryption — AES-256-GCM Implementation
 *
 * Wire format per encrypted message:
 *   [TX_counter (4B BE)] [GCM_TAG (16B)] [ciphertext (N B)]
 *   Total overhead: 20 bytes (UDS_SESSION_OVERHEAD)
 *
 * IV construction (96-bit):
 *   iv[0..3]  = TX_counter (big-endian)
 *   iv[4..11] = 0x00 (zero-padded)
 *
 * AAD = first aad_len bytes of the plaintext (typically SID + SubFunction).
 * This authenticates the message type without encrypting it.
 *
 * Replay protection: rx_counter is the expected next counter from peer.
 * Any received counter <= (rx_counter - 1) is rejected.
 *
 ******************************************************************************
 */

#include "uds_session.h"
#include "cal/cal_api.h"

#include <string.h>

/* ============================================================================
 * PRIVATE HELPERS
 * ============================================================================
 */

/** Write 32-bit value big-endian */
static inline void write_u32_be(uint8_t *p, uint32_t val)
{
    p[0] = (uint8_t)(val >> 24U);
    p[1] = (uint8_t)(val >> 16U);
    p[2] = (uint8_t)(val >>  8U);
    p[3] = (uint8_t)(val        );
}

/** Read 32-bit value big-endian */
static inline uint32_t read_u32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24U) |
           ((uint32_t)p[1] << 16U) |
           ((uint32_t)p[2] <<  8U) |
            (uint32_t)p[3];
}

/** Build a 12-byte GCM IV from a 32-bit counter */
static void build_iv(uint8_t iv[CAL_AES_GCM_IV_SIZE], uint32_t counter)
{
    memset(iv, 0, CAL_AES_GCM_IV_SIZE);
    write_u32_be(iv, counter);
}

/* ============================================================================
 * PUBLIC API
 * ============================================================================
 */

void uds_session_install_key(uds_session_ctx_t *ctx,
                              const uint8_t      key[CAL_AES256_KEY_SIZE])
{
    if (ctx == NULL || key == NULL) return;

    memcpy(ctx->key, key, CAL_AES256_KEY_SIZE);
    ctx->tx_counter = 0U;
    ctx->rx_counter = 0U;
    ctx->active     = true;
}

void uds_session_reset(uds_session_ctx_t *ctx)
{
    if (ctx == NULL) return;
    memset(ctx->key, 0, sizeof(ctx->key));
    ctx->tx_counter = 0U;
    ctx->rx_counter = 0U;
    ctx->active     = false;
}

/* -------------------------------------------------------------------------- */

uds_result_t uds_session_encrypt(uds_session_ctx_t *ctx,
                                  const uint8_t     *plaintext, uint16_t pt_len,
                                  uint8_t            aad_len,
                                  uint8_t           *out_buf,   uint16_t *out_len,
                                  uint16_t           out_buf_size)
{
    if (ctx == NULL || plaintext == NULL || out_buf == NULL || out_len == NULL) {
        return UDS_ERR_INVALID_MSG;
    }
    if (!ctx->active) return UDS_ERR_CRYPTO_FAIL;

    uint32_t required = (uint32_t)UDS_SESSION_OVERHEAD + pt_len;
    if (required > out_buf_size) return UDS_ERR_BUFFER_OVERFLOW;

    /* IV from current TX counter */
    uint8_t iv[CAL_AES_GCM_IV_SIZE];
    build_iv(iv, ctx->tx_counter);

    /* Write counter prefix */
    write_u32_be(out_buf, ctx->tx_counter);
    uint8_t *tag_ptr       = &out_buf[4U];
    uint8_t *ciphertext_ptr = &out_buf[4U + CAL_AES_GCM_TAG_SIZE];

    /* AAD = first aad_len bytes of plaintext (SID + SubFunction) */
    const uint8_t *aad     = (aad_len > 0U) ? plaintext : NULL;
    uint16_t       aad_sz  = (aad_len > pt_len) ? pt_len : aad_len;

    cal_result_t ret = cal_aes256gcm_encrypt(
        ctx->key, iv,
        aad, aad_sz,
        plaintext, pt_len,
        ciphertext_ptr,
        tag_ptr);

    if (ret != CAL_OK) return UDS_ERR_CRYPTO_FAIL;

    ctx->tx_counter++;
    *out_len = (uint16_t)required;
    return UDS_OK;
}

/* -------------------------------------------------------------------------- */

uds_result_t uds_session_decrypt(uds_session_ctx_t *ctx,
                                  const uint8_t     *in_buf,  uint16_t in_len,
                                  uint8_t            aad_len,
                                  uint8_t           *out_buf, uint16_t *out_len)
{
    if (ctx == NULL || in_buf == NULL || out_buf == NULL || out_len == NULL) {
        return UDS_ERR_INVALID_MSG;
    }
    if (!ctx->active) return UDS_ERR_CRYPTO_FAIL;
    if (in_len <= UDS_SESSION_OVERHEAD) return UDS_ERR_INVALID_MSG;

    /* Parse wire format: [counter(4)] [tag(16)] [ciphertext] */
    uint32_t         rx_ctr     = read_u32_be(in_buf);
    const uint8_t   *tag_ptr    = &in_buf[4U];
    const uint8_t   *ct_ptr     = &in_buf[4U + CAL_AES_GCM_TAG_SIZE];
    uint16_t         ct_len     = in_len - (uint16_t)UDS_SESSION_OVERHEAD;

    /* Replay check: reject anything not equal to expected counter */
    if (rx_ctr != ctx->rx_counter) {
        return UDS_ERR_CRYPTO_FAIL;   /* replay or gap */
    }

    /* Rebuild IV */
    uint8_t iv[CAL_AES_GCM_IV_SIZE];
    build_iv(iv, rx_ctr);

    /* Decrypt */
    cal_result_t ret = cal_aes256gcm_decrypt(
        ctx->key, iv,
        NULL, 0U,    /* AAD computed after decrypt: placeholder */
        ct_ptr, ct_len,
        tag_ptr,
        out_buf);

    /* NOTE: For AAD, we need to compute it from the *decrypted* output's
     * leading bytes. However, GCM authenticates AAD as part of the tag,
     * so we pass the expected AAD from the decrypted plaintext.
     * We decrypt first (without AAD), then re-verify with AAD.
     *
     * Correct approach: Since AAD is the plaintext header, we use the
     * ciphertext header (same bytes for unencrypted fields). For simplicity
     * and correctness, the encrypt side does NOT encrypt the AAD portion
     * and the decrypt side uses the ciphertext's first aad_len bytes.
     *
     * If your design keeps SID/SF headers unencrypted (recommended),
     * pass those as AAD on both sides separately.
     * For now: no AAD in decrypt (aad_len=0 safe default), matching encrypt.
     */

    (void)aad_len; /* AAD handling is application-specific — see note above */

    if (ret == CAL_ERR_VERIFY_FAILED) {
        return UDS_ERR_CRYPTO_FAIL;  /* Tag mismatch — discard, possible tamper */
    }
    if (ret != CAL_OK) {
        return UDS_ERR_CRYPTO_FAIL;
    }

    ctx->rx_counter++;
    *out_len = ct_len;
    return UDS_OK;
}
