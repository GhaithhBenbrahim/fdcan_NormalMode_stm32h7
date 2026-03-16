/**
 ******************************************************************************
 * @file    cal_backend.c
 * @brief   CAL Runtime Dispatcher + Algorithm-Independent Operations
 *
 * Responsibilities:
 *   1. Owns the mbedTLS entropy + CTR-DRBG context (shared by all backends)
 *   2. Implements cal_select_mode() / cal_get_backend() / cal_get_mode()
 *   3. Provides thin wrapper implementations of cal_api.h functions:
 *      - Vtable-routed:  keygen, sign, verify, ecdh_shared_secret, cert_verify_chain
 *      - Always classic: hkdf, hmac_sha256, aes256gcm_encrypt/decrypt, rng
 *
 * @author  Ghaith Ben Brahim
 * @date    2026-03-15
 ******************************************************************************
 */

#include "cal_backend.h"
#include "cal_api.h"

/* mbedTLS 2.16.2 */
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/gcm.h"

#include <string.h>

/* ============================================================================
 * SHARED RNG CONTEXT
 * Exposed as extern to classical / pqc / hybrid backends.
 * ============================================================================
 */
mbedtls_entropy_context  g_entropy;
mbedtls_ctr_drbg_context g_ctr_drbg;

static bool s_cal_initialized = false;

/** CTR-DRBG personalisation string */
static const char k_pers[] = "UDS-PQC-AUTH-CAL-v2";

/* ============================================================================
 * RUNTIME BACKEND SELECTION
 * ============================================================================
 */

/** Convenience array: index with cal_mode_t */
const cal_backend_t * const cal_backends[CAL_MODE_COUNT] = {
    [CAL_MODE_CLASSICAL] = &cal_backend_classical,
    [CAL_MODE_PQC]       = &cal_backend_pqc,
    [CAL_MODE_HYBRID]    = &cal_backend_hybrid,
};

/** Active backend — defaults to classical at startup */
static const cal_backend_t *g_backend   = &cal_backend_classical;
static cal_mode_t            g_cal_mode  = CAL_MODE_CLASSICAL;

/* ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

cal_result_t cal_init(void)
{
    if (s_cal_initialized) return CAL_OK;

    mbedtls_entropy_init(&g_entropy);
    mbedtls_ctr_drbg_init(&g_ctr_drbg);

    int ret = mbedtls_ctr_drbg_seed(&g_ctr_drbg,
                                     mbedtls_entropy_func,
                                     &g_entropy,
                                     (const unsigned char *)k_pers,
                                     sizeof(k_pers) - 1U);
    if (ret != 0) {
        mbedtls_ctr_drbg_free(&g_ctr_drbg);
        mbedtls_entropy_free(&g_entropy);
        return CAL_ERR_CRYPTO;
    }

    s_cal_initialized = true;
    return CAL_OK;
}

void cal_deinit(void)
{
    if (!s_cal_initialized) return;
    mbedtls_ctr_drbg_free(&g_ctr_drbg);
    mbedtls_entropy_free(&g_entropy);
    s_cal_initialized = false;
}

/* ============================================================================
 * RUNTIME BACKEND SELECTOR
 * ============================================================================
 */

cal_result_t cal_select_mode(cal_mode_t mode)
{
    if ((uint32_t)mode >= (uint32_t)CAL_MODE_COUNT) return CAL_ERR_INVALID_PARAM;

    /* Check if the backend has at least keygen implemented (not all-NULL stub) */
    if (cal_backends[mode]->keygen == NULL) return CAL_ERR_NOT_SUPPORTED;

    g_backend  = cal_backends[mode];
    g_cal_mode = mode;
    return CAL_OK;
}

const cal_backend_t *cal_get_backend(void)
{
    return g_backend;
}

cal_mode_t cal_get_mode(void)
{
    return g_cal_mode;
}

uint8_t cal_get_alg_indicator(void)
{
    return g_backend->alg_indicator;
}

/* ============================================================================
 * VTABLE-ROUTED WRAPPERS
 * These forward to g_backend function pointers.
 * The algorithm parameter is kept in cal_api.h signatures for future
 * intra-backend disambiguation (e.g. hybrid needs to know which alg).
 * ============================================================================
 */

cal_result_t cal_rng(uint8_t *buf, uint16_t len)
{
    if (buf == NULL || len == 0U) return CAL_ERR_INVALID_PARAM;
    if (!s_cal_initialized)       return CAL_ERR_NOT_INIT;

    return (mbedtls_ctr_drbg_random(&g_ctr_drbg, buf, (size_t)len) == 0)
           ? CAL_OK : CAL_ERR_CRYPTO;
}

cal_result_t cal_keygen(cal_algorithm_t alg, cal_keypair_t *kp_out)
{
    (void)alg;   /* implicit in backend choice; kept for API compatibility */
    if (!s_cal_initialized)           return CAL_ERR_NOT_INIT;
    if (g_backend->keygen == NULL)    return CAL_ERR_NOT_SUPPORTED;
    return g_backend->keygen(kp_out);
}

cal_result_t cal_sign(cal_algorithm_t  alg,
                      const uint8_t   *priv,     uint16_t priv_len,
                      const uint8_t   *msg,      uint16_t msg_len,
                      cal_signature_t *sig_out)
{
    (void)alg;
    if (!s_cal_initialized)        return CAL_ERR_NOT_INIT;
    if (g_backend->sign == NULL)   return CAL_ERR_NOT_SUPPORTED;
    return g_backend->sign(priv, priv_len, msg, msg_len, sig_out);
}

cal_result_t cal_verify(cal_algorithm_t        alg,
                        const cal_pubkey_t    *pub,
                        const uint8_t         *msg,     uint16_t msg_len,
                        const cal_signature_t *sig)
{
    (void)alg;
    if (!s_cal_initialized)         return CAL_ERR_NOT_INIT;
    if (g_backend->verify == NULL)  return CAL_ERR_NOT_SUPPORTED;
    return g_backend->verify(pub, msg, msg_len, sig);
}

cal_result_t cal_ecdh_shared_secret(const uint8_t     *priv,     uint16_t priv_len,
                                    const cal_pubkey_t *peer_pub,
                                    uint8_t            *secret_out,
                                    uint16_t           *secret_len)
{
    if (!s_cal_initialized)              return CAL_ERR_NOT_INIT;
    if (g_backend->dh_compute == NULL)   return CAL_ERR_NOT_SUPPORTED;
    return g_backend->dh_compute(priv, priv_len, peer_pub, secret_out, secret_len);
}

cal_result_t cal_cert_verify_chain(const uint8_t *cert_der, uint16_t cert_len,
                                   const uint8_t *ca_cert_der, uint16_t ca_len,
                                   cal_pubkey_t  *pub_key_out)
{
    if (!s_cal_initialized)              return CAL_ERR_NOT_INIT;
    if (g_backend->cert_verify == NULL)  return CAL_ERR_NOT_SUPPORTED;
    return g_backend->cert_verify(cert_der, cert_len, ca_cert_der, ca_len, pub_key_out);
}

/* ============================================================================
 * ALGORITHM-INDEPENDENT WRAPPERS (always classical — no vtable)
 * HKDF, HMAC, AES-256-GCM: these don't change with the signature scheme.
 * ============================================================================
 */

cal_result_t cal_hkdf(const uint8_t *ikm,  uint16_t ikm_len,
                      const uint8_t *salt, uint16_t salt_len,
                      const uint8_t *info, uint16_t info_len,
                      uint8_t       *okm_out, uint16_t okm_len)
{
    if (ikm == NULL || okm_out == NULL || okm_len == 0U || okm_len > CAL_HKDF_MAX_OKM) {
        return CAL_ERR_INVALID_PARAM;
    }
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int ret = mbedtls_hkdf(md,
                            salt,    (size_t)salt_len,
                            ikm,     (size_t)ikm_len,
                            info,    (size_t)info_len,
                            okm_out, (size_t)okm_len);
    return (ret == 0) ? CAL_OK : CAL_ERR_CRYPTO;
}

cal_result_t cal_hmac_sha256(const uint8_t *key,  uint16_t key_len,
                              const uint8_t *msg,  uint16_t msg_len,
                              uint8_t        mac_out[CAL_HMAC_SHA256_SIZE])
{
    if (key == NULL || msg == NULL || mac_out == NULL) return CAL_ERR_INVALID_PARAM;
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int ret = mbedtls_md_hmac(md,
                               key, (size_t)key_len,
                               msg, (size_t)msg_len,
                               mac_out);
    return (ret == 0) ? CAL_OK : CAL_ERR_CRYPTO;
}

cal_result_t cal_aes256gcm_encrypt(const uint8_t  key[CAL_AES256_KEY_SIZE],
                                   const uint8_t  iv[CAL_AES_GCM_IV_SIZE],
                                   const uint8_t *aad,       uint16_t aad_len,
                                   const uint8_t *plaintext, uint16_t pt_len,
                                   uint8_t       *ct_out,
                                   uint8_t        tag_out[CAL_AES_GCM_TAG_SIZE])
{
    if (key == NULL || iv == NULL || ct_out == NULL || tag_out == NULL) {
        return CAL_ERR_INVALID_PARAM;
    }
    if (pt_len > 0U && plaintext == NULL) return CAL_ERR_INVALID_PARAM;

    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    cal_result_t cal_ret = CAL_ERR_CRYPTO;

    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES,
                                   key, CAL_AES256_KEY_SIZE * 8U);
    if (ret != 0) goto cleanup;

    ret = mbedtls_gcm_crypt_and_tag(&ctx,
                                     MBEDTLS_GCM_ENCRYPT,
                                     (size_t)pt_len,
                                     iv,  (size_t)CAL_AES_GCM_IV_SIZE,
                                     aad, (size_t)aad_len,
                                     plaintext, ct_out,
                                     (size_t)CAL_AES_GCM_TAG_SIZE, tag_out);
    if (ret == 0) cal_ret = CAL_OK;

cleanup:
    mbedtls_gcm_free(&ctx);
    return cal_ret;
}

cal_result_t cal_aes256gcm_decrypt(const uint8_t  key[CAL_AES256_KEY_SIZE],
                                   const uint8_t  iv[CAL_AES_GCM_IV_SIZE],
                                   const uint8_t *aad,        uint16_t aad_len,
                                   const uint8_t *ciphertext, uint16_t ct_len,
                                   const uint8_t  tag[CAL_AES_GCM_TAG_SIZE],
                                   uint8_t       *pt_out)
{
    if (key == NULL || iv == NULL || tag == NULL || pt_out == NULL) {
        return CAL_ERR_INVALID_PARAM;
    }

    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    cal_result_t cal_ret = CAL_ERR_CRYPTO;

    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES,
                                   key, CAL_AES256_KEY_SIZE * 8U);
    if (ret != 0) goto cleanup;

    ret = mbedtls_gcm_auth_decrypt(&ctx,
                                    (size_t)ct_len,
                                    iv,  (size_t)CAL_AES_GCM_IV_SIZE,
                                    aad, (size_t)aad_len,
                                    tag, (size_t)CAL_AES_GCM_TAG_SIZE,
                                    ciphertext, pt_out);
    if (ret == 0) {
        cal_ret = CAL_OK;
    } else if (ret == MBEDTLS_ERR_GCM_AUTH_FAILED) {
        cal_ret = CAL_ERR_VERIFY_FAILED;  /* tag mismatch — possible tampering */
    }

cleanup:
    mbedtls_gcm_free(&ctx);
    return cal_ret;
}
