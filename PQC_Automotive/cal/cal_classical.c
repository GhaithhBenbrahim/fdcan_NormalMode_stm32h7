/**
 ******************************************************************************
 * @file    cal_classical.c
 * @brief   CAL Classical Backend — mbedTLS 2.16.2 Implementation
 *
 * Implements the cal_backend_t vtable for ECDSA-P256 + ECDH-P256.
 * Uses mbedTLS 2.16.2 API (STM32CubeIDE package).
 *
 * Key API differences vs mbedTLS 3.x:
 *   - SHA-256       : mbedtls_sha256_ret() instead of mbedtls_sha256()
 *   - ECDSA sign    : needs mbedtls_ecdsa_context with .grp + .d loaded
 *   - ECDSA verify  : needs mbedtls_ecdsa_context with .grp + .Q loaded
 *   - No _restartable variants (3.x only)
 *
 * The RNG context (s_entropy, s_ctr_drbg) lives in cal_backend.c which
 * calls cal_classical_init() / cal_classical_deinit().
 *
 * @author  Ghaith Ben Brahim
 * @date    2026-03-15
 ******************************************************************************
 */

#include "cal_backend.h"
#include "cal_api.h"

/* mbedTLS 2.16.2 includes */
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/sha256.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/gcm.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/bignum.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include <string.h>

/* ============================================================================
 * EXTERNAL RNG — provided by cal_backend.c (shared across all backends)
 * ============================================================================
 */
extern mbedtls_ctr_drbg_context g_ctr_drbg;

/* ============================================================================
 * PRIVATE HELPERS
 * ============================================================================
 */

/**
 * @brief  Compute SHA-256(msg) using mbedTLS 2.16.2 _ret API.
 */
static int sha256_compute(const uint8_t *msg, uint16_t msg_len,
                           uint8_t hash[CAL_SHA256_SIZE])
{
    /* mbedtls_sha256_ret: returns 0 on success, negative on error */
    return mbedtls_sha256_ret(msg, (size_t)msg_len, hash, 0 /* is224 = false */);
}

/* ============================================================================
 * CLASSICAL BACKEND FUNCTIONS (static — not directly callable by UDS code)
 * ============================================================================
 */

/* --------------------------------------------------------------------------
 * keygen: ECDSA/ECDH-P256 ephemeral keypair
 * -------------------------------------------------------------------------- */
static cal_result_t classical_keygen(cal_keypair_t *kp_out)
{
    if (kp_out == NULL) return CAL_ERR_INVALID_PARAM;

    cal_result_t        cal_ret = CAL_ERR_CRYPTO;
    mbedtls_ecp_group   grp;
    mbedtls_mpi         d;
    mbedtls_ecp_point   Q;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);

    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) goto cleanup;

    ret = mbedtls_ecp_gen_keypair(&grp, &d, &Q,
                                   mbedtls_ctr_drbg_random, &g_ctr_drbg);
    if (ret != 0) goto cleanup;

    /* Private key: raw big-endian scalar, zero-padded to 32 bytes */
    ret = mbedtls_mpi_write_binary(&d, kp_out->priv, CAL_ECDSA_PRIVKEY_SIZE);
    if (ret != 0) goto cleanup;
    kp_out->priv_len = CAL_ECDSA_PRIVKEY_SIZE;

    /* Public key: 0x04 || X || Y = 65 bytes (uncompressed) */
    size_t pub_len = 0U;
    ret = mbedtls_ecp_point_write_binary(&grp, &Q,
                                          MBEDTLS_ECP_PF_UNCOMPRESSED,
                                          &pub_len,
                                          kp_out->pub.bytes,
                                          CAL_MAX_PUBKEY_SIZE);
    if (ret != 0) goto cleanup;

    kp_out->pub.length = (uint16_t)pub_len;
    kp_out->pub.alg    = CAL_ALG_ECDSA_P256;
    cal_ret            = CAL_OK;

cleanup:
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return cal_ret;
}

/* --------------------------------------------------------------------------
 * sign: ECDSA-P256 — sign SHA-256(msg)
 *
 * mbedTLS 2.16.2 change vs 3.x:
 *   Use mbedtls_ecdsa_context (= mbedtls_ecp_keypair) and load .grp + .d.
 *   Call mbedtls_ecdsa_write_signature() — no _restartable in 2.x.
 * -------------------------------------------------------------------------- */
static cal_result_t classical_sign(const uint8_t   *priv,     uint16_t priv_len,
                                    const uint8_t   *msg,      uint16_t msg_len,
                                    cal_signature_t *sig_out)
{
    if (priv == NULL || msg == NULL || sig_out == NULL) return CAL_ERR_INVALID_PARAM;
    if (priv_len != CAL_ECDSA_PRIVKEY_SIZE)             return CAL_ERR_INVALID_PARAM;

    cal_result_t       cal_ret = CAL_ERR_CRYPTO;
    uint8_t            hash[CAL_SHA256_SIZE];
    mbedtls_ecdsa_context ecdsa;

    mbedtls_ecdsa_init(&ecdsa);

    /* Hash the message (mbedTLS 2.16.2 uses _ret suffix) */
    if (sha256_compute(msg, msg_len, hash) != 0) goto cleanup;

    /* Load group into ecdsa context (ecdsa_context IS ecp_keypair in 2.x) */
    int ret = mbedtls_ecp_group_load(&ecdsa.grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) goto cleanup;

    /* Load private key scalar */
    ret = mbedtls_mpi_read_binary(&ecdsa.d, priv, (size_t)priv_len);
    if (ret != 0) goto cleanup;

    /* Sign: produces DER-encoded (r, s), no _restartable in 2.16 */
    size_t sig_len = 0U;
    ret = mbedtls_ecdsa_write_signature(&ecdsa,
                                         MBEDTLS_MD_SHA256,
                                         hash, sizeof(hash),
                                         sig_out->bytes, &sig_len,
                                         mbedtls_ctr_drbg_random, &g_ctr_drbg);
    if (ret != 0) goto cleanup;

    sig_out->length = (uint16_t)sig_len;
    cal_ret         = CAL_OK;

cleanup:
    mbedtls_ecdsa_free(&ecdsa);
    return cal_ret;
}

/* --------------------------------------------------------------------------
 * verify: ECDSA-P256 — verify SHA-256(msg) against signature
 *
 * mbedTLS 2.16.2: load .grp + .Q into ecdsa_context, call read_signature().
 * -------------------------------------------------------------------------- */
static cal_result_t classical_verify(const cal_pubkey_t    *pub,
                                      const uint8_t         *msg,     uint16_t msg_len,
                                      const cal_signature_t *sig)
{
    if (pub == NULL || msg == NULL || sig == NULL) return CAL_ERR_INVALID_PARAM;
    if (pub->length == 0U || sig->length == 0U)   return CAL_ERR_INVALID_PARAM;

    cal_result_t      cal_ret = CAL_ERR_CRYPTO;
    uint8_t           hash[CAL_SHA256_SIZE];
    mbedtls_ecdsa_context ecdsa;

    mbedtls_ecdsa_init(&ecdsa);

    if (sha256_compute(msg, msg_len, hash) != 0) goto cleanup;

    /* Load group */
    int ret = mbedtls_ecp_group_load(&ecdsa.grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) goto cleanup;

    /* Load the public key point into ecdsa.Q */
    ret = mbedtls_ecp_point_read_binary(&ecdsa.grp, &ecdsa.Q,
                                         pub->bytes, (size_t)pub->length);
    if (ret != 0) goto cleanup;

    /* Validate the point is on the curve */
    ret = mbedtls_ecp_check_pubkey(&ecdsa.grp, &ecdsa.Q);
    if (ret != 0) goto cleanup;

    /* Verify DER signature against SHA-256 hash */
    ret = mbedtls_ecdsa_read_signature(&ecdsa,
                                        hash, sizeof(hash),
                                        sig->bytes, (size_t)sig->length);
    if (ret == 0) {
        cal_ret = CAL_OK;
    } else {
        cal_ret = CAL_ERR_VERIFY_FAILED;
    }

cleanup:
    mbedtls_ecdsa_free(&ecdsa);
    return cal_ret;
}

/* --------------------------------------------------------------------------
 * dh_compute: ECDH-P256 shared secret
 * (Same API in 2.16 and 3.x — no changes needed here)
 * -------------------------------------------------------------------------- */
static cal_result_t classical_dh_compute(const uint8_t     *priv,     uint16_t priv_len,
                                          const cal_pubkey_t *peer_pub,
                                          uint8_t            *secret_out,
                                          uint16_t           *secret_len)
{
    if (priv == NULL || peer_pub == NULL || secret_out == NULL || secret_len == NULL) {
        return CAL_ERR_INVALID_PARAM;
    }
    if (priv_len != CAL_ECDSA_PRIVKEY_SIZE) return CAL_ERR_INVALID_PARAM;

    cal_result_t      cal_ret = CAL_ERR_CRYPTO;
    mbedtls_ecp_group grp;
    mbedtls_mpi       d, z;
    mbedtls_ecp_point Q;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);
    mbedtls_ecp_point_init(&Q);

    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) goto cleanup;

    ret = mbedtls_mpi_read_binary(&d, priv, (size_t)priv_len);
    if (ret != 0) goto cleanup;

    ret = mbedtls_ecp_point_read_binary(&grp, &Q,
                                         peer_pub->bytes, (size_t)peer_pub->length);
    if (ret != 0) goto cleanup;

    ret = mbedtls_ecp_check_pubkey(&grp, &Q);
    if (ret != 0) goto cleanup;

    /* Compute Z = d * Q; extract X-coordinate as shared secret */
    ret = mbedtls_ecdh_compute_shared(&grp, &z, &Q, &d,
                                       mbedtls_ctr_drbg_random, &g_ctr_drbg);
    if (ret != 0) goto cleanup;

    ret = mbedtls_mpi_write_binary(&z, secret_out, CAL_ECDH_SHARED_SECRET_SIZE);
    if (ret != 0) goto cleanup;

    *secret_len = CAL_ECDH_SHARED_SECRET_SIZE;
    cal_ret     = CAL_OK;

cleanup:
    mbedtls_mpi_free(&z);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return cal_ret;
}

/* --------------------------------------------------------------------------
 * cert_verify: X.509 v3 DER chain + extract public key
 * -------------------------------------------------------------------------- */
static cal_result_t classical_cert_verify(const uint8_t *cert_der, uint16_t cert_len,
                                           const uint8_t *ca_cert_der, uint16_t ca_len,
                                           cal_pubkey_t  *pub_key_out)
{
    if (cert_der == NULL || ca_cert_der == NULL || pub_key_out == NULL) {
        return CAL_ERR_INVALID_PARAM;
    }

    cal_result_t   cal_ret = CAL_ERR_CRYPTO;
    mbedtls_x509_crt cert, ca_cert;

    mbedtls_x509_crt_init(&cert);
    mbedtls_x509_crt_init(&ca_cert);

    int ret = mbedtls_x509_crt_parse_der(&ca_cert, ca_cert_der, (size_t)ca_len);
    if (ret != 0) goto cleanup;

    ret = mbedtls_x509_crt_parse_der(&cert, cert_der, (size_t)cert_len);
    if (ret != 0) goto cleanup;

    /* Verify leaf signed by CA */
    uint32_t flags = 0U;
    ret = mbedtls_x509_crt_verify(&cert, &ca_cert, NULL, NULL,
                                   &flags, NULL, NULL);
    if (ret != 0 || flags != 0U) {
        cal_ret = CAL_ERR_VERIFY_FAILED;
        goto cleanup;
    }

    /* Extract subject public key — must be ECDSA on secp256r1 */
    mbedtls_pk_context *pk = &cert.pk;
    if (mbedtls_pk_get_type(pk) != MBEDTLS_PK_ECKEY) {
        cal_ret = CAL_ERR_INVALID_PARAM;
        goto cleanup;
    }

    /* In mbedTLS 2.x, mbedtls_pk_ec() returns mbedtls_ecp_keypair*
     * whose .grp and .Q are directly accessible struct members.      */
    mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(*pk);

    size_t pub_len = 0U;
    ret = mbedtls_ecp_point_write_binary(&ecp->grp, &ecp->Q,
                                          MBEDTLS_ECP_PF_UNCOMPRESSED,
                                          &pub_len,
                                          pub_key_out->bytes,
                                          CAL_MAX_PUBKEY_SIZE);
    if (ret != 0) goto cleanup;

    pub_key_out->length = (uint16_t)pub_len;
    pub_key_out->alg    = CAL_ALG_ECDSA_P256;
    cal_ret             = CAL_OK;

cleanup:
    mbedtls_x509_crt_free(&cert);
    mbedtls_x509_crt_free(&ca_cert);
    return cal_ret;
}

/* ============================================================================
 * KEM stubs — not applicable for classical backend
 * ============================================================================
 */
static cal_result_t classical_kem_encap(const cal_pubkey_t *server_pub,
                                         uint8_t *ct_out, uint16_t *ct_len,
                                         uint8_t *ss_out, uint16_t *ss_len)
{
    (void)server_pub; (void)ct_out; (void)ct_len; (void)ss_out; (void)ss_len;
    return CAL_ERR_NOT_SUPPORTED;
}

static cal_result_t classical_kem_decap(const uint8_t *priv, uint16_t priv_len,
                                         const uint8_t *ct,   uint16_t ct_len,
                                         uint8_t *ss_out, uint16_t *ss_len)
{
    (void)priv; (void)priv_len; (void)ct; (void)ct_len; (void)ss_out; (void)ss_len;
    return CAL_ERR_NOT_SUPPORTED;
}

/* ============================================================================
 * EXPORTED BACKEND VTABLE
 * ============================================================================
 */
const cal_backend_t cal_backend_classical = {
    .name          = "Classical ECDSA-P256",
    .alg_indicator = 0x01U,                 /* UDS_ALG_IND_ECDSA_P256 */
    .keygen        = classical_keygen,
    .sign          = classical_sign,
    .verify        = classical_verify,
    .dh_compute    = classical_dh_compute,
    .cert_verify   = classical_cert_verify,
    .kem_encap     = classical_kem_encap,   /* returns NOT_SUPPORTED */
    .kem_decap     = classical_kem_decap,   /* returns NOT_SUPPORTED */
};
