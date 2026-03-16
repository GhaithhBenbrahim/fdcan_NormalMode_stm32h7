/**
 ******************************************************************************
 * @file    cal_hybrid.c
 * @brief   CAL Hybrid Backend — Classical + PQC Combined (Week 11 Stub)
 *
 * All functions return CAL_ERR_NOT_SUPPORTED until Week 11 implementation.
 *
 * Week 11 implementation plan:
 *   - keygen():     generate BOTH ECDSA-P256 + ML-DSA-2 keypairs
 *   - sign():       concatenate ECDSA-P256 sig + ML-DSA-2 sig
 *   - verify():     verify BOTH signatures (fail if either invalid)
 *   - dh_compute(): run BOTH ECDH-P256 and ML-KEM-512, then:
 *                   shared_secret = HKDF(ECDH_secret || KEM_secret)
 *   - cert_verify():verify composite cert containing both pub keys
 *
 * The hybrid mode provides protection against:
 *   - Classical-only attack (quantum adversary)
 *   - PQC-only attack (undiscovered classical vulnerability in ML-DSA)
 *
 * @author  Ghaith Ben Brahim
 * @date    2026-03-15
 ******************************************************************************
 */

#include "cal_backend.h"

static cal_result_t hybrid_keygen(cal_keypair_t *kp_out)
{
    /* TODO Week 11: call both cal_backend_classical.keygen and cal_backend_pqc.keygen */
    (void)kp_out;
    return CAL_ERR_NOT_SUPPORTED;
}

static cal_result_t hybrid_sign(const uint8_t   *priv, uint16_t priv_len,
                                 const uint8_t   *msg,  uint16_t msg_len,
                                 cal_signature_t *sig_out)
{
    /* TODO Week 11: sig = ECDSA_sig || ML-DSA-2_sig */
    (void)priv; (void)priv_len; (void)msg; (void)msg_len; (void)sig_out;
    return CAL_ERR_NOT_SUPPORTED;
}

static cal_result_t hybrid_verify(const cal_pubkey_t    *pub,
                                   const uint8_t         *msg,     uint16_t msg_len,
                                   const cal_signature_t *sig)
{
    /* TODO Week 11: verify both sigs, fail if either invalid */
    (void)pub; (void)msg; (void)msg_len; (void)sig;
    return CAL_ERR_NOT_SUPPORTED;
}

static cal_result_t hybrid_dh_compute(const uint8_t     *priv,     uint16_t priv_len,
                                       const cal_pubkey_t *peer_pub,
                                       uint8_t            *secret_out,
                                       uint16_t           *secret_len)
{
    /* TODO Week 11: HKDF(ECDH_secret || KEM_shared_secret) */
    (void)priv; (void)priv_len; (void)peer_pub; (void)secret_out; (void)secret_len;
    return CAL_ERR_NOT_SUPPORTED;
}

static cal_result_t hybrid_cert_verify(const uint8_t *cert_der,    uint16_t cert_len,
                                        const uint8_t *ca_cert_der, uint16_t ca_len,
                                        cal_pubkey_t  *pub_key_out)
{
    /* TODO Week 11: composite cert parser */
    (void)cert_der; (void)cert_len; (void)ca_cert_der; (void)ca_len; (void)pub_key_out;
    return CAL_ERR_NOT_SUPPORTED;
}

static cal_result_t hybrid_kem_encap(const cal_pubkey_t *server_pub,
                                      uint8_t *ct_out, uint16_t *ct_len,
                                      uint8_t *ss_out, uint16_t *ss_len)
{
    (void)server_pub; (void)ct_out; (void)ct_len; (void)ss_out; (void)ss_len;
    return CAL_ERR_NOT_SUPPORTED;
}

static cal_result_t hybrid_kem_decap(const uint8_t *priv, uint16_t priv_len,
                                      const uint8_t *ct,   uint16_t ct_len,
                                      uint8_t *ss_out, uint16_t *ss_len)
{
    (void)priv; (void)priv_len; (void)ct; (void)ct_len; (void)ss_out; (void)ss_len;
    return CAL_ERR_NOT_SUPPORTED;
}

/* ============================================================================
 * EXPORTED HYBRID BACKEND VTABLE
 * ============================================================================
 */
const cal_backend_t cal_backend_hybrid = {
    .name          = "Hybrid ECDSA+ML-DSA-2",
    .alg_indicator = 0x20U,              /* UDS_ALG_IND_HYBRID */
    .keygen        = hybrid_keygen,
    .sign          = hybrid_sign,
    .verify        = hybrid_verify,
    .dh_compute    = hybrid_dh_compute,
    .cert_verify   = hybrid_cert_verify,
    .kem_encap     = hybrid_kem_encap,
    .kem_decap     = hybrid_kem_decap,
};
