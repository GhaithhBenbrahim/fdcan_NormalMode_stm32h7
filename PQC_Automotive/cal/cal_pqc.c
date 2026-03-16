/**
 ******************************************************************************
 * @file    cal_pqc.c
 * @brief   CAL PQC Backend — ML-DSA-2 + ML-KEM-512 (Week 9 Stub)
 *
 * All functions return CAL_ERR_NOT_SUPPORTED until Week 9 implementation.
 * The vtable structure is fully defined so the compiler validates call sites.
 *
 * Week 9 implementation plan:
 *   - Port PQClean ML-DSA-2 to STM32H7 (pqm4 optimised variant)
 *   - Port PQClean ML-KEM-512
 *   - keygen()     → pqcrystals_dilithium2_keypair()
 *   - sign()       → pqcrystals_dilithium2_signature()
 *   - verify()     → pqcrystals_dilithium2_verify()
 *   - kem_encap()  → pqcrystals_kyber512_enc()
 *   - kem_decap()  → pqcrystals_kyber512_dec()
 *   - dh_compute() → NOT USED for PQC (kem_encap/decap replace it)
 *   - cert_verify()→ custom parser for ML-DSA-2 composite certs
 *
 * Key sizes (Week 9):
 *   ML-DSA-2 private key : 2528 bytes
 *   ML-DSA-2 public key  : 1312 bytes
 *   ML-DSA-2 signature   : 2420 bytes
 *   ML-KEM-512 pubkey    :  800 bytes
 *   ML-KEM-512 ciphertext:  768 bytes
 *   Shared secret        :   32 bytes
 *
 * NOTE: CAL_MAX_PUBKEY_SIZE and CAL_MAX_SIG_SIZE in cal_types.h will
 *       need to be updated to 1312 and 2420 respectively in Week 9.
 *
 * @author  Ghaith Ben Brahim
 * @date    2026-03-15
 ******************************************************************************
 */

#include "cal_backend.h"

/* ============================================================================
 * PQC STUB FUNCTIONS — all return CAL_ERR_NOT_SUPPORTED
 * ============================================================================
 */

static cal_result_t pqc_keygen(cal_keypair_t *kp_out)
{
    (void)kp_out;
    return CAL_ERR_NOT_SUPPORTED;
}

static cal_result_t pqc_sign(const uint8_t   *priv,     uint16_t priv_len,
                               const uint8_t   *msg,      uint16_t msg_len,
                               cal_signature_t *sig_out)
{
    (void)priv; (void)priv_len; (void)msg; (void)msg_len; (void)sig_out;
    return CAL_ERR_NOT_SUPPORTED;
}

static cal_result_t pqc_verify(const cal_pubkey_t    *pub,
                                const uint8_t         *msg,     uint16_t msg_len,
                                const cal_signature_t *sig)
{
    (void)pub; (void)msg; (void)msg_len; (void)sig;
    return CAL_ERR_NOT_SUPPORTED;
}

static cal_result_t pqc_dh_compute(const uint8_t     *priv,     uint16_t priv_len,
                                    const cal_pubkey_t *peer_pub,
                                    uint8_t            *secret_out,
                                    uint16_t           *secret_len)
{
    /* PQC uses kem_encap / kem_decap instead of DH */
    (void)priv; (void)priv_len; (void)peer_pub; (void)secret_out; (void)secret_len;
    return CAL_ERR_NOT_SUPPORTED;
}

static cal_result_t pqc_cert_verify(const uint8_t *cert_der,    uint16_t cert_len,
                                     const uint8_t *ca_cert_der, uint16_t ca_len,
                                     cal_pubkey_t  *pub_key_out)
{
    (void)cert_der; (void)cert_len; (void)ca_cert_der; (void)ca_len; (void)pub_key_out;
    return CAL_ERR_NOT_SUPPORTED;
}

static cal_result_t pqc_kem_encap(const cal_pubkey_t *server_pub,
                                   uint8_t *ct_out, uint16_t *ct_len,
                                   uint8_t *ss_out, uint16_t *ss_len)
{
    /* TODO Week 9: pqcrystals_kyber512_enc(ct_out, ss_out, server_pub->bytes) */
    (void)server_pub; (void)ct_out; (void)ct_len; (void)ss_out; (void)ss_len;
    return CAL_ERR_NOT_SUPPORTED;
}

static cal_result_t pqc_kem_decap(const uint8_t *priv, uint16_t priv_len,
                                   const uint8_t *ct,   uint16_t ct_len,
                                   uint8_t *ss_out, uint16_t *ss_len)
{
    /* TODO Week 9: pqcrystals_kyber512_dec(ss_out, ct, priv) */
    (void)priv; (void)priv_len; (void)ct; (void)ct_len; (void)ss_out; (void)ss_len;
    return CAL_ERR_NOT_SUPPORTED;
}

/* ============================================================================
 * EXPORTED PQC BACKEND VTABLE
 * ============================================================================
 */
const cal_backend_t cal_backend_pqc = {
    .name          = "PQC ML-DSA-2",
    .alg_indicator = 0x10U,              /* UDS_ALG_IND_ML_DSA_2 */
    .keygen        = pqc_keygen,
    .sign          = pqc_sign,
    .verify        = pqc_verify,
    .dh_compute    = pqc_dh_compute,
    .cert_verify   = pqc_cert_verify,
    .kem_encap     = pqc_kem_encap,
    .kem_decap     = pqc_kem_decap,
};
