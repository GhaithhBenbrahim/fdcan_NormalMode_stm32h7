/**
 ******************************************************************************
 * @file    cal_backend.h
 * @brief   Crypto Abstraction Layer — Runtime Backend Vtable
 *
 * Defines the cal_backend_t function-pointer table that drives runtime
 * crypto-mode switching. The TouchGFX GUI (Week 11-12) calls
 * cal_select_mode() to switch between Classical / PQC / Hybrid before
 * starting a new authentication sequence.
 *
 * Only algorithm-specific operations are in the vtable:
 *   keygen, sign, verify, dh_compute (ECDH or KEM-substitute), cert_verify,
 *   kem_encap, kem_decap.
 *
 * Algorithm-independent operations (HKDF, HMAC, AES-GCM, RNG) are NOT
 * in the vtable — they are always called directly from mbedTLS.
 *
 * @author  Ghaith Ben Brahim
 * @date    2026-03-15
 ******************************************************************************
 */
#ifndef CAL_BACKEND_H
#define CAL_BACKEND_H

#include "cal_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * BACKEND VTABLE
 * All function pointers use the same parameter signatures as cal_api.h
 * so cal_backend.c can forward directly with no type casts.
 * ============================================================================
 */
typedef struct cal_backend_s {

    /** Human-readable name shown on TouchGFX screen, e.g. "Classical ECDSA-P256" */
    const char    *name;

    /** UDS algorithmIndicator byte sent in 0x29 messages for this mode */
    uint8_t        alg_indicator;

    /* ---- Asymmetric key operations ---------------------------------------- */

    /**
     * @brief Generate an asymmetric keypair suited for both signing and DH.
     *        Classical: ECDSA/ECDH-P256 keypair (same structure).
     *        PQC (Week 9): separate sig_keygen / kem_keygen will be needed.
     */
    cal_result_t (*keygen)(cal_keypair_t *kp_out);

    /**
     * @brief Sign a message (hash computed internally).
     *        Classical: ECDSA-P256 DER signature.
     *        PQC (Week 9): ML-DSA-2 signature.
     */
    cal_result_t (*sign)(const uint8_t     *priv,     uint16_t priv_len,
                         const uint8_t     *msg,      uint16_t msg_len,
                         cal_signature_t   *sig_out);

    /**
     * @brief Verify a signature (hash computed internally).
     */
    cal_result_t (*verify)(const cal_pubkey_t    *pub,
                           const uint8_t         *msg,     uint16_t msg_len,
                           const cal_signature_t *sig);

    /**
     * @brief Compute DH shared secret.
     *        Classical: ECDH(priv, peer_pub) → 32-byte X-coord.
     *        PQC: replaced by kem_encap / kem_decap below.
     *        Hybrid: calls both and concatenates.
     */
    cal_result_t (*dh_compute)(const uint8_t     *priv,     uint16_t priv_len,
                               const cal_pubkey_t *peer_pub,
                               uint8_t            *secret_out,
                               uint16_t           *secret_len);

    /**
     * @brief Verify an X.509 certificate chain and extract the public key.
     *        Classical: ECDSA-P256 cert (DER).
     *        PQC (Week 9): ML-DSA-2 cert (custom or composite DER).
     */
    cal_result_t (*cert_verify)(const uint8_t *cert_der,     uint16_t cert_len,
                                const uint8_t *ca_cert_der,  uint16_t ca_len,
                                cal_pubkey_t  *pub_key_out);

    /* ---- KEM (PQC Week 9, NULL for Classical) ----------------------------- */

    /**
     * @brief KEM Encapsulate (client): given server's KEM public key,
     *        produce ciphertext and shared secret.
     *        NULL for classical backend.
     */
    cal_result_t (*kem_encap)(const cal_pubkey_t *server_pub,
                              uint8_t            *ct_out,       uint16_t *ct_len,
                              uint8_t            *ss_out,       uint16_t *ss_len);

    /**
     * @brief KEM Decapsulate (server): given ciphertext and private key,
     *        recover shared secret.
     *        NULL for classical backend.
     */
    cal_result_t (*kem_decap)(const uint8_t *priv,        uint16_t priv_len,
                              const uint8_t *ct,           uint16_t ct_len,
                              uint8_t       *ss_out,       uint16_t *ss_len);

} cal_backend_t;

/* ============================================================================
 * CONCRETE BACKENDS
 * Defined in their respective .c files; declared extern here.
 * ============================================================================
 */

/** Classical: ECDSA-P256 sign/verify + ECDH-P256 key exchange (TODAY) */
extern const cal_backend_t cal_backend_classical;

/** PQC: ML-DSA-2 sign/verify + ML-KEM-512 key encapsulation (Week 9) */
extern const cal_backend_t cal_backend_pqc;

/** Hybrid: Classical + PQC combined (Week 11) */
extern const cal_backend_t cal_backend_hybrid;

/** Convenience array indexed by cal_mode_t */
extern const cal_backend_t * const cal_backends[CAL_MODE_COUNT];

/* ============================================================================
 * RUNTIME SELECTOR — called by TouchGFX GUI (Week 11)
 * ============================================================================
 */

/**
 * @brief  Switch the active crypto backend at runtime.
 *         Safe to call between authentication sessions.
 *         NOT thread-safe — call only while no auth is in progress.
 * @param  mode  CAL_MODE_CLASSICAL / CAL_MODE_PQC / CAL_MODE_HYBRID
 * @retval CAL_OK or CAL_ERR_NOT_SUPPORTED if mode not yet implemented
 */
cal_result_t cal_select_mode(cal_mode_t mode);

/**
 * @brief  Get the currently active backend (for reading .name, .alg_indicator).
 */
const cal_backend_t *cal_get_backend(void);

/**
 * @brief  Get current mode enum.
 */
cal_mode_t cal_get_mode(void);

#ifdef __cplusplus
}
#endif

#endif /* CAL_BACKEND_H */
