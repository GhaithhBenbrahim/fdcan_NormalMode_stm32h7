/**
 ******************************************************************************
 * @file    uds_types.h
 * @brief   UDS Layer — Common Types, NRC Codes, Limits
 *
 * Contains UDS service IDs, subfunction codes for 0x29, NRC codes,
 * and all message field constants. No crypto types here.
 *
 * @author  Ghaith Ben Brahim
 * @date    2026-03-15
 ******************************************************************************
 */
#ifndef UDS_TYPES_H
#define UDS_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include "cal/cal_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * UDS SERVICE IDs
 * ============================================================================
 */
#define UDS_SID_AUTHENTICATION          0x29U
#define UDS_SID_POSITIVE_RESPONSE_MASK  0x40U
#define UDS_SID_NEGATIVE_RESPONSE       0x7FU

/* 0x29 positive response SID */
#define UDS_SID_AUTH_RESPONSE           (UDS_SID_AUTHENTICATION | UDS_SID_POSITIVE_RESPONSE_MASK)

/* ============================================================================
 * SERVICE 0x29 SUBFUNCTIONS (ISO 14229-1:2020 Table 74)
 * ============================================================================
 */
typedef enum {
    UDS_0x29_SF_DEAUTHENTICATE                      = 0x00U, /**< DA   — end session */
    UDS_0x29_SF_VERIFY_CERT_UNIDIRECTIONAL          = 0x01U, /**< VCU  — send cert   */
    UDS_0x29_SF_VERIFY_CERT_BIDIRECTIONAL           = 0x02U, /**< VCB  — not used    */
    UDS_0x29_SF_PROOF_OF_OWNERSHIP                  = 0x03U, /**< POWN — send proof  */
    UDS_0x29_SF_TRANSMIT_CERTIFICATE                = 0x04U, /**< TC   — optional    */
    UDS_0x29_SF_AUTHENTICATION_CONFIGURATION        = 0x08U, /**< AC   — query caps  */
} uds_0x29_subfunction_t;

/* ============================================================================
 * ALGORITHM INDICATORS (OEM-defined, appear in UDS messages)
 * Maps to cal_algorithm_t — same numeric values.
 * ============================================================================
 */
#define UDS_ALG_IND_ECDSA_P256   0x01U   /**< Classical ECDSA/ECDH P-256 */
#define UDS_ALG_IND_ML_DSA_2     0x10U   /**< PQC ML-DSA-2 (Week 9)      */
#define UDS_ALG_IND_ML_KEM_512   0x11U   /**< PQC ML-KEM-512 (Week 9)    */
#define UDS_ALG_IND_HYBRID       0x20U   /**< Hybrid (Week 11)            */

/* communicationConfiguration byte (offset 2 in VCU request) */
#define UDS_COMM_CFG_SESSION_KEY_REQUEST   0x01U  /**< Bit 0: client requests session key info */

/* ============================================================================
 * NEGATIVE RESPONSE CODES (minimal set for PQC demo scope)
 * ============================================================================
 */
typedef enum {
    UDS_NRC_POSITIVE                         = 0x00U, /**< Not actually sent */
    UDS_NRC_CONDITIONS_NOT_CORRECT           = 0x22U, /**< Wrong session/state */
    UDS_NRC_REQUEST_SEQUENCE_ERROR           = 0x26U, /**< Wrong subfunction order */
    UDS_NRC_REQUEST_OUT_OF_RANGE             = 0x31U, /**< Unsupported algorithm */
    UDS_NRC_INVALID_KEY                      = 0x35U, /**< Cert verify / signature fail */
    UDS_NRC_UPLOAD_DOWNLOAD_NOT_ACCEPTED     = 0x70U, /**< Internal error fallback */
    UDS_NRC_RESPONSE_PENDING                 = 0x78U, /**< Request correctly received - response pending */
} uds_nrc_t;

/* ============================================================================
 * UDS RESULT CODES (internal layer return codes)
 * ============================================================================
 */
typedef enum {
    UDS_OK                      =  0, /**< Success — response ready in TX buf */
    UDS_PENDING                 =  1, /**< Processing async — no response yet  */
    UDS_ERR_INVALID_MSG         = -1,
    UDS_ERR_WRONG_STATE         = -2,
    UDS_ERR_CRYPTO_FAIL         = -3,
    UDS_ERR_CERT_INVALID        = -4,
    UDS_ERR_BUFFER_OVERFLOW     = -5,
    UDS_ERR_UNKNOWN_SUBFUNCTION = -6,
    UDS_ERR_UNKNOWN_ALG         = -7,
    UDS_ERR_TIMEOUT             = -8,
} uds_result_t;

/* ============================================================================
 * TIMING PARAMETERS (ISO 14229-2)
 * ============================================================================
 */
#define UDS_P2_SERVER_MAX                50U     /**< Default response time (ms) */
#define UDS_P2_STAR_SERVER_MAX           5000U   /**< Extended response time (ms) */
#define UDS_RESPONSE_PENDING_INTERVAL    45U     /**< Server sends 0x78 before timeout */

/* ============================================================================
 * MESSAGE SIZE CONSTANTS (ISO 14229-1:2020 §10.4 message formats)
 * ============================================================================
 */

/* VCU Request (0x29 0x01) field sizes */
#define UDS_VCU_REQ_COMM_CFG_OFFSET         2U
#define UDS_VCU_REQ_CERT_LEN_OFFSET         3U   /**< 2-byte big-endian */
#define UDS_VCU_REQ_CERT_DATA_OFFSET        5U
#define UDS_VCU_REQ_MIN_LEN                 6U   /**< SID+SF+commCfg+certLen(2)+algInd */

/* VCU Response (0x69 0x01) fixed field sizes */
#define UDS_VCU_RSP_CHALL_LEN_SIZE          1U
#define UDS_VCU_RSP_CHALL_SIZE              CAL_CHALLENGE_SIZE   /* 32 */
#define UDS_VCU_RSP_EPHKEY_LEN_SIZE         1U
#define UDS_VCU_RSP_EPHKEY_SIZE             CAL_ECDSA_PUBKEY_SIZE /* 65 */
/* Total: 2 (SID+SF) + 1 + 32 + 1 + 65 = 101 bytes */
#define UDS_VCU_RSP_TOTAL_LEN               101U

/* POWN Request (0x29 0x03) field offsets */
#define UDS_POWN_REQ_ALG_IND_OFFSET         2U
#define UDS_POWN_REQ_PROOF_LEN_OFFSET       3U   /**< 2-byte big-endian */
#define UDS_POWN_REQ_PROOF_DATA_OFFSET      5U
#define UDS_POWN_REQ_MIN_LEN                6U

/* POWN Response: SID+SF + keyInfoLen(1) + HMAC(32) = 35 bytes */
#define UDS_POWN_RSP_SESSION_INFO_LEN       CAL_HMAC_SHA256_SIZE  /* 32 */
#define UDS_POWN_RSP_TOTAL_LEN              (2U + 1U + UDS_POWN_RSP_SESSION_INFO_LEN)

/* NRC response: SID_NR(1) + SID(1) + NRC(1) = 3 bytes */
#define UDS_NRC_RESPONSE_LEN                3U

/* ============================================================================
 * PARSED MESSAGE STRUCTS (populated by codec, consumed by server/client)
 * All pointers are into the caller's ISO-TP RX buffer — zero-copy.
 * ============================================================================
 */

/**
 * @brief  Parsed VCU request (0x29 0x01).
 */
typedef struct {
    uint8_t         comm_cfg;           /**< communicationConfiguration byte */
    const uint8_t  *cert;               /**< Pointer into RX buf — DER cert  */
    uint16_t        cert_len;
    const uint8_t  *challenge_client;   /**< Optional client challenge or NULL */
    uint8_t         challenge_client_len;
    uint8_t         alg_indicator;      /**< Algorithm indicator              */
} uds_vcu_request_t;

/**
 * @brief  Parsed VCU response (0x69 0x01).
 */
typedef struct {
    const uint8_t  *challenge_server;   /**< 32-byte server challenge         */
    uint8_t         challenge_server_len;
    const uint8_t  *eph_pubkey_server;  /**< 65-byte uncompressed ECDH pubkey */
    uint8_t         eph_pubkey_server_len;
} uds_vcu_response_t;

/**
 * @brief  Parsed POWN request (0x29 0x03).
 */
typedef struct {
    uint8_t         alg_indicator;
    const uint8_t  *proof;              /**< Signature bytes (DER ECDSA)      */
    uint16_t        proof_len;
    const uint8_t  *challenge_echo;     /**< Optional server challenge echo or NULL */
    uint8_t         challenge_echo_len;
    const uint8_t  *eph_pubkey_client;  /**< 65-byte ephemeral ECDH pubkey    */
    uint8_t         eph_pubkey_client_len;
} uds_pown_request_t;

#ifdef __cplusplus
}
#endif

#endif /* UDS_TYPES_H */
