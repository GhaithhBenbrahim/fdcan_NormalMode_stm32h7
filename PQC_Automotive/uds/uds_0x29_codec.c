/**
 ******************************************************************************
 * @file    uds_0x29_codec.c
 * @brief   UDS 0x29 Message Encoder / Decoder Implementation
 *
 * Pure message parsing — no crypto, no state, fully testable in isolation.
 * All decoders return pointers into the source buffer (zero-copy).
 *
 * @author  Ghaith Ben Brahim
 * @date    2026-03-15
 ******************************************************************************
 */

#include "uds_0x29_codec.h"
#include <string.h>

/* ============================================================================
 * PRIVATE HELPERS
 * ============================================================================
 */

/** Read a 16-bit big-endian value */
static inline uint16_t read_u16_be(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8U) | p[1]);
}

/** Write a 16-bit big-endian value */
static inline void write_u16_be(uint8_t *p, uint16_t val)
{
    p[0] = (uint8_t)(val >> 8U);
    p[1] = (uint8_t)(val & 0xFFU);
}

/* ============================================================================
 * DECODERS
 * ============================================================================
 */

uds_result_t uds_0x29_decode_vcu_request(const uint8_t     *buf,
                                          uint16_t           len,
                                          uds_vcu_request_t *out)
{
    if (buf == NULL || out == NULL) return UDS_ERR_INVALID_MSG;

    /* Minimum: SID(1) + SF(1) + commCfg(1) + certLen(2) + algInd(1) = 6 */
    if (len < UDS_VCU_REQ_MIN_LEN) return UDS_ERR_INVALID_MSG;

    /* Validate SID and subfunction */
    if (buf[0] != UDS_SID_AUTHENTICATION)             return UDS_ERR_INVALID_MSG;
    if (buf[1] != UDS_0x29_SF_VERIFY_CERT_UNIDIRECTIONAL) return UDS_ERR_INVALID_MSG;

    out->comm_cfg  = buf[UDS_VCU_REQ_COMM_CFG_OFFSET];

    /* Certificate length (2-byte big-endian at offset 3) */
    uint16_t cert_len = read_u16_be(&buf[UDS_VCU_REQ_CERT_LEN_OFFSET]);
    if (cert_len == 0U) return UDS_ERR_INVALID_MSG;

    /* Bounds check: offset 5 + cert_len must fit in buf */
    uint32_t after_cert = (uint32_t)UDS_VCU_REQ_CERT_DATA_OFFSET + cert_len;
    if (after_cert > (uint32_t)len) return UDS_ERR_INVALID_MSG;

    out->cert     = &buf[UDS_VCU_REQ_CERT_DATA_OFFSET];
    out->cert_len = cert_len;

    uint16_t pos = (uint16_t)after_cert;

    /* Optional client challenge length (1 byte) */
    if (pos >= len) return UDS_ERR_INVALID_MSG;   /* Need at least algInd */
    uint8_t chall_len = buf[pos++];

    if (chall_len > 0U) {
        if ((uint32_t)pos + chall_len > (uint32_t)len) return UDS_ERR_INVALID_MSG;
        out->challenge_client     = &buf[pos];
        out->challenge_client_len = chall_len;
        pos += chall_len;
    } else {
        out->challenge_client     = NULL;
        out->challenge_client_len = 0U;
    }

    /* Algorithm indicator (last byte) */
    if (pos >= len) return UDS_ERR_INVALID_MSG;
    out->alg_indicator = buf[pos];

    return UDS_OK;
}

/* -------------------------------------------------------------------------- */

uds_result_t uds_0x29_decode_vcu_response(const uint8_t      *buf,
                                           uint16_t            len,
                                           uds_vcu_response_t *out)
{
    if (buf == NULL || out == NULL) return UDS_ERR_INVALID_MSG;

    /* Minimum: SID(1)+SF(1)+challLen(1)+chall(≥1)+keyLen(1)+key(≥1) = 6 */
    if (len < 6U) return UDS_ERR_INVALID_MSG;

    if (buf[0] != UDS_SID_AUTH_RESPONSE)                        return UDS_ERR_INVALID_MSG;
    if (buf[1] != UDS_0x29_SF_VERIFY_CERT_UNIDIRECTIONAL)       return UDS_ERR_INVALID_MSG;

    uint16_t pos = 2U;

    /* challengeServerLength */
    uint8_t chall_len = buf[pos++];
    if (chall_len == 0U || (uint32_t)pos + chall_len > (uint32_t)len) {
        return UDS_ERR_INVALID_MSG;
    }
    out->challenge_server     = &buf[pos];
    out->challenge_server_len = chall_len;
    pos += chall_len;

    /* ephemeralPublicKeyServerLength */
    if (pos >= len) return UDS_ERR_INVALID_MSG;
    uint8_t key_len = buf[pos++];
    if (key_len == 0U || (uint32_t)pos + key_len > (uint32_t)len) {
        return UDS_ERR_INVALID_MSG;
    }
    out->eph_pubkey_server     = &buf[pos];
    out->eph_pubkey_server_len = key_len;

    return UDS_OK;
}

/* -------------------------------------------------------------------------- */

uds_result_t uds_0x29_decode_pown_request(const uint8_t      *buf,
                                           uint16_t            len,
                                           uds_pown_request_t *out)
{
    if (buf == NULL || out == NULL) return UDS_ERR_INVALID_MSG;

    /* Minimum: SID(1)+SF(1)+algInd(1)+proofLen(2)+proof(≥1) = 6 */
    if (len < UDS_POWN_REQ_MIN_LEN) return UDS_ERR_INVALID_MSG;

    if (buf[0] != UDS_SID_AUTHENTICATION)        return UDS_ERR_INVALID_MSG;
    if (buf[1] != UDS_0x29_SF_PROOF_OF_OWNERSHIP) return UDS_ERR_INVALID_MSG;

    out->alg_indicator = buf[UDS_POWN_REQ_ALG_IND_OFFSET];

    /* proofOfOwnershipClientLength (2-byte big-endian) */
    uint16_t proof_len = read_u16_be(&buf[UDS_POWN_REQ_PROOF_LEN_OFFSET]);
    if (proof_len == 0U) return UDS_ERR_INVALID_MSG;

    uint32_t after_proof = (uint32_t)UDS_POWN_REQ_PROOF_DATA_OFFSET + proof_len;
    if (after_proof > (uint32_t)len) return UDS_ERR_INVALID_MSG;

    out->proof     = &buf[UDS_POWN_REQ_PROOF_DATA_OFFSET];
    out->proof_len = proof_len;

    uint16_t pos = (uint16_t)after_proof;

    /* Optional server challenge echo length (1 byte) */
    if (pos >= len) return UDS_ERR_INVALID_MSG;
    uint8_t echo_len = buf[pos++];
    if (echo_len > 0U) {
        if ((uint32_t)pos + echo_len > (uint32_t)len) return UDS_ERR_INVALID_MSG;
        out->challenge_echo     = &buf[pos];
        out->challenge_echo_len = echo_len;
        pos += echo_len;
    } else {
        out->challenge_echo     = NULL;
        out->challenge_echo_len = 0U;
    }

    /* ephemeralPublicKeyClientLength (1 byte) */
    if (pos >= len) return UDS_ERR_INVALID_MSG;
    uint8_t eph_key_len = buf[pos++];
    if (eph_key_len == 0U || (uint32_t)pos + eph_key_len > (uint32_t)len) {
        return UDS_ERR_INVALID_MSG;
    }

    /* Reuse cal_pubkey_t for structured access by server */
    static cal_pubkey_t s_eph_client_pub; /* temporary decode buffer */
    if (eph_key_len > CAL_MAX_PUBKEY_SIZE) return UDS_ERR_INVALID_MSG;
    memcpy(s_eph_client_pub.bytes, &buf[pos], eph_key_len);
    s_eph_client_pub.length = eph_key_len;
    s_eph_client_pub.alg    = CAL_ALG_ECDSA_P256;

    out->eph_pubkey_client     = &buf[pos];  /* raw pointer for reference */
    out->eph_pubkey_client_len = eph_key_len;

    return UDS_OK;
}

/* ============================================================================
 * ENCODERS
 * ============================================================================
 */

uint16_t uds_0x29_encode_vcu_response(uint8_t           *buf,
                                       uint16_t           buf_len,
                                       const uint8_t      challenge_server[CAL_CHALLENGE_SIZE],
                                       const cal_pubkey_t *eph_pub_server)
{
    if (buf == NULL || challenge_server == NULL || eph_pub_server == NULL) return 0U;
    if (buf_len < UDS_VCU_RSP_TOTAL_LEN) return 0U;

    uint16_t pos = 0U;

    buf[pos++] = UDS_SID_AUTH_RESPONSE;                        /* 0x69 */
    buf[pos++] = UDS_0x29_SF_VERIFY_CERT_UNIDIRECTIONAL;       /* 0x01 */

    /* challengeServer */
    buf[pos++] = (uint8_t)CAL_CHALLENGE_SIZE;                  /* 32   */
    memcpy(&buf[pos], challenge_server, CAL_CHALLENGE_SIZE);
    pos += CAL_CHALLENGE_SIZE;

    /* ephemeralPublicKeyServer */
    buf[pos++] = (uint8_t)eph_pub_server->length;              /* 65   */
    memcpy(&buf[pos], eph_pub_server->bytes, eph_pub_server->length);
    pos += eph_pub_server->length;

    return pos;
}

/* -------------------------------------------------------------------------- */

uint16_t uds_0x29_encode_pown_response(uint8_t       *buf,
                                        uint16_t       buf_len,
                                        const uint8_t  session_key_info[CAL_HMAC_SHA256_SIZE])
{
    if (buf == NULL || session_key_info == NULL) return 0U;
    if (buf_len < UDS_POWN_RSP_TOTAL_LEN)        return 0U;

    uint16_t pos = 0U;

    buf[pos++] = UDS_SID_AUTH_RESPONSE;                /* 0x69 */
    buf[pos++] = UDS_0x29_SF_PROOF_OF_OWNERSHIP;       /* 0x03 */
    buf[pos++] = (uint8_t)UDS_POWN_RSP_SESSION_INFO_LEN; /* 32 */
    memcpy(&buf[pos], session_key_info, UDS_POWN_RSP_SESSION_INFO_LEN);
    pos += UDS_POWN_RSP_SESSION_INFO_LEN;

    return pos;   /* 35 bytes */
}

/* -------------------------------------------------------------------------- */

uint16_t uds_0x29_encode_nrc(uint8_t   *buf,
                              uint16_t   buf_len,
                              uint8_t    sid,
                              uds_nrc_t  nrc)
{
    if (buf == NULL || buf_len < UDS_NRC_RESPONSE_LEN) return 0U;

    buf[0] = UDS_SID_NEGATIVE_RESPONSE;  /* 0x7F */
    buf[1] = sid;
    buf[2] = (uint8_t)nrc;

    return UDS_NRC_RESPONSE_LEN;
}

/* -------------------------------------------------------------------------- */

uint16_t uds_0x29_encode_vcu_request(uint8_t       *buf,         uint16_t  buf_len,
                                      uint8_t        comm_cfg,
                                      const uint8_t *cert_der,    uint16_t  cert_len,
                                      const uint8_t *challenge_client,
                                      uint8_t        chall_client_len,
                                      uint8_t        alg_indicator)
{
    if (buf == NULL || cert_der == NULL || cert_len == 0U) return 0U;

    /* Calculate total size */
    uint32_t total = 2U               /* SID + SF     */
                   + 1U               /* commCfg      */
                   + 2U               /* certLen      */
                   + cert_len
                   + 1U               /* challClientLen */
                   + chall_client_len
                   + 1U;              /* algIndicator */

    if (total > buf_len) return 0U;

    uint16_t pos = 0U;

    buf[pos++] = UDS_SID_AUTHENTICATION;
    buf[pos++] = UDS_0x29_SF_VERIFY_CERT_UNIDIRECTIONAL;
    buf[pos++] = comm_cfg;

    write_u16_be(&buf[pos], cert_len);
    pos += 2U;

    memcpy(&buf[pos], cert_der, cert_len);
    pos += cert_len;

    buf[pos++] = chall_client_len;
    if (chall_client_len > 0U && challenge_client != NULL) {
        memcpy(&buf[pos], challenge_client, chall_client_len);
        pos += chall_client_len;
    }

    buf[pos++] = alg_indicator;

    return pos;
}

/* -------------------------------------------------------------------------- */

uint16_t uds_0x29_encode_pown_request(uint8_t           *buf,        uint16_t buf_len,
                                       uint8_t            alg_indicator,
                                       const uint8_t     *proof,       uint16_t proof_len,
                                       const uint8_t     *challenge_echo,
                                       uint8_t            chall_echo_len,
                                       const cal_pubkey_t *eph_pub_client)
{
    if (buf == NULL || proof == NULL || eph_pub_client == NULL) return 0U;

    uint32_t total = 2U               /* SID + SF       */
                   + 1U               /* algIndicator   */
                   + 2U               /* proofLen       */
                   + proof_len
                   + 1U               /* challEchoLen   */
                   + chall_echo_len
                   + 1U               /* ephKeyLen      */
                   + eph_pub_client->length;

    if (total > buf_len) return 0U;

    uint16_t pos = 0U;

    buf[pos++] = UDS_SID_AUTHENTICATION;
    buf[pos++] = UDS_0x29_SF_PROOF_OF_OWNERSHIP;
    buf[pos++] = alg_indicator;

    write_u16_be(&buf[pos], proof_len);
    pos += 2U;

    memcpy(&buf[pos], proof, proof_len);
    pos += proof_len;

    buf[pos++] = chall_echo_len;
    if (chall_echo_len > 0U && challenge_echo != NULL) {
        memcpy(&buf[pos], challenge_echo, chall_echo_len);
        pos += chall_echo_len;
    }

    buf[pos++] = (uint8_t)eph_pub_client->length;
    memcpy(&buf[pos], eph_pub_client->bytes, eph_pub_client->length);
    pos += eph_pub_client->length;

    return pos;
}
