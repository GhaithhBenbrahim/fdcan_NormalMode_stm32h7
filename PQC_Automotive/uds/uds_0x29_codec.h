/**
 ******************************************************************************
 * @file    uds_0x29_codec.h
 * @brief   UDS 0x29 Message Encoder / Decoder (no crypto, no state)
 *
 * Pure message serialisation: takes raw byte buffers from ISO-TP and
 * returns populated structs with pointers into the original buffer (zero-copy).
 * Likewise, encodes response structs into caller-provided TX buffers.
 *
 * @author  Ghaith Ben Brahim
 * @date    2026-03-15
 ******************************************************************************
 */
#ifndef UDS_0x29_CODEC_H
#define UDS_0x29_CODEC_H

#include "uds_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * DECODERS — populate structs with zero-copy pointers into RX buffer
 * ============================================================================
 */

/**
 * @brief  Decode a VCU request (SID=0x29, SF=0x01).
 * @param  buf     Raw ISO-TP payload (starting at SID byte)
 * @param  len     Payload length
 * @param  out     Populated on success (pointers into buf — do not free buf!)
 * @retval UDS_OK or UDS_ERR_INVALID_MSG
 */
uds_result_t uds_0x29_decode_vcu_request(const uint8_t       *buf,
                                          uint16_t             len,
                                          uds_vcu_request_t   *out);

/**
 * @brief  Decode a VCU response (SID=0x69, SF=0x01) — used by CLIENT side.
 * @param  buf     Raw ISO-TP payload
 * @param  len     Payload length
 * @param  out     Populated on success
 * @retval UDS_OK or UDS_ERR_INVALID_MSG
 */
uds_result_t uds_0x29_decode_vcu_response(const uint8_t        *buf,
                                           uint16_t              len,
                                           uds_vcu_response_t   *out);

/**
 * @brief  Decode a POWN request (SID=0x29, SF=0x03) — used by SERVER side.
 * @param  buf     Raw ISO-TP payload
 * @param  len     Payload length
 * @param  out     Populated on success
 * @retval UDS_OK or UDS_ERR_INVALID_MSG
 */
uds_result_t uds_0x29_decode_pown_request(const uint8_t        *buf,
                                           uint16_t              len,
                                           uds_pown_request_t   *out);

/* ============================================================================
 * ENCODERS — write response into caller-provided TX buffer
 * Returns number of bytes written, or 0 on error.
 * ============================================================================
 */

/**
 * @brief  Encode VCU positive response (0x69 0x01).
 *         Format: [0x69][0x01][chall_len(1)][chall(32)][key_len(1)][key(65)]
 * @param  buf              TX buffer
 * @param  buf_len          TX buffer capacity
 * @param  challenge_server 32-byte server nonce (freshly generated)
 * @param  eph_pub_server   Server's ephemeral ECDH public key (65 bytes)
 * @retval Bytes written (101) or 0 on buffer overflow
 */
uint16_t uds_0x29_encode_vcu_response(uint8_t           *buf,
                                       uint16_t           buf_len,
                                       const uint8_t      challenge_server[CAL_CHALLENGE_SIZE],
                                       const cal_pubkey_t *eph_pub_server);

/**
 * @brief  Encode POWN positive response (0x69 0x03) with sessionKeyInfo.
 *         Format: [0x69][0x03][info_len(1)][session_key_info(32)]
 *         sessionKeyInfo = HMAC-SHA256(session_key, "ECU-SESSION-PROOF" || challenge_server)
 * @param  buf              TX buffer
 * @param  buf_len          TX buffer capacity
 * @param  session_key_info 32-byte HMAC proof (pre-computed by server)
 * @retval Bytes written (35) or 0 on buffer overflow
 */
uint16_t uds_0x29_encode_pown_response(uint8_t       *buf,
                                        uint16_t       buf_len,
                                        const uint8_t  session_key_info[CAL_HMAC_SHA256_SIZE]);

/**
 * @brief  Encode a Negative Response Code message.
 *         Format: [0x7F][SID][NRC]
 * @param  buf     TX buffer (must be >= 3 bytes)
 * @param  buf_len TX buffer capacity
 * @param  sid     Service ID that triggered the NRC
 * @param  nrc     Negative response code (uds_nrc_t)
 * @retval Bytes written (3) or 0
 */
uint16_t uds_0x29_encode_nrc(uint8_t *buf, uint16_t buf_len,
                              uint8_t  sid,  uds_nrc_t nrc);

/**
 * @brief  Encode a VCU request (0x29 0x01) — used by CLIENT side.
 * @param  buf              TX buffer
 * @param  buf_len          TX buffer capacity
 * @param  comm_cfg         communicationConfiguration (use UDS_COMM_CFG_SESSION_KEY_REQUEST)
 * @param  cert_der         Client DER certificate
 * @param  cert_len         Certificate length
 * @param  challenge_client Optional client challenge (NULL to omit)
 * @param  chall_client_len Challenge length (0 to omit)
 * @param  alg_indicator    Algorithm indicator (UDS_ALG_IND_ECDSA_P256)
 * @retval Bytes written or 0 on overflow
 */
uint16_t uds_0x29_encode_vcu_request(uint8_t       *buf,         uint16_t  buf_len,
                                      uint8_t        comm_cfg,
                                      const uint8_t *cert_der,    uint16_t  cert_len,
                                      const uint8_t *challenge_client,
                                      uint8_t        chall_client_len,
                                      uint8_t        alg_indicator);

/**
 * @brief  Encode a POWN request (0x29 0x03) — used by CLIENT side.
 * @param  buf              TX buffer
 * @param  buf_len          TX buffer capacity
 * @param  alg_indicator    Algorithm indicator
 * @param  proof            ECDSA signature (DER)
 * @param  proof_len        Signature length
 * @param  challenge_echo   Server challenge echo (NULL to omit)
 * @param  chall_echo_len   Echo length (0 to omit)
 * @param  eph_pub_client   Client's ephemeral ECDH public key
 * @retval Bytes written or 0 on overflow
 */
uint16_t uds_0x29_encode_pown_request(uint8_t           *buf,        uint16_t buf_len,
                                       uint8_t            alg_indicator,
                                       const uint8_t     *proof,       uint16_t proof_len,
                                       const uint8_t     *challenge_echo,
                                       uint8_t            chall_echo_len,
                                       const cal_pubkey_t *eph_pub_client);

#ifdef __cplusplus
}
#endif

#endif /* UDS_0x29_CODEC_H */
