/**
 ******************************************************************************
 * @file    uds_core.h
 * @brief   UDS Core — SID Dispatcher
 *
 * Receives complete ISO-TP payloads and routes them to the correct
 * service handler (currently only 0x29). Designed for non-blocking
 * use from both bare-metal callbacks and FreeRTOS tasks.
 *
 * Bare-metal usage:
 *   Set up the ISO-TP RX callback to call uds_core_process():
 *
 *     void isotp_rx_cb(uint8_t *data, uint16_t len, isotp_result_t result) {
 *         if (result == ISOTP_OK) {
 *             uint16_t tx_len = 0;
 *             uds_core_process(data, len, g_tx_buf, &tx_len);
 *             if (tx_len > 0) isotp_send(&g_inst, g_tx_buf, tx_len);
 *         }
 *     }
 *
 * FreeRTOS usage (Week 12):
 *   Replace the callback with a queue push, then poll uds_core_process()
 *   from the UDS task — no code changes inside this module.
 *
 * @author  Ghaith Ben Brahim
 * @date    2026-03-15
 ******************************************************************************
 */
#ifndef UDS_CORE_H
#define UDS_CORE_H

#include "uds_types.h"
#include "uds_0x29_server.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CORE CONFIGURATION
 * ============================================================================
 */
typedef struct {
    uds_srv_config_t auth_cfg;   /**< Config for service 0x29 (CA cert etc.) */
} uds_core_config_t;

/* ============================================================================
 * API
 * ============================================================================
 */

/**
 * @brief  Initialise UDS core with service configurations.
 *         Also calls cal_init() — call this once at startup.
 * @param  cfg  Core configuration
 * @retval UDS_OK or error
 */
uds_result_t uds_core_init(const uds_core_config_t *cfg);

/**
 * @brief  Reset the authentication state machine (e.g. on session timeout).
 */
void uds_core_reset_auth(void);

/**
 * @brief  Process a complete incoming UDS message.
 *
 *         Call from ISO-TP RX callback (bare-metal) or UDS task (RTOS).
 *         Dispatches on SID byte (rx_buf[0]).
 *
 * @param  rx_buf   ISO-TP payload
 * @param  rx_len   Payload length
 * @param  tx_buf   Buffer for response (caller-allocated, >= 256 bytes)
 * @param  tx_len   [out] Response length (0 = no response to send)
 * @retval UDS_OK on positive response, negative on internal errors
 *         (an NRC is still placed in tx_buf on most errors)
 */
uds_result_t uds_core_process(const uint8_t *rx_buf, uint16_t  rx_len,
                               uint8_t       *tx_buf, uint16_t *tx_len);

/**
 * @brief  Access the internal server context (for session key retrieval).
 */
const uds_srv_ctx_t *uds_core_get_server_ctx(void);

#ifdef __cplusplus
}
#endif

#endif /* UDS_CORE_H */
