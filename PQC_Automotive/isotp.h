/**
 ******************************************************************************
 * @file    isotp.h
 * @brief   ISO-TP (ISO 15765-2) — Header for Extended First Frame Support
 *
 * Updated ISOTP_MAX_MESSAGE_SIZE to 15360 bytes (15 KB) to support:
 *   - Classical certs: ~588 B
 *   - ML-DSA-2 certs: ~1500 B (Week 9)
 *   - ML-DSA-87 certs + signatures: up to ~15 KB (worst-case PQC)
 *
 * @author  Ghaith Ben Brahim
 * @date    2026-03-15
 ******************************************************************************
 */
#ifndef ISOTP_H
#define ISOTP_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONFIGURATION CONSTANTS
 * ============================================================================
 */

/** Maximum ISO-TP message size (bytes). Extended FF supports messages > 4095B.
 *  15 KB covers all PQC cert + signature scenarios. */
#define ISOTP_MAX_MESSAGE_SIZE      15360U

/** CAN-FD maximum DLC = 64 bytes */
#define ISOTP_CAN_FD_MAX_DLC        64U

/** Single Frame maximum payload (CAN-FD): 64 - 1 PCI = 63, but spec says 62 */
#define ISOTP_SF_MAX_PAYLOAD        62U

/** Standard First Frame max message length (12-bit field = 4095 max) */
#define ISOTP_STANDARD_FF_LIMIT     4095U

/** Consecutive Frame maximum payload: 64 - 1 PCI = 63 bytes */
#define ISOTP_CF_MAX_PAYLOAD        63U

/** Default block size (0 = send all without waiting for FC) */
#define ISOTP_DEFAULT_BLOCK_SIZE    0U

/** Default STmin in milliseconds */
#define ISOTP_DEFAULT_STMIN_MS      0U

/** Timeout waiting for FC frame after FF (N_Bs = 1000ms per ISO 15765-2) */
#define ISOTP_TIMEOUT_BS_MS         1000U

/** Timeout waiting for CF frame (N_Cr = 1000ms per ISO 15765-2) */
#define ISOTP_TIMEOUT_CR_MS         1000U

/** Maximum number of WAIT frames before aborting */
#define ISOTP_MAX_WAIT_FRAMES       10U

/* ============================================================================
 * DEBUG LOGGING
 * ============================================================================
 */
#ifdef ISOTP_DEBUG_ENABLE
    #include <stdio.h>
    #define ISOTP_DEBUG(fmt, ...) printf("[ISO-TP] " fmt, ##__VA_ARGS__)
#else
    #define ISOTP_DEBUG(fmt, ...) do {} while(0)
#endif

/* ============================================================================
 * PCI TYPES
 * ============================================================================
 */
typedef enum {
    ISOTP_PCI_TYPE_SF = 0x00,   /**< Single Frame       */
    ISOTP_PCI_TYPE_FF = 0x01,   /**< First Frame        */
    ISOTP_PCI_TYPE_CF = 0x02,   /**< Consecutive Frame  */
    ISOTP_PCI_TYPE_FC = 0x03,   /**< Flow Control       */
} isotp_pci_type_t;

typedef enum {
    ISOTP_FC_STATUS_CTS      = 0x00,   /**< Continue To Send */
    ISOTP_FC_STATUS_WAIT     = 0x01,   /**< Wait             */
    ISOTP_FC_STATUS_OVERFLOW = 0x02,   /**< Overflow         */
} isotp_fc_status_t;

/* ============================================================================
 * STATE MACHINE
 * ============================================================================
 */
typedef enum {
    ISOTP_STATE_IDLE          = 0x00,
    ISOTP_STATE_TX_WAIT_FC    = 0x01,
    ISOTP_STATE_TX_CF         = 0x02,
    ISOTP_STATE_RX_CF         = 0x10,
} isotp_state_t;

/* ============================================================================
 * RESULT CODES
 * ============================================================================
 */
typedef enum {
    ISOTP_OK                  =  0,
    ISOTP_ERROR_INVALID       = -1,
    ISOTP_ERROR_BUSY          = -2,
    ISOTP_ERROR_TIMEOUT_BS    = -3,
    ISOTP_ERROR_TIMEOUT_CR    = -4,
    ISOTP_ERROR_OVERFLOW      = -5,
    ISOTP_ERROR_INVALID_SN    = -6,
    ISOTP_ERROR_INVALID_FS    = -7,
    ISOTP_ERROR_UNEXPECTED    = -8,
    ISOTP_ERROR_WFT_OVRN      = -9,
} isotp_result_t;

/* ============================================================================
 * INSTANCE STRUCTURE
 * Buffers are static — 15 KB TX + 15 KB RX = 30 KB total per instance.
 * On STM32H7B3 (1.4 MB RAM) this is well within budget.
 * ============================================================================
 */
typedef struct {
    /* CAN IDs */
    uint32_t tx_id;
    uint32_t rx_id;

    /* TX state */
    isotp_state_t tx_state;
    uint8_t       tx_buffer[ISOTP_MAX_MESSAGE_SIZE];
    uint32_t      tx_length;
    uint32_t      tx_index;
    uint8_t       tx_sn;
    uint8_t       tx_bs;
    uint8_t       tx_bs_counter;
    uint8_t       tx_stmin;
    uint8_t       tx_wft_counter;
    uint32_t      tx_timestamp;
    uint32_t      tx_timeout_start;

    /* RX state */
    isotp_state_t rx_state;
    uint8_t       rx_buffer[ISOTP_MAX_MESSAGE_SIZE];
    uint32_t      rx_length;
    uint32_t      rx_index;
    uint8_t       rx_sn;
    uint8_t       rx_bs_counter;
    uint32_t      rx_timeout_start;

    /* HAL callbacks (set before calling isotp_send/isotp_receive_can_frame) */
    isotp_result_t (*send_can_frame)(uint32_t id, const uint8_t *data, uint8_t dlc);
    uint32_t       (*get_timestamp_ms)(void);

    /* User callbacks */
    void (*tx_callback)(isotp_result_t result);
    void (*rx_callback)(uint8_t *data, uint16_t length, isotp_result_t result);

} isotp_instance_t;

/* ============================================================================
 * PUBLIC API
 * ============================================================================
 */

isotp_result_t isotp_init(isotp_instance_t *instance, uint32_t tx_id, uint32_t rx_id);
isotp_result_t isotp_send(isotp_instance_t *instance, const uint8_t *data, uint32_t length);
isotp_result_t isotp_process(isotp_instance_t *instance);
isotp_result_t isotp_receive_can_frame(isotp_instance_t *instance,
                                        uint32_t can_id,
                                        const uint8_t *data,
                                        uint8_t dlc);

void           isotp_set_tx_callback(isotp_instance_t *instance,
                                      void (*callback)(isotp_result_t result));
void           isotp_set_rx_callback(isotp_instance_t *instance,
                                      void (*callback)(uint8_t *data, uint16_t length,
                                                        isotp_result_t result));

isotp_state_t  isotp_get_tx_state(const isotp_instance_t *instance);
isotp_state_t  isotp_get_rx_state(const isotp_instance_t *instance);
bool           isotp_is_tx_idle(const isotp_instance_t *instance);
void           isotp_abort_tx(isotp_instance_t *instance);
void           isotp_abort_rx(isotp_instance_t *instance);

#ifdef __cplusplus
}
#endif

#endif /* ISOTP_H */
