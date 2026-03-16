/**
 ******************************************************************************
 * @file    isotp.c
 * @brief   ISO-TP (ISO 15765-2) Implementation for STM32H7 + CAN-FD
 * @author  Ghaith Ben Brahim
 * @date    2026-02-26
 ******************************************************************************
 */

#include "isotp.h"
#include <string.h>

/* ============================================================================
 * PRIVATE MACROS
 * ============================================================================
 */

/* Protocol Control Information (PCI) byte masks */
#define PCI_TYPE_MASK      0xF0
#define PCI_SF_DL_MASK     0x0F
#define PCI_FF_DL_HIGH     0x0F
#define PCI_CF_SN_MASK     0x0F
#define PCI_FC_FS_MASK     0x0F

/* Calculate elapsed time handling uint32_t wraparound */
#define ELAPSED_TIME_MS(start, now)  ((now) >= (start) ? ((now) - (start)) : (UINT32_MAX - (start) + (now)))

/* ============================================================================
 * PRIVATE FUNCTION PROTOTYPES
 * ============================================================================
 */

static isotp_result_t send_single_frame(isotp_instance_t* inst, const uint8_t* data, uint8_t length);
static isotp_result_t send_first_frame(isotp_instance_t* inst);
static isotp_result_t send_consecutive_frame(isotp_instance_t* inst);
static isotp_result_t send_flow_control(isotp_instance_t* inst, isotp_fc_status_t status);

static isotp_result_t handle_single_frame(isotp_instance_t* inst, const uint8_t* data, uint8_t dlc);
static isotp_result_t handle_first_frame(isotp_instance_t* inst, const uint8_t* data, uint8_t dlc);
static isotp_result_t handle_consecutive_frame(isotp_instance_t* inst, const uint8_t* data, uint8_t dlc);
static isotp_result_t handle_flow_control(isotp_instance_t* inst, const uint8_t* data, uint8_t dlc);

static void complete_transmission(isotp_instance_t* inst, isotp_result_t result);
static void complete_reception(isotp_instance_t* inst, isotp_result_t result);

static bool check_timeout(uint32_t start_time, uint32_t current_time, uint32_t timeout_ms);

/* ============================================================================
 * PUBLIC FUNCTIONS - API IMPLEMENTATION
 * ============================================================================
 */

isotp_result_t isotp_init(isotp_instance_t* instance, uint32_t tx_id, uint32_t rx_id)
{
    if (instance == NULL) {
        return ISOTP_ERROR_INVALID;
    }
    
    /* Clear entire structure */
    memset(instance, 0, sizeof(isotp_instance_t));
    
    /* Set CAN IDs */
    instance->tx_id = tx_id;
    instance->rx_id = rx_id;
    
    /* Initialize state machines */
    instance->tx_state = ISOTP_STATE_IDLE;
    instance->rx_state = ISOTP_STATE_IDLE;
    
    ISOTP_DEBUG("ISO-TP: Initialized (TX=0x%03lX, RX=0x%03lX)\r\n", tx_id, rx_id);
    
    return ISOTP_OK;
}

isotp_result_t isotp_send(isotp_instance_t* instance, const uint8_t* data, uint32_t length)
{
    if (instance == NULL || data == NULL) {
        return ISOTP_ERROR_INVALID;
    }
    
    if (length == 0 || length > ISOTP_MAX_MESSAGE_SIZE) {
        ISOTP_DEBUG("ISO-TP: Invalid length %u\r\n", length);
        return ISOTP_ERROR_INVALID;
    }
    
    /* Check if transmitter is busy */
    if (instance->tx_state != ISOTP_STATE_IDLE) {
        ISOTP_DEBUG("ISO-TP: TX busy\r\n");
        return ISOTP_ERROR_BUSY;
    }
    
    /* Check HAL function pointer */
    if (instance->send_can_frame == NULL) {
        ISOTP_DEBUG("ISO-TP: send_can_frame not configured\r\n");
        return ISOTP_ERROR_INVALID;
    }
    
    /* Copy data to TX buffer */
    memcpy(instance->tx_buffer, data, length);
    instance->tx_length = length;
    instance->tx_index = 0;
    instance->tx_sn = 1;  // Sequence starts at 1 (0 is reserved)
    instance->tx_bs_counter = 0;
    instance->tx_wft_counter = 0;
    
    /* Single Frame: ≤ 62 bytes */
    if (length <= ISOTP_SF_MAX_PAYLOAD) {
        return send_single_frame(instance, data, (uint8_t)length);
    }
    
    /* Multi-Frame: > 62 bytes */
    return send_first_frame(instance);
}

isotp_result_t isotp_process(isotp_instance_t* instance)
{
    if (instance == NULL || instance->get_timestamp_ms == NULL) {
        return ISOTP_ERROR_INVALID;
    }
    
    uint32_t current_time = instance->get_timestamp_ms();
    
    /* ========================================================================
     * TX STATE MACHINE
     * ========================================================================
     */
    switch (instance->tx_state) {
        case ISOTP_STATE_TX_WAIT_FC:
            /* Waiting for Flow Control - check timeout */
            if (check_timeout(instance->tx_timeout_start, current_time, ISOTP_TIMEOUT_BS_MS)) {
                ISOTP_DEBUG("ISO-TP: Timeout waiting for FC\r\n");
                complete_transmission(instance, ISOTP_ERROR_TIMEOUT_BS);
                return ISOTP_ERROR_TIMEOUT_BS;
            }
            break;
            
        case ISOTP_STATE_TX_CF:
            /* Check if STmin elapsed */
            if (instance->tx_stmin > 0) {
                uint32_t elapsed = ELAPSED_TIME_MS(instance->tx_timestamp, current_time);
                if (elapsed < instance->tx_stmin) {
                    break;  // Wait for STmin
                }
            }
            
            /* Send next Consecutive Frame */
            send_consecutive_frame(instance);
            break;
            
        default:
            break;
    }
    
    /* ========================================================================
     * RX STATE MACHINE
     * ========================================================================
     */
    switch (instance->rx_state) {
        case ISOTP_STATE_RX_CF:
            /* Waiting for Consecutive Frame - check timeout */
            if (check_timeout(instance->rx_timeout_start, current_time, ISOTP_TIMEOUT_CR_MS)) {
                ISOTP_DEBUG("ISO-TP: Timeout waiting for CF\r\n");
                complete_reception(instance, ISOTP_ERROR_TIMEOUT_CR);
                return ISOTP_ERROR_TIMEOUT_CR;
            }
            break;
            
        default:
            break;
    }
    
    return ISOTP_OK;
}

isotp_result_t isotp_receive_can_frame(isotp_instance_t* instance, 
                                        uint32_t can_id, 
                                        const uint8_t* data, 
                                        uint8_t dlc)
{
    if (instance == NULL || data == NULL || dlc == 0) {
        return ISOTP_ERROR_INVALID;
    }
    
    /* Filter: only process frames with our RX ID */
    if (can_id != instance->rx_id) {
        return ISOTP_OK;  // Ignore, not for us
    }
    
    /* Extract PCI type from first byte */
    uint8_t pci_type = (data[0] & PCI_TYPE_MASK) >> 4;
    
    switch (pci_type) {
        case ISOTP_PCI_TYPE_SF:
            return handle_single_frame(instance, data, dlc);
            
        case ISOTP_PCI_TYPE_FF:
            return handle_first_frame(instance, data, dlc);
            
        case ISOTP_PCI_TYPE_CF:
            return handle_consecutive_frame(instance, data, dlc);
            
        case ISOTP_PCI_TYPE_FC:
            return handle_flow_control(instance, data, dlc);
            
        default:
            ISOTP_DEBUG("ISO-TP: Unknown PCI type 0x%X\r\n", pci_type);
            return ISOTP_ERROR_UNEXPECTED;
    }
}

/* Continue with setter functions... */
void isotp_set_tx_callback(isotp_instance_t* instance, 
                            void (*callback)(isotp_result_t result))
{
    if (instance != NULL) {
        instance->tx_callback = callback;
    }
}

void isotp_set_rx_callback(isotp_instance_t* instance, 
                            void (*callback)(uint8_t* data, uint16_t length, isotp_result_t result))
{
    if (instance != NULL) {
        instance->rx_callback = callback;
    }
}

isotp_state_t isotp_get_tx_state(const isotp_instance_t* instance)
{
    return (instance != NULL) ? instance->tx_state : ISOTP_STATE_IDLE;
}

isotp_state_t isotp_get_rx_state(const isotp_instance_t* instance)
{
    return (instance != NULL) ? instance->rx_state : ISOTP_STATE_IDLE;
}

bool isotp_is_tx_idle(const isotp_instance_t* instance)
{
    return (instance != NULL) && (instance->tx_state == ISOTP_STATE_IDLE);
}

void isotp_abort_tx(isotp_instance_t* instance)
{
    if (instance != NULL) {
        instance->tx_state = ISOTP_STATE_IDLE;
        instance->tx_length = 0;
        ISOTP_DEBUG("ISO-TP: TX aborted\r\n");
    }
}

void isotp_abort_rx(isotp_instance_t* instance)
{
    if (instance != NULL) {
        instance->rx_state = ISOTP_STATE_IDLE;
        instance->rx_length = 0;
        ISOTP_DEBUG("ISO-TP: RX aborted\r\n");
    }
}

/* ============================================================================
 * PRIVATE FUNCTIONS - TRANSMISSION
 * ============================================================================
 */

/**
 * @brief  Send Single Frame (SF)
 * @param  inst: ISO-TP instance
 * @param  data: Message data
 * @param  length: Message length (1-62 bytes)
 * @retval ISOTP_OK on success
 */
static isotp_result_t send_single_frame(isotp_instance_t* inst, const uint8_t* data, uint8_t length)
{
    uint8_t can_frame[ISOTP_CAN_FD_MAX_DLC] = {0};
    
    /* PCI byte: 0x0N where N = length */
    can_frame[0] = (ISOTP_PCI_TYPE_SF << 4) | (length & 0x0F);
    
    /* Copy data */
    memcpy(&can_frame[1], data, length);
    
    /* Send CAN frame */
    isotp_result_t result = inst->send_can_frame(inst->tx_id, can_frame, length + 1);
    
    if (result == ISOTP_OK) {
        ISOTP_DEBUG("ISO-TP: Sent SF (%u bytes)\r\n", length);
        inst->tx_state = ISOTP_STATE_IDLE;
        
        /* Call TX callback */
        if (inst->tx_callback != NULL) {
            inst->tx_callback(ISOTP_OK);
        }
    } else {
        ISOTP_DEBUG("ISO-TP: SF send failed\r\n");
        inst->tx_state = ISOTP_STATE_IDLE;
    }
    
    return result;
}

/**
 * @brief  Send First Frame (FF)
 * @param  inst: ISO-TP instance
 * @retval ISOTP_OK on success
 */
static isotp_result_t send_first_frame(isotp_instance_t* inst)
{
    uint8_t can_frame[ISOTP_CAN_FD_MAX_DLC] = {0};
    uint8_t payload_len = 0;

    if (inst->tx_length <= ISOTP_STANDARD_FF_LIMIT )
    {
        /* Standard FF: [1L LL] [Payload...] */
        can_frame[0] = (ISOTP_PCI_TYPE_FF << 4) | ((inst->tx_length >> 8) & 0x0F);
        can_frame[1] = inst->tx_length & 0xFF;

        payload_len = 62; // 64 - 2 PCI bytes
        memcpy(&can_frame[2], inst->tx_buffer, payload_len);
    }
    else
    {
        /* Extended FF: [10 00] [LL LL LL LL] [Payload...] */
        can_frame[0] = (ISOTP_PCI_TYPE_FF << 4); // This results in 0x10
        can_frame[1] = 0x00;                     // Second byte must be 0x00 for extended

        can_frame[2] = (uint8_t)(inst->tx_length >> 24);
        can_frame[3] = (uint8_t)(inst->tx_length >> 16);
        can_frame[4] = (uint8_t)(inst->tx_length >> 8);
        can_frame[5] = (uint8_t)(inst->tx_length & 0xFF);

        payload_len = 58; // 64 - 6 PCI/Length bytes
        memcpy(&can_frame[6], inst->tx_buffer, payload_len);
    }
    
    /* FIX: Use the calculated payload_len to update the index */
    inst->tx_index = payload_len;
    inst->tx_state = ISOTP_STATE_TX_WAIT_FC;
    
    if (inst->get_timestamp_ms != NULL) {
        inst->tx_timeout_start = inst->get_timestamp_ms();
    }
    
    isotp_result_t result = inst->send_can_frame(inst->tx_id, can_frame, ISOTP_CAN_FD_MAX_DLC);
    
    if (result == ISOTP_OK) {
        ISOTP_DEBUG("ISO-TP: Sent FF (Total: %u, Data in FF: %u)\r\n",
                    inst->tx_length, payload_len);
    } else {
        complete_transmission(inst, result);
    }
    
    return result;
}

/**
 * @brief  Send Consecutive Frame (CF)
 * @param  inst: ISO-TP instance
 * @retval ISOTP_OK on success
 */
static isotp_result_t send_consecutive_frame(isotp_instance_t* inst)
{
    uint8_t can_frame[ISOTP_CAN_FD_MAX_DLC] = {0};
    
    /* Calculate remaining bytes */
    uint16_t remaining = inst->tx_length - inst->tx_index;
    uint8_t payload_len = (remaining > ISOTP_CF_MAX_PAYLOAD) ? 
                          ISOTP_CF_MAX_PAYLOAD : (uint8_t)remaining;
    
    /* PCI byte: 0x2N where N = sequence number (0-15) */
    can_frame[0] = (ISOTP_PCI_TYPE_CF << 4) | (inst->tx_sn & 0x0F);
    
    /* Copy data */
    memcpy(&can_frame[1], &inst->tx_buffer[inst->tx_index], payload_len);
    
    /* Send CAN frame */
    isotp_result_t result = inst->send_can_frame(inst->tx_id, can_frame, payload_len + 1);
    
    if (result != ISOTP_OK) {
        ISOTP_DEBUG("ISO-TP: CF send failed\r\n");
        complete_transmission(inst, result);
        return result;
    }
    
    ISOTP_DEBUG("ISO-TP: Sent CF [SN=%u] (%u bytes, %u/%u total)\r\n",
                inst->tx_sn, payload_len, inst->tx_index + payload_len, inst->tx_length);
    
    /* Update state */
    inst->tx_index += payload_len;
    inst->tx_sn = (inst->tx_sn + 1) & 0x0F;  // Wrap at 15
    inst->tx_bs_counter++;
    
    /* Update timestamp for STmin */
    if (inst->get_timestamp_ms != NULL) {
        inst->tx_timestamp = inst->get_timestamp_ms();
    }
    
    /* Check if transmission complete */
    if (inst->tx_index >= inst->tx_length) {
        ISOTP_DEBUG("ISO-TP: TX complete (%u bytes)\r\n", inst->tx_length);
        complete_transmission(inst, ISOTP_OK);
        return ISOTP_OK;
    }
    
    /* Check if we need to wait for next Flow Control */
    if (inst->tx_bs > 0 && inst->tx_bs_counter >= inst->tx_bs) {
        ISOTP_DEBUG("ISO-TP: Block complete, waiting for FC\r\n");
        inst->tx_state = ISOTP_STATE_TX_WAIT_FC;
        inst->tx_bs_counter = 0;
        
        /* Start timeout */
        if (inst->get_timestamp_ms != NULL) {
            inst->tx_timeout_start = inst->get_timestamp_ms();
        }
    }
    
    return ISOTP_OK;
}

/**
 * @brief  Send Flow Control (FC) frame
 * @param  inst: ISO-TP instance
 * @param  status: Flow status (CTS, WAIT, OVERFLOW)
 * @retval ISOTP_OK on success
 */
static isotp_result_t send_flow_control(isotp_instance_t* inst, isotp_fc_status_t status)
{
    uint8_t can_frame[ISOTP_CAN_FD_MAX_DLC] = {0};
    
    /* PCI byte: 0x3S where S = flow status */
    can_frame[0] = (ISOTP_PCI_TYPE_FC << 4) | (status & 0x0F);
    
    /* Block Size */
    can_frame[1] = ISOTP_DEFAULT_BLOCK_SIZE;
    
    /* STmin */
    can_frame[2] = ISOTP_DEFAULT_STMIN_MS;
    
    /* Send CAN frame */
    isotp_result_t result = inst->send_can_frame(inst->tx_id, can_frame, 3);
    
    if (result == ISOTP_OK) {
        ISOTP_DEBUG("ISO-TP: Sent FC [FS=%u, BS=%u, STmin=%u]\r\n",
                    status, ISOTP_DEFAULT_BLOCK_SIZE, ISOTP_DEFAULT_STMIN_MS);
    } else {
        ISOTP_DEBUG("ISO-TP: FC send failed\r\n");
    }
    
    return result;
}

/* ============================================================================
 * PRIVATE FUNCTIONS - RECEPTION
 * ============================================================================
 */

/**
 * @brief  Handle received Single Frame (SF)
 * @param  inst: ISO-TP instance
 * @param  data: CAN frame data
 * @param  dlc: CAN frame length
 * @retval ISOTP_OK on success
 */
static isotp_result_t handle_single_frame(isotp_instance_t* inst, const uint8_t* data, uint8_t dlc)
{
    /* Extract length from PCI byte */
    uint8_t length = data[0] & PCI_SF_DL_MASK;
    
    /* Validate length */
    if (length == 0 || length > ISOTP_SF_MAX_PAYLOAD || length > (dlc - 1)) {
        ISOTP_DEBUG("ISO-TP: Invalid SF length %u (DLC=%u)\r\n", length, dlc);
        return ISOTP_ERROR_INVALID;
    }
    
    /* If reception was in progress, this is unexpected */
    if (inst->rx_state != ISOTP_STATE_IDLE) {
        ISOTP_DEBUG("ISO-TP: Unexpected SF (RX was busy)\r\n");
        complete_reception(inst, ISOTP_ERROR_UNEXPECTED);
    }
    
    /* Copy data to RX buffer */
    memcpy(inst->rx_buffer, &data[1], length);
    inst->rx_length = length;
    
    ISOTP_DEBUG("ISO-TP: Received SF (%u bytes)\r\n", length);
    
    /* Complete reception */
    complete_reception(inst, ISOTP_OK);
    
    return ISOTP_OK;
}

/**
 * @brief  Handle received First Frame (FF)
 * @param  inst: ISO-TP instance
 * @param  data: CAN frame data
 * @param  dlc: CAN frame length
 * @retval ISOTP_OK on success
 */
static isotp_result_t handle_first_frame(isotp_instance_t* inst, const uint8_t* data, uint8_t dlc)
{
    uint32_t length = 0;
    uint8_t payload_offset = 2; // Default for standard FF

    /* 1. Extract Length based on Standard vs Extended FF */
    if ((data[0] == 0x10) && (data[1] == 0x00)) {
        /* Extended First Frame: [10 00] [4-byte length] */
        length = ((uint32_t)data[2] << 24) |
                 ((uint32_t)data[3] << 16) |
                 ((uint32_t)data[4] << 8)  |
                 ((uint32_t)data[5]);
        payload_offset = 6;
    } else {
        /* Standard First Frame: [1L LL] [1-byte length] */
        length = ((uint32_t)(data[0] & 0x0F) << 8) | data[1];
        payload_offset = 2;
    }
    
    /* 2. Validate length */
    // Note: Standard FF max is 4095. Extended is used for > 4095.
    if (length <= 7 || length > ISOTP_MAX_MESSAGE_SIZE) {
        ISOTP_DEBUG("ISO-TP: Invalid FF length %u\r\n", length);
        send_flow_control(inst, ISOTP_FC_STATUS_OVERFLOW);
        return ISOTP_ERROR_INVALID;
    }
    
    /* 3. Manage State: If reception was in progress, reset it */
    if (inst->rx_state != ISOTP_STATE_IDLE) {
        ISOTP_DEBUG("ISO-TP: Unexpected FF (resetting RX)\r\n");
        // Optional: Call a cleanup function here if needed
    }
    
    /* 4. Initialize reception tracking */
    inst->rx_length = length;
    inst->rx_sn = 1;          // Next expected Consecutive Frame
    inst->rx_bs_counter = 0;
    
    /* 5. Calculate and Copy initial payload */
    // Ensure we don't read past the provided DLC
    uint16_t payload_len = (dlc > payload_offset) ? (dlc - payload_offset) : 0;

    // Safety check: Don't overflow the destination buffer
    if (payload_len > (ISOTP_MAX_MESSAGE_SIZE)) {
        payload_len = ISOTP_MAX_MESSAGE_SIZE;
    }

    memcpy(inst->rx_buffer, &data[payload_offset], payload_len);
    inst->rx_index = payload_len;
    
    ISOTP_DEBUG("ISO-TP: Received %s FF (Total: %u, Got: %u)\r\n",
                (payload_offset == 6) ? "Extended" : "Standard", length, payload_len);
    
    /* 6. Send Flow Control: Continue To Send (CTS) */
    send_flow_control(inst, ISOTP_FC_STATUS_CTS);
    
    /* 7. Finalize State and Timers */
    inst->rx_state = ISOTP_STATE_RX_CF;
    
    if (inst->get_timestamp_ms != NULL) {
        inst->rx_timeout_start = inst->get_timestamp_ms();
    }
    
    return ISOTP_OK;
}

/**
 * @brief  Handle received Consecutive Frame (CF)
 * @param  inst: ISO-TP instance
 * @param  data: CAN frame data
 * @param  dlc: CAN frame length
 * @retval ISOTP_OK on success
 */
static isotp_result_t handle_consecutive_frame(isotp_instance_t* inst, const uint8_t* data, uint8_t dlc)
{
    /* Check if we're expecting a CF */
    if (inst->rx_state != ISOTP_STATE_RX_CF) {
        ISOTP_DEBUG("ISO-TP: Unexpected CF (not in RX_CF state)\r\n");
        return ISOTP_ERROR_UNEXPECTED;
    }
    
    /* Extract sequence number */
    uint8_t sn = data[0] & PCI_CF_SN_MASK;
    
    /* Validate sequence number */
    if (sn != inst->rx_sn) {
        ISOTP_DEBUG("ISO-TP: Invalid SN (expected %u, got %u)\r\n", inst->rx_sn, sn);
        complete_reception(inst, ISOTP_ERROR_INVALID_SN);
        return ISOTP_ERROR_INVALID_SN;
    }
    
    /* Calculate payload length */
    uint16_t remaining = inst->rx_length - inst->rx_index;
    uint8_t payload_len = (dlc > 1) ? (dlc - 1) : 0;
    
    if (payload_len > ISOTP_CF_MAX_PAYLOAD) {
        payload_len = ISOTP_CF_MAX_PAYLOAD;
    }
    
    if (payload_len > remaining) {
        payload_len = (uint8_t)remaining;
    }
    
    /* Copy data */
    memcpy(&inst->rx_buffer[inst->rx_index], &data[1], payload_len);
    inst->rx_index += payload_len;
    inst->rx_sn = (inst->rx_sn + 1) & 0x0F;  // Wrap at 15
    inst->rx_bs_counter++;
    
    ISOTP_DEBUG("ISO-TP: Received CF [SN=%u] (%u bytes, %u/%u total)\r\n",
                sn, payload_len, inst->rx_index, inst->rx_length);
    
    /* Reset timeout */
    if (inst->get_timestamp_ms != NULL) {
        inst->rx_timeout_start = inst->get_timestamp_ms();
    }
    
    /* Check if reception complete */
    if (inst->rx_index >= inst->rx_length) {
        ISOTP_DEBUG("ISO-TP: RX complete (%u bytes)\r\n", inst->rx_length);
        complete_reception(inst, ISOTP_OK);
        return ISOTP_OK;
    }
    
    /* Check if we need to send Flow Control */
    if (ISOTP_DEFAULT_BLOCK_SIZE > 0 && inst->rx_bs_counter >= ISOTP_DEFAULT_BLOCK_SIZE) {
        ISOTP_DEBUG("ISO-TP: Block complete, sending FC\r\n");
        send_flow_control(inst, ISOTP_FC_STATUS_CTS);
        inst->rx_bs_counter = 0;
    }
    
    return ISOTP_OK;
}

/**
 * @brief  Handle received Flow Control (FC) frame
 * @param  inst: ISO-TP instance
 * @param  data: CAN frame data
 * @param  dlc: CAN frame length
 * @retval ISOTP_OK on success
 */
static isotp_result_t handle_flow_control(isotp_instance_t* inst, const uint8_t* data, uint8_t dlc)
{
    /* Check if we're expecting FC */
    if (inst->tx_state != ISOTP_STATE_TX_WAIT_FC) {
        ISOTP_DEBUG("ISO-TP: Unexpected FC (not waiting for FC)\r\n");
        return ISOTP_ERROR_UNEXPECTED;
    }
    
    /* Validate DLC */
    if (dlc < 3) {
        ISOTP_DEBUG("ISO-TP: Invalid FC DLC %u\r\n", dlc);
        return ISOTP_ERROR_INVALID;
    }
    
    /* Extract FC parameters */
    uint8_t flow_status = data[0] & PCI_FC_FS_MASK;
    uint8_t block_size = data[1];
    uint8_t stmin = data[2];
    
    ISOTP_DEBUG("ISO-TP: Received FC [FS=%u, BS=%u, STmin=%u]\r\n",
                flow_status, block_size, stmin);
    
    switch (flow_status) {
        case ISOTP_FC_STATUS_CTS:
            /* Continue To Send */
            inst->tx_bs = block_size;
            inst->tx_stmin = stmin;
            inst->tx_bs_counter = 0;
            inst->tx_wft_counter = 0;  // Reset wait counter
            inst->tx_state = ISOTP_STATE_TX_CF;
            
            /* Send first CF immediately (STmin starts after first CF) */
            if (inst->get_timestamp_ms != NULL) {
                inst->tx_timestamp = inst->get_timestamp_ms() - inst->tx_stmin;
            }
            
            ISOTP_DEBUG("ISO-TP: Continuing transmission\r\n");
            break;
            
        case ISOTP_FC_STATUS_WAIT:
            /* Wait - increment counter and check limit */
            inst->tx_wft_counter++;
            
            if (inst->tx_wft_counter >= ISOTP_MAX_WAIT_FRAMES) {
                ISOTP_DEBUG("ISO-TP: Too many Wait frames (%u)\r\n", inst->tx_wft_counter);
                complete_transmission(inst, ISOTP_ERROR_WFT_OVRN);
                return ISOTP_ERROR_WFT_OVRN;
            }
            
            ISOTP_DEBUG("ISO-TP: Wait frame %u/%u\r\n", inst->tx_wft_counter, ISOTP_MAX_WAIT_FRAMES);
            
            /* Stay in WAIT_FC state */
            /* Reset timeout */
            if (inst->get_timestamp_ms != NULL) {
                inst->tx_timeout_start = inst->get_timestamp_ms();
            }
            break;
            
        case ISOTP_FC_STATUS_OVERFLOW:
            /* Overflow - abort transmission */
            ISOTP_DEBUG("ISO-TP: Receiver overflow\r\n");
            complete_transmission(inst, ISOTP_ERROR_OVERFLOW);
            return ISOTP_ERROR_OVERFLOW;
            
        default:
            /* Invalid flow status */
            ISOTP_DEBUG("ISO-TP: Invalid FS %u\r\n", flow_status);
            complete_transmission(inst, ISOTP_ERROR_INVALID_FS);
            return ISOTP_ERROR_INVALID_FS;
    }
    
    return ISOTP_OK;
}

/* ============================================================================
 * PRIVATE FUNCTIONS - UTILITIES
 * ============================================================================
 */

/**
 * @brief  Complete transmission and call callback
 * @param  inst: ISO-TP instance
 * @param  result: Result code
 */
static void complete_transmission(isotp_instance_t* inst, isotp_result_t result)
{
    /* Reset TX state */
    inst->tx_state = ISOTP_STATE_IDLE;
    inst->tx_length = 0;
    inst->tx_index = 0;
    
    /* Call callback */
    if (inst->tx_callback != NULL) {
        inst->tx_callback(result);
    }
}

/**
 * @brief  Complete reception and call callback
 * @param  inst: ISO-TP instance
 * @param  result: Result code
 */
static void complete_reception(isotp_instance_t* inst, isotp_result_t result)
{
    uint16_t length = inst->rx_length;
    
    /* Reset RX state */
    inst->rx_state = ISOTP_STATE_IDLE;
    
    /* Call callback with data (must copy if needed, as buffer will be reused) */
    if (inst->rx_callback != NULL) {
        inst->rx_callback(inst->rx_buffer, length, result);
    }
    
    /* Clear buffer */
    inst->rx_length = 0;
    inst->rx_index = 0;
}

/**
 * @brief  Check if timeout has occurred
 * @param  start_time: Start timestamp
 * @param  current_time: Current timestamp
 * @param  timeout_ms: Timeout duration in milliseconds
 * @retval true if timeout occurred, false otherwise
 */
static bool check_timeout(uint32_t start_time, uint32_t current_time, uint32_t timeout_ms)
{
    uint32_t elapsed = ELAPSED_TIME_MS(start_time, current_time);
    return (elapsed >= timeout_ms);
}

/* ============================================================================
 * END OF FILE
 * ============================================================================
 */