/**
 ******************************************************************************
 * @file    uds_core.c
 * @brief   UDS Core — SID Dispatcher Implementation
 ******************************************************************************
 */

#include "uds_core.h"
#include "uds_0x29_server.h"
#include "cal/cal_api.h"

#include <string.h>

static uds_srv_ctx_t    s_srv_ctx;
static uds_core_config_t s_cfg;
static bool             s_initialized = false;

uds_result_t uds_core_init(const uds_core_config_t *cfg)
{
    if (cfg == NULL) return UDS_ERR_INVALID_MSG;

    s_cfg = *cfg;

    /* Initialise the Crypto Abstraction Layer (RNG, mbedTLS contexts) */
    if (cal_init() != CAL_OK) return UDS_ERR_CRYPTO_FAIL;

    /* Initialise service 0x29 server context */
    uds_result_t ret = uds_0x29_server_init(&s_srv_ctx, &s_cfg.auth_cfg);
    if (ret != UDS_OK) return ret;

    s_initialized = true;
    return UDS_OK;
}

void uds_core_reset_auth(void)
{
    uds_0x29_server_reset(&s_srv_ctx);
}

uds_result_t uds_core_process(const uint8_t *rx_buf, uint16_t  rx_len,
                               uint8_t       *tx_buf, uint16_t *tx_len)
{
    if (rx_buf == NULL || tx_buf == NULL || tx_len == NULL) return UDS_ERR_INVALID_MSG;

    *tx_len = 0U;

    if (!s_initialized) {
        *tx_len = uds_0x29_encode_nrc(tx_buf, 256U,
                                       (rx_len > 0U) ? rx_buf[0] : 0x00U,
                                       UDS_NRC_CONDITIONS_NOT_CORRECT);
        return UDS_ERR_WRONG_STATE;
    }

    if (rx_len < 1U) return UDS_ERR_INVALID_MSG;

    uint8_t sid = rx_buf[0];

    switch (sid) {
        case UDS_SID_AUTHENTICATION:
            return uds_0x29_server_process(&s_srv_ctx, rx_buf, rx_len, tx_buf, tx_len);

        default:
            /* Unknown SID */
            *tx_len = uds_0x29_encode_nrc(tx_buf, 256U, sid,
                                           UDS_NRC_REQUEST_OUT_OF_RANGE);
            return UDS_ERR_UNKNOWN_SUBFUNCTION;
    }
}

const uds_srv_ctx_t *uds_core_get_server_ctx(void)
{
    return &s_srv_ctx;
}
