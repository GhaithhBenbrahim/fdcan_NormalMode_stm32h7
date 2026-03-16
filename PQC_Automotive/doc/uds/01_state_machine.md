# UDS 0x29 — Authentication State Machine

## 1. Core Specification & Timing Handshake

Automotive ISO 14229 mandates strict response timings on the diagnostic bus. The UDS Service 0x29 Unidirectional PKI authentication involves heavy mathematical operations (X.509 validation, ECDH key exchange, ECDSA/ML-DSA signature verification). 

Because these operations comfortably exceed the default `P2_Server_Max` (50ms) limit, the ECU Server implements an **Asynchronous Pending State Machine** paired with generic ISO-TP **Negative Response Code (NRC) 0x78**.

## 2. Server (ECU) Asynchronous Flow

The server context (`uds_srv_ctx_t`) retains all authentication variables between external requests.

### State: `UDS_SRV_STATE_VCU_PROCESSING`
1. The Tester (VCI) sends a `VerifyCertificateUnidirectional` (0x29 0x01) request along with the 800+ byte DER certificate.
2. The ECU's `uds_0x29_server_process()` decodes the packet. It validates generic fields (algorithm indicators).
3. If basic checks pass, the ECU instantly sets its state to `VCU_PROCESSING` and writes a `[0x7F 0x29 0x78]` (Response Pending) frame into the `tx_buf`, returning `UDS_PENDING`.
4. The ISO-TP core immediately transmits this over the CAN FD bus. 
5. On the very next CPU poll (or RTOS tick), `process_vcu()` resumes. It runs `cal_cert_verify_chain()`, which takes ~121ms.
6. Once complete, it builds the `0x69 0x01` response containing the 32-byte generated challenge and the ephemeral server public key, transitioning to `UDS_SRV_STATE_CHALLENGE_SENT`.

### State: `UDS_SRV_STATE_POWN_PROCESSING`
1. The Tester sends the `ProofOfOwnership` (0x29 0x03) request, carrying the client's signature and ephemeral public key.
2. The ECU validates the `challenge_echo` array against its own stored challenge.
3. The ECU immediately outputs a `0x78 Response Pending` NRC and transitions to `POWN_PROCESSING`.
4. On the next tick, it crunches the `cal_verify()` signature validation and `cal_ecdh_shared_secret()` math (~122ms to ~180ms total).
5. If math validates, the HKDF generates the Session Key, and the server transmits the `0x69 0x03` positive response containing the `sessionKeyInfo` proof. State updates to `UDS_SRV_STATE_AUTHENTICATED`.

### The Stale Context Eraser
If the ECU is in `CHALLENGE_SENT` but suddenly receives a new `0x29 0x01` request, it identifies an abandoned flow. The ECU calls `uds_0x29_server_reset(ctx)` mechanically zeroing the RAM arrays (challenge, ephemeral keys) and accepts the new request to prevent diagnostic deadlocks.

## 3. Client (VCI) P2/P2* Timer Tracking

The Client is accountable for tracking diagnostic timeouts using RTOS ticks (`HAL_GetTick()`).

1. **Active Timers**: When `uds_0x29_client_build_vcu()` dispatches a CAN frame, the Application assigns `p2_timeout = 50ms`.
2. **0x78 Mitigation**: If `on_isotp_rx` triggers an incoming `0x7F 0x29 0x78` message, the Client intercepts this gracefully. Instead of calling a generic UDS Error Event, the Client resets the timer: `p2_timeout = 5000ms` (`P2_Star_Server_Max`).
3. **Session Reset**: If `p2_timeout` naturally expires inside the applications `while(1)` polling loop, the Application executes `uds_0x29_client_reset(&g_cli_ctx)` and alerts the TouchGFX GUI of a total communication failure.

## 4. API Reference: `uds_0x29_server.h`

```c
uds_result_t uds_0x29_server_init(uds_srv_ctx_t *ctx, const uds_srv_config_t *cfg);
```
> Copies the const `cfg` (containing the CA Certificate pointer) into a local static variable. The `ctx` manages the ephemeral execution state.

```c
uds_result_t uds_0x29_server_process(uds_srv_ctx_t *ctx,
                                     const uint8_t *rx_buf, uint16_t rx_len,
                                     uint8_t *tx_buf, uint16_t *tx_len);
```
> Called constantly. Takes raw ISO-TP frames. Returns `UDS_OK` (frame ready), `UDS_PENDING` (0x78 frame ready, call again soon), or a negative error.
