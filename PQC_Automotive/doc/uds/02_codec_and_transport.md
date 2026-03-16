# UDS 0x29 — Zero-Copy Codec & Transport Flow

## 1. The RAM Allocation Problem

Traditional UDS decoders allocate a complete `struct` for every incoming message, heavily `memcpy`ing fields out of the incoming CAN buffers.

With Post-Quantum Cryptography implementations, an ML-DSA-2 public key is 1312 bytes and the signature is 2420 bytes. A standard ML-DSA-2 `0x29 0x03` ProofOfOwnership frame can reach **~4500 bytes**. Copying this buffer into a temporary struct wastes 4.5 KB of Stack RAM instantly and severely slows down the microprocessor on an embedded STM32 layer.

## 2. Zero-Copy Implementation (`uds_0x29_codec.c`)

This framework exclusively solves the memory constraints by using overlay structs containing const pointers right back into the ISO-TP memory.

### The Decoder Struct
```c
// uds_types.h
typedef struct {
    uint8_t         alg_indicator;
    const uint8_t  *proof;              // Direct pointer into RX buf!
    uint16_t        proof_len;
    const uint8_t  *challenge_echo;     // Direct pointer into RX buf!
    uint8_t         challenge_echo_len;
    const uint8_t  *eph_pubkey_client;  // Direct pointer into RX buf!
    uint8_t         eph_pubkey_client_len;
} uds_pown_request_t;
```

When `uds_0x29_server_process` is executed, the `rx_buf` points strictly to the `isotp_receive()` buffer. `uds_0x29_decode_pown_request` shifts through the packet structure linearly:

1. Grabs the 1-byte `alg_indicator`.
2. Reads the 2-byte Big-Endian length array for the signature.
3. Sets `out->proof = &buf[offset]`.
4. Skips the offset forward by the length amount.

No strings or byte arrays are `memcpy`'d. 
The sole architectural constraint of this design is that **the ISO-TP buffer CANNOT be freed, shifted, or erased until the UDS state machine returns `UDS_OK` or drops the session**.

## 3. Encoders & Buffer Protection

Conversely, all encoders (`uds_0x29_encode_vcu_response`, etc.) require the caller (the Server) to provide its own `tx_buf` along with maximum limits (`buf_len`).

```c
uint16_t rsp_len = uds_0x29_encode_vcu_response(tx_buf, SRV_TX_BUF_MIN,
                                                ctx->challenge_server,
                                                &ctx->eph_key_server.pub);
if (rsp_len == 0U) return UDS_ERR_BUFFER_OVERFLOW;
```

If the buffer is too small, it returns `0U`, bubbling up `UDS_ERR_BUFFER_OVERFLOW` safely without memory corruption. The ECU Server uses a pre-allocated stack buffer of 256 bytes for UDS responses, knowing that `0x69 0x01` and `0x69 0x03` are always small (they contain hashes or tiny ECDH keys). 

## 4. Integration with ISO-TP (15 KB Configuration)

The ISO 14229-1 standard uses ISO-TP to manage standard CAN frames constraint (8/64 bytes) to form network frames.

Because ML-DSA/KEM certificates routinely exceed the 12-bit ISO-TP frame limit (4095 Bytes), the underlying ISO-TP framework must be set up with `ISOTP_MAX_MESSAGE_SIZE = 15360U` (15 KB), triggering the **ISO-TP 32-bit Extended Length Frame** structure.

The ECU utilizes `isotp_set_rx_callback(&g_isotp, on_isotp_rx)` to funnel reassembled CAN data dynamically into `uds_core_process()`. The transmission happens seamlessly via `isotp_send(&g_isotp, tx_buf, tx_len)`.
