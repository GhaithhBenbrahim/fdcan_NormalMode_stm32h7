# UDS 0x29 — Session Security & Application (AES-256-GCM)

## 1. Post-Authentication Reality

When the Unidirectional PKI Sequence naturally concludes, the ECU Server transitions to `UDS_SRV_STATE_AUTHENTICATED`.

Simultaneously, the ECU derived an HKDF-SHA256 mathematical derivative labeled `session_key` (32 bytes). The VCI Tester received a Server validation HMAC (`sessionKeyInfo`), accepted it, and safely deposited its identical clone of the `session_key` into `uds_session_ctx_t`.

With identical, ephemeral 32-byte keys, the UDS transaction leaves PKI architecture and enters **Symmetric Wrapping**.

## 2. Advanced Encryption System (AES-256-GCM)

The Application Layer now proxies all sensitive standard UDS services (Like 0x2E Write Data, 0x31 Routine Control) through `uds_session.c`.

Galois/Counter Mode (GCM) is an **Authenticated Encryption with Associated Data (AEAD)** cipher. It guarantees three absolute properties:
1. **Confidentiality**: A CAN-bus sniffer sees garbled ciphertext, preventing network recon or extraction of sensitive variables.
2. **Integrity**: Any bit-flip alteration from MITM tampering destroys the mathematically bound 16-byte Authentication MAC Tag at the packet's tail.
3. **Replay Rejection**: By binding counters exclusively into the GCM nonce/IV string, re-run CAN scripts fail validation natively inside the decryption mathematics.

## 3. Implementation Flow (`uds_session.c`)

### Frame Formatting
The Encrypted UDS Service Frame is structured:
`[Associated Data] || [Encrypted Payload] || [16-Byte Auth Tag] || [4-byte Counter]`

### Transmitting (VCI tester)
```c
uint8_t payload[] = { 0x2E, 0x01, 0x02, 0xFF }; // Turn off safety limits

uds_result_t res = uds_session_encrypt(&g_session, 
                                       payload, sizeof(payload), 
                                       1,       /* AAD Length (Leave 0x2E plain) */
                                       tx_buf, &tx_len, sizeof(tx_buf));
```

The GCM encrypter pushes its internal `g_session.tx_counter` directly into the `mbedtls_gcm_auth_decrypt` 12-byte IV vector. The encrypted packet is shipped onto the CAN bus via ISO-TP.

### Receiving (ECU Server)
When an `on_isotp_rx` signal triggers logic on a locked ISO-TP port, the ECU pushes the payload to `uds_session_decrypt()`.

```c
uds_result_t res = uds_session_decrypt(&g_session, 
                                       rx_buf, rx_len, 
                                       1, /* Expecting 1-byte AAD */
                                       decrypted_buf, &dec_len);
```

The underlying mathematical logic in `mbedtls_gcm_auth_decrypt`:
1. Checks the embedded MAC tag. If tampering occurred, returns error (Packet Dropped).
2. Extracts the `rx_counter`. If `embedded_counter <= ctx->rx_counter`, it's an overt Replay Attack. Packet heavily aborted and system alerted.
3. Outputs the cleartext payload (`0x2E 0x01...`). 

The `decrypted_buf` is immediately fed into the traditional UDS processing architecture to execute the secured WriteData or SecurityAccess routines.
