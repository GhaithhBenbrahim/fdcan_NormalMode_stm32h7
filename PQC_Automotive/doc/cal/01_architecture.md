# Crypto Abstraction Layer (CAL) — Architecture & Implementation

## 1. Introduction

The Crypto Abstraction Layer (CAL) is the foundation of the PQC Automotive UDS implementation. Because Post-Quantum Cryptography (PQC) standards (such as ML-DSA and ML-KEM) differ significantly in memory, timing, and API structures from Classical Cryptography (ECDSA, RSA), the diagnostic application (UDS 0x29) cannot contain direct references to cryptographic libraries.

**The CAL guarantees zero UDS code changes when migrating from Classical (mbedTLS) to PQC (PQClean).**

## 2. The Internal Architecture

The CAL is divided into four structural tiers:

1. **Shared Types (`cal_types.h`)**: Defines the maximum boundary limits for stack allocation (e.g., `CAL_MAX_SIG_SIZE` = 2420 for ML-DSA) and the return codes.
2. **Public Facade (`cal_api.h`)**: The functions that UDS actually calls (e.g., `cal_sign()`). 
3. **The Dispatcher (`cal_backend.c/.h`)**: Holds the active `g_backend` vtable pointer and the shared Hardware RNG instances.
4. **Concrete Implementations**:
   - `cal_classical.c`: mbedTLS 2.16.2 wrapper.
   - `cal_pqc.c`: PQClean wrapper (Week 9).
   - `cal_hybrid.c`: Combined operations wrapper (Week 11).

## 3. The Runtime Vtable Mechanism

To support dynamic switching from a TouchGFX GUI, the CAL does not use compile-time `#ifdef` macros to select algorithms. Instead, it uses a C-struct Vtable (`cal_backend_t`).

### The Vector Table Structure
```c
// cal_backend.h
typedef struct {
    cal_result_t (*keygen)(cal_keypair_t *out_key);
    cal_result_t (*sign)(const uint8_t *priv_key, uint16_t priv_len,
                         const uint8_t *msg,      uint16_t msg_len,
                         cal_signature_t *sig_out);
    cal_result_t (*verify)(const cal_pubkey_t *pub_key,
                           const uint8_t *msg, uint16_t msg_len,
                           const cal_signature_t *sig);
    cal_result_t (*dh_compute)(const uint8_t *priv_key, uint16_t priv_len,
                               const cal_pubkey_t *peer_pub,
                               uint8_t *secret_out, uint16_t *secret_len);
    cal_result_t (*cert_verify)(const uint8_t *cert_der, uint16_t cert_len,
                                const uint8_t *ca_der,   uint16_t ca_len,
                                cal_pubkey_t *out_pub);
    uint8_t      alg_indicator;
} cal_backend_t;
```

### Modes of Operation
Calling `cal_select_mode(CAL_MODE_CLASSICAL)` assigns `g_backend = &cal_backend_classical`. When UDS calls `cal_sign()`, the dispatcher executes `g_backend->sign(...)`. 

This mechanism allows the UDS `alg_indicator` transmitted over CAN to change dynamically based on the active backend via `cal_get_alg_indicator()`.

## 4. Shared Cryptographic Primitives

The dispatcher (`cal_backend.c`) natively handles algorithms that are shared across all backends to save flash memory and reduce redundancy.

### Hardware Random Number Generation (RNG)
The CAL initializes a single `mbedtls_ctr_drbg_context` and `mbedtls_entropy_context` during `cal_init()`. This is shared whether the system is generating a Classical P-256 ephemeral key or an ML-DSA challenge.

```c
cal_result_t cal_rng(uint8_t *buf, uint16_t len) {
    if (mbedtls_ctr_drbg_random(&g_ctr_drbg, buf, len) != 0) return CAL_ERR_CRYPTO;
    return CAL_OK;
}
```

### HKDF and Session Key Verification
The UDS 0x29 protocol derives a 32-byte AES-256 Session Key from the ephemeral shared secret. Regardless of whether the shared secret was derived via ECDH (32 bytes) or ML-KEM (32-64 bytes), the derivation algorithm is always **HKDF-SHA256**. The proof-of-ownership `sessionKeyInfo` is always **HMAC-SHA256**. Therefore, these are implemented directly in `cal_backend.c`.

## 5. Classical Backend Nuances (mbedTLS 2.16.2)

The `cal_classical.c` file is highly tailored to the older mbedTLS 2.16.2 library included with STM32CubeIDE.

1. **SHA-256 Engine**: Due to mbedTLS versioning, the code uses `mbedtls_sha256_ret()` rather than the newer context-free macros, handling the `int` returns strictly.
2. **ECDSA Contexts**: ECDSA signing natively uses the `mbedtls_ecdsa_context`. The CAL code explicitly maps the `cal_pubkey_t` and `cal_signature_t` raw byte arrays into the `mbedtls_mpi` big-number structures.
3. **X.509 Parsing**: Certificate verification extracts the public key from the validated DER payload using `mbedtls_pk_ec()`.

## 6. Memory & Stack Guarantees

The `cal_types.h` structures are intentionally bounded to the maximum size required by ML-DSA-2:

| Structure | Classical Need | PQC Provisioned |
|-----------|----------------|-----------------|
| `cal_pubkey_t` | 65 Bytes | 1312 Bytes |
| `cal_signature_t`| 72 Bytes | 2420 Bytes |

Due to these massive 1.3KB and 2.4KB sizes, **UDS code never passes CAL structures by value**, only by const reference pointers (`cal_signature_t *sig_out`), preventing stack overflows on the RTOS threads.
