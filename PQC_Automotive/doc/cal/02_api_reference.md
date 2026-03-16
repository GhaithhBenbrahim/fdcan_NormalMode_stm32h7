# Crypto Abstraction Layer (CAL) — API Reference

## 1. Unified Types (`cal_types.h`)

All algorithms use standardized container structs. These define the maximum safe boundaries for memory allocation on the RTOS stack.

### Constants
* `CAL_MAX_PUBKEY_SIZE`: 1312 bytes (Driven by ML-DSA-2 public key size)
* `CAL_MAX_SIG_SIZE`: 2420 bytes (Driven by ML-DSA-2 signature size)
* `CAL_CHALLENGE_SIZE`: 32 bytes (Always fixed)
* `CAL_AES256_KEY_SIZE`: 32 bytes (Always fixed)

### Structures
```c
typedef struct {
    uint8_t  bytes[CAL_MAX_PUBKEY_SIZE];
    uint16_t length;
    cal_algorithm_t alg;
} cal_pubkey_t;

typedef struct {
    uint8_t  bytes[CAL_MAX_SIG_SIZE];
    uint16_t length;
} cal_signature_t;
```
> **Performance Note**: To avoid 4KB structs being copied continuously by value, UDS and CAL functions exclusively pass these structures by pointer (`cal_pubkey_t *`).

## 2. The Public API (`cal_api.h`)

This is the exact interface the UDS 0x29 logic uses when processing requests. No `mbedtls_` prefixes are permitted outside of the CAL.

### Initialization & Configuration
```c
// Boots the global RNG and DRBG contexts
cal_result_t cal_init(void);

// Swaps the active Vtable (CAL_MODE_CLASSICAL | CAL_MODE_PQC | CAL_MODE_HYBRID)
void cal_select_mode(cal_mode_t mode);

// Returns the UDS Subfunction parameter (e.g., 0x01 or 0x10) for the CAN frame
uint8_t cal_get_alg_indicator(void);
```

### Signature & Verification (PKI Phase)
```c
// Ask the CA to cryptographically verify the client's DER cert, returning the Public Key
cal_result_t cal_cert_verify_chain(const uint8_t *cert_der, uint16_t cert_len,
                                   const uint8_t *ca_der,   uint16_t ca_len,
                                   cal_pubkey_t  *out_pub);

// Sign the POWN auth_token 
cal_result_t cal_sign(cal_algorithm_t alg,
                      const uint8_t *priv_key, uint16_t priv_len,
                      const uint8_t *msg,      uint16_t msg_len,
                      cal_signature_t *sig_out);

// Verify the POWN signature
cal_result_t cal_verify(cal_algorithm_t alg,
                        const cal_pubkey_t *pub_key,
                        const uint8_t *msg,        uint16_t msg_len,
                        const cal_signature_t *sig);
```

### Key Exchange (Session Phase)
```c
// Generate ephemeral ECDH or ML-KEM keys for session derivation
cal_result_t cal_keygen(cal_algorithm_t alg, cal_keypair_t *out_key);

// Combine our private ephemeral with their public ephemeral
cal_result_t cal_ecdh_shared_secret(const uint8_t *priv_key,  uint16_t priv_len,
                                    const cal_pubkey_t *peer_pub,
                                    uint8_t *secret_out,      uint16_t *secret_len);
```

### Derivation & Proof
```c
// Turn the messy shared DH secret into a clean AES-256 session key
cal_result_t cal_hkdf(const uint8_t *ikm,  uint16_t ikm_len,
                      const uint8_t *salt, uint16_t salt_len,
                      const uint8_t *info, uint16_t info_len,
                      uint8_t *okm_out,    uint16_t okm_len);

// Create the MAC for the sessionKeyInfo transmission
cal_result_t cal_hmac_sha256(const uint8_t *key, uint16_t key_len,
                             const uint8_t *msg, uint16_t msg_len,
                             uint8_t *mac_out);
```
