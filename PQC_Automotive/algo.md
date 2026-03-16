# Cryptographic Algorithms

Classical cryptography algorithms used in this implementation.

---

## ECDSA-P256 (Digital Signatures)

**Algorithm:** Elliptic Curve Digital Signature Algorithm  
**Curve:** NIST P-256 (secp256r1)  
**Standard:** FIPS 186-4  
**Security Level:** 128-bit

### Parameters

- **Field:** Prime field (256-bit prime)
- **Curve equation:** y² = x³ - 3x + b
- **Base point order:** ~2^256
- **Private key:** 32 bytes (random scalar)
- **Public key:** 65 bytes (uncompressed point: 0x04 || X || Y)
- **Signature:** ~72 bytes (DER-encoded r, s values)

### Performance

| Operation | Time |
|-----------|------|
| Keygen | 56 ms |
| Sign | 63 ms |
| Verify | 122 ms |

### Why ECDSA-P256?

✅ Smaller signatures (72B vs 256B for RSA-2048)  
✅ Stronger security (128-bit vs 112-bit for RSA)  
✅ Faster signing (3.1× faster than RSA-2048)  
✅ Industry standard (TLS, code signing, automotive)

---

## ECDH-P256 (Key Exchange)

**Algorithm:** Elliptic Curve Diffie-Hellman  
**Curve:** NIST P-256 (secp256r1)  
**Standard:** NIST SP 800-56A Rev. 3  
**Security Level:** 128-bit

### Parameters

- **Private key:** 32 bytes (random scalar)
- **Public key:** 65 bytes (curve point)
- **Shared secret:** 32 bytes (X-coordinate)

### Performance

| Operation | Time |
|-----------|------|
| Keygen | 58 ms |
| Compute shared secret | 57 ms |

### Key Exchange Flow
```
Client                          Server
──────                          ──────
Generate (sk_c, pk_c)           Generate (sk_s, pk_s)
         pk_s ←─────────────
         ─────────────→ pk_c
Compute: ss = ECDH(sk_c, pk_s)  Compute: ss = ECDH(sk_s, pk_c)

Both sides have identical shared secret (ss)
```

### Why ECDH-P256?

✅ Forward secrecy (ephemeral keys)  
✅ Efficient (57 ms per side)  
✅ Standard (TLS 1.3, automotive)

---

## X.509 v3 Certificates

**Format:** DER (Distinguished Encoding Rules)  
**Signature:** ECDSA with SHA-256  
**Standard:** RFC 5280

### Certificate Structure
```
Certificate:
├── Version: v3
├── Serial Number: 160-bit random
├── Signature Algorithm: ecdsa-with-SHA256
├── Issuer: CA Distinguished Name
├── Validity:
│   ├── Not Before: UTC timestamp
│   └── Not After: UTC timestamp
├── Subject: Device Distinguished Name
├── Subject Public Key Info:
│   ├── Algorithm: ECDSA
│   ├── Curve: secp256r1
│   └── Public Key: 65 bytes
├── Extensions:
│   ├── Basic Constraints: CA:FALSE
│   ├── Key Usage: Digital Signature, Key Agreement
│   ├── Extended Key Usage: Client/Server Auth
│   ├── Subject Key Identifier
│   └── Authority Key Identifier
└── Signature: ECDSA signature by CA
```

### Certificate Sizes

| Certificate | Size |
|-------------|------|
| CA | 528 bytes |
| VCI | 588 bytes |
| ECU | 585 bytes |

### Performance

| Operation | Time |
|-----------|------|
| Parse DER | <1 ms |
| Validate chain | 121 ms |

---

## AES-256-GCM (Authenticated Encryption)

**Algorithm:** Advanced Encryption Standard - Galois/Counter Mode  
**Key Size:** 256-bit  
**Standard:** NIST SP 800-38D

### Parameters

- **Key:** 32 bytes
- **IV (Nonce):** 12 bytes (must be unique per message)
- **Tag:** 16 bytes (authentication tag)
- **Block size:** 16 bytes

### Performance

- **Encrypt/Decrypt:** <1 ms (hardware accelerated)
- **Hardware:** STM32 CRYP peripheral

### Why AES-256-GCM?

✅ Authenticated encryption (confidentiality + integrity)  
✅ Hardware accelerated (<1 ms)  
✅ No padding oracle vulnerabilities  
✅ Standard (TLS 1.3, IPsec)

---

## HKDF-SHA256 (Key Derivation)

**Algorithm:** HMAC-based Key Derivation Function  
**Hash:** SHA-256  
**Standard:** RFC 5869

### Parameters

- **IKM:** Input Key Material (e.g., ECDH shared secret)
- **Salt:** Optional random value
- **Info:** Context-specific label
- **OKM:** Output Key Material (derived key)

### Derivation Process
```
1. Extract: PRK = HMAC-SHA256(salt, IKM)
2. Expand:  OKM = HMAC-SHA256(PRK, info || 0x01)
```

### Performance

- **Derive 32B key:** <1 ms (hardware accelerated)

### Why HKDF?

✅ Cryptographically strong key derivation  
✅ Context separation via "info" parameter  
✅ Standard (TLS 1.3, Signal Protocol)

---

## SHA-256 (Cryptographic Hash)

**Algorithm:** Secure Hash Algorithm 256-bit  
**Standard:** FIPS 180-4

### Parameters

- **Input:** Any length
- **Output:** 32 bytes (256 bits)
- **Block size:** 64 bytes

### Performance

| Input Size | Time |
|------------|------|
| 3 bytes | <1 ms |
| 1024 bytes | <1 ms |

**Hardware:** STM32 HASH peripheral

---

## HMAC-SHA256 (Message Authentication)

**Algorithm:** Hash-based Message Authentication Code  
**Hash:** SHA-256  
**Standard:** FIPS 198-1

### Parameters

- **Key:** 32 bytes (recommended)
- **Message:** Any length
- **MAC:** 32 bytes

### Performance

- **Compute/Verify:** <1 ms (partially hardware accelerated)

---

## Hardware Acceleration Summary

| Algorithm | Hardware | Peripheral | Speedup |
|-----------|----------|------------|---------|
| AES-128/256 | ✅ Yes | CRYP | ~10× |
| SHA-256 | ✅ Yes | HASH | ~5× |
| RNG | ✅ Yes | RNG | N/A |
| ECDSA | ❌ No | Software | — |
| ECDH | ❌ No | Software | — |
| RSA | ❌ No | Software | — |

**Note:** STM32H7B3 lacks ECC hardware acceleration. All elliptic curve operations run in Mbed TLS software.

---

## Security Levels

| Algorithm | Security Level | Quantum Resistant? |
|-----------|----------------|---------------------|
| ECDSA-P256 | 128-bit | ❌ No (Shor's algorithm) |
| ECDH-P256 | 128-bit | ❌ No (Shor's algorithm) |
| AES-256 | 256-bit → 128-bit* | ⚠️ Partial (Grover's algorithm) |
| SHA-256 | 256-bit → 128-bit* | ⚠️ Partial (Grover's algorithm) |

*Grover's algorithm provides quadratic speedup, effectively halving security bits.

**Mitigation:** Post-Quantum Cryptography (PQC) in Weeks 8-10, Hybrid mode in Week 11.

---

## References

- **FIPS 186-4** - Digital Signature Standard
- **NIST SP 800-56A** - Key-Establishment Schemes
- **NIST SP 800-38D** - GCM Mode
- **RFC 5280** - X.509 Certificates
- **RFC 5869** - HKDF