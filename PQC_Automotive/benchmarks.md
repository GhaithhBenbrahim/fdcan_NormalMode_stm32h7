# Performance Benchmarks

Complete benchmark results for classical cryptography implementation.

---

## Test Configuration

**Hardware:**
- Board: STM32H7B3I-DK
- MCU: STM32H7B3LIH6Q
- CPU: ARM Cortex-M7 @ 280 MHz
- Cache: I-Cache + D-Cache enabled

**Software:**
- Compiler: GCC ARM 10.3.1
- Optimization: -O2 (speed)
- Mbed TLS: 3.5.x
- OS: Bare-metal (no RTOS)

**Test Method:**
- Timing: HAL_GetTick() (1 ms resolution)
- Runs: 4 iterations averaged
- Date: March 11-14, 2026

---

## Results Summary

### Symmetric Cryptography (Hardware Accelerated)

| Operation | Time | Hardware |
|-----------|------|----------|
| AES-128 ECB Encrypt (16B) | <1 ms | CRYP |
| AES-128 ECB Decrypt (16B) | <1 ms | CRYP |
| AES-256-GCM Encrypt (256B) | <1 ms | CRYP |
| AES-256-GCM Decrypt (256B) | <1 ms | CRYP |
| SHA-256 Hash (3B) | <1 ms | HASH |
| SHA-256 Hash (1KB) | <1 ms | HASH |
| HMAC-SHA256 (64B) | <1 ms | Partial |
| HKDF Derive (32B) | <1 ms | Partial |
| RNG Generate (32B) | <1 ms | RNG |

**Note:** <1 ms = below HAL_GetTick() 1ms resolution

---

### Asymmetric Cryptography (Software)

#### ECDSA-P256

| Operation | Time | Notes |
|-----------|------|-------|
| Keygen | 56 ms | Generate private + public key |
| Sign | 63 ms | Sign message hash |
| Verify | 122 ms | Verify signature |
| **Total Auth** | **185 ms** | Sign + Verify |

**Signature size:** 72 bytes (DER-encoded)

#### ECDH-P256

| Operation | Time | Notes |
|-----------|------|-------|
| Client Keygen | 58 ms | Generate ephemeral keypair |
| Server Keygen | 57 ms | Generate ephemeral keypair |
| Client Shared Secret | 57 ms | Compute from server's public key |
| Server Shared Secret | 57 ms | Compute from client's public key |
| **Total Key Exchange** | **115 ms** | Both sides |

**Shared secret size:** 32 bytes

---

### X.509 Certificate Operations

| Operation | Time | Notes |
|-----------|------|-------|
| Parse CA Cert (528B) | <1 ms | DER format |
| Parse VCI Cert (588B) | <1 ms | DER format |
| Validate Certificate Chain | 121 ms | Includes ECDSA verify |

---

### RSA-2048 (Reference Only)

| Operation | Time | Notes |
|-----------|------|-------|
| Keygen | 5512 ms | Probabilistic prime generation |
| Sign | 200 ms | PKCS#1 v1.5 |
| Verify | 3 ms | Small exponent (e=65537) |
| **Total Auth** | **203 ms** | Sign + Verify |

**Signature size:** 256 bytes

**Note:** RSA included for comparison only. ECDSA is recommended.

---

## ECDSA vs RSA Comparison

| Metric | ECDSA-P256 | RSA-2048 | Advantage |
|--------|------------|----------|-----------|
| **Keygen Time** | 56 ms | 5512 ms | **ECDSA 98× faster** |
| **Sign Time** | 63 ms | 200 ms | **ECDSA 3.1× faster** |
| **Verify Time** | 122 ms | 3 ms | **RSA 40× faster** |
| **Total Auth** | 185 ms | 203 ms | **ECDSA 1.1× faster** |
| **Signature Size** | 72 bytes | 256 bytes | **ECDSA 3.5× smaller** |
| **Security Level** | 128-bit | 112-bit | **ECDSA stronger** |

### Key Findings

✅ **ECDSA advantages:**
- 98× faster key generation
- 3.1× faster signing
- 3.5× smaller signatures (critical for CAN bus)
- Stronger security (128-bit vs 112-bit)

⚠️ **RSA advantage:**
- 40× faster verification (but rarely done in automotive)

**Recommendation:** Use ECDSA-P256 for production.

---

## Complete Authentication Flow

### Timing Breakdown
```
Complete Authentication (ECDSA-P256):
├── Certificate validation: 121 ms
├── Challenge generation:    63 ms (ECDSA sign)
├── Challenge verification: 122 ms (ECDSA verify)
├── ECDH client keygen:      58 ms
├── ECDH server keygen:      57 ms
├── ECDH shared secrets:    114 ms (57 ms × 2)
├── HKDF key derivation:     <1 ms
└── Total:                  ~536 ms
```

**Breakdown by category:**
- ECDSA operations: 306 ms (57%)
- ECDH operations: 229 ms (43%)
- Other: <1 ms (0%)

---

## Optimization Impact

### Compiler Optimization (-O0 vs -O2)

| Algorithm | -O0 | -O2 | Speedup |
|-----------|-----|-----|---------|
| ECDSA Sign | ~214 ms | 63 ms | **3.4×** |
| ECDSA Verify | ~415 ms | 122 ms | **3.4×** |
| RSA Keygen | ~88 sec | 5.5 sec | **16×** |
| RSA Sign | ~680 ms | 200 ms | **3.4×** |

**Conclusion:** -O2 optimization is critical (3-16× performance gain).

---

## Hardware Acceleration Impact

### AES-256-GCM (with vs without CRYP)

| Mode | Encrypt (256B) | Speedup |
|------|----------------|---------|
| Software | ~10 ms | 1× |
| Hardware (CRYP) | <1 ms | **~10×** |

### SHA-256 (with vs without HASH)

| Mode | Hash (1KB) | Speedup |
|------|------------|---------|
| Software | ~5 ms | 1× |
| Hardware (HASH) | <1 ms | **~5×** |

**Conclusion:** Hardware acceleration is essential for symmetric crypto.

---

## Memory Usage

### Stack Usage (Approximate)

| Function | Stack |
|----------|-------|
| ECDSA Sign | ~2 KB |
| ECDSA Verify | ~2 KB |
| ECDH Shared Secret | ~2 KB |
| AES-256-GCM | ~512 B |
| X.509 Parse | ~4 KB |

### Flash Usage

| Component | Size |
|-----------|------|
| Mbed TLS Library | ~150 KB |
| Benchmark Code | ~20 KB |
| Certificates (const arrays) | ~2 KB |
| **Total** | **~172 KB** |

---

## Key Takeaways

1. **Symmetric crypto is fast** (<1 ms with hardware acceleration)
2. **ECDSA-P256 is practical** (185 ms total for sign+verify)
3. **ECDH-P256 is efficient** (115 ms for full key exchange)
4. **ECDSA beats RSA** for automotive (smaller signatures, faster)
5. **Hardware acceleration is critical** (10× speedup for AES/SHA)
6. **Compiler optimization matters** (3.4× speedup with -O2)

---

## Baseline for PQC Comparison

These classical results serve as the **performance baseline** for comparing:

- **Week 8-10:** PQC (ML-DSA-2 + ML-KEM-512)
- **Week 11:** Hybrid (Classical + PQC combined)

**Target:** Demonstrate PQC feasibility within automotive constraints (<1 second total authentication).