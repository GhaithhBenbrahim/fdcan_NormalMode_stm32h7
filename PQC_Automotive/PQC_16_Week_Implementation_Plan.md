# 📋 Complete 16-Week Implementation Plan

**Project:** Post-Quantum Cryptography for Automotive UDS Authentication  
**Platform:** STM32H7B3I-DK (Dual-Board Setup)  
**Timeline:** Weeks 5-16 (March - June 2026)

---

## 📚 Table of Contents

- [Libraries & Tools Summary](#libraries--tools-summary)
- [Project Repository Structure](#project-repository-structure)
- [PHASE 1: Classical Crypto Baseline (Weeks 5-6)](#phase-1-classical-crypto-baseline-weeks-5-6)
- [PHASE 2: PQC Theory & Implementation (Weeks 7-10)](#phase-2-pqc-theory--implementation-weeks-7-10)
- [PHASE 3: Session Encryption & Demo (Weeks 11-12)](#phase-3-session-encryption--demo-weeks-11-12)
- [PHASE 4: GUI & Final Demo (Weeks 13-14)](#phase-4-gui--final-demo-weeks-13-14)
- [PHASE 5: Documentation & Defense (Weeks 15-16)](#phase-5-documentation--defense-weeks-15-16)
- [Summary Timeline](#summary-timeline)
- [Risk Management](#risk-management)
- [Resources Required](#resources-required)
- [Success Criteria](#success-criteria)

---

## Libraries & Tools Summary

| Component | Library/Tool | Purpose |
|-----------|-------------|---------|
| **Classical Crypto** | ARM Mbed TLS 3.5.x | RSA-2048, ECDH-P256, AES-GCM, SHA-256 |
| **PQC Crypto** | PQClean (pqm4 for Cortex-M) | ML-KEM-512, ML-DSA-2 |
| **Hardware Acceleration** | STM32H7 CRYP peripheral | AES-256-GCM (via HAL) |
| **Certificate Generation** | Python + cryptography lib | Offline cert generation |
| **Build System** | STM32CubeIDE | Project management |
| **Version Control** | Git + GitHub | Source code management |

---

## Project Repository Structure
```
pqc-automotive-auth/
├── README.md
├── docs/
│   ├── ARCHITECTURE.md
│   ├── API_REFERENCE.md
│   ├── BENCHMARK_REPORT.md
│   └── SECURITY_ANALYSIS.md
│
├── scripts/
│   ├── generate_certificates.py
│   ├── extract_keys.py
│   └── benchmark_analysis.py
│
├── iso_tp_client/                    (VCI/Tester)
│   ├── Core/
│   │   ├── Inc/
│   │   │   ├── uds/
│   │   │   │   ├── uds_authentication.h
│   │   │   │   └── uds_pki.h
│   │   │   ├── crypto/
│   │   │   │   ├── classical/
│   │   │   │   │   ├── rsa.h
│   │   │   │   │   ├── ecdh.h
│   │   │   │   │   └── aes_gcm.h
│   │   │   │   ├── pqc/
│   │   │   │   │   ├── ml_kem.h
│   │   │   │   │   └── ml_dsa.h
│   │   │   │   └── cert/
│   │   │   │       ├── cert_parser.h
│   │   │   │       └── cert_data.h
│   │   │   └── demo/
│   │   │       └── demo_pki_auth.h
│   │   └── Src/ (mirrors Inc structure)
│   │
│   ├── Middlewares/
│   │   └── Third_Party/
│   │       ├── mbedtls/
│   │       └── pqclean/
│   │
│   └── results/
│       ├── classical_performance.csv
│       └── pqc_performance.csv
│
├── iso_tp_server/                    (ECU)
│   └── (similar structure to client)
│
└── thesis/
    ├── chapters/
    │   ├── 01_introduction.md
    │   ├── 02_quantum_threat_pqc.md
    │   ├── 03_system_architecture.md
    │   ├── 04_implementation.md
    │   ├── 05_results_analysis.md
    │   └── 06_conclusion.md
    ├── figures/
    └── references.bib
```

---

# PHASE 1: Classical Crypto Baseline (Weeks 5-6)

## Week 5: Classical Cryptography Integration

### 🎯 Objectives
- Integrate ARM Mbed TLS library
- Implement RSA-2048 signing/verification
- Implement ECDH-P256 key exchange
- Enable STM32H7 CRYP hardware acceleration for AES
- Verify basic cryptographic operations

### 📋 Tasks

#### Day 1-2: Mbed TLS Integration
- Download and integrate Mbed TLS 3.5.x
- Configure `mbedtls_config.h` for STM32H7
- Enable hardware acceleration for AES (CRYP peripheral)
- Compile and resolve dependencies
- Test basic operations (SHA-256, AES-128)

**Deliverables:**
- Mbed TLS compiling successfully
- Hardware-accelerated AES functional
- Basic crypto tests passing

#### Day 3: RSA-2048 Implementation
- Create `rsa.h` and `rsa.c` wrapper modules
- Implement RSA-PSS signing function
- Implement RSA-PSS verification function
- Create key generation utility (for testing)
- Measure performance (sign/verify times)

**Deliverables:**
- RSA signing/verification working
- Performance baseline (~40-60ms sign, ~3-5ms verify)

#### Day 4: ECDH-P256 Implementation
- Create `ecdh.h` and `ecdh.c` modules
- Implement ephemeral keypair generation
- Implement shared secret computation
- Test ECDH key exchange between two instances
- Measure performance (~10-15ms per operation)

**Deliverables:**
- ECDH key exchange functional
- Shared secret correctly computed on both sides

#### Day 5: AES-256-GCM with Hardware Acceleration
- Enable STM32H7 CRYP peripheral via CubeMX
- Implement `aes_gcm.h` and `aes_gcm.c`
- Create encrypt/decrypt functions with authentication
- Test with known test vectors
- Verify hardware acceleration is active

**Deliverables:**
- AES-GCM encryption/decryption working
- Hardware acceleration confirmed (~0.5ms for 64 bytes)

#### Day 6-7: Unit Testing & Integration
- Create test suite for all crypto primitives
- Test RSA + ECDH integration (full classical flow)
- Measure memory usage (stack, heap, flash)
- Document API for each module
- Code review and cleanup

**Deliverables:**
- All crypto tests passing
- Memory usage documented
- API documentation complete

---

## Week 6: Classical PKI Flow Implementation

### 🎯 Objectives
- Generate RSA certificates using Python
- Implement simple certificate parser
- Implement UDS 0x29 PKI messages
- Complete end-to-end classical authentication
- Baseline performance measurements

### 📋 Tasks

#### Day 1: Python Certificate Generation
- Create `generate_certificates.py` script
- Generate self-signed X.509 certificates (RSA-2048)
- Export certificates in DER format
- Create C header files with certificate data
- Document certificate format

**Deliverables:**
- Python script generating valid RSA certificates
- Client and server certificates ready
- Certificate embedded in firmware as byte array

#### Day 2: Certificate Parser
- Create `cert_parser.h` and `cert_parser.c`
- Implement simple DER parser for X.509
- Extract public key from certificate
- Extract certificate metadata
- Validate certificate signature (self-signed)

**Deliverables:**
- Certificate parser extracting RSA public key
- Basic validation working

#### Day 3-4: UDS 0x29 PKI Messages
- Implement `uds_authentication.h` and `uds_authentication.c`
- Create message encoding/decoding functions
- Implement SubFunction 0x01 (verifyCertificateUnidirectional)
- Implement SubFunction 0x03 (proofOfOwnership)
- Handle multi-frame ISO-TP transfers

**Deliverables:**
- UDS 0x29 message encoding/decoding complete
- ISO-TP integration for large messages (cert ~500B, signature ~256B)

#### Day 5: End-to-End Classical Authentication
- Integrate all components (client + server)
- Implement complete PKI authentication flow:
  1. Client sends certificate
  2. Server verifies certificate, sends challenge + ECDH pubkey
  3. Client signs challenge, computes shared secret
  4. Server verifies signature, computes shared secret
  5. Both derive session key
- Test authentication success/failure scenarios

**Deliverables:**
- Complete classical authentication working
- Session key established on both sides

#### Day 6: Performance Benchmarking
- Measure authentication time (total flow)
- Measure individual crypto operations
- Measure ISO-TP transfer times
- Measure memory usage (RAM, flash)
- Create baseline performance report

**Deliverables:**
- Classical baseline performance data:
  - Total auth time: ~60-80ms
  - RSA cert: ~500 bytes (8 frames, ~7ms)
  - RSA signature: ~256 bytes (5 frames, ~4ms)
  - Memory usage documented

#### Day 7: Documentation & Testing
- Create detailed flow diagrams
- Document message formats
- Create test cases (100+ iterations)
- Verify stability and error handling
- Prepare Week 6 completion report

**Deliverables:**
- Classical PKI authentication fully documented
- Baseline performance report complete
- Code ready for PQC integration

---

# PHASE 2: PQC Theory & Implementation (Weeks 7-10)

## Week 7: Quantum Threat & PQC Theory (Writing Week)

### 🎯 Objectives
- Write thesis Chapter 2: Quantum Threat & Post-Quantum Cryptography
- Research quantum computing threat timeline
- Compare QKD vs PQC approaches
- Justify PQC selection for automotive

### 📋 Tasks

#### Day 1: Quantum Computing Threat Research
- Study Shor's algorithm (breaks RSA, ECDH)
- Study Grover's algorithm (weakens symmetric crypto)
- Research CRQC timeline estimates (2030-2040)
- Analyze "harvest now, decrypt later" attacks
- Review NIST quantum threat assessments

**Deliverables:**
- Section 2.1 draft: "The Quantum Computing Threat" (4-5 pages)

#### Day 2: Quantum Cryptography (QKD) Research
- Study BB84 protocol fundamentals
- Study E91 protocol (entanglement-based)
- Research QKD limitations (distance, cost, infrastructure)
- Analyze automotive applicability
- Review commercial QKD deployments

**Deliverables:**
- Section 2.2 draft: "Quantum Cryptography (QKD)" (3-4 pages)

#### Day 3: Post-Quantum Cryptography Research
- Study NIST PQC competition (2016-2024)
- Deep dive into lattice-based cryptography
- Study ML-KEM (FIPS 203) specification
- Study ML-DSA (FIPS 204) specification
- Review NIST security levels

**Deliverables:**
- Section 2.3 draft: "Post-Quantum Cryptography" (4-5 pages)

#### Day 4: QKD vs PQC Comparison Analysis
- Create detailed comparison table
- Analyze infrastructure requirements
- Analyze cost implications
- Evaluate automotive feasibility
- Justify PQC over QKD for automotive

**Deliverables:**
- Section 2.4 draft: "QKD vs PQC Comparison" (2-3 pages)

#### Day 5: Automotive PQC Justification
- Analyze CAN-FD/Ethernet compatibility
- Evaluate OTA update feasibility
- Cost-benefit analysis for mass production
- Review ISO/SAE 21434 cybersecurity requirements
- Industry adoption roadmap

**Deliverables:**
- Section 2.5 draft: "Why PQC for Automotive" (2-3 pages)

#### Day 6: Figures, Tables, References
- Create quantum threat timeline diagram
- Create QKD vs PQC comparison table
- Create ML-KEM/ML-DSA algorithm overview figures
- Compile references bibliography
- Format chapter according to thesis template

**Deliverables:**
- Complete figures and tables
- Bibliography with 30+ references

#### Day 7: Review, Revise, Finalize
- Review entire chapter for coherence
- Revise technical accuracy
- Proofread for grammar/spelling
- Get feedback from advisor (if possible)
- Finalize Chapter 2

**Deliverables:**
- ✅ Complete Chapter 2 (15-20 pages)
- ✅ Ready for thesis integration

---

## Week 8: PQC Library Integration

### 🎯 Objectives
- Port PQClean library to STM32H7
- Implement ML-KEM-512 (keygen, encapsulate, decapsulate)
- Implement ML-DSA-2 (keygen, sign, verify)
- Optimize for Cortex-M7 architecture
- Unit test all PQC operations

### 📋 Tasks

#### Day 1-2: PQClean Integration
- Download PQClean or pqm4 (Cortex-M optimized)
- Integrate ML-KEM-512 and ML-DSA-2 implementations
- Configure build system (Makefiles/CubeIDE)
- Resolve compilation issues
- Optimize for STM32H7 (use ARM DSP instructions if available)

**Deliverables:**
- PQClean compiling in project
- ML-KEM and ML-DSA libraries linked

#### Day 3: ML-KEM-512 Implementation
- Create `ml_kem.h` and `ml_kem.c` wrapper
- Implement key generation function
- Implement encapsulation function
- Implement decapsulation function
- Test with known test vectors

**Deliverables:**
- ML-KEM-512 keygen working
- Encapsulation/decapsulation producing correct shared secrets
- Performance measured (~15-25ms per operation)

#### Day 4: ML-DSA-2 Implementation
- Create `ml_dsa.h` and `ml_dsa.c` wrapper
- Implement key generation function
- Implement signing function
- Implement verification function
- Test with known test vectors

**Deliverables:**
- ML-DSA-2 keygen working
- Sign/verify producing correct results
- Performance measured (~50-100ms sign, ~30-50ms verify)

#### Day 5: Memory Optimization
- Measure stack usage for each operation
- Optimize memory allocation (reduce peaks)
- Ensure operations fit in 512KB RAM
- Profile flash usage
- Optimize code size if needed

**Deliverables:**
- Memory usage within constraints
- Stack profiling report

#### Day 6-7: PQC Unit Testing
- Create comprehensive test suite
- Test all ML-KEM operations
- Test all ML-DSA operations
- Test edge cases and error conditions
- Measure and document performance

**Deliverables:**
- All PQC tests passing
- Performance data documented
- API documentation complete

---

## Week 9: PQC PKI Flow Implementation

### 🎯 Objectives
- Generate ML-DSA certificates
- Modify certificate parser for PQC
- Implement UDS 0x29 with ML-KEM + ML-DSA
- Complete end-to-end PQC authentication
- Initial performance comparison

### 📋 Tasks

#### Day 1: Python PQC Certificate Generation
- Extend `generate_certificates.py` for ML-DSA
- Generate self-signed certificates with ML-DSA-2 signatures
- Embed ML-DSA public keys (1312 bytes)
- Export in simplified format (or extend DER parser)
- Create C header files

**Deliverables:**
- Python script generating ML-DSA certificates
- PQC certificates embedded in firmware

#### Day 2: Certificate Parser Updates
- Extend `cert_parser.c` for PQC certificates
- Extract ML-DSA public key (1312 bytes)
- Parse PQC-specific fields
- Validate ML-DSA certificate signature
- Support both classical and PQC certificates

**Deliverables:**
- Certificate parser handling PQC certs
- Public key extraction working

#### Day 3-4: UDS 0x29 PQC Integration
- Modify UDS message encoding for larger payloads
- Update SubFunction 0x01 for PQC (cert ~1500B)
- Update SubFunction 0x03 for PQC (signature ~2420B)
- Handle extended ISO-TP transfers
- Test message fragmentation

**Deliverables:**
- UDS 0x29 handling PQC-sized messages
- ISO-TP correctly fragmenting large signatures

#### Day 5: End-to-End PQC Authentication
- Integrate ML-KEM and ML-DSA into auth flow
- Implement complete PQC PKI authentication:
  1. Client sends ML-DSA certificate (~1500B)
  2. Server verifies cert, sends challenge + ML-KEM pubkey (800B)
  3. Client encapsulates ML-KEM, signs challenge (2420B)
  4. Server decapsulates, verifies signature
  5. Both derive session key
- Test authentication flow

**Deliverables:**
- Complete PQC authentication working
- Session key established

#### Day 6: Performance Comparison
- Measure PQC authentication time
- Compare classical vs PQC:
  - Total authentication time
  - Individual operation times
  - ISO-TP transfer times
  - Memory usage
- Create comparison report

**Deliverables:**
- PQC performance data
- Initial comparison table (classical vs PQC)

#### Day 7: Testing & Validation
- Run 100+ authentication iterations
- Test error scenarios
- Verify session key consistency
- Stress test memory usage
- Debug and optimize

**Deliverables:**
- PQC authentication stable and tested
- Ready for benchmarking phase

---

## Week 10: Performance Benchmarking & Analysis

### 🎯 Objectives
- Comprehensive performance benchmarking
- Memory profiling (RAM, flash, stack)
- Comparative analysis (classical vs PQC)
- Generate benchmark report
- Identify optimization opportunities

### 📋 Tasks

#### Day 1-2: Crypto Operation Benchmarking
- Measure RSA sign/verify times (1000 iterations)
- Measure ECDH operations (1000 iterations)
- Measure ML-DSA sign/verify times (1000 iterations)
- Measure ML-KEM encaps/decaps times (1000 iterations)
- Measure AES-GCM encrypt/decrypt times
- Calculate min/max/avg/stddev for each operation

**Deliverables:**
- Detailed crypto operation performance data
- Statistical analysis (mean, variance)

#### Day 2-3: Authentication Flow Benchmarking
- Measure complete classical authentication (500 iterations)
- Measure complete PQC authentication (500 iterations)
- Break down timing by phase:
  - Certificate transmission
  - Challenge generation/response
  - Signature verification
  - Session key derivation
- Measure end-to-end latency

**Deliverables:**
- Complete authentication timing data
- Phase-by-phase breakdown

#### Day 3-4: Memory Profiling
- Measure flash usage (code size):
  - Classical crypto libraries
  - PQC crypto libraries
  - Application code
- Measure static RAM usage:
  - Global variables
  - Crypto context structures
- Measure dynamic RAM usage:
  - Stack high-water mark
  - Heap allocations (if any)
- Profile per-operation memory peaks

**Deliverables:**
- Complete memory usage report
- Identify memory bottlenecks

#### Day 4-5: ISO-TP Transfer Analysis
- Measure transfer times for different payload sizes
- Analyze impact of STmin = 1ms
- Calculate effective throughput
- Compare classical vs PQC data sizes:
  - Certificate size
  - Signature size
  - Total bytes transferred

**Deliverables:**
- ISO-TP performance analysis
- Data size comparison table

#### Day 5-6: Comparative Analysis & Report
- Create comprehensive comparison tables
- Generate performance graphs
- Calculate PQC overhead percentages:
  - Time overhead
  - Memory overhead
  - Network overhead
- Analyze cost vs benefit
- Write benchmark report

**Deliverables:**
- Complete benchmark report (BENCHMARK_REPORT.md)
- Performance graphs and tables
- CSV data files

#### Day 7: Optimization & Documentation
- Identify optimization opportunities
- Implement quick wins (if any)
- Document performance characteristics
- Update API documentation
- Prepare Week 10 completion report

**Deliverables:**
- Optimized implementation
- Complete performance documentation
- Ready for Phase 3

---

# PHASE 3: Session Encryption & Demo (Weeks 11-12)

## Week 11: AES-GCM Session Encryption

### 🎯 Objectives
- Implement session key management
- Encrypt UDS diagnostic messages with AES-256-GCM
- Implement encrypted Read/Write operations
- Test encrypted communication flow
- Demonstrate complete security chain

### 📋 Tasks

#### Day 1-2: Session Key Derivation
- Implement HKDF (HMAC-based Key Derivation)
- Derive session key from shared secret (ECDH or ML-KEM)
- Implement session key verification (HMAC proof)
- Create session context structure
- Test key derivation consistency (client == server)

**Deliverables:**
- Session key derivation working
- Both sides have identical session keys

#### Day 2-3: Encrypted UDS Messages
- Implement UDS message encryption wrapper
- Encrypt request messages before ISO-TP send
- Decrypt response messages after ISO-TP receive
- Add authentication tag validation
- Handle nonce/IV management (counter-based)

**Deliverables:**
- UDS messages encrypted with AES-256-GCM
- Decryption and authentication working

#### Day 3-4: Encrypted Diagnostics Implementation
- Implement encrypted ReadDataByIdentifier (0x22)
  - Read VIN (DID 0xF190)
  - Read software version
  - Read ECU serial number
- Implement encrypted WriteDataByIdentifier (0x2E)
  - Write configuration parameters
- Implement encrypted ReadDTCInformation (0x19)
  - Read diagnostic trouble codes

**Deliverables:**
- Encrypted read operations working
- Encrypted write operations working
- Encrypted DTC reading working

#### Day 4-5: Session Lifecycle Management
- Implement session timeout handling
- Implement session termination
- Handle re-authentication
- Test session expiration scenarios
- Implement secure session cleanup

**Deliverables:**
- Session management complete
- Timeout and cleanup working

#### Day 5-6: Integration Testing
- Test complete flow: Auth → Encrypted diagnostics
- Test with both classical and PQC authentication
- Test error scenarios (wrong key, tampered data)
- Verify authentication tag validation
- Stress test session management

**Deliverables:**
- Complete encrypted communication working
- Error handling verified

#### Day 7: Performance & Documentation
- Measure encryption/decryption overhead
- Document session key protocol
- Create sequence diagrams
- Update API documentation
- Prepare demo scenarios

**Deliverables:**
- Encryption overhead documented (~0.5-1ms per message)
- Complete documentation
- Demo scenarios defined

---

## Week 12: FreeRTOS Integration

### 🎯 Objectives
- Integrate FreeRTOS into project
- Implement event-driven ISO-TP task
- Implement UDS authentication task
- Configure task priorities and synchronization
- Production-ready architecture

### 📋 Tasks

#### Day 1-2: FreeRTOS Setup
- Enable FreeRTOS in STM32CubeMX
- Configure RTOS kernel (1ms tick, heap size)
- Create task structure:
  - ISO-TP processing task
  - UDS authentication task
  - Demo/GUI task
- Configure priorities (ISO-TP = High, others = Normal)
- Test basic RTOS functionality

**Deliverables:**
- FreeRTOS running with multiple tasks
- Task switching working correctly

#### Day 2-3: ISO-TP Task Implementation
- Convert ISO-TP to event-driven model
- Wake on CAN RX interrupt (event flags)
- Process ISO-TP with 1ms timeout
- Handle TX completion callbacks
- Test ISO-TP under RTOS

**Deliverables:**
- ISO-TP running as RTOS task
- Event-driven processing working
- Performance maintained

#### Day 3-4: UDS Authentication Task
- Implement authentication state machine
- Handle authentication request/response
- Coordinate with ISO-TP task (message passing)
- Implement task synchronization (semaphores/mutexes)
- Test authentication under RTOS

**Deliverables:**
- UDS authentication running as task
- Task communication working
- Synchronization correct

#### Day 4-5: Task Synchronization
- Implement proper semaphore usage
- Prevent race conditions in shared resources
- Protect crypto operations (thread-safe)
- Test concurrent access scenarios
- Verify no deadlocks

**Deliverables:**
- Thread-safe implementation
- No race conditions
- Stable under stress test

#### Day 5-6: Production Architecture
- Implement error recovery mechanisms
- Add task watchdogs
- Implement proper resource cleanup
- Optimize task stack sizes
- Monitor CPU usage

**Deliverables:**
- Production-quality task architecture
- CPU usage optimized (<30% average)
- Stack usage profiled

#### Day 7: Testing & Documentation
- Test complete system under RTOS
- Run extended stress tests (1000+ iterations)
- Document task architecture
- Create timing diagrams
- Update system documentation

**Deliverables:**
- RTOS integration complete and stable
- Architecture documented
- Ready for demo development

---

# PHASE 4: GUI & Final Demo (Weeks 13-14)

## Week 13: Demo Application Development

### 🎯 Objectives
- Create visual demonstration application
- Implement side-by-side comparison (Classical vs PQC)
- Display real-time performance metrics
- Create interactive demo script
- Polish user interface

### 📋 Tasks

#### Day 1-2: Demo GUI Framework
- Design GUI layout (LCD display or serial terminal)
- Implement menu system
- Create visual progress indicators
- Implement performance metric display
- Add color coding (success = green, fail = red)

**Deliverables:**
- GUI framework functional
- Menu navigation working

#### Day 2-3: Classical Authentication Demo
- Create demo sequence for classical auth
- Display step-by-step progress:
  - "Sending RSA certificate..."
  - "Challenge received..."
  - "Signing with RSA-2048..."
  - "Authentication complete"
- Show performance metrics (timing, data size)
- Display session key status

**Deliverables:**
- Classical demo sequence complete
- Visual feedback working

#### Day 3-4: PQC Authentication Demo
- Create demo sequence for PQC auth
- Display step-by-step progress:
  - "Sending ML-DSA certificate..."
  - "ML-KEM key exchange..."
  - "Signing with ML-DSA-2..."
  - "Authentication complete"
- Show performance metrics
- Highlight quantum-resistance

**Deliverables:**
- PQC demo sequence complete
- Side-by-side comparison ready

#### Day 4-5: Encrypted Diagnostics Demo
- Create encrypted diagnostics sequence
- Show encrypted Read VIN operation
- Show encrypted Read DTCs operation
- Show encrypted Write configuration
- Display before/after encryption

**Deliverables:**
- Encrypted diagnostics demo complete
- Visual representation of encryption

#### Day 5-6: Performance Comparison Display
- Create comparison summary screen
- Display side-by-side metrics:
  - Authentication time (Classical vs PQC)
  - Data transferred (bytes)
  - Memory usage
  - Security level
- Create visual graphs/charts
- Add "Overhead Analysis" section

**Deliverables:**
- Performance comparison display complete
- Metrics clearly visualized

#### Day 7: Demo Polish & Scripting
- Create automated demo script
- Add narration/commentary text
- Implement demo reset functionality
- Test demo flow (5-minute complete demo)
- Polish visual appearance

**Deliverables:**
- Complete demo application
- Automated demo script
- Ready for final testing

---

## Week 14: Final Integration & Testing

### 🎯 Objectives
- End-to-end system testing
- Error scenario validation
- Performance validation
- Demo rehearsal
- Bug fixes and polish

### 📋 Tasks

#### Day 1-2: End-to-End Testing
- Run 500+ complete authentication cycles
- Test both classical and PQC paths
- Test encrypted diagnostics (100+ operations)
- Verify no memory leaks
- Monitor system stability

**Deliverables:**
- System stable over extended testing
- No critical bugs found

#### Day 2-3: Error Scenario Testing
- Test invalid certificates
- Test signature verification failures
- Test corrupted encrypted messages
- Test session timeout scenarios
- Test resource exhaustion scenarios
- Verify error handling and recovery

**Deliverables:**
- All error scenarios handled gracefully
- System recovers correctly

#### Day 3-4: Performance Validation
- Verify performance meets expectations:
  - Classical auth: <80ms
  - PQC auth: <150ms
  - Encrypted message: <2ms overhead
- Validate memory usage within budget
- Confirm no performance regressions
- Re-run all benchmarks

**Deliverables:**
- Performance validated
- All benchmarks passing

#### Day 4-5: Demo Rehearsal
- Practice complete demo presentation
- Test demo under various conditions
- Prepare for failures (backup plan)
- Time demo (target: 10-15 minutes)
- Get feedback from colleagues/advisor

**Deliverables:**
- Demo rehearsed and polished
- Backup scenarios prepared

#### Day 5-6: Bug Fixes & Optimization
- Fix any discovered bugs
- Optimize critical paths if needed
- Clean up debug code
- Finalize code comments
- Prepare code for submission

**Deliverables:**
- All known bugs fixed
- Code clean and documented

#### Day 7: Final System Validation
- Final complete system test
- Verify all features working
- Create system validation report
- Tag release version in Git
- Archive final binaries

**Deliverables:**
- ✅ Complete working system
- ✅ Validated and ready for defense
- ✅ Code repository tagged

---

# PHASE 5: Documentation & Defense (Weeks 15-16)

## Week 15: Thesis Writing

### 🎯 Objectives
- Complete all thesis chapters
- Create figures, tables, and graphs
- Write results and analysis
- Format according to university template
- Prepare for advisor review

### 📋 Tasks

#### Day 1: Chapter 3 - System Architecture
- Describe overall system architecture
- Document hardware setup
- Explain software architecture
- Create block diagrams
- Describe ISO-TP and UDS integration

**Deliverables:**
- Chapter 3 complete (10-12 pages)

#### Day 2: Chapter 4 - Implementation (Part 1)
- Classical cryptography implementation
- Mbed TLS integration details
- RSA and ECDH implementation
- Certificate handling
- Performance optimizations

**Deliverables:**
- Chapter 4.1-4.2 complete (8-10 pages)

#### Day 3: Chapter 4 - Implementation (Part 2)
- PQC implementation details
- PQClean integration
- ML-KEM and ML-DSA implementation
- Memory optimization strategies
- FreeRTOS integration

**Deliverables:**
- Chapter 4.3-4.4 complete (8-10 pages)

#### Day 4: Chapter 5 - Results & Analysis
- Present all benchmark results
- Create performance comparison tables
- Create performance graphs
- Analyze classical vs PQC overhead
- Discuss memory usage
- Security analysis

**Deliverables:**
- Chapter 5 complete (12-15 pages)
- All figures and tables created

#### Day 5: Chapter 6 - Conclusion & Future Work
- Summarize contributions
- Discuss achievements
- Analyze limitations
- Propose future improvements:
  - Bidirectional authentication
  - Extended ISO-TP (>4GB)
  - Hardware acceleration for PQC
  - Additional PQC algorithms
- Final remarks

**Deliverables:**
- Chapter 6 complete (4-5 pages)

#### Day 6: Formatting & References
- Format entire thesis (university template)
- Complete bibliography (50+ references)
- Add table of contents
- Number all figures and tables
- Add appendices (code listings, datasheets)
- Proofread entire document

**Deliverables:**
- Complete thesis manuscript formatted

#### Day 7: Review & Revision
- Full thesis review
- Check technical accuracy
- Grammar and spelling check
- Get feedback from advisor
- Make final revisions
- Generate PDF for submission

**Deliverables:**
- ✅ Complete thesis ready for submission
- ✅ PDF generated

---

## Week 16: Defense Preparation

### 🎯 Objectives
- Create defense presentation
- Prepare demo for defense
- Practice presentation
- Prepare for questions
- Final submission

### 📋 Tasks

#### Day 1-2: Presentation Creation
- Create PowerPoint/Beamer slides (30-40 slides)
- Structure: Introduction → Problem → Solution → Results → Conclusion
- Include key diagrams from thesis
- Include performance graphs
- Add demo video/screenshots
- Keep slides concise and visual

**Deliverables:**
- Defense presentation complete

#### Day 2-3: Demo Preparation
- Prepare live demo for defense
- Create demo video backup (in case of technical issues)
- Test demo on presentation laptop
- Prepare demo script with narration
- Time demo (target: 5-7 minutes)

**Deliverables:**
- Live demo ready
- Backup video recorded

#### Day 3-4: Practice Sessions
- Practice presentation (3-5 times)
- Time presentation (target: 20-25 minutes)
- Practice with demo
- Get feedback from colleagues
- Refine based on feedback

**Deliverables:**
- Presentation polished
- Timing optimized

#### Day 4-5: Question Preparation
- Anticipate potential questions:
  - Why PQC over QKD?
  - Why unidirectional vs bidirectional?
  - Memory constraints discussion
  - Performance overhead justification
  - Security analysis
  - Future automotive deployment
- Prepare clear, concise answers
- Practice Q&A session

**Deliverables:**
- Q&A preparation complete
- Answers rehearsed

#### Day 5-6: Final Preparation
- Review entire thesis one last time
- Review all presentation slides
- Test demo equipment
- Prepare backup plans (USB, cloud backup)
- Get good rest before defense

**Deliverables:**
- Fully prepared for defense
- All materials ready

#### Day 7: Defense Day
- Arrive early
- Set up equipment
- Deep breath 😊
- Present confidently
- Demonstrate system
- Answer questions
- Celebrate! 🎉

**Deliverables:**
- ✅ Successful defense
- ✅ PFE complete!

---

# Summary Timeline

## Phase Overview

| Phase | Weeks | Focus | Key Deliverable |
|-------|-------|-------|----------------|
| **Phase 1** | 5-6 | Classical Baseline | Working classical authentication |
| **Phase 2** | 7-10 | PQC Theory & Implementation | Working PQC authentication + benchmarks |
| **Phase 3** | 11-12 | Session Encryption & RTOS | Complete secure system |
| **Phase 4** | 13-14 | Demo & Testing | Polished demonstration |
| **Phase 5** | 15-16 | Documentation & Defense | Thesis + successful defense |

## Critical Milestones

| Week | Milestone | Status Check |
|------|-----------|-------------|
| 6 | ✅ Classical auth working | Can authenticate with RSA+ECDH? |
| 7 | ✅ PQC theory chapter done | Chapter 2 complete? |
| 9 | ✅ PQC auth working | Can authenticate with ML-KEM+ML-DSA? |
| 10 | ✅ Benchmarks complete | Have performance comparison data? |
| 12 | ✅ System integrated | FreeRTOS + encryption working? |
| 14 | ✅ Demo ready | Can run 10-min demo successfully? |
| 16 | ✅ Defense ready | Thesis submitted + presentation ready? |

---

# Risk Management

## Potential Risks & Mitigations

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| PQC library porting issues | Medium | High | Start early (Week 8), allocate 2 weeks |
| Memory constraints (RAM) | Medium | High | Profile early, optimize algorithms |
| Integration bugs | High | Medium | Continuous testing, allocate buffer time |
| Demo failure on defense day | Low | High | Record backup video, test extensively |
| Thesis writing delays | Medium | High | Start writing early (Week 7), stay on schedule |
| Advisor unavailable for review | Low | Medium | Schedule reviews in advance, have backup reviewers |

## Contingency Plans

**If running behind schedule:**
- **Week 8-9:** Simplify certificate format (skip full X.509, use raw format)
- **Week 11:** Skip some encrypted UDS services (focus on 0x22 only)
- **Week 13:** Simplify GUI (terminal-based instead of graphical)

**If ahead of schedule:**
- Implement bidirectional authentication (comparison)
- Add more UDS services
- Optimize PQC algorithms further
- Add hardware PKA acceleration for classical crypto

---

# Resources Required

## Hardware
- 2× STM32H7B3I-DK boards ✅ (already have)
- CAN-FD cables and terminators ✅ (already have)
- ST-Link debugger ✅ (integrated in board)
- PC for development ✅ (already have)

## Software
- STM32CubeIDE (free) ✅
- Mbed TLS 3.5.x (open source) ✅
- PQClean (open source) ✅
- Python 3.x + cryptography library (free) ✅
- Git (version control, free) ✅
- LaTeX or Word (thesis writing) ✅

## Documentation Access
- ISO 14229-1:2020 ✅ (already have)
- NIST FIPS 203 (ML-KEM) - free online
- NIST FIPS 204 (ML-DSA) - free online
- Academic papers (via university library)

---

# Success Criteria

**By Week 16, you will have successfully:**

✅ Implemented complete PKI authentication (Classical + PQC)  
✅ Demonstrated all cryptographic primitives (key exchange, signature, encryption)  
✅ Measured and documented performance (Classical vs PQC comparison)  
✅ Created working demo application  
✅ Written complete thesis (80-100 pages)  
✅ Prepared and delivered successful defense presentation  
✅ Published code repository on GitHub  
✅ Graduated! 🎓

---

**END OF PLAN**

*This plan is a living document. Adjust as needed based on progress and circumstances. Good luck! 🚀*