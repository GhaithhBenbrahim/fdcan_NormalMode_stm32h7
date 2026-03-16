# Presentation: Securing Automotive Networks against the Quantum Threat

## 1. Introduction: The Quantum Threat (Problematic)

Good morning everyone. Today I want to discuss the future of our automotive security architecture, specifically the fast-approaching threat of Quantum Computing and how we are engineering our ECUs to handle it.

Since the late 1990s, the entire world—including our automotive diagnostics and Over-The-Air (OTA) updates—has relied on Asymmetric Cryptography, primarily **RSA** and **Elliptic Curve Cryptography (ECC)**. These algorithms are based on math problems like prime factorization and the discrete logarithm. For a classical computer, reversing these math problems takes thousands of years. 

However, in 1994, Peter Shor published **Shor's Algorithm**. Shor proved mathematically that a sufficiently large Quantum Computer can solve these exact mathematical foundations exponentially faster. This means when Cryptographically Relevant Quantum Computers (CRQCs) come online, ECC and RSA will be instantly broken. Confidentiality and authenticity of vehicle networks will drop to zero. 

Because vehicles have a lifespan of 10 to 15 years, cars we design today might still be on the road when quantum computers arrive. We have to solve this now.

---

## 2. Why Not Quantum Key Distribution (QKD)?

When people think about "Quantum Security," they often jump to **Quantum Key Distribution (QKD)**. QKD uses actual quantum mechanics (like firing single entangled photons through a fiber-optic cable) to establish perfectly secure keys. If anyone tries to intercept the photon, the laws of quantum physics dictate that the photon's state drops, alerting the sender to the intrusion.

While this is amazing for securing bank-to-bank fiber optic lines, **QKD is impossible for automotive**. 
- It requires dedicated hardware, lasers, and pristine fiber-optic cables.
- You cannot run entangled photons over a copper CAN bus.
- It cannot provide digital signatures (like signing an OTA firmware update).

---

## 3. The Solution: Post-Quantum Cryptography (PQC)

The actual solution mandated by NIST (The National Institute of Standards and Technology) is **Post-Quantum Cryptography (PQC)**. 

Unlike QKD, PQC does not require quantum hardware. PQC relies on fundamentally new, extremely complex mathematics (like *Lattice-based cryptography*) that both classical computers and quantum computers fail at trying to break. 

NIST recently standardized two primary algorithms:
- **ML-DSA** (formerly Dilithium) for Digital Signatures (Authentication & OTA updates).
- **ML-KEM** (formerly Kyber) for Key Encapsulation (Establishing secure sessions).

Because these are just mathematical algorithms, we can run them right now on our standard STM32 microcontrollers. However, the challenge is that these algorithms use massive keys and signatures (often 10x to 50x larger than ECC)—meaning we have to completely rethink our vehicle network constraints.

---

## 4. Project Overview & Phases

My project focuses on implementing this NIST-mandated Post-Quantum capability into our native ECU architecture, specifically targeting UDS Service 0x29 (Authentication). 

The project is structured in progressive phases (without strict deadlines):

1. **Phase 1: Automotive Transport Baseline**
   Because PQC certificates exceed 15 KB, standard CAN frames (8 bytes) fail instantly. We must establish a robust ISO-TP layer capable of extended 32-bit payloads.
2. **Phase 2: The Crypto Abstraction Layer (CAL)**
   Building a dynamic Vtable abstraction layer that separates the UDS logic from the math. This allows us to hot-swap between mbedTLS (Classical) and PQClean (PQC) seamlessly.
3. **Phase 3: The Classical UDS 0x29 State Machine**
   Implementing the Unidirectional PKI flow (VerifyCertificate + ProofOfOwnership) using Classical ECDSA algorithms to validate the timing, state transitions, and memory limits.
4. **Phase 4: Post-Quantum Integration**
   Swapping out the Classical algorithms for ML-DSA and ML-KEM, dealing with the massive memory footprint, and optimizing the cryptography to fit on the STM32 stack.
5. **Phase 5: Hybrid Mode & GUI Demonstration**
   Mounting the architecture to a TouchGFX GUI to visually demonstrate the runtime hot-swapping between Classical and PQC modes over a live twin-board FDCAN network.

---

## 5. Current Advancement & Next Steps

I'm happy to report that we have successfully completed the foundational phases.

### What is working right now:
1. **The Transport Layer**: Our heavily modified `iso_tp.c` is live and tested over FDCAN. We have successfully overridden the 4095-byte limit and validated buffer transfers up to **15.3 KB**, giving us the hardware capacity to move ML-DSA data across the bus.
2. **The CAL Engine**: The `cal_backend_t` Vtable structure is active. We have fully wrapped mbedTLS 2.16.2 covering X.509 verification, ECDH key derivation, HKDF, and AES-256-GCM.
3. **UDS 0x29 Service Implementation**: The ECU and VCI state machines are complete.
   - We implemented a **Zero-Copy memory overlay** that saves 4 KB of RAM per request.
   - We mathematically proved that PQC will crash default ISO 14229 P2 timers (50ms). To solve this, I've implemented a native **NRC 0x78 (Response Pending)** asynchronous state machine. When the ECU receives a 0x29 command, it instantly requests 5000ms from the Tester, giving the STM32 enough time to crunch the cryptography without dropping the CAN session.

### The Immediate Next Step: Testing
With the complete UDS 0x29 flow and Classical cryptography fully modeled and integrated into our `main.c` loops, my immediate next step is to flash this onto the twin STM32H7 evaluation boards. I will be capturing the runtime benchmarks and verifying the `0x78` P2 extended timers over live FDCAN. Once this classical baseline is locked, we drag-and-drop the PQC maths on top of it.

Thank you.
