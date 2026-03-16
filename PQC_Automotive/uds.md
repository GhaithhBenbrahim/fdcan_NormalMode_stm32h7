📋 ISO 14229-1:2020 Service 0x29 SubFunctions
Complete SubFunction Table:
c/* ════════════════════════════════════════════════════════════════
   Service 0x29: Authentication SubFunctions (ISO 14229-1:2020)
   ════════════════════════════════════════════════════════════════ */

/* Common SubFunctions (M = Mandatory) */
#define UDS_0x29_DEAUTHENTICATE                     0x00  // M - DA
#define UDS_0x29_AUTHENTICATION_CONFIGURATION       0x08  // M - AC

/* PKI Certificate Exchange (APCE) - C1 = Conditional */
#define UDS_0x29_VERIFY_CERT_UNIDIRECTIONAL         0x01  // C1 - VCU
#define UDS_0x29_VERIFY_CERT_BIDIRECTIONAL          0x02  // C1 - VCB
#define UDS_0x29_PROOF_OF_OWNERSHIP                 0x03  // C1 - POWN
#define UDS_0x29_TRANSMIT_CERTIFICATE               0x04  // C1 - TC

/* Challenge-Response (ACR) - C2 = Conditional */
#define UDS_0x29_REQUEST_CHALLENGE_FOR_AUTH         0x05  // C2 - RCFA
#define UDS_0x29_VERIFY_POWN_UNIDIRECTIONAL         0x06  // C2 - VPOWNU
#define UDS_0x29_VERIFY_POWN_BIDIRECTIONAL          0x07  // C2 - VPOWNB

/* Reserved */
#define UDS_0x29_RESERVED_START                     0x09
#define UDS_0x29_RESERVED_END                       0x7F
```

---

## 🚨 **CRITICAL CORRECTION: SubFunction Numbers Changed!**

### **What Changed from ISO Document You Showed First:**

| ISO Table 74 | Previous ISO Text | What We Use (PKI APCE) |
|--------------|-------------------|------------------------|
| 0x00 | deAuthenticate | ✅ 0x00 (common) |
| **0x01** | **verifyCertificateUnidirectional** | ✅ **0x01 (VCU)** |
| **0x02** | **verifyCertificateBidirectional** | ⚠️ 0x02 (VCB - bidirectional) |
| **0x03** | **proofOfOwnership** | ✅ **0x03 (POWN)** |
| **0x04** | **transmitCertificate** | ✅ 0x04 (TC) |
| 0x05 | requestChallengeForAuthentication | ❌ ACR only |
| 0x06 | verifyProofOfOwnershipUnidirectional | ❌ ACR only |
| 0x07 | verifyProofOfOwnershipBidirectional | ❌ ACR only |
| 0x08 | authenticationConfiguration | ✅ 0x08 (common) |

---

## ✅ **CORRECTED: PKI APCE Unidirectional Flow**

### **We Use ONLY These SubFunctions:**
```
PKI Certificate Exchange (APCE) - Unidirectional:
═════════════════════════════════════════════════

SubFunction 0x01: verifyCertificateUnidirectional (VCU)
├── Client → Server
├── Sends: Certificate + Challenge (optional) + Config
└── Initiates authentication

SubFunction 0x03: proofOfOwnership (POWN)
├── Client → Server
├── Sends: Signature + Ephemeral Public Key
└── Proves ownership of certificate private key

SubFunction 0x00: deAuthenticate (DA) - Optional
└── Ends authenticated session

SubFunction 0x04: transmitCertificate (TC) - Optional
└── Independent certificate transmission
```

---

## 🔄 **FINAL CORRECTED Flow (ISO 14229-1:2020 PKI APCE)**
```
VCI (Client)                                    ECU (Server)
════════════════════════════════════════════════════════════════════

Prerequisites:
- VCI has: certificate_client + private_key_client
- ECU has: certificate_ca (to verify client)

────────────────────────────────────────────────────────────────────
STEP 1-2: Client initiates authentication with 0x01
────────────────────────────────────────────────────────────────────

(1) Client creates challenge_client (optional)

(2) Client sends: SubFunction 0x01 (VCU)
    ↓
    Request: [29 01] + communicationConfiguration
                    + certificateClientLength (2B)
                    + certificateClient (DER, ~588B)
                    + challengeClient (optional, 32B)
                    + algorithmIndicator (0x01 = ECDH-P256)
    ──────────────────────────────────────────────────→

────────────────────────────────────────────────────────────────────
STEP 3-7: Server validates cert and responds with challenge
────────────────────────────────────────────────────────────────────

                                                (3) Verify certificate_client
                                                    - Parse DER certificate
                                                    - Validate with CA cert
                                                    - Extract public key
                                                    
                                                (4) Create challenge_server
                                                    - Generate random (32B)
                                                    
                                                (5) Generate ECDH keypair
                                                    - ephemeral_private_server
                                                    - ephemeral_public_server
                                                    
                                                (7) Prepare response
    ←──────────────────────────────────────────────────
    Response: [69 01] + challengeServerLength
                     + challengeServer (32B)
                     + ephemeralPublicKeyServerLength
                     + ephemeralPublicKeyServer (65B)

────────────────────────────────────────────────────────────────────
STEP 9-11: Client generates proof and sends 0x03
────────────────────────────────────────────────────────────────────

(9) Client generates ECDH keypair
    - ephemeral_private_client
    - ephemeral_public_client
    - shared_secret = ECDH(ephemeral_private_client,
                           ephemeral_public_server)

(10) Client calculates proof_of_ownership
     auth_token = challengeServer || ephemeralPublicKeyClient
     hash = SHA256(auth_token)
     signature = ECDSA_sign(private_key_client, hash)

(11) Client sends: SubFunction 0x03 (POWN)
     ↓
     Request: [29 03] + algorithmIndicator (0x01 = ECDSA-P256)
                     + proofOfOwnershipClientLength (2B)
                     + proofOfOwnershipClient (signature, ~72B)
                     + challengeServerEcho (optional, 32B)
                     + ephemeralPublicKeyClientLength
                     + ephemeralPublicKeyClient (65B)
     ──────────────────────────────────────────────────→

────────────────────────────────────────────────────────────────────
STEP 12-15: Server verifies proof and grants access
────────────────────────────────────────────────────────────────────

                                                (12) Verify proof_of_ownership
                                                     auth_token = challengeServer ||
                                                                  ephemeralPublicKeyClient
                                                     hash = SHA256(auth_token)
                                                     ECDSA_verify(public_key_client,
                                                                  hash, signature)
                                                     
                                                (13) Derive session key
                                                     shared_secret = ECDH(
                                                       ephemeral_private_server,
                                                       ephemeral_public_client)
                                                     session_key = HKDF(shared_secret)
                                                     
                                                (14) Grant access rights
                                                     Set authenticated state
                                                     
                                                (15) Send response
    ←──────────────────────────────────────────────────
    Response: [69 03] + sessionKeyInfo (optional)

────────────────────────────────────────────────────────────────────
STEP 16-18: Client derives session key and enables encryption
────────────────────────────────────────────────────────────────────

(16) Client derives session_key
     session_key = HKDF(shared_secret)

(17) Client verifies session_key_info (optional)

(18) Client enables session_key
     Ready for encrypted diagnostics

════════════════════════════════════════════════════════════════════
AUTHENTICATED SESSION ESTABLISHED
All subsequent diagnostic messages encrypted with AES-256-GCM
════════════════════════════════════════════════════════════════════

📝 FINAL CORRECTED Message Formats
SubFunction 0x01: verifyCertificateUnidirectional (VCU)
Request (Client → Server):
cOffset  Field                           Size    Description
──────────────────────────────────────────────────────────────────
0       SID                             1       0x29
1       SubFunction                     1       0x01 (VCU)
2       communicationConfiguration      1       Bit 0: sessionKeyRequest
                                                Bits 1-7: Reserved
3-4     certificateClientLength         2       Big-endian (e.g., 0x024C = 588)
5-592   certificateClient               588     DER format
593     challengeClientLength           1       Optional (0 if not used)
594-625 challengeClient                 32      Optional random challenge
626     algorithmIndicator              1       0x01 = ECDH-P256
Total size: ~627 bytes (fits in ISO-TP max 4095 bytes)
Response (Server → Client):
cOffset  Field                           Size    Description
──────────────────────────────────────────────────────────────────
0       SID                             1       0x69 (positive: 0x29 + 0x40)
1       SubFunction                     1       0x01 (echo)
2       challengeServerLength           1       32 (0x20)
3-34    challengeServer                 32      Random challenge
35      ephemeralPublicKeyServerLength  1       65 (0x41)
36-100  ephemeralPublicKeyServer        65      Uncompressed ECDH public key
Total size: 101 bytes

SubFunction 0x03: proofOfOwnership (POWN)
Request (Client → Server):
cOffset  Field                           Size    Description
──────────────────────────────────────────────────────────────────
0       SID                             1       0x29
1       SubFunction                     1       0x03 (POWN)
2       algorithmIndicator              1       0x01 = ECDSA-P256
3-4     proofOfOwnershipClientLength    2       Big-endian (~72 = 0x0048)
5-76    proofOfOwnershipClient          72      ECDSA signature (DER)
77      challengeServerEchoLength       1       Optional (0 if not used)
78-109  challengeServerEcho             32      Optional (echo challenge)
110     ephemeralPublicKeyClientLength  1       65 (0x41)
111-175 ephemeralPublicKeyClient        65      Uncompressed ECDH public key
Total size: ~176 bytes
Response (Server → Client):
cOffset  Field                           Size    Description
──────────────────────────────────────────────────────────────────
0       SID                             1       0x69 (positive response)
1       SubFunction                     1       0x03 (echo)
2       sessionKeyInfoLength            1       Optional (implementation-specific)
3-N     sessionKeyInfo                  N       Optional encrypted session info
Minimum size: 2 bytes (if no sessionKeyInfo)

📊 Updated Architecture with Correct SubFunctions
State Machine (Corrected):
ctypedef enum {
    UDS_AUTH_STATE_IDLE = 0,               // No authentication
    
    /* PKI APCE Unidirectional */
    UDS_AUTH_STATE_VCU_SENT,               // After 0x01 sent
    UDS_AUTH_STATE_CHALLENGE_RECEIVED,     // After 0x01 response
    UDS_AUTH_STATE_POWN_SENT,              // After 0x03 sent
    UDS_AUTH_STATE_AUTHENTICATED,          // After 0x03 response
    UDS_AUTH_STATE_SESSION_ACTIVE,         // Encryption enabled
    
    /* Error states */
    UDS_AUTH_STATE_FAILED,
    UDS_AUTH_STATE_TIMEOUT
    
} uds_auth_state_t;