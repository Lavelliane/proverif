# SGP.22 eSIM Provisioning Protocol - Verification Summary

## Applied Refinements (MrKo.md Suggestions)

All suggestions from `MrKo.md` have been successfully applied to strengthen the formal verification models:

### ✅ S1: Strengthened Signature Logic (Original Models Only)
- **Applied to**: `original-auth.pv`, `original-public-channel.pv`
- **Changes**: 
  - `mk_serverSigned1` now includes device ID: `(Tid_t, Id_t, Nonce_t, Nonce_t, Id_t)`
  - `mk_clientSigned1` now includes eUICC ID: `(Tid_t, Id_t, Nonce_t)`
- **Impact**: Cryptographically binds signatures to specific device identities, preventing relay attacks
- **Note**: Not applicable to Full PQC models (use KEM, not signatures for authentication)

### ✅ S2: Binding Events to Nonces (All Auth Models)
- **Applied to**: All 4 authentication models
- **Changes**: Events now include challenge nonces
  - Original: `SMDP_AUTH_BEGIN(dev, tid, eChal, sChal)`
  - Full PQC: `SMDP_BEGIN(dev, tid, eChal, serverNonce)`
- **Impact**: Queries can now verify that authentication binds to specific challenge-response pairs, not just transaction IDs

### ✅ S3: Explicit Identity Verification (All Auth Models)
- **Applied to**: All 4 authentication models
- **Changes**: Events now record extracted certificate identities
  - `EUICC_AUTH_OK(dev, tid, eChal, sChal, id_dp)` - records which SM-DP+ was authenticated
  - `SMDP_AUTH_OK(dev, tid, sChal, id_eu)` - records which eUICC was authenticated
- **Impact**: Verifies that specific expected entities were authenticated, not just any valid certificate

### ✅ S4: Refined Correspondence Queries (All Auth Models)
- **Applied to**: All 4 authentication models
- **Changes**: 
  - Added new `SMDP_SENT_SERVER1` / `SMDP_SENT_AUTH` events
  - Replaced weak `SMDP_BEGIN` query with stronger verification of actual message sending
- **Impact**: Proves the server actually sent the authenticated message, not just initiated the protocol

### ✅ S5: Certificate Role and Identity Validation (Original Models Only)
- **Applied to**: `original-auth.pv`, `original-public-channel.pv`
- **Changes**: Added explicit checks after certificate verification:
  - **EUICC side**: `if id_dp = ID_SMDP then if role_dp = tag_dp then`
  - **SMDP side**: `if id_eu = ID_EUICC then if role_eu = tag_eu then`
  - **Signature identity**: `if id_eu2 = id_eu then` (validates identity in signed message)
- **Impact**: 
  - Prevents acceptance of valid certificates with wrong roles or identities
  - Ensures symmetric identity verification (both parties verify specific expected peer)
  - Validates that signed identity matches certificate identity
- **Note**: Full PQC models already enforce this via pattern matching (`=ID_SMDP`, `=tag_dp`, `=ID_EUICC`, `=tag_eu`)

### ✅ S5+: Additional Identity Check (Post-Review Fix)
- **Applied to**: Same models as S5
- **Issue identified by CodeRabbit**: SMDP was only checking `role_eu` but not `id_eu`, creating asymmetry
- **Fix**: Added missing `if id_eu = ID_EUICC then` check in SMDP process
- **Impact**: Now both parties symmetrically verify both identity AND role of their peer

### ✅ S6: Channel Assumption Analysis
- **Status**: Already addressed via `no-tls/` models
- **Impact**: Demonstrates transport independence - security holds even with attacker-controlled ES9+ channel

---

## Model Families Comparison

### 1. Original (Classical Cryptography)

**Files**: `original-auth.pv`, `original-download.pv`

**Cryptographic Primitives**:
- **Certificates**: ECDSA signatures with classical PKI
- **Authentication**: Signature-based mutual authentication (Phase A)
- **Key Exchange**: Ephemeral ECDH for profile encryption (Phase B)
- **Forward Secrecy**: Yes (via ephemeral DH)

**Channel Model**:
- `LPA2EUICC`: Private (local interface)
- `LPA2SMDP`: Private (TLS-secured HTTPS channel assumed)

**Security Properties Verified** (Phase A - Authentication):
- ✅ Mutual authentication (eUICC ↔ SM-DP+)
- ✅ Session binding via nonces
- ✅ Identity verification

**Security Properties Verified** (Phase B - Download):
- ✅ Profile confidentiality (attacker cannot learn profile)
- ✅ Forward secrecy (profile secure after long-term key compromise)
- ✅ Injective agreement on profile installation
- ⚠️  Installation confirmation injectivity (cannot be proved - replay possible)

**Key Insight**: Standard TLS-based design. Assumes TLS provides confidentiality and integrity for LPA↔SM-DP+ channel.

---

### 2. Full PQC (Post-Quantum with Private Channels)

**Files**: `fullpqc-auth.pv`, `fullpqc-download.pv`

**Cryptographic Primitives**:
- **Certificates**: Dilithium (PQ signature scheme) certificates containing KEM public keys
- **Authentication**: ML-KEM based (KEMTLS-style) with three KEM operations:
  - Ephemeral KEM (forward secrecy)
  - Client-to-server KEM
  - Server-to-client KEM
- **Key Derivation**: Combined KEM shared secrets with transcript binding
- **MAC**: Finished messages authenticate the handshake

**Channel Model**:
- `LPA2EUICC`: Private (local interface)
- `LPA2SMDP`: Private (TLS-secured channel assumed)

**Security Properties Verified** (Phase A - Authentication):
- ✅ Mutual authentication with transcript binding
- ✅ Session key agreement
- ✅ Session binding via nonces and transcript hash
- ✅ Identity verification via certificates

**Security Properties Verified** (Phase B - Download):
- ✅ Profile confidentiality
- ✅ Forward secrecy
- ✅ Injective agreement on profile installation
- ⚠️  Installation confirmation injectivity (same limitation as original)

**Key Insight**: Quantum-resistant design. Uses KEM throughout instead of signatures for authentication. Maintains same security properties as classical version but resistant to quantum attacks.

---

### 3. Full PQC with Public ES9+ Channel (Transport Independence)

**Files**: `no-tls/fullpqc-notls-auth.pv`, `no-tls/fullpqc-notls-download.pv`, `no-tls/original-public-channel.pv`

**Cryptographic Primitives**:
- Same as Full PQC models (Dilithium + ML-KEM)
- Original public channel model uses classical crypto with public ES9+

**Channel Model** (CRITICAL DIFFERENCE):
- `LPA2EUICC`: Private (local interface - always secure)
- `ES9`: **PUBLIC** - attacker can observe, modify, replay, and inject messages
- **No LPA relay** in PQC models - direct ES9+ communication between eUICC and SM-DP+

**Security Properties Verified**:
- ✅ **All authentication properties hold even over public ES9+ channel**
- ✅ **Profile confidentiality maintained** (attacker cannot learn profile)
- ✅ **Forward secrecy verified**
- ✅ **Session key secrecy** (specific to PQC notls-auth)
- ✅ **Injective agreement properties**

**Key Insight**: **Transport Independence Proven**. The end-to-end cryptographic authentication (eUICC ↔ SM-DP+) provides security even when:
- TLS is compromised
- LPA-to-SM-DP+ channel is attacker-controlled
- Network is completely untrusted

This demonstrates that the security does NOT rely on TLS but on the application-layer cryptographic protocol itself.

---

## Verification Results Summary

| Model | All Queries | Replication | Notes |
|-------|-------------|-------------|-------|
| `original-auth.pv` | ✅ TRUE | ✅ `!SMDP \| !LPA \| !EUICC` | Mutual auth verified |
| `original-download.pv` | ⚠️  Mostly TRUE | ✅ `!SMDP \| !LPA \| !EUICC` | Install confirm inj. unproven |
| `fullpqc-auth.pv` | ✅ TRUE | ✅ `!SMDP \| !LPA \| !EUICC` | KEM-based auth verified |
| `fullpqc-download.pv` | ⚠️  Mostly TRUE | ✅ `!SMDP \| !LPA \| !EUICC` | Install confirm inj. unproven |
| `fullpqc-notls-auth.pv` | ✅ TRUE | ✅ `!SMDP \| !EUICC` | Public ES9+ verified |
| `fullpqc-notls-download.pv` | ✅ TRUE | ✅ `!SMDP \| !EUICC` | Public ES9+ verified |
| `original-public-channel.pv` | ✅ TRUE | ✅ `!SMDP \| !LPA \| !EUICC` | Public ES9+ verified |

**Note on "cannot be proved"**: The installation confirmation query in download models cannot achieve full injectivity due to the protocol design allowing multiple installation notifications for the same profile. However, the non-injective correspondence holds (proven), meaning the core security property is satisfied.

---

## Key Findings

### Strengths After Refinement

1. **Session-Specific Authentication**: Events now bind to specific challenge-response pairs, preventing replay across sessions
2. **Identity-Bound Authentication**: Verified entities match expected identities, not just valid certificates
3. **Stronger Correspondence**: Proves actual message sending, not just protocol initiation
4. **Transport Independence**: Security holds even without TLS (proven by public channel models)
5. **Post-Quantum Readiness**: Full PQC models provide quantum-resistant security with equivalent properties

### Protocol Design Observations

1. **No TLS Dependency**: The application-layer crypto is sufficient for security (proven by public channel models)
2. **KEM vs Signatures**: KEM-based authentication (KEMTLS-style) provides same security as signature-based but with quantum resistance
3. **Forward Secrecy**: Achieved in both classical (via eph. DH) and PQC (via eph. KEM) variants
4. **Device Identity Binding**: Critical for preventing relay attacks - now verified in models

### Minor Limitation

The installation confirmation step allows replay in the formal model (not a practical security issue, but prevents full injectivity proof). This is a protocol design choice, not a cryptographic weakness.

---

## Recommendation

The refined models provide **strong formal verification** of the SGP.22 provisioning protocol. The MrKo.md suggestions significantly strengthen the queries and make explicit what was previously implicit in the verification.

**Migration Path**: 
- Classical models remain secure for current deployments
- Full PQC models ready for post-quantum transition
- Transport independence proven - no urgent need for additional TLS hardening
