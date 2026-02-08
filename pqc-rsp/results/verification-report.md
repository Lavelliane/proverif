# Full PQC eSIM Provisioning - ProVerif Verification Report

**Date:** February 8, 2026  
**Tool:** ProVerif 2.x  
**Scope:** SGP.22 Consumer eSIM Provisioning with Full PQC Stack

---

## Models Verified

| # | Model | File | Channel Model | Phase |
|---|-------|------|---------------|-------|
| 1 | fullpqc-auth | `models/fullpqc-auth.pv` | Private (TLS) | A: Mutual Authentication |
| 2 | fullpqc-download | `models/fullpqc-download.pv` | Private (TLS) | B: Profile Download |
| 3 | fullpqc-notls-auth | `models/no-tls/fullpqc-notls-auth.pv` | Public (ES9+) | A: Mutual Authentication |
| 4 | fullpqc-notls-download | `models/no-tls/fullpqc-notls-download.pv` | Public (ES9+) | B: Profile Download |

---

## Verification Results Summary

### ALL QUERIES PASS ACROSS ALL MODELS

| Property | Auth (TLS) | Download (TLS) | Auth (No-TLS) | Download (No-TLS) |
|----------|:----------:|:--------------:|:--------------:|:------------------:|
| Mutual Auth (eUICC authenticates SM-DP+) | TRUE | -- | TRUE | -- |
| Mutual Auth (SM-DP+ authenticates eUICC) | TRUE | -- | TRUE | -- |
| Session Key Agreement | TRUE | -- | TRUE | -- |
| Session Key Secrecy | TRUE | -- | TRUE | -- |
| Forward Secrecy (session key) | TRUE | -- | TRUE | -- |
| Finished Message Auth (eUICC->SMDP) | TRUE | -- | TRUE | -- |
| Finished Message Auth (SMDP->eUICC) | TRUE | -- | TRUE | -- |
| Profile Confidentiality | -- | TRUE | -- | TRUE |
| Profile Forward Secrecy | -- | TRUE | -- | TRUE |
| Profile Install Authenticity (inj) | -- | TRUE | -- | TRUE |
| Install Confirmation Authenticity (inj) | -- | TRUE | -- | TRUE |

**Legend:** TRUE = ProVerif proved the property holds. `--` = not applicable to this phase.

---

## Detailed Results

### 1. fullpqc-auth.pv (Private Channel - Phase A)

```
Query inj-event(EUICC_AUTH_OK) ==> inj-event(SMDP_SENT_AUTH)             is true.
Query inj-event(SMDP_AUTH_OK) ==> inj-event(EUICC_SENT_FINISHED)         is true.
Query inj-event(SMDP_KEY) ==> inj-event(EUICC_KEY)                       is true.
Query not attacker(secret_payload)                                        is true.
Query not attacker(secret_payload) phase 1                                is true.
Query inj-event(SMDP_VERIFIED_FINISHED) ==> inj-event(EUICC_SENT_FINISHED) is true.
Query inj-event(EUICC_VERIFIED_FINISHED) ==> inj-event(SMDP_SENT_FINISHED) is true.
```

**7/7 queries verified.**

### 2. fullpqc-download.pv (Private Channel - Phase B)

```
Query not attacker(secret_profile)                                        is true.
Query not attacker(secret_profile) phase 1                                is true.
Query inj-event(EUICC_PROFILE_INSTALLED) ==> inj-event(SMDP_BOUND_PROFILE) is true.
Query inj-event(SMDP_INSTALL_CONFIRMED) ==> inj-event(EUICC_PROFILE_INSTALLED) is true.
```

**4/4 queries verified.**

### 3. fullpqc-notls-auth.pv (Public Channel - Phase A)

```
Query inj-event(EUICC_AUTH_OK) ==> inj-event(SMDP_SENT_AUTH)             is true.
Query inj-event(SMDP_AUTH_OK) ==> inj-event(EUICC_SENT_FINISHED)         is true.
Query inj-event(SMDP_KEY) ==> inj-event(EUICC_KEY)                       is true.
Query not attacker(secret_payload)                                        is true.
Query not attacker(secret_payload) phase 1                                is true.
Query inj-event(SMDP_VERIFIED_FINISHED) ==> inj-event(EUICC_SENT_FINISHED) is true.
Query inj-event(EUICC_VERIFIED_FINISHED) ==> inj-event(SMDP_SENT_FINISHED) is true.
```

**7/7 queries verified.**

### 4. fullpqc-notls-download.pv (Public Channel - Phase B)

```
Query not attacker(secret_profile)                                        is true.
Query not attacker(secret_profile) phase 1                                is true.
Query inj-event(EUICC_PROFILE_INSTALLED) ==> inj-event(SMDP_BOUND_PROFILE) is true.
Query inj-event(SMDP_INSTALL_CONFIRMED) ==> inj-event(EUICC_PROFILE_INSTALLED) is true.
```

**4/4 queries verified.**

---

## Security Properties Verified

### Critical Properties

| # | SGP.22 Req | Property | Description |
|---|-----------|----------|-------------|
| 1 | #9 | **Mutual Authentication** | eUICC authenticates SM-DP+ via certificate verification + KEM-based key confirmation. SM-DP+ authenticates eUICC via Finished message MAC verification. Injective correspondence holds. |
| 2 | #3 | **Session Key Agreement** | Both parties derive the same session key. The KDF binds ephemeral, client, and server KEM shared secrets with a full transcript. |
| 3 | #12 | **Session Key Secrecy** | Attacker cannot recover data encrypted under the session key, even when observing all public channel traffic. |
| 4 | #13 | **Profile Confidentiality** | The attacker cannot learn the eSIM profile. Profile is encrypted under an ephemeral KEM shared secret to a fresh per-session key. |
| 5 | #14 | **Forward Secrecy** | Session keys and profiles remain secret even after long-term key compromise (SK_SMDP_KEM and SK_EUICC_KEM leaked in phase 1). Ephemeral keys provide protection. |

### Important Properties

| # | SGP.22 Req | Property | Description |
|---|-----------|----------|-------------|
| 6 | #10 | **Profile Install Authenticity** | Every profile installation on the eUICC corresponds to a unique profile bound by the SM-DP+ (injective agreement). |
| 7 | #10 | **Install Confirmation Authenticity** | Every SM-DP+ install confirmation corresponds to a unique eUICC installation event (injective agreement). |
| 8 | #10 | **Finished Message Authenticity** | Each verified Finished message was produced by the claimed party (injective agreement for both directions). |
| 9 | #17 | **Profile Integrity** | Implicit via MAC verification in the profile download protocol. |
| 10 | #27 | **Transport Independence** | All security properties hold over the public ES9+ channel (proven by the no-TLS models where ES9 is public). |

---

## Fixes Applied (from pre-fix state)

### fullpqc-download.pv

| Fix | Description | Impact |
|-----|-------------|--------|
| Deterministic KEM model | Switched from nondeterministic `kem_encaps(pk)` to deterministic `kem_enc(pk, r)` + `kem_ss(pk, r) [private]`. Enables ProVerif to distinguish ciphertexts across sessions. | Enables injective agreement proofs |
| CT_PREPARE binding in install KDF | `kdf_bind_install` now includes `CT_PREPARE` ciphertext, binding install confirmation to the specific SM-DP+ session that initiated the download. | Fixes injective agreement for install confirmation |
| PK_EU_PROFILE binding in install KDF | `kdf_bind_install` now includes `PK_EU_PROFILE`, binding install confirmation to the specific ephemeral key exchange. | Strengthens session binding |
| Complete forward secrecy test | Phase 1 now leaks both `SK_SMDP_KEM` and `SK_EUICC_KEM`. | More thorough FS verification |
| Unified MAC scheme | Switched from separate `auth_mac`/`profile_mac` types to unified `mac(SymKey_t, bitstring)`. | Cleaner model, consistent with no-TLS variant |

### fullpqc-notls-auth.pv

| Fix | Description | Impact |
|-----|-------------|--------|
| **Channel deadlock fixed** | Replaced all `LPA2EUICC` usage in eUICC with `ES9`. Previously, eUICC waited on private `LPA2EUICC` but nobody wrote to it -- all queries passed **vacuously**. | **CRITICAL: queries are now meaningful** |
| Removed LPA process | Direct SM-DP+ ↔ eUICC communication over public ES9+. | Matches no-LPA architecture |
| Proper session key secrecy test | Replaced meaningless `free test_session_key` with actual test: encrypt `secret_payload` under derived session key, output ciphertext on public channel. | Meaningful secrecy verification |
| Forward secrecy test added | Added `phase 1` leak of `SK_SMDP_KEM` + query for `secret_payload` in phase 1. | New property verified |

### fullpqc-notls-download.pv

| Fix | Description | Impact |
|-----|-------------|--------|
| **Channel deadlock fixed** | Replaced all `LPA2EUICC` usage in eUICC with `ES9`. Same deadlock as auth model. | **CRITICAL: queries are now meaningful** |
| Auth KEM layer added | New `CT_AUTH` KEM encapsulation to `PK_EUICC_KEM` with `kdf_auth` binding, providing identity-bound authentication for the profile package. | Stronger authentication (matches private channel model) |
| CT_PREPARE binding in install KDF | `kdf_install` includes `CT_PREPARE`, binding install to specific SMDP session. | Fixes injective agreement |
| PK_EU_PROFILE binding in install KDF | `kdf_install` includes `PK_EU_PROFILE`. | Strengthens session binding |
| Complete forward secrecy test | Phase 1 leaks both `SK_SMDP_KEM` and `SK_EUICC_KEM`. | More thorough FS verification |

---

## Cryptographic Stack

| Layer | Private Channel (TLS) | Public Channel (No-TLS) |
|-------|----------------------|------------------------|
| Certificate Signatures | PQ Signatures (Dilithium) | PQ Signatures (Dilithium) |
| KEM Primitive | ML-KEM (deterministic model) | ML-KEM (deterministic model) |
| Phase A Handshake | KEMTLS: 3-KEM (ephemeral + client + server) | KEMTLS: 3-KEM (ephemeral + client + server) |
| Phase A Key Confirmation | MAC-based Finished messages | MAC-based Finished messages |
| Phase B Auth | KEM to long-term keys + MAC binding | KEM to long-term keys + MAC binding + auth KEM |
| Phase B Profile Encryption | KEM to ephemeral key + symmetric enc | KEM to ephemeral key + symmetric enc |
| Phase B Install Confirmation | KEM + MAC with (tid, iccid, PK_EU_PROFILE, CT_PREPARE) | KEM + MAC with (tid, iccid, PK_EU_PROFILE, CT_PREPARE) |
| Transport | TLS-protected LPA ↔ SM-DP+ channel | Public ES9+ (attacker-controlled) |

---

## Threat Model

- **Dolev-Yao attacker:** Can observe, intercept, modify, replay, and inject messages on public channels.
- **Public channels:** `c` (certificate distribution), `ES9` (SM-DP+ communication in no-TLS models).
- **Private channels:** `LPA2EUICC`, `LPA2SMDP` (in TLS models only).
- **Compromised keys (forward secrecy):** `SK_SMDP_KEM` and `SK_EUICC_KEM` leaked after protocol completion (phase 1).
- **Trusted:** Root CA signing key `SK_ROOT_CA`.
