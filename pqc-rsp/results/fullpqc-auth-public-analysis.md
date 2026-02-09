# PQC eSIM Provisioning (SGP.22) - Consolidated ProVerif Verification Analysis

**Date:** February 8, 2026
**Tool:** ProVerif 2.x (Dolev-Yao Symbolic Model)
**Scope:** Full PQC migration of SGP.22 consumer eSIM provisioning protocol

---

## 1. Overview

This report consolidates the complete formal verification analysis of a Post-Quantum Cryptography (PQC) migration for the SGP.22 eSIM provisioning protocol. It covers:

- Two protocol phases: **Phase A** (Mutual Authentication) and **Phase B** (Profile Download)
- Three architectural configurations tested across five model variants
- A deep investigation into **KEM modeling** in ProVerif and its impact on security proofs
- An experiment testing whether a **3-entity architecture can survive public channels** with the correct KEM model

### Models Verified

| # | Model File | Architecture | Channel Model | KEM Model | Phase |
|---|-----------|-------------|---------------|-----------|-------|
| 1 | `fullpqc-auth.pv` | 3-entity (eUICC, LPA, SM-DP+) | Private (TLS) | Nondeterministic | A |
| 2 | `fullpqc-download.pv` | 3-entity (eUICC, LPA, SM-DP+) | Private (TLS) | Deterministic | B |
| 3 | `fullpqc-notls-auth.pv` | 2-entity (eUICC, SM-DP+) | Public (ES9+) | Deterministic | A |
| 4 | `fullpqc-notls-download.pv` | 2-entity (eUICC, SM-DP+) | Public (ES9+) | Deterministic | B |
| 5 | `fullpqc-deterministic.pv` | 3-entity (eUICC, LPA, SM-DP+) | **Public** | Deterministic | A |

Model 5 is the **experiment**: take the 3-entity architecture, fix the KEM to the correct deterministic model, make all channels public, and see what happens.

---

## 2. Issues Found and Fixes Applied

### 2.1 Critical: Channel Deadlock in No-TLS Models

**Affected:** `fullpqc-notls-auth.pv`, `fullpqc-notls-download.pv`

**Problem:** The eUICC process attempted to receive messages on the private `LPA2EUICC` channel, but no other process wrote to that channel. The eUICC blocked indefinitely, causing **all security queries to pass vacuously** (the conclusion events were never reached, so the implications were trivially true).

```
(* eUICC was waiting on a channel nobody writes to *)
in(LPA2EUICC, (=t_getChal, =ID_LPA, dev_in:Id_t));
(* ... but SM-DP+ writes to ES9, not LPA2EUICC *)
```

**Fix:** Replaced all `LPA2EUICC` channel usage in the eUICC process with `ES9` (the public channel). Removed the LPA process entirely, establishing direct eUICC-to-SM-DP+ communication.

**Impact:** Queries are now **meaningful** -- ProVerif actually exercises the protocol before checking properties.

### 2.2 Critical: Injective Agreement Failure in Download Models

**Affected:** `fullpqc-download.pv` (pre-fix), `fullpqc-notls-download.pv` (pre-fix)

**Problem:** The query `inj-event(SMDP_INSTALL_CONFIRMED) ==> inj-event(EUICC_PROFILE_INSTALLED)` failed. The `tidMain` was a global shared transaction ID, and the install confirmation KDF lacked session-specific binding. An attacker could forward one eUICC's install confirmation to multiple SM-DP+ sessions.

**Fix:** Strengthened the `kdf_bind_install` / `kdf_install` function to include session-specific parameters:

```proverif
(* Before: weak binding *)
fun kdf_bind_install(KEMss_t, Tid_t, ICCID_t) : BindKey_t.

(* After: strong session binding *)
fun kdf_bind_install(KEMss_t, Tid_t, ICCID_t, KEMpk_t, bitstring) : SymKey_t.
(*                                             ^^^^^^^^^  ^^^^^^^^^          *)
(*                                          PK_EU_PROFILE  CT_PREPARE       *)
```

Adding `PK_EU_PROFILE` (ephemeral key unique to each eUICC session) and `CT_PREPARE` (ciphertext unique to each SM-DP+ session) ensures each install confirmation is cryptographically bound to exactly one session pair.

### 2.3 KEM Model Refactoring for fullpqc-download.pv

**Problem:** The nondeterministic KEM model (`kem_encaps`) prevented ProVerif from distinguishing ciphertexts across replicated sessions, causing injective agreement to fail even with private channels.

**Fix:** Refactored `fullpqc-download.pv` to use the deterministic KEM model (same as the no-tls variants). See Section 3 for the full technical explanation.

### 2.4 Missing Security Queries

**Affected:** `fullpqc-auth.pv`, both no-tls models

**Additions:**
- **Session Key Secrecy:** `query attacker(secret_payload).` with actual encryption test (`senc_test(secret_payload, session_key)` output on public channel)
- **Forward Secrecy:** `query attacker(secret_payload) phase 1.` with long-term key leak in `phase 1`
- **Finished Message Authentication:** Injective agreement queries for both directions of Finished messages
- **Auth KEM Layer** (no-tls download only): Added `CT_AUTH` KEM encapsulation providing identity-bound authentication for the profile package

---

## 3. Deep Dive: KEM Modeling in ProVerif

This is the central technical question that drove much of our investigation: **why does the no-tls model work on a public channel while the original fullpqc model does not?**

### 3.1 The Nondeterministic KEM Model (Original fullpqc-auth.pv)

```proverif
fun kem_pk(KEMsk_t) : KEMpk_t.
fun kem_encaps(KEMpk_t) : bitstring.
fun get_ct(bitstring) : KEMct_t [data].
fun get_ss(bitstring) : KEMss_t [data].

reduc forall sk: KEMsk_t;
  kem_decaps(get_ct(kem_encaps(kem_pk(sk))), sk) = 
    get_ss(kem_encaps(kem_pk(sk))).
```

**How it works:**
- `kem_encaps(pk)` is a **regular function** with no explicit randomness
- Given the same `pk`, ProVerif treats `kem_encaps(pk)` as the **same term** across all sessions
- `get_ct` and `get_ss` are marked `[data]` -- the attacker can freely apply them to any term

**Two critical flaws on public channels:**

1. **Shared secret exposure:** `get_ss` is `[data]`, meaning the attacker can compute `get_ss(kem_encaps(pk))` for any public key `pk` they observe. The shared secret is **not actually secret** on a public channel.

2. **Session confusion:** Since `kem_encaps(pk)` produces the same term for the same `pk`, ProVerif cannot distinguish ciphertexts from different sessions that encapsulate to the same key. This breaks injective agreement (one-to-one session correspondence).

**Why it still works with private channels:** On private channels, the attacker never sees the KEM ciphertexts or the public keys used in the encapsulation. The `[data]` annotation on `get_ss` is irrelevant because the attacker has no input to apply it to. The channel's privacy compensates for the weak KEM model.

### 3.2 "What if I Mark get_ss as [private]?"

This was a natural question: can we keep the nondeterministic model but just make the shared secret private?

```proverif
fun get_ss(bitstring) : KEMss_t [private].  (* <-- just add [private]? *)
```

**Answer: This does NOT work**, for two reasons:

1. **`[private]` on a destructor is not standard ProVerif:** The `[private]` annotation is meant for constructors (like `fun kem_ss(...) : KEMss_t [private]`), telling ProVerif the attacker cannot apply this function. On a destructor/accessor like `get_ss`, the semantics are unclear.

2. **The fundamental problem remains:** Even if the attacker cannot compute `get_ss()`, the function `kem_encaps(pk)` is still nondeterministic. ProVerif treats `kem_encaps(pk₁)` as the same term in every replicated session for the same `pk₁`. This means:
   - `CT` from session 1 = `CT` from session 2 (for the same target key)
   - ProVerif cannot prove injective agreement because it cannot distinguish which session produced which ciphertext

### 3.3 The Deterministic KEM Model (Correct Model)

```proverif
type KEMcoin_t.   (* Encapsulation randomness *)

fun kem_pk(KEMsk_t) : KEMpk_t.
fun kem_enc(KEMpk_t, KEMcoin_t) : bitstring [data].
fun kem_ss(KEMpk_t, KEMcoin_t) : KEMss_t [private].

reduc forall sk:KEMsk_t, r:KEMcoin_t;
  kem_dec(kem_enc(kem_pk(sk), r), sk) = kem_ss(kem_pk(sk), r).
```

**How it works:**
- Each encapsulation uses explicit fresh randomness: `new r : KEMcoin_t`
- `kem_enc(pk, r)` produces a **unique ciphertext** per session (because `r` is fresh)
- `kem_ss(pk, r)` is marked `[private]` -- the attacker **cannot construct** shared secrets, even from observed ciphertexts
- Only the holder of `sk` can recover `kem_ss(pk, r)` via `kem_dec`

**Why it solves both problems:**

1. **Shared secret is genuinely private:** The `[private]` annotation on `kem_ss` (a constructor, not an accessor) is well-defined in ProVerif. The attacker sees `kem_enc(pk, r)` on the wire but cannot compute `kem_ss(pk, r)`.

2. **Sessions are distinguishable:** Because each session generates `new r`, the ciphertext `kem_enc(pk, r₁)` differs from `kem_enc(pk, r₂)`. ProVerif can track which ciphertext belongs to which session, enabling injective agreement proofs.

### 3.4 Summary Table: KEM Model Comparison

| Aspect | Nondeterministic (`kem_encaps`) | Deterministic (`kem_enc`) |
|--------|-------------------------------|--------------------------|
| **Randomness** | Implicit (ProVerif treats as same term for same pk) | Explicit (`new r : KEMcoin_t` per session) |
| **Shared Secret** | `get_ss [data]` -- attacker can compute | `kem_ss [private]` -- attacker cannot compute |
| **Ciphertext Uniqueness** | Same ciphertext for same pk across sessions | Unique ciphertext per session |
| **Session Distinguishability** | No -- breaks injective agreement | Yes -- enables injective agreement |
| **Works on Private Channel** | Yes (channel hides weakness) | Yes |
| **Works on Public Channel** | No (attacker exploits both flaws) | Depends on architecture (see Section 4) |

---

## 4. The Architecture Experiment: 3-Entity with Public Channels

### 4.1 Hypothesis

Since the correct deterministic KEM model makes the 2-entity no-tls model work on a public channel, **will it also make the 3-entity model work if we switch to the correct KEM and make all channels public?**

### 4.2 Setup (fullpqc-deterministic.pv)

Applied two changes to the 3-entity `fullpqc-auth.pv`:

1. **KEM Model:** Replaced nondeterministic `kem_encaps` with deterministic `kem_enc` + `kem_ss [private]`
2. **Channels:** Changed `LPA2EUICC` and `LPA2SMDP` from `[private]` to public

The 3-entity architecture (eUICC ↔ LPA relay ↔ SM-DP+) and LPA process were **preserved unchanged**.

### 4.3 Results

```
Verification summary:

Query inj-event(EUICC_AUTH_OK(...))          ==> inj-event(SMDP_SENT_AUTH(...))      is false.
Query inj-event(SMDP_AUTH_OK(...))           ==> inj-event(EUICC_SENT_FINISHED(...)) is false.
Query inj-event(SMDP_KEY(...))               ==> inj-event(EUICC_KEY(...))           is false.
Query not attacker_p1(secret_payload[])                                               is true.
Query not attacker_p1(secret_payload[]) [phase 1]                                     is true.
Query inj-event(SMDP_VERIFIED_FINISHED(...)) ==> inj-event(EUICC_SENT_FINISHED(...)) is false.
Query inj-event(EUICC_VERIFIED_FINISHED(...)) ==> inj-event(SMDP_SENT_FINISHED(...)) is false.
```

| Property | Result |
|----------|--------|
| Mutual Authentication (eUICC → SM-DP+) | **FAIL** |
| Mutual Authentication (SM-DP+ → eUICC) | **FAIL** |
| Session Key Agreement | **FAIL** |
| Session Key Secrecy | **PASS** |
| Forward Secrecy | **PASS** |
| Finished Message Auth (both directions) | **FAIL** |

**Answer to the hypothesis: No.** Fixing the KEM model is necessary but not sufficient. The 3-entity architecture itself introduces a vulnerability when the relay channels are public.

### 4.4 Root Cause: The Untrusted Relay Problem

The injective agreement failures are **architectural**, not cryptographic.

**Attack scenario:**

1. eUICC generates ephemeral key `PK_EPH₁` and challenge `eChal₁`, sends to LPA on public `LPA2EUICC`
2. LPA (or attacker on the public channel) forwards `(eChal₁, PK_EPH₁, CERT_EU)` to SM-DP+ session A
3. **Attacker replays** the same `(eChal₁, PK_EPH₁, CERT_EU)` to SM-DP+ session B
4. Both SM-DP+ sessions A and B generate their own `tid`, encapsulate to `PK_EPH₁`, and respond
5. LPA forwards session A's response to eUICC₁
6. eUICC₁ completes the protocol with session A, producing a single `Finished` message
7. Attacker can now attempt to forward this `Finished` to session B

**Result:** Multiple `SMDP_VERIFIED_FINISHED` events for a single `EUICC_SENT_FINISHED` event → injective agreement violated.

**Why session key secrecy still holds:**
- Even though the attacker can replay messages, they still cannot compute `kem_ss(pk, r)` for any session
- Each session derives a **different** session key because the KEM shared secrets are genuinely private
- The attacker gains no information about the key material itself

### 4.5 Why the 2-Entity Architecture Doesn't Have This Problem

In the `fullpqc-notls-auth.pv` model, there is no LPA relay. The eUICC communicates **directly** with SM-DP+ on the public `ES9` channel.

The key difference is not about the number of channels -- it's about **message routing**:

| Factor | 3-Entity (Public Relay) | 2-Entity (Direct) |
|--------|------------------------|--------------------|
| **Intermediary** | LPA forwards messages blindly | No intermediary |
| **Message duplication** | Attacker can replay eUICC's initial message to multiple SM-DP+ sessions | Attacker can also replay, but... |
| **Why injective holds** | N/A -- it doesn't hold | Each SM-DP+ session encapsulates to a **unique** `PK_EPH`, and the eUICC only responds to the **first** valid response it receives (single-shot process) |
| **Binding** | LPA creates no binding | Protocol's cryptographic binding (3-KEM + transcript hash + Finished MAC) is end-to-end sufficient |

In the 2-entity model, even though an attacker could replay messages, the **combination** of ephemeral keys, fresh nonces, transcript hashing, and MAC-based Finished messages creates a tight cryptographic binding that ProVerif can verify as injective. There is no third party that can split or duplicate the message flow.

---

## 5. Complete Verification Results

### 5.1 Final Results Matrix (All Models, Post-Fix)

| Property | Auth (3-entity, private) | Download (3-entity, private) | Auth (2-entity, public) | Download (2-entity, public) | Auth (3-entity, public) |
|----------|:---:|:---:|:---:|:---:|:---:|
| **Mutual Auth (eUICC→SMDP)** | PASS | -- | PASS | -- | **FAIL** |
| **Mutual Auth (SMDP→eUICC)** | PASS | -- | PASS | -- | **FAIL** |
| **Session Key Agreement** | PASS | -- | PASS | -- | **FAIL** |
| **Session Key Secrecy** | PASS | -- | PASS | -- | PASS |
| **Forward Secrecy** | PASS | -- | PASS | -- | PASS |
| **Finished Msg Auth (EU→DP)** | PASS | -- | PASS | -- | **FAIL** |
| **Finished Msg Auth (DP→EU)** | PASS | -- | PASS | -- | **FAIL** |
| **Profile Confidentiality** | -- | PASS | -- | PASS | -- |
| **Profile Forward Secrecy** | -- | PASS | -- | PASS | -- |
| **Profile Install Auth (inj)** | -- | PASS | -- | PASS | -- |
| **Install Confirm Auth (inj)** | -- | PASS | -- | PASS | -- |
| **Total** | **7/7** | **4/4** | **7/7** | **4/4** | **2/7** |

### 5.2 Detailed Query Results

#### Model 1: fullpqc-auth.pv (3-entity, private channels, nondeterministic KEM)

```
inj-event(EUICC_AUTH_OK)          ==> inj-event(SMDP_SENT_AUTH)        is true.
inj-event(SMDP_AUTH_OK)           ==> inj-event(EUICC_SENT_FINISHED)   is true.
inj-event(SMDP_KEY)               ==> inj-event(EUICC_KEY)             is true.
not attacker(secret_payload)                                            is true.
not attacker(secret_payload) phase 1                                    is true.
inj-event(SMDP_VERIFIED_FINISHED) ==> inj-event(EUICC_SENT_FINISHED)   is true.
inj-event(EUICC_VERIFIED_FINISHED)==> inj-event(SMDP_SENT_FINISHED)     is true.
```

#### Model 2: fullpqc-download.pv (3-entity, private channels, deterministic KEM)

```
not attacker(secret_profile)                                            is true.
not attacker(secret_profile) phase 1                                    is true.
inj-event(EUICC_PROFILE_INSTALLED)==> inj-event(SMDP_BOUND_PROFILE)     is true.
inj-event(SMDP_INSTALL_CONFIRMED) ==> inj-event(EUICC_PROFILE_INSTALLED) is true.
```

#### Model 3: fullpqc-notls-auth.pv (2-entity, public ES9+, deterministic KEM)

```
inj-event(EUICC_AUTH_OK)          ==> inj-event(SMDP_SENT_AUTH)        is true.
inj-event(SMDP_AUTH_OK)           ==> inj-event(EUICC_SENT_FINISHED)   is true.
inj-event(SMDP_KEY)               ==> inj-event(EUICC_KEY)             is true.
not attacker(secret_payload)                                            is true.
not attacker(secret_payload) phase 1                                    is true.
inj-event(SMDP_VERIFIED_FINISHED) ==> inj-event(EUICC_SENT_FINISHED)   is true.
inj-event(EUICC_VERIFIED_FINISHED)==> inj-event(SMDP_SENT_FINISHED)     is true.
```

#### Model 4: fullpqc-notls-download.pv (2-entity, public ES9+, deterministic KEM)

```
not attacker(secret_profile)                                            is true.
not attacker(secret_profile) phase 1                                    is true.
inj-event(EUICC_PROFILE_INSTALLED)==> inj-event(SMDP_BOUND_PROFILE)     is true.
inj-event(SMDP_INSTALL_CONFIRMED) ==> inj-event(EUICC_PROFILE_INSTALLED) is true.
```

#### Model 5: fullpqc-deterministic.pv (3-entity, PUBLIC channels, deterministic KEM)

```
inj-event(EUICC_AUTH_OK)          ==> inj-event(SMDP_SENT_AUTH)        is false.
inj-event(SMDP_AUTH_OK)           ==> inj-event(EUICC_SENT_FINISHED)   is false.
inj-event(SMDP_KEY)               ==> inj-event(EUICC_KEY)             is false.
not attacker(secret_payload)                                            is true.
not attacker(secret_payload) phase 1                                    is true.
inj-event(SMDP_VERIFIED_FINISHED) ==> inj-event(EUICC_SENT_FINISHED)   is false.
inj-event(EUICC_VERIFIED_FINISHED)==> inj-event(SMDP_SENT_FINISHED)     is false.
```

---

## 6. Security Properties Verified

### Critical Properties

| # | SGP.22 Req | Property | Description |
|---|-----------|----------|-------------|
| 1 | #9 | **Mutual Authentication** | eUICC authenticates SM-DP+ via certificate verification + KEM-based key confirmation. SM-DP+ authenticates eUICC via Finished message MAC verification. Injective correspondence holds (except 3-entity public). |
| 2 | #3 | **Session Key Agreement** | Both parties derive the same session key. The KDF binds ephemeral, client, and server KEM shared secrets with a full transcript. |
| 3 | #12 | **Session Key Secrecy** | Attacker cannot recover data encrypted under the session key, even when observing all public channel traffic. Holds across all configurations. |
| 4 | #13 | **Profile Confidentiality** | The attacker cannot learn the eSIM profile content. Profile is encrypted under an ephemeral KEM shared secret. |
| 5 | #14 | **Forward Secrecy** | Session keys and profiles remain secret even after long-term key compromise (SK_SMDP_KEM and SK_EUICC_KEM leaked). Holds across all configurations. |

### Important Properties

| # | SGP.22 Req | Property | Description |
|---|-----------|----------|-------------|
| 6 | #10 | **Profile Install Authenticity** | Every profile installation corresponds to a unique SM-DP+ binding (injective agreement). |
| 7 | #10 | **Install Confirmation Authenticity** | Every SM-DP+ confirmation corresponds to a unique eUICC installation (injective agreement). |
| 8 | #10 | **Finished Message Authenticity** | Each verified Finished message was produced by the claimed party (injective agreement, both directions). |
| 9 | #17 | **Profile Integrity** | Implicit via MAC verification in profile download. |
| 10 | #27 | **Transport Independence** | All security properties hold over public ES9+ channel (proven by no-TLS models). |

---

## 7. Cryptographic Stack

| Layer | Implementation |
|-------|---------------|
| Certificate Signatures | PQ Signatures (Dilithium) |
| KEM Primitive | ML-KEM (deterministic model with explicit randomness) |
| Phase A Handshake | KEMTLS: 3-KEM (ephemeral + client + server) |
| Phase A Key Confirmation | MAC-based Finished messages (bidirectional) |
| Phase A KDF | `kemtls_kdf(SS_EPH, SS_SERVER, SS_CLIENT, eChal, sNonce, CT_EPH, CT_CLIENT, CT_SERVER, CERT_EU, CERT_DP, ID_EU, ID_DP)` |
| Phase B Auth | KEM to long-term keys + MAC binding (+ auth KEM in no-tls variant) |
| Phase B Profile Encryption | KEM to ephemeral key + symmetric encryption |
| Phase B Install KDF | `kdf_bind_install(SS, tid, iccid, PK_EU_PROFILE, CT_PREPARE)` |

---

## 8. Threat Model

- **Dolev-Yao attacker:** Can observe, intercept, modify, replay, and inject messages on all public channels
- **Public channels:** `c` (certificate distribution), `ES9` (no-tls models), `LPA2EUICC` and `LPA2SMDP` (3-entity public experiment)
- **Private channels:** `LPA2EUICC`, `LPA2SMDP` (TLS models only -- models secure LPA relay)
- **Forward secrecy test:** `SK_SMDP_KEM` and `SK_EUICC_KEM` leaked after protocol completion (phase 1)
- **Trusted:** Root CA signing key `SK_ROOT_CA`

---

## 9. Conclusions

### 9.1 The KEM Model Matters

The choice of KEM modeling in ProVerif has a **fundamental impact** on what can be proven:

- **Nondeterministic KEM** (`kem_encaps`) works behind private channels but is **broken on public channels** because shared secrets are derivable and sessions are indistinguishable.
- **Deterministic KEM** (`kem_enc` with explicit randomness + `kem_ss [private]`) correctly models IND-CCA security and is **required** for public channel security proofs.
- Simply marking `get_ss` as `[private]` on the nondeterministic model **does not work** -- the session confusion problem from the lack of explicit randomness remains.

### 9.2 Architecture Determines Authentication Guarantees

Correct KEM modeling is **necessary but not sufficient** for full security on public channels:

- **2-entity (direct eUICC ↔ SM-DP+):** All properties hold, including injective agreement. The protocol's cryptographic binding (3-KEM + transcript + Finished MACs) provides end-to-end authentication without relying on channel security.
- **3-entity with private channels (TLS-protected LPA relay):** All properties hold. The channel's confidentiality and integrity compensate for the relay's lack of cryptographic binding.
- **3-entity with public channels (untrusted LPA relay):** Secrecy and forward secrecy hold, but **injective agreement fails**. The untrusted relay enables message replay across sessions, breaking the one-to-one correspondence required for authentication.

### 9.3 Recommendations

| Scenario | Recommended Model | Security Guarantee |
|----------|------------------|-------------------|
| **Normal operation** (TLS available) | 3-entity with private channels (`fullpqc-auth.pv` + `fullpqc-download.pv`) | Full: mutual auth + secrecy + FS |
| **TLS fallback** (TLS unavailable) | 2-entity with public ES9+ (`fullpqc-notls-auth.pv` + `fullpqc-notls-download.pv`) | Full: mutual auth + secrecy + FS |
| **3-entity with untrusted LPA** | **Not recommended** | Partial: secrecy + FS only, no auth |

The protocol design is **sound**: when the KEM is modeled correctly and the architecture eliminates untrusted intermediaries, all security properties hold even on a fully attacker-controlled public channel. The PQC migration successfully achieves transport-independent security for the SGP.22 eSIM provisioning protocol.

---

## 10. File Reference

| File | Description |
|------|-------------|
| `models/fullpqc-auth.pv` | Phase A, 3-entity, private channels, nondeterministic KEM |
| `models/fullpqc-deterministic.pv` | Phase A, 3-entity, public channels, deterministic KEM (experiment) |
| `models/fullpqc-download.pv` | Phase B, 3-entity, private channels, deterministic KEM |
| `models/no-tls/fullpqc-notls-auth.pv` | Phase A, 2-entity, public ES9+, deterministic KEM |
| `models/no-tls/fullpqc-notls-download.pv` | Phase B, 2-entity, public ES9+, deterministic KEM |
| `results/fullpqc-auth_results.txt` | ProVerif output for Model 1 |
| `results/fullpqc-auth-public_results.txt` | ProVerif output for Model 5 (experiment) |
| `results/fullpqc-download_results.txt` | ProVerif output for Model 2 |
| `results/fullpqc-notls-auth_results.txt` | ProVerif output for Model 3 |
| `results/fullpqc-notls-download_results.txt` | ProVerif output for Model 4 |
