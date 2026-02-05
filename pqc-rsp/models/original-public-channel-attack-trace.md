# Attack Trace: Classical RSP with Compromised TLS (Public ES9+ Channel)

## Protocol Flow with Attacker Observation

```mermaid
sequenceDiagram
    participant EUICC as eUICC
    participant LPA as LPA<br/>(Relay)
    participant ATTACKER as Attacker<br/>(Controls ES9+)
    participant SMDP as SM-DP+

    Note over EUICC,SMDP: Phase A: Mutual Authentication

    EUICC->>LPA: GetEUICCChallenge
    LPA->>EUICC: eChal (nonce)
    
    EUICC->>LPA: (dev, eChal)
    LPA->>ATTACKER: (dev, eChal) [PUBLIC ES9+]
    Note over ATTACKER: ⚠️ Attacker observes eChal
    
    ATTACKER->>SMDP: (dev, eChal) [PUBLIC ES9+]
    
    SMDP->>SMDP: Generate tid, sChal
    SMDP->>SMDP: Sign: serverSigned1(tid, eChal, sChal)
    SMDP->>ATTACKER: (dev, tid, serverSigned, serverSig, Cert_DPauth) [PUBLIC ES9+]
    Note over ATTACKER: ⚠️ Attacker observes:<br/>- Transaction ID (tid)<br/>- Server signature<br/>- SM-DP+ certificate<br/>Cannot forge without SK_DPauth
    
    ATTACKER->>LPA: (dev, tid, serverSigned, serverSig, Cert_DPauth) [PUBLIC ES9+]
    LPA->>EUICC: (dev, tid, serverSigned, serverSig, Cert_DPauth)
    
    EUICC->>EUICC: Verify Cert_DPauth, serverSig
    EUICC->>EUICC: Check eChal matches
    EUICC->>EUICC: Sign: clientSigned1(tid, sChal)
    
    EUICC->>LPA: (dev, clientSigned, clientSig, Cert_EUICC)
    LPA->>ATTACKER: (dev, clientSigned, clientSig, Cert_EUICC) [PUBLIC ES9+]
    Note over ATTACKER: ⚠️ Attacker observes:<br/>- Client signature<br/>- eUICC certificate<br/>Cannot forge without SK_EUICC
    
    ATTACKER->>SMDP: (dev, clientSigned, clientSig, Cert_EUICC) [PUBLIC ES9+]
    SMDP->>SMDP: Verify Cert_EUICC, clientSig
    SMDP->>SMDP: Check tid, sChal match
    Note over SMDP: Authentication Complete ✓

    Note over EUICC,SMDP: Phase B: Profile Download

    SMDP->>SMDP: Sign: serverSigned2(tid)
    SMDP->>ATTACKER: (dev, tid, serverSig2) [PUBLIC ES9+]
    Note over ATTACKER: ⚠️ Attacker observes PrepareDownload signature
    
    ATTACKER->>LPA: (dev, tid, serverSig2) [PUBLIC ES9+]
    LPA->>EUICC: PrepareDownload(tid, serverSig2)
    
    EUICC->>EUICC: Verify serverSig2
    EUICC->>EUICC: Generate ephemeral DH: (sk_eu_eph, pk_eu_eph)
    EUICC->>EUICC: Sign: clientSigned2(tid, pk_eu_eph)
    
    EUICC->>LPA: (dev, pk_eu_eph, clientSig2)
    LPA->>ATTACKER: (dev, pk_eu_eph, clientSig2) [PUBLIC ES9+]
    Note over ATTACKER: ⚠️ Attacker observes:<br/>- eUICC ephemeral public key<br/>Cannot compute sk_eu_eph (ECDH secure)
    
    ATTACKER->>SMDP: (dev, pk_eu_eph, clientSig2) [PUBLIC ES9+]
    
    SMDP->>SMDP: Verify clientSig2
    SMDP->>SMDP: Generate ephemeral DH: (sk_dp_eph, pk_dp_eph)
    SMDP->>SMDP: Compute: shs = DH(sk_dp_eph, pk_eu_eph)
    SMDP->>SMDP: Derive: k_enc, k_mac = KDF(shs)
    SMDP->>SMDP: Encrypt profile: encrypted_profile = Enc(profile, k_enc)
    SMDP->>SMDP: MAC: bpp_mac = MAC(bpp_body, k_mac)
    SMDP->>SMDP: Sign: serverSigned3(tid, pk_dp_eph)
    
    SMDP->>ATTACKER: (dev, bpp_body, bpp_mac, serverSig3) [PUBLIC ES9+]
    Note over ATTACKER: ⚠️ Attacker observes:<br/>- Encrypted profile<br/>- SM-DP+ ephemeral public key<br/>- MAC<br/>Cannot decrypt without:<br/>- sk_eu_eph (ECDH secure)<br/>- sk_dp_eph (ECDH secure)
    
    ATTACKER->>LPA: (dev, bpp_body, bpp_mac, serverSig3) [PUBLIC ES9+]
    LPA->>EUICC: LoadBoundProfilePackage(bpp_body, bpp_mac, serverSig3)
    
    EUICC->>EUICC: Verify serverSig3
    EUICC->>EUICC: Extract pk_dp_eph
    EUICC->>EUICC: Compute: shs = DH(sk_eu_eph, pk_dp_eph)
    EUICC->>EUICC: Derive: k_enc, k_mac = KDF(shs)
    EUICC->>EUICC: Verify MAC
    EUICC->>EUICC: Decrypt: profile = Dec(encrypted_profile, k_enc)
    EUICC->>EUICC: Install profile, generate ICCID
    
    EUICC->>LPA: (dev, tid, iccid, installSig)
    LPA->>ATTACKER: (dev, tid, iccid, installSig) [PUBLIC ES9+]
    Note over ATTACKER: ⚠️ Attacker observes:<br/>- Installation confirmation<br/>- ICCID<br/>Cannot forge without SK_EUICC
    
    ATTACKER->>SMDP: (dev, tid, iccid, installSig) [PUBLIC ES9+]
    SMDP->>SMDP: Verify installSig
    Note over SMDP: Installation Confirmed ✓
```

## Security Analysis

### ✅ What the Attacker CAN Observe (Public ES9+ Channel):
1. **All messages** between LPA and SM-DP+ on ES9+ interface
2. **Transaction IDs** (tid)
3. **Nonces** (eChal, sChal)
4. **Certificates** (Cert_DPauth, Cert_EUICC)
5. **Signatures** (serverSig, clientSig)
6. **Ephemeral public keys** (pk_eu_eph, pk_dp_eph)
7. **Encrypted profile packages** (encrypted_profile)
8. **MACs** (bpp_mac)
9. **Installation confirmations** (iccid, installSig)

### ❌ What the Attacker CANNOT Do (Security Properties Hold):
1. **Cannot forge signatures** without private keys (SK_DPauth, SK_EUICC)
2. **Cannot compute DH shared secret** without private ephemeral keys
3. **Cannot decrypt profile** without the shared secret
4. **Cannot impersonate** either party without private keys
5. **Cannot break forward secrecy** (ephemeral keys deleted after use)

### Key Insight:
Even with **completely compromised TLS** (public ES9+ channel), the classical RSP protocol maintains security because:
- **ECDSA signatures** provide authentication (cannot be forged)
- **Ephemeral ECDH** provides confidentiality and forward secrecy
- **Application-layer cryptography** protects the profile independently of transport security

This demonstrates that **proper application-layer security** can provide defense-in-depth even when transport security fails.
