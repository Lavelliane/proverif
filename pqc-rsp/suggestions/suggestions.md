# ProVerif Model Refinement Recommendations

## 1. Strengthening the Signature Logic (LPA-eUICC Relation)

In the current model, the query for `EUICC_AUTH_OK` returns true simply because the LPA (device) correctly relays the message, rather than through cryptographic verification of the device itself. To reflect a more realistic cryptographic binding between the LPA and eUICC, we should refine the data constructors for signatures as follows:

```proverif
fun mk_serverSigned1(Tid_t, Id_t, Nonce_t, Nonce_t, Id_t) : bitstring [data].
fun mk_clientSigned1(Tid_t, Id_t, Nonce_t) : bitstring [data].
```

## 2. Binding Events to Core Variables (Nonces)

Currently, the events only track `(dev, tid)`, which means the model cannot guarantee that authentication is tied to a specific session without including the challenges (`eChal`, `sChal`). To address this limitation, I recommend updating the event parameters to include these session-specific nonces:

```proverif
SMDP_AUTH_BEGIN(dev, tid, eChal, sChal)
EUICC_AUTH_OK(dev, tid, eChal, sChal, ID_SMDP)
SMDP_AUTH_OK(dev, tid, sChal)
```

## 3. Explicit Identity Verification

The model currently lacks direct recording of which specific entity was authenticated. To strengthen identity verification, we should include the IDs extracted from certificates within the authentication events:

```proverif
event EUICC_AUTH_OK(dev, tid, ID_SMDP).
event SMDP_AUTH_OK(dev, tid, ID_EUICC). (* ID extracted from eUICC certificate *)
```

## 4. Refining the Correspondence Query

The current query `EUICC_AUTH_OK ==> SMDP_AUTH_BEGIN` is too weak because the `BEGIN` event only indicates that the server started a process. To ensure actual mutual authentication has occurred, we should verify that the server actually generated and sent the specific signature.

**Proposed Query:**

```proverif
event SMDP_SENT_SERVER1(dev, tid, eChal, sChal, ID_SMDP).

query dev:Id_t, tid:Tid_t, e:Nonce_t, s:Nonce_t;
  inj-event(EUICC_AUTH_OK(dev, tid, e, s, ID_SMDP))
    ==> inj-event(SMDP_SENT_SERVER1(dev, tid, e, s, ID_SMDP)).
```

## 5. Validating Certificate Roles and IDs

Currently, the model performs `checkcert` but does not verify whether the `id_dp` or `role_dp` matches the expected values (e.g., `role_dp == tag_dp`). Without these checks, the model implicitly assumes that any certificate signed by the CI is valid for any role. To prevent this overly permissive behavior, we need to add explicit equality checks after the certificate is decomposed.

## 6. Channel Assumption Analysis

If the channel between the LPA and eUICC is modeled as private, the verification results may be trivially satisfied. To add meaningful depth to the security analysis, we should consider modeling the TLS channel (LPA-to-SMDP+) as an open or untrusted channel. This would allow us to verify whether the end-to-end cryptographic signatures (eUICC-to-SMDP+) remain secure even when the intermediate channel is compromised.