# Cross-language permit test vector (Faz 22.6 T-3)

Pins the Go `CanonicalPayload()` byte-for-byte to the Java reference
(`OperationPermit.canonicalPayload()`), and the Go verifier to a real
ECDSA P-256 / SHA256withECDSA signature over those bytes.

## Provenance (Codex T-3 revision #7)

- **Java source of truth:** `Halildeu/platform-backend` @ commit
  `3b59a0c54aa42523c57a4291222765a9899368bb` (origin/main at vector build,
  2026-06-12) —
  `endpoint-admin-service/src/main/java/com/example/endpointadmin/remoteaccess/bridge/contract/OperationPermit.java`
  and `…/remoteaccess/RemoteSessionCapability.java`.
- **vector-canonical.hex** was produced by compiling those two REAL Java
  files (javac 25, no modifications) plus a throwaway `VectorMain` that
  constructs the permit below and prints `HexFormat.of().formatHex(p.canonicalPayload())`.
- **broker-permit-pub.pem / vector-sig.b64**: a throwaway openssl P-256
  keypair (`openssl ecparam -name prime256v1 -genkey`) signed the payload
  bytes (`openssl dgst -sha256 -sign`, ASN.1 DER → base64) and the signature
  was verified back (`openssl dgst -sha256 -verify … : Verified OK`) before
  the PRIVATE KEY WAS DELETED. Only the public key is committed (B1.4d
  fixture precedent — no committed private key, gitleaks-clean).

## Vector permit fields

| field | value |
|---|---|
| alg | `SHA256withECDSA` |
| kid | `permit-key-2026-01` |
| permitVersion | `1` |
| policyVersion | `policy-v3` |
| decisionId | `sess-0001:op-0001` |
| sessionId | `sess-0001` |
| operationId | `op-0001` |
| deviceId | `device-windows-7f3a` |
| operatorSubject | `operator-1@example.com` |
| capability | `CONSTRAINED_PTY` |
| commandHash | sha256("hostname") = `7063dece7cccf374d9fa1ee30ff23300fa42477e064e69be7bb6d01c0cfff682` |
| issuedAtEpochMillis | `1780000000000` |
| expiresAtEpochMillis | `1780000300000` |
| seq | `7` |

Regeneration: repeat the steps above against the current platform-backend
origin/main; the hex MUST NOT change unless the (frozen) canonical layout is
deliberately versioned (that would be a new DOMAIN tag, a breaking wire
event, never a silent edit).
