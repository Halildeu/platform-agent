# D10-5 — Agent Attestation Depth (ADR-0034 §11/D10 item #5)

> **Gate:** ADR-0034 §11/D10 #5 — "agent attestation: SBOM + SLSA + reproducible
> build + runtime binary-hash + cert posture, auto-rollback on mismatch."
> **Status (2026-06-12):** 🔶 partial.
> - ✅ broker-side attestation-statement verifier (B1.4c/d, platform-backend)
> - ✅ SBOM CI (Syft SPDX, `gate-sbom.yml`)
> - ✅ **reproducible-build proof (D10-5a, THIS — `gate-reproducible-build.yml`)**
> - ⏳ runtime binary-hash self-attestation (D10-5b/c) + rollback semantics (D10-5d)
> **Design consult:** Codex thread `019ebc4c`.

## The two hashes are DIFFERENT (do not conflate)

| Hash | What it is | Used by |
|---|---|---|
| `unsigned_repro_sha256` | the byte-identical UNSIGNED build (D10-5a proof) | provenance evidence ("the bytes the SBOM describes") |
| `runtime_artifact_sha256` | the REAL running bytes on the endpoint — the **signed** exe (signature+timestamp) or the runtime exe installed from the MSI | the runtime attestation ALLOWLIST (D10-5b/c) |

The signed release exe and the MSI are **deliberately NOT reproducible** (Authenticode
signature + embedded timestamp vary build-to-build). So the runtime allowlist can never
use the reproducible-proof hash — it uses the signed/MSI runtime-artifact hash. The
reproducible proof exists to show the *source→unsigned-binary* path is deterministic
(supply-chain provenance), the foundation the signed-artifact allowlist sits on.

## D10-5a — reproducible build (DONE, this PR)

`gate-reproducible-build.yml` builds the unsigned `endpoint-agent.exe` TWICE from the
same source on a pinned toolchain and asserts byte-identical SHA-256. Determinism profile
(Codex `019ebc4c`):

- `-trimpath -buildvcs=false -mod=readonly -buildid=` + pinned `BuildVersion=0.1.0-repro`
  (run-number-free) + `SOURCE_DATE_EPOCH`
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 GOTOOLCHAIN=local`
- Go pinned from `go.mod` + `go mod verify`
- a **separate `GOCACHE` per build** (so a cache hit can't mask non-determinism)
- **no `.syso`** resource (the proof is resourceless/unsigned; the versioninfo `.syso`
  belongs to the signed release path only)

Local proof (darwin/arm64 cross-compile, go1.26.2): two builds →
`954d0633978039ed019eab62ca4e6f9039a728fb386ea5015e93aa0978575555` (identical). CI repeats
this on a `go.mod`-pinned toolchain.

## Remaining (NOT in this slice)

- **D10-5b — runtime self-hash compute + report (agent):** at startup/heartbeat the agent
  computes SHA-256 of its OWN running executable (`os.Executable` → read → sha256) and
  REPORTS it as attestation evidence over the existing mTLS/heartbeat channel — the agent
  never self-judges (no chicken-and-egg: the hash is computed at runtime, never embedded).
  Evidence shape (Codex): `attestationEvidence{schemaVersion, binarySha256, hashAlgorithm,
  buildVersion, computedAt}` (snake_case on the auto-enroll path). **No full path** (PII/
  operational leak) — a channel tag or path-hash only. **Gated** on the broker schema's
  unknown-field tolerance (cross-repo contract) — must not merge agent-only blind.
- **D10-5c — broker verifier + expected-hash allowlist (platform-backend):** compare the
  reported runtime hash against the signed/MSI allowlist; mismatch → deny/quarantine. May
  touch the same `AttestationVerifier`/permit surface as T-4a-ii — sequence after it.
- **D10-5d — rollback semantics:** the agent CANNOT cleanly roll back its own running
  process. "Auto-rollback on mismatch" decomposes into: (a) broker DENIES the session on
  mismatch (the verifier's job); (b) the agent's existing `accepted=false` fail-closed
  heartbeat path already halts operation; (c) true reinstall-last-known-good is the
  installer/self-update lane (`install.ps1` rollback + `internal/selfupdate` activation
  rollback) + the 22.5 M7 rollback drill — a SEPARATE operator/installer concern.
