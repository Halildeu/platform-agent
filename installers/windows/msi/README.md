# Endpoint Agent MSI (Faz 22.5 M4 — package-readiness)

> **LAB-ONLY / NON-PROD.** This MSI is self-signed (lab tier). It is a
> **package-readiness** deliverable, **not** GPO-domain-pilot or production
> readiness. Production requires Authenticode trusted-signing (Faz 22.2 / operator
> cert) + AppLocker/WDAC/EDR signer preflight + a GPO 5-PC domain pilot — all
> operator/domain-gated follow-ups.

## Design — ps1-wrapper MSI (Codex `019ead14` AGREE)

The MSI is a thin **payload / ARP / upgrade-orchestration** owner. The installer
logic is **not** reimplemented in WiX; the MSI runs the canonical
[`install.ps1`](../install.ps1) (and [`uninstall.ps1`](../uninstall.ps1)) as a
deferred custom action running as **SYSTEM** (the GPO computer-assigned context).

| Concern | Owner |
|---|---|
| Payload/cache, ARP entry, public properties, major-upgrade, MSI log | **MSI** (`EndpointAgent.wxs`) |
| Service create, AG-026C `Environment` regkey, SDDL/tamper hardening, credential preservation, auto-enroll/HMAC mode | **`install.ps1`** (single source of truth) |

The MSI writes **no** `ServiceInstall` and **no** service-config/env registry —
that stays `install.ps1`'s job (ADR-0029 Katman 4).

- **Payload staging** is versioned + separate from the runtime dir:
  `C:\Program Files\EndpointAgentInstaller\<version>\payload\…` (MSI-owned) vs the
  script-managed runtime `C:\Program Files\EndpointAgent\…`. The running script
  never deletes its own payload on upgrade/uninstall.
- The deferred CA calls [`run-agent-install.ps1`](./run-agent-install.ps1), which
  maps MSI public properties → `install.ps1` parameters and splats them.

## Secret handling — the MSI carries NO token

- **Prod / domain / GPO path is TOKENLESS**: set `AUTO_ENROLL=1` (+ optional
  `AUTO_ENROLL_API_URL`, `AUTO_ENROLL_CERT_SAN_URI_PREFIX`,
  `AUTO_ENROLL_JITTER_SECONDS`). Enrollment uses the machine cert / mTLS
  (ADR-0029 Katman 3). **Never put an HMAC enrollment token in an MSI/MST** — a
  GPO MST sits on SYSVOL, is client-cached, and is broadly readable.
- **Lab HMAC fallback** reads its token from a **SYSTEM/Admins-only file you
  pre-stage out-of-band**; pass its path via the non-secret `ENROLL_RESPONSE_FILE`
  property. The secret therefore never enters a MSI property, CustomActionData, or
  the verbose log. `run-agent-install.ps1` shreds the file after use. Lab tokens
  must be short-TTL / single-use / backend-revocable.

## Public properties (all non-secret)

| Property | → `install.ps1` | Notes |
|---|---|---|
| `API_URL` | `-ApiUrl` | HMAC API base |
| `AUTO_ENROLL` | `-AutoEnroll` | `1`/`true` ⇒ tokenless domain path |
| `AUTO_ENROLL_API_URL` | `-AutoEnrollApiUrl` | mTLS edge |
| `AUTO_ENROLL_CERT_SUBJECT_SUFFIX` / `AUTO_ENROLL_CERT_SAN_URI_PREFIX` | matching params | cert-store query narrowing |
| `AUTO_ENROLL_JITTER_SECONDS` | `-AutoEnrollJitterSeconds` | wave de-sync |
| `LOG_DIR`, `INSTALL_ID`, `MAINTENANCE_TOKEN_HASH`, `SERVICE_NAME` | matching params | |
| `ENROLL_RESPONSE_FILE` | (lab token file path) | non-secret path |
| `PURGE_CONFIG` | uninstall purge gate | `1` ⇒ purge credential/config |

`SERVICE_SDDL` is intentionally **not** exposed (its `;` would break the
`;`-delimited config blob; `install.ps1`'s default SDDL is already hardened).

## Upgrade & uninstall semantics

- **Major upgrade** = uninstall-old + install-new in one session;
  `RemoveExistingProducts` is `afterInstallExecute`. The upgrade install **never**
  passes `-ResetCredentialStore` and (HMAC path) **never** a new token, so the
  DPAPI credential store is **preserved** (same device keeps enrollment).
- **Fleet re-config** requires a **ProductVersion bump** (no
  `AllowSameVersionUpgrades`). An MST change does **not** auto-apply to installed
  clients.
- **Uninstall** preserves credential/config by **default**; pass `PURGE_CONFIG=1`
  to purge. GPO "uninstall when out of scope" also preserves locally — backend
  **revoke/decommission is a separate action**, not implied by uninstall.

## Build (Windows + WiX v4)

```powershell
dotnet tool install --global wix
wix extension add -g WixToolset.Util.wixext
.\build-msi.ps1 -AgentExe <path>\endpoint-agent.exe -Version 0.1.1
# -> out\EndpointAgent-0.1.1-lab.msi + out\msi-build-manifest.json (production=false)
```

`-SigningMode` selects the tier: `lab` (default, self-signed, `production=false`) or `none` (unsigned — what the release pipeline uses before Linux signing). `trusted` is **removed** here (signing moved to the Linux pipeline; passing it throws).

## Trusted signing activation (Faz 22.2 / AG-018) — Linux internal CA, FREE

> **Owner decisions (2026-06-10): NO paid services AND NO Windows Server / AD CS.** The production trust path signs on a **self-hosted LINUX runner** with `osslsigncode` and an **internal 2-tier OpenSSL CA** — `$0`, no Windows Server, no Azure. The private key NEVER leaves that host and is NEVER a GitHub secret (PFX-in-GitHub FORBIDDEN): the runner user calls a **sudoers-pinned wrapper** (`codesign-sign`) that reads the `0400` leaf key as a dedicated `codesign` user. Trust is **internal** (the root reaches Windows machines via the agent installer importing it — TOFU — for domain-joined AND workgroup boxes alike); it is NOT public Windows trust.

The pipeline builds where Windows tools live, signs on Linux, verifies on Windows:

- `.github/workflows/release-msi-signed.yml` — `config-check` (always; visible `::notice::` when unconfigured) → `build-unsigned` (windows-hosted, `-SigningMode none`) → `sign` (self-hosted `[linux,signing]`, `osslsigncode` via the pinned wrapper, RFC3161 timestamp, fail-closed) → `verify-windows` (windows-hosted, `signtool verify /pa` + **independent chain-to-pinned-root** + thumbprint allowlist → only then manifest `production=true`).
- `scripts/codesign/generate-ca.sh` (2-tier CA: root `CA:TRUE,pathlen:0`, no EKU; leaf `codeSigning` EKU), `install-signing-host.sh` (osslsigncode + pinned wrapper + sudoers), `codesign-sign.sh` (the wrapper).

**Operator activation** (free — no billing, no Windows Server anywhere):

1. Run `generate-ca.sh` + `install-signing-host.sh` on the Linux signing host (staging-sw) — creates the CA, the `codesign`/`gh-runner` users, the `0400` keys, and the sudoers-pinned wrapper.
2. A dedicated **self-hosted runner** labelled `[self-hosted, linux, signing]`, running as `gh-runner`.
3. **Repo variables** (non-secret — thumbprints/SHA256/URLs are public pins; the key is on the host): `CODESIGN_ENABLED=true`, `CODESIGN_LEAF_THUMBPRINT_ALLOWLIST` (SHA1 CSV), `CODESIGN_ROOT_CERT_SHA256` (pin), `CODESIGN_TIMESTAMP_URL` (free `http://timestamp.digicert.com`).
4. **GitHub environment** `trusted-signing-prod` with **required reviewers** + a **protected-tag ruleset** (`v*.*.*`).

Then a clean `v0.2.0` tag (no `-lab`/`-rc`, on `main`) activates `release-msi-signed.yml` → manifest `production=true` / `signing_tier=trusted-internal-ca` / `trust_scope=installer-imported-internal-ca` / `publicly_trusted=false`. Key custody is **host-fs-restricted** (pre-prod exception, Codex 019eb0dd); Vault Transit/HSM is a follow-up phase (board platform-agent#132). Installer root import (TOFU) is a separate PR; AppLocker/WDAC/EDR signer preflight + GPO domain pilot remain separate operator/domain gates.

## Install / GPO

```powershell
# Lab HMAC (token pre-staged out-of-band):
'<lab-token>' | Set-Content C:\Windows\Temp\ea-enroll.txt   # SYSTEM/Admins ACL
msiexec /i EndpointAgent-0.1.1-lab.msi /qn /l*v C:\ProgramData\EndpointAgent\logs\msi.log `
  API_URL=https://testai.acik.com/api/v1/endpoint-agent ENROLL_RESPONSE_FILE=C:\Windows\Temp\ea-enroll.txt

# Domain / GPO (tokenless):
msiexec /i EndpointAgent-0.1.1-lab.msi /qn AUTO_ENROLL=1 `
  AUTO_ENROLL_API_URL=https://endpoint-agent-mtls.testai.acik.com/api/v1/endpoint-agent
```

GPO computer-assignment + an MST carrying only non-secret config; the deferred CA
runs as SYSTEM at startup. Domain-pilot prerequisites (UNC path + Domain Computers
read/exec, "always wait for network at startup", slow-link, AppLocker/WDAC/EDR
signer allow) are **P0 gates owned by the domain pilot**, not this slice.
