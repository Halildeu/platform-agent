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

`-SigningMode` selects the tier: `lab` (default, self-signed, `production=false`), `trusted` (**AD CS internal**, `production=true` — see below), or `none` (unsigned).

## Trusted signing activation (Faz 22.2 / AG-018) — AD CS, FREE

> **Owner decision: NO paid services → Azure Trusted Signing (pay-as-you-go) is EXCLUDED.** The production trust path is an **AD CS internal code-signing cert** — Windows Server Enterprise CA, **$0, built-in** (ADR-0029). The cert + private key live on a **self-hosted Windows signing runner** (PFX-in-GitHub FORBIDDEN). Trust is **internal/AD-domain** (the AD CS root reaches domain machines' Trusted Publisher via GPO — free); it is NOT public Windows trust.

The `.github/workflows/release-msi-adcs.yml` workflow is a **ready-but-inert skeleton**: it stays skipped (visible `::notice::`) until the operator enables it, and `build-msi.ps1 -SigningMode trusted` is **fail-closed** (throws if `ADCS_*` is unset — never ships unsigned-as-production). No PFX / secret — the key never leaves the runner's machine store.

**Operator activation** (free — no billing anywhere):

1. **AD CS Code Signing cert** (duplicate the "Code Signing" template on the corp Enterprise CA, `CN=EndpointAgent CodeSign`) enrolled into the signing runner's `LocalMachine\My` with a **non-exportable** private key.
2. A dedicated **self-hosted runner** labelled `[self-hosted, windows, signing]`, AD-joined, with the Windows SDK `signtool` + WiX.
3. **Repo variables** (non-secret — thumbprints/URLs aren't secrets; the key is on the runner): `ADCS_SIGNING_ENABLED=true`, `ADCS_SIGNING_CERT_THUMBPRINT`, `ADCS_THUMBPRINT_ALLOWLIST` (CSV), `ADCS_TIMESTAMP_URL` (free public option `http://timestamp.digicert.com`).
4. **GitHub environment** `trusted-signing-prod` with **required reviewers** + a **protected-tag ruleset** (`v*.*.*`).

Then a clean `v0.2.0` tag (no `-lab`/`-rc`, on `main`) → `release-msi-adcs.yml` runs on the self-hosted runner → `build-msi.ps1 -SigningMode trusted` **pre-flights the cert** (private key, validity, Code-Signing EKU, thumbprint allowlist, chain) → signs the MSI + the 5 staged files with `signtool /sm /sha1 <thumbprint> /tr <TSA> /td SHA256 /fd SHA256` → **verifies each with `signtool verify /pa`** (no import) + RFC3161 timestamp + signer-thumbprint allowlist → manifest `production=true` / `signing_tier=trusted-adcs` / `trust_scope=internal-ad-domain` / `publicly_trusted=false`. The lab `msi-build.yml` is untouched and a CI guard asserts the fail-closed behavior. AppLocker/WDAC/EDR signer preflight (the AD CS root in Trusted Publisher via GPO) + GPO domain pilot remain separate operator/domain gates.

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
