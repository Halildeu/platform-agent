# Agent Command Contract

Bu sozlesme backend ile Go agent arasindaki komut modelini tanimlar.

-------------------------------------------------------------------------------
## 1. Temel Kural
-------------------------------------------------------------------------------

Backend agent'a raw shell, raw PowerShell, raw CMD veya raw bash gondermez.
Agent yalniz whitelist edilmis command type'lari calistirir.

-------------------------------------------------------------------------------
## 2. API Prefix
-------------------------------------------------------------------------------

Agent backend'e outbound HTTPS ile baglanir:

```text
POST /api/v1/endpoint-agent/enroll
POST /api/v1/endpoint-agent/heartbeat
POST /api/v1/endpoint-agent/inventory
POST /api/v1/endpoint-agent/users/snapshot
GET  /api/v1/endpoint-agent/commands/next
POST /api/v1/endpoint-agent/commands/{commandId}/result
```

-------------------------------------------------------------------------------
## 3. Request Identity ve Imza Alanlari
-------------------------------------------------------------------------------

MVP enrollment sonrasi her agent su kimlikle konusur:

```text
agentId
agentSecret
installId
```

Password reset veya user disable gibi hassas komutlardan once HMAC-signed
request modeli devreye alinacaktir. mTLS daha sonraki hardening fazidir; HMAC
tasarimi password reset implementasyonundan once tamamlanir.

Beklenen header seti:

```http
X-Agent-Id: <uuid>
X-Agent-Timestamp: <unix-ms>
X-Agent-Nonce: <random-128-bit>
X-Agent-Signature: hmac-sha256(method + path + timestamp + nonce + bodyHash)
```

Backend su kontrolleri yapar:

```text
timestamp skew <= 5 dakika
nonce replay cache icinde tekrar yok
agent status active
bodyHash request body ile uyumlu
signature agentSecret ile dogrulaniyor
```

-------------------------------------------------------------------------------
## 4. Command Type Listesi
-------------------------------------------------------------------------------

MVP:

```text
COLLECT_INVENTORY
LIST_LOCAL_USERS
GET_LOGGED_IN_USER
GET_USER_HOME_PATHS
DISABLE_LOCAL_USER
ENABLE_LOCAL_USER
RESET_LOCAL_USER_PASSWORD
LIST_ALLOWED_DIRECTORY
```

V2:

```text
DOWNLOAD_ALLOWED_FILE
UPLOAD_ALLOWED_FILE
COLLECT_EVENT_LOG_SUMMARY
OSQUERY_QUERY
RESTART_AGENT
INSTALL_SOFTWARE       (AG-027 / Faz 22.5 — see Section 11)
```

Yasak:

```text
RUN_POWERSHELL
RUN_CMD
RUN_BASH
DELETE_ANY_FILE
BROWSE_ANY_PATH
INSTALL_ARBITRARY_SOFTWARE
```

-------------------------------------------------------------------------------
## 5. Command Claim ve Idempotency
-------------------------------------------------------------------------------

Command calistirma akisi:

```text
QUEUED -> CLAIMED -> RUNNING -> SUCCEEDED | FAILED | UNSUPPORTED | EXPIRED
```

`GET /commands/next` yalniz command okumaz; backend atomik olarak claim eder:

```text
where status = QUEUED
and endpoint_id = agent.endpoint_id
order by priority desc, created_at asc
limit 1
for update skip locked
```

Claim alanlari:

```text
claimedByAgentId
claimId
claimedAt
claimExpiresAt
attemptNumber
```

Claim TTL:

```text
default: 2 dakika
long-running commands: command-specific TTL
```

Agent crash veya network kesintisi durumunda:

```text
CLAIMED/RUNNING command claimExpiresAt gecerse backend re-claim edebilir.
Non-idempotent command'lar default olarak otomatik re-run edilmez.
```

Idempotency kuralı:

```text
commandId + claimId + attemptNumber result icinde zorunlu
POST /commands/{commandId}/result ayni commandId+claimId ile tekrar gelirse idempotent kabul edilir
farkli result body ile tekrar gelirse conflict olarak audit edilir
```

Non-idempotent komutlar:

```text
RESET_LOCAL_USER_PASSWORD
UPLOAD_ALLOWED_FILE
DOWNLOAD_ALLOWED_FILE
```

Bu komutlar icin retry policy explicit olmalidir.

Idempotent veya repeat-safe komutlar:

```text
COLLECT_INVENTORY
LIST_LOCAL_USERS
GET_LOGGED_IN_USER
GET_USER_HOME_PATHS
DISABLE_LOCAL_USER
ENABLE_LOCAL_USER
LIST_ALLOWED_DIRECTORY
```

Not: `DISABLE_LOCAL_USER` ve `ENABLE_LOCAL_USER` hedef state'e zaten ulasmissa
success + no-op summary donebilir.

-------------------------------------------------------------------------------
## 6. Command Payload Ornegi
-------------------------------------------------------------------------------

```json
{
  "commandId": "8f716fe5-1f1a-4d6c-b18b-4cb26e86cf3d",
  "type": "DISABLE_LOCAL_USER",
  "requestedBy": "admin@example.local",
  "reason": "Helpdesk ticket #1842",
  "payload": {
    "username": "test.user"
  }
}
```

Password reset payload'inda password loglanmaz:

```json
{
  "commandId": "8f716fe5-1f1a-4d6c-b18b-4cb26e86cf3d",
  "type": "RESET_LOCAL_USER_PASSWORD",
  "requestedBy": "admin@example.local",
  "reason": "Helpdesk ticket #1843",
  "payload": {
    "username": "test.user",
    "newPasswordSecret": "<redacted>"
  }
}
```

`LIST_LOCAL_USERS` result detail ornegi:

```json
{
  "users": [
    {
      "username": "local.admin",
      "comment": "Local administrator account",
      "disabled": false,
      "lockedOut": false,
      "passwordRequired": true
    }
  ]
}
```

`COLLECT_INVENTORY` result detail identity block ornegi:

```json
{
  "inventory": {
    "hostname": "HALILKOOLUB735",
    "osFamily": "WINDOWS",
    "osName": "windows",
    "architecture": "amd64",
    "agentVersion": "0.1.0-dev",
    "identity": {
      "hostname": "HALILKOOLUB735",
      "osVersion": "10.0.26200",
      "osBuild": "26200",
      "domain": "WORKGROUP",
      "workgroup": "WORKGROUP",
      "partOfDomain": false,
      "azureAdJoined": "NO",
      "domainJoined": "NO",
      "workplaceJoined": "NO",
      "domainProbe": "SKIPPED_NOT_DOMAIN_JOINED",
      "loggedIn": {
        "accountHash": "sha256:<16hex>",
        "accountAuthorityHash": "sha256:<16hex>",
        "sidHash": "sha256:<16hex>",
        "sidMask": "sid:<16hex>"
      },
      "classification": "LOCAL"
    }
  }
}
```

Identity block read-only'dir. Raw UPN/e-posta, full SID, raw tenant/device GUID,
password, token veya Bearer degeri tasimaz; hash veya mask kullanir.

`COLLECT_INVENTORY` payload `includeSoftware` argumani (opsiyonel, default
false) yazilim envanteri detayini secer (AG-025/AG-026):

```json
{
  "commandId": "...",
  "type": "COLLECT_INVENTORY",
  "payload": {
    "includeSoftware": true
  }
}
```

`includeSoftware=false` (AG-025H lightweight default): inventory.software
alani PAYLOAD'DA YER ALMAZ. Registry enumeration ve WinGet probe hic
calistirilmaz; heartbeat / auto-enroll bu defaulti kullanir. Wire
payload yalniz host/os/identity tasir.

`includeSoftware=true`: inventory.software blogu attach edilir + apps
full liste tasir; agent tarafinda size cap uygulanir (`DefaultMaxApps=5000`,
`DefaultMaxPayloadBytes=1 MiB`) ve `truncated=true` flag'i ile rapor
edilir.

`COLLECT_INVENTORY` result detail software block ornegi (yalnizca
includeSoftware=true ile gonderilir):

```json
{
  "inventory": {
    "software": {
      "supported": true,
      "appCount": 138,
      "wingetReady": true,
      "wingetVersion": "1.7.10861",
      "schemaVersion": 1
    }
  }
}
```

Software block icin HARD boundary:

```text
1. UninstallString full degeri payload'a girmez; sadece uninstallStringPresent bool
2. MSI ProductCode GUID raw tasinmaz; sadece msiProductCodeHash (SHA-256 ilk 16 hex)
3. HKCU default scope DISI; default sadece HKLM + HKLM\WOW6432Node
4. WinGet readiness yalniz path + version + systemContextReady; install/search/source yok
5. DisplayName / Publisher / DisplayVersion serbest metni sanitize edilir
   (JWT, email, UPN, full SID, user path, license key -> [REDACTED])
```

### 6.A `COLLECT_INVENTORY` payload `includeWinGetEgress` (AG-026A, Faz 22.5)

`COLLECT_INVENTORY` payload `includeWinGetEgress` argumani (opsiyonel,
default false) **AG-026A read-only WinGet source/egress readiness
preflight**ini secer:

```json
{
  "commandId": "...",
  "type": "COLLECT_INVENTORY",
  "payload": {
    "includeSoftware": true,
    "includeWinGetEgress": true
  }
}
```

`includeWinGetEgress=false` (default): inventory.wingetEgress alani
PAYLOAD'DA YER ALMAZ. Source list, package query, ve DNS/TCP/HTTPS
egress probleri hic calistirilmaz; heartbeat / auto-enroll bu defaulti
kullanir. AG-025H lightweight contract bozulmaz.

`includeWinGetEgress=true`: inventory.wingetEgress blogu attach edilir;
agent `winget source list` (read-only fixed argv) + `winget show --id
7zip.7zip --exact --disable-interactivity` (sabit package id) +
hard-coded egress hostname listesine karsi DNS/TCP/HTTPS reachability
probleri calistirir.

`inventory.wingetEgress` result detail ornegi:

```json
{
  "inventory": {
    "wingetEgress": {
      "supported": true,
      "schemaVersion": 1,
      "probeDurationMs": 4380,
      "timeout": false,
      "sources": [
        {
          "name": "winget",
          "argument": "https://cdn.winget.microsoft.com/cache",
          "type": "Microsoft.PreIndexed.Package",
          "trustLevel": "Trusted"
        },
        {
          "name": "msstore",
          "argument": "https://storeedgefd.dsx.mp.microsoft.com/v9.0",
          "type": "Microsoft.Rest",
          "trustLevel": "Trusted"
        }
      ],
      "sourceListError": "",
      "packageQuery": {
        "packageId": "7zip.7zip",
        "found": true,
        "exitCode": 0,
        "durationMs": 1820,
        "timeout": false
      },
      "egress": {
        "dns": [
          {"target": "cdn.winget.microsoft.com", "ok": true, "durationMs": 12},
          {"target": "storeedgefd.dsx.mp.microsoft.com", "ok": true, "durationMs": 14}
        ],
        "tcp": [
          {"target": "cdn.winget.microsoft.com:443", "ok": true, "durationMs": 38},
          {"target": "storeedgefd.dsx.mp.microsoft.com:443", "ok": true, "durationMs": 41}
        ],
        "https": [
          {"target": "https://cdn.winget.microsoft.com", "ok": true, "durationMs": 152},
          {"target": "https://storeedgefd.dsx.mp.microsoft.com", "ok": true, "durationMs": 167}
        ],
        "proxyConfigured": false
      }
    }
  }
}
```

AG-026A WinGet source/egress block icin HARD boundary (Codex 019e6b5d
plan-time kilit sart + 019e6b70 iter-1 absorb):

```text
1. install / upgrade / uninstall / settings / export / import / hash /
   validate / pin / configure / download / repair / features /
   complete / debug / source add|remove|update|reset subcommand'lari
   HIC calistirilmaz; package fixed-argv `show` ve `source list`
   disinda winget yardimi cagrilamaz.
2. Package id `7zip.7zip` (FixedPackageQueryID) hard-coded.
   `SourceEgressOptions` artik `PackageID` alani TASIMAZ; `runPackageQuery`
   sabiti dogrudan kullanir (compile-time pinning — runtime guard'a
   gerek yok). Reflection-based `TestSourceEgressOptionsHasNoOverrideFields`
   testi alan eklendiginde build kirilmasini saglar.
3. Egress hostname listesi unexported `defaultEgressTargets` arrayinde
   tutulur. `DefaultEgressTargets()` callerlara KOPYA doner —
   canonical liste mutate edilemez. `SourceEgressOptions` `Targets`
   alani TASIMAZ; production callerlar listeyi degistiremez.
4. Approved catalog client / unauthorized software detection / install
   execution AG-026A scope'unda DEGIL — sirayla BE-020, BE-023/BE-025,
   AG-027 sorumlu.
5. Source argument (URL), source error reason, proxy URL ve egress
   error reason serbest metni `security.RedactSoftwareString` (proxy
   userinfo `url.User=nil` ile ek olarak strip edilir) ile sanitize
   edilir — user path, SID, JWT, license-shaped string, embedded
   credential payload'a raw girmez.
6. winget LocalSystem'da `source list` icin fail dondurursa readiness
   yeni `sourceListError` alaninda sanitised reason tasir + timeout
   ise overall `timeout` flag flips. `show` icin fail dondurursa
   `packageQuery.errorReason` doldurulur. Egress fail her bir
   `egress.{dns,tcp,https}[i].errorReason` ile rapor edilir; timeout
   olusursa yine overall `timeout` flag flips. Implementation failure
   degildir — agent exit code degismez.
7. Overall preflight bütçesi `opts.Timeout` ile clamp edilir: root
   `context.WithTimeout` her sub-probe'u kapsar; `perProbeSlice` 250ms
   floor ile remaining root budget'i still-to-run probelar arasinda
   böler. Bir sub-probe stall etse bile total wall-clock budget'i
   asmaz.
```

Implementation referansi: `internal/winget/source_egress.go`
(`RunSourceEgressPreflight` + `DetectSourceEgress` platform giris noktasi),
`internal/inventory/inventory.go` (`CollectOptions.IncludeWinGetEgress`),
`internal/commands/executor.go` (`COLLECT_INVENTORY` payload parse).

-------------------------------------------------------------------------------
## 7. Command Result
-------------------------------------------------------------------------------

```json
{
  "commandId": "8f716fe5-1f1a-4d6c-b18b-4cb26e86cf3d",
  "claimId": "8b4af102-e203-43fb-ad45-7533d7c56f52",
  "attemptNumber": 1,
  "status": "SUCCEEDED",
  "summary": "Local user disabled",
  "startedAt": "2026-04-28T11:00:00+03:00",
  "finishedAt": "2026-04-28T11:00:03+03:00"
}
```

Status listesi:

```text
QUEUED
CLAIMED
RUNNING
SUCCEEDED
FAILED
UNSUPPORTED
EXPIRED
```

Result payload secret tasimaz. Password reset result yalniz sonuc ozeti tasir:

```json
{
  "status": "SUCCEEDED",
  "summary": "Local user password reset completed"
}
```

-------------------------------------------------------------------------------
## 8. Capability Bildirimi
-------------------------------------------------------------------------------

Windows agent ornegi:

```json
{
  "osFamily": "WINDOWS",
  "architecture": "x64",
  "capabilities": [
    "COLLECT_INVENTORY",
    "LIST_LOCAL_USERS",
    "GET_LOGGED_IN_USER",
    "GET_USER_HOME_PATHS"
  ]
}
```

Not: `DISABLE_LOCAL_USER`, `ENABLE_LOCAL_USER` ve
`RESET_LOCAL_USER_PASSWORD` intentionally capability listesinde yoktur. Adapter,
RBAC/audit/saga ve pilot gate kanitlari gelmeden backend'e advertise edilmez.

macOS agent ilk faz ornegi:

```json
{
  "osFamily": "MACOS",
  "architecture": "arm64",
  "capabilities": [
    "COLLECT_INVENTORY",
    "GET_LOGGED_IN_USER",
    "GET_USER_HOME_PATHS"
  ]
}
```

-------------------------------------------------------------------------------
## 9. Offline State Machine
-------------------------------------------------------------------------------

Agent network veya backend kesintisinde local command cache tutmaz. Authoritative
command queue backend'dedir.

State modeli:

```text
STARTING
ENROLLING
ONLINE
DEGRADED
OFFLINE
RE_ENROLL_REQUIRED
STOPPING
```

Gecis kurallari:

```text
ONLINE -> DEGRADED
  3 ardışık heartbeat/poll hatasi

DEGRADED -> OFFLINE
  backoff max seviyeye ulasir veya 10 dakika backend'e ulasilamaz

OFFLINE -> ONLINE
  heartbeat success

ONLINE/DEGRADED/OFFLINE -> RE_ENROLL_REQUIRED
  backend 401/403 + reason agent_revoked | secret_rotated | unknown_agent
```

Agent offline iken yeni local command calistirmaz. Yalniz log ve telemetry
buffer'i sinirli boyutta tutulabilir.

-------------------------------------------------------------------------------
## 10. Polling Davranisi
-------------------------------------------------------------------------------

1000 endpoint hedefi icin jitter zorunludur:

```text
heartbeatIntervalSeconds: 60
commandPollIntervalSeconds: 30-60
inventoryIntervalMinutes: 30-60
jitterPercent: 20
commandTimeoutSeconds: 120
```

Agent ayni anda tek command calistirir. Command calisirken yeni command claim
edilmez.

-------------------------------------------------------------------------------
## 11. AG-027 — INSTALL_SOFTWARE Command Contract (Faz 22.5)
-------------------------------------------------------------------------------

`INSTALL_SOFTWARE` is the canonical agent-side install execution command.
The agent re-verifies the AG-026A WinGet source/egress readiness,
pre-detects whether the catalog package is already present, runs
`winget install` with a hard-coded argument vector, and post-verifies via
the catalog's detection rule. v1 supports `WINGET_PACKAGE` detection
rules only; any other detection rule type is rejected fail-closed
BEFORE mutation.

Codex 019e6bfa plan-time AGREE (iter-2) — schema locked.

### 11.1 Wire-safe request payload

```json
{
  "commandType": "INSTALL_SOFTWARE",
  "commandResultId": "<uuid>",
  "idempotencyKey": "<uuid>",
  "catalogItemId": "<uuid>",
  "catalogItemKey": "7zip.7zip",
  "catalogRowVersion": 7,
  "provider": "WINGET",
  "packageId": "7zip.7zip",
  "argsPolicyPreset": "DEFAULT",
  "versionPredicate": {
    "type": "LATEST" | "EXACT" | "MINIMUM" | "RANGE",
    "spec": null | "24.07" | "[24.0,)"
  },
  "resolvedVersion": null,
  "detectionRule": {
    "type": "WINGET_PACKAGE",
    "packageId": "7zip.7zip"
  }
}
```

`argsPolicyPreset` is an enum slot, NOT a free-text command-line
string. v1 accepts exactly two values, each mapping to a hard-coded
`[]string` arg slice in the agent (`install_winget.go::argsPresets`):

- `DEFAULT` → `install --id <pkg> --exact --source winget --silent
  --accept-package-agreements --accept-source-agreements
  --disable-interactivity --no-upgrade`
- `VENDOR_RECOMMENDED_WINGET_NO_UPGRADE` → same arg slice as DEFAULT
  for v1, distinct name for audit-trail intent. Future widening may
  add presets without renaming this constant.

`resolvedVersion` is BE-022's responsibility: when `versionPolicy.type =
EXACT`, BE-022 resolves the catalog spec to a concrete version string
at command-issue time. When `type = LATEST`, `resolvedVersion = null`
and the agent does not enforce a version constraint post-install.

### 11.2 Wire-safe result payload

```json
{
  "finalStatus": "SUCCEEDED" | "SUCCEEDED_NOOP" | "SUCCEEDED_REBOOT_REQUIRED"
              | "FAILED_PREEXISTING_VERSION_CONFLICT"
              | "FAILED_UNSUPPORTED_DETECTION_RULE"
              | "FAILED_UNSUPPORTED_ARGS_POLICY"
              | "FAILED_UNSUPPORTED_PLATFORM"
              | "FAILED_EGRESS"
              | "FAILED_INSTALL"
              | "FAILED_VERIFICATION"
              | "FAILED_TIMEOUT"
              | "FAILED_INTERNAL",
  "schemaVersion": 1,
  "supported": true,
  "failedReasonCode": null,
  "exitCode": 0,
  "durationMs": 18234,
  "rebootRequired": false,
  "killStrategy": null,
  "preDetect":  { "satisfied": false, "matchedPackageId": null, "matchedVersion": null },
  "postVerification": { "satisfied": true, "matchedPackageId": "7zip.7zip", "matchedVersion": "24.07", "ruleType": "WINGET_PACKAGE" },
  "egress": { /* AG-026A SourceEgressReadiness shape */ },
  "stdoutTail":  "...(last ~4 KiB)",
  "stdoutTruncated":  true,
  "stdoutTotalBytes": 18432,
  "stderrTail":  "...(last ~4 KiB)",
  "stderrTruncated": false,
  "stderrTotalBytes": 312
}
```

The result is shipped via `CommandResult.Details.install`. The
top-level `CommandResult.Status` is derived from `finalStatus`:
SUCCEEDED / SUCCEEDED_NOOP / SUCCEEDED_REBOOT_REQUIRED → `SUCCEEDED`;
FAILED_UNSUPPORTED_* → `UNSUPPORTED`; everything else → `FAILED`. The
fine-grained `finalStatus` stays in `Details.install.finalStatus` so
audit / UI / compliance consumers can read the exact verdict.

### 11.3 Decision pipeline

```text
1. validate detectionRule.type ∈ {WINGET_PACKAGE}
   else FAILED_UNSUPPORTED_DETECTION_RULE (no mutation)

2. validate argsPolicyPreset ∈ {DEFAULT, VENDOR_RECOMMENDED_WINGET_NO_UPGRADE}
   else FAILED_UNSUPPORTED_ARGS_POLICY (no mutation)

3. locator() locates winget.exe
   else FAILED_UNSUPPORTED_PLATFORM (no mutation)

4. egressVerify() re-runs AG-026A SourceEgressPreflight
   if !ready → FAILED_EGRESS (no mutation)

5. pre-detect via `winget list --id <pkg> --exact --source winget`
   • present + versionPredicate satisfied → SUCCEEDED_NOOP
   • present + versionPredicate fails    → FAILED_PREEXISTING_VERSION_CONFLICT
                                            (no silent upgrade)
   • not present                          → proceed

6. run winget install (30-min hard cap; timeout → process-tree kill via
   `taskkill /F /T /PID` fallback; killStrategy field carries audit
   evidence)

7. post-verify via `winget list ...`
   • satisfied + versionPredicate ok  → SUCCEEDED (or SUCCEEDED_REBOOT_REQUIRED
                                         when exit 3010 / reboot signal)
   • satisfied but version mismatch    → FAILED_VERIFICATION
   • not satisfied                     → FAILED_VERIFICATION
```

### 11.3a Installer log redaction (AG-027L)

The `stdoutTail` / `stderrTail` fields in the install result are
routed through `security.RedactInstallerString` before they land on
the wire. The function is layered:

1. **AG-027L installer-specific patterns first** — applied to the raw
   tail in this order so subsequent baseline patterns cannot eat the
   structural anchors:
   - `https://user:pass@host/...` → `https://[REDACTED]@host/...`
     (URL userinfo segment, scheme + host preserved for operator
     debuggability).
   - `KEY=value` property/CLI assignment where KEY belongs to the
     credential family — license/serial/activation keys, API / access /
     refresh / OAuth / auth / ID tokens, client / secret key
     variants. Covers bare (`LICENSEKEY`), snake_case
     (`CLIENT_SECRET`), kebab-case (`client-secret`) and camelCase
     (`clientSecret`) shapes. Case-insensitive, bare + quoted values,
     KEY name preserved (`LICENSEKEY=[REDACTED]`). Allowlist tracked
     in `internal/security/redact_installer.go` so silent widening
     stays out of operator surprise.
   - Token-bearing query parameters: same credential family as
     above (`?token=`, `?client_secret=`, `?id_token=`, `?api-key=`,
     etc.), first or follow-on (`&key=`) parameter position, value
     masked up to next `&` / whitespace / end-of-string.
2. **AG-025/AG-026 baseline (`security.RedactSoftwareString`) second**
   — JWT (`eyJ…` shape), `password=` / `pwd=` / `pass=` assignments,
   email/UPN, full domain SIDs, `C:\Users\<account>\` path segment,
   product-key shape (five 5-char alphanumeric groups separated by
   hyphens — Windows/Office style).

What AG-027L deliberately does **not** scrub:

- Public-by-design paths (`C:\ProgramData\<vendor>\`,
  `C:\Program Files\<vendor>\`, temp dirs without user context).
- Bare hostnames / computer names — operational identifiers, not
  credentials.
- Version strings, build numbers, package IDs.
- Installer exit codes (numeric) — those are wire metadata, not log.

The redaction layer is enforced inside `sanitizeForWire` in
`internal/winget/install_winget.go`; no install command path can
bypass it. Tests live in `internal/security/redact_installer_test.go`
and lock both positive (each pattern redacts) and negative (look-
alikes such as `LICENSES_VALIDATED=1` or `?version=1.2.3` survive)
behavior.

### 11.4 Security invariants

- **No shell.** `os/exec.Cmd` argument vector only; no `fmt.Sprintf`,
  no `--%-style` interpolation of payload fields, no shell escapes.
  Payload-supplied package id reaches the arg slice via the hard-
  coded `%PKG%` placeholder substitution in `ArgsForPreset`.
- **No free-text args.** `argsPolicyPreset` is an enum; an unknown
  preset is rejected fail-closed BEFORE locator + winget invocation.
- **No mutation under unverifiable rules.** Detection rule type
  `!= WINGET_PACKAGE` rejected BEFORE install.
- **No silent upgrade.** Pre-detect that finds an installed-but-
  wrong-version package raises FAILED_PREEXISTING_VERSION_CONFLICT
  instead of dropping `--no-upgrade` or invoking `winget upgrade`.

### 11.4.1 Effective install timeout

`Runner.RunOnce` now dispatches per-command-type timeouts. For
`INSTALL_SOFTWARE` it uses `Config.InstallCommandTimeout`
(default 30 min, env var `ENDPOINT_AGENT_INSTALL_COMMAND_TIMEOUT`),
not the lightweight `CommandTimeout` (default 120 s) that read-only
commands inherit. The agent-side `RunInstall` derives its own
30-min ceiling from this parent context, so the effective cap is
`min(InstallCommandTimeout, 30min)`. Codex 019e6c0d iter-2 absorb.

### 11.5 Known v1 limitations (deferred to follow-ups)

- **Windows Job Object atomic process-tree kill** — v1 uses
  `taskkill /F /T /PID` fallback after `Process.Kill()`; the narrow
  race window between `cmd.Start()` and the kill request is
  documented as `killStrategy = "taskkill_tree"` or `"process_kill_only"`
  in the result. A Job Object implementation that pre-binds the
  spawned tree is RT-AG-027-F1 (post-v1 hardening).
- **Detection rules beyond `WINGET_PACKAGE`** (`REGISTRY_UNINSTALL`,
  `FILE_EXISTS`, `FILE_SHA256`) — fail-closed in v1; widening planned
  under AG-028.
- **Server-side issuer** — BE-022 lands as the sibling backend PR
  that publishes the dual-control `INSTALL_SOFTWARE` issuer, catalog
  snapshot pinning, BE-021A install-preflight integration. AG-027
  ships the canonical wire-shape so BE-022 can adopt it byte-for-byte.

-------------------------------------------------------------------------------
## 12. AG-030 — Pending Reboot Detection (Faz 22.5.2 posture quartet)
-------------------------------------------------------------------------------

### 12.1 Scope

Read-only registry probe that answers a single question: "would a
reboot now clear pending OS-level state?". The probe never triggers
a reboot, never asks the user, never mutates state. AG-030 is one of
the four Sprint B P1 posture quartet items (AG-030 + AG-031 + AG-032
+ AG-033) and is the first to land.

### 12.2 Opt-in payload bit

Default `COLLECT_INVENTORY` does NOT invoke the probe. AG-025H
lightweight guard pattern: the heartbeat / auto-enroll loop never
opts in. Backend opts in explicitly via:

```json
{
  "type": "COLLECT_INVENTORY",
  "payload": {
    "includePendingReboot": true
  }
}
```

When omitted or false, `inventory.PendingReboot` is `nil` and the
wire payload omits the field entirely.

### 12.3 Wire-safe result payload

```json
{
  "schemaVersion": 1,
  "supported": true,
  "pendingReboot": true,
  "probeComplete": true,
  "signals": {
    "cbsRebootPending": true,
    "windowsUpdateRebootRequired": false,
    "pendingFileRenameOperations": false,
    "computerNameChangePending": false,
    "updateExeVolatile": true,
    "netlogonJoinPending": false
  },
  "sources": [
    "CBS_REBOOT_PENDING",
    "UPDATE_EXE_VOLATILE"
  ],
  "probeErrors": [],
  "probeDurationMs": 12
}
```

Boolean precedence (Codex 019e749c iter-1 absorb):

- `pendingReboot` is the OR of all populated `signals` booleans.
- `probeComplete` is `true` if and only if `probeErrors` is empty.
  A single read failure flips it to `false` — the caller MUST treat
  `probeComplete=false` as "evidence incomplete", not "no reboot
  needed".
- `supported=false` on non-Windows runtimes carries the
  `UNSUPPORTED_PLATFORM` error code; `pendingReboot` stays false
  because there is no positive evidence, but consumers cannot infer
  "no reboot needed" without `supported=true` AND
  `probeComplete=true`.

### 12.4 Sources probed (v1)

| Source enum | Registry / file marker |
|---|---|
| `CBS_REBOOT_PENDING` | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending` subkey exists (WOW64_64KEY view) |
| `WINDOWS_UPDATE_REBOOT_REQUIRED` | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired` subkey exists (WOW64_64KEY view) |
| `PENDING_FILE_RENAME_OPERATIONS` | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager` `PendingFileRenameOperations` REG_MULTI_SZ present AND non-empty |
| `COMPUTER_NAME_CHANGE_PENDING` | `HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName` != `\ComputerName` (case-insensitive + trim-normalized; raw names do NOT leak) |
| `UPDATE_EXE_VOLATILE` | `HKLM\SOFTWARE\Microsoft\Updates\UpdateExeVolatile` `Flags` REG_DWORD value: missing key/value = false, Flags=0 = false, Flags!=0 = true, non-DWORD = probe error (Codex 019e749c iter-1 P0#4 absorb) |
| `NETLOGON_JOIN_PENDING` | `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon` `JoinDomain` OR `AvoidSpnSet` value exists |

### 12.5 Security invariants

- **Registry reads only.** No `SetValue`, no `CreateKey`, no
  `DeleteKey`. Subkey existence checks open with `QUERY_VALUE`
  permission only.
- **Raw value contents NEVER leak.** PendingFileRenameOperations
  entries, ComputerName strings, Netlogon value contents stay on
  the host. Only the derived bool reaches the wire.
- **No remediation surface.** The agent reports posture only; the
  backend / operator decides what to do with `pendingReboot=true`.
  AG-030 does not expose a "reboot now" command.
- **64-bit registry view.** `SOFTWARE\...` markers use
  `WOW64_64KEY` so a 32-bit agent binary still reads the 64-bit
  hive view. `SYSTEM\...` markers are not subject to redirection.

### 12.6 Known v1 exclusions (planned for future PRs or out of scope)

- **SCCM `CCM_ClientUtilities.DetermineIfRebootPending()`** — out of
  scope for the agent-only AG-030 v1; depends on SCCM client
  presence and adds COM/WMI cost.
- **Office RestartManager / .NET runtime restart / third-party AV
  reboot markers** — vendor-specific, noisy, LocalSystem-context
  fragile. Not covered.
- **`PendingFileRenameOperations2`** — additional MULTI_SZ marker;
  cheap follow-up candidate but excluded from v1 surface to keep
  the contract narrow.
- **`PostRebootReporting`** — same: candidate for v2 widening once
  v1 telemetry confirms false-positive rate is low.

---

## 13. AG-031 — Endpoint Security Posture (Faz 22.5.2 posture quartet)

The endpoint security posture probe answers the question "what
state are the host's security controls in right now?" — without
ever touching them. It runs once per opt-in COLLECT_INVENTORY and
returns a wire-safe roll-up covering antivirus, host-based firewall
and drive encryption.

### 13.1 Scope

The probe is strictly **read-only**:

- It NEVER enables or disables a control (no Set-MpPreference, no
  Enable-NetFirewallProfile, no Manage-bde, no policy push).
- It NEVER runs a sample scan, decrypts a volume, or exports a
  recovery key.
- It NEVER surfaces vendor product names, drive identifiers
  (letters, mountpoints, volume GUIDs), recovery passwords or key
  protector contents on the wire.

It answers the posture question: "is Defender on / off / unknown,
is the firewall on per-profile with block-by-default, is the system
drive encrypted, how many data drives are encrypted out of how
many."

### 13.2 Opt-in payload bit

`COLLECT_INVENTORY` accepts an opt-in bit:

```json
{
  "type": "COLLECT_INVENTORY",
  "payload": { "includeSecurityPosture": true }
}
```

Default = `false`. Heartbeat / auto-enroll never opt in; the
AG-025H lightweight contract stays cheap.

### 13.3 Wire-safe result payload

`Snapshot.securityPosture` is omitted unless the caller opted in.
When present:

```json
{
  "securityPosture": {
    "schemaVersion": 1,
    "supported": true,
    "probeComplete": true,
    "antivirus": {
      "microsoftDefender": {
        "present": true,
        "antivirusEnabled": true,
        "realTimeProtectionEnabled": true,
        "signatureAgeDays": 0,
        "engineVersionPresent": true,
        "tamperProtected": true
      },
      "nonMicrosoftAvPresent": false,
      "avProductCount": 1
    },
    "firewall": {
      "domain":  { "enabled": true, "defaultInboundAction": "BLOCK" },
      "private": { "enabled": true, "defaultInboundAction": "BLOCK" },
      "public":  { "enabled": true, "defaultInboundAction": "BLOCK" }
    },
    "bitlocker": {
      "systemDrivePresent": true,
      "systemDriveEncrypted": true,
      "systemDriveProtected": true,
      "systemDriveEncryptionActive": false,
      "dataDriveCount": 0,
      "encryptedDataDriveCount": 0,
      "protectedDataDriveCount": 0,
      "suspendedDriveCount": 0
    },
    "probeDurationMs": 1234
  }
}
```

Tri-state semantics (Codex 019e74c3 iter-2 + iter-3 absorb — doc
distinguishes "successful zero readout" from "source unavailable"
without overclaiming per-field null-to-probeComplete mapping):

- `antivirusEnabled`, `realTimeProtectionEnabled`, `tamperProtected`,
  `nonMicrosoftAvPresent` are **nullable booleans**.
  - `null` means **the source did not return a usable value for
    this field**. Possible causes: the source-level cmdlet
    succeeded but the property was missing on the returned object
    (PSObject property guard); the source-level cmdlet failed
    (surfaced via a typed `probeErrors[]` entry — `ACCESS_DENIED`,
    `CMDLET_UNAVAILABLE`, `POWERSHELL_FAILED`); or the cmdlet was
    not present on the host. **Note**: a per-field `null` does NOT
    by itself guarantee an entry in `probeErrors[]`. Source-level
    read failures (catch-block paths like SecurityCenter2 failure,
    the `NO_EVIDENCE` fail-closed guard) always append a structured
    error and flip `probeComplete=false`, but a single missing
    Defender property does not.
  - `false` means **the source ran successfully and the control is
    off / not present**. Canonical examples:
    - `nonMicrosoftAvPresent=false` + `avProductCount=0` =
      SecurityCenter2 cmdlet succeeded with zero AV products
      registered (distinguished from cmdlet failure, which is
      `null/null` + a `probeErrors[]` entry).
    - `antivirusEnabled=false` = Defender installed but disabled.
  - Operators MUST NOT collapse `null` to `false` — they carry
    different semantics. Backend consumers should treat per-field
    `null` as "unknown for this signal" rather than negative
    posture, and rely on `probeComplete` only for **source-level**
    read completeness.
- `signatureAgeDays`, `avProductCount` are nullable integers with
  the same semantics: `null` = unavailable / no usable value;
  numeric value (including `0`) = successful readout. The same
  source-level vs per-field caveat applies — a `null` integer here
  does not by itself guarantee `probeComplete=false`.
- `probeComplete` is **source-level read completeness**: `true` iff
  `probeErrors` is empty. Source-level failures (a sub-source try
  block falling through to its catch, the `NO_EVIDENCE`
  fail-closed guard) always append a structured error and flip
  `probeComplete=false`. Per-field nulls that did not trigger a
  source-level failure leave `probeComplete=true` intact;
  consumers MUST treat such fields as "unknown" rather than infer
  posture from the absence of a value.

### 13.4 Sources probed (v1)

| Source         | Cmdlet                                                   | Surfaces                                                                                                       |
| -------------- | -------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Defender       | `Get-MpComputerStatus`                                   | `present`, `antivirusEnabled`, `realTimeProtectionEnabled`, `signatureAgeDays`, `engineVersionPresent`, `tamperProtected` |
| SecurityCenter | `Get-CimInstance -Namespace root\SecurityCenter2 AntiVirusProduct` | `nonMicrosoftAvPresent`, `avProductCount` (count only — never `displayName`)                          |
| Firewall       | `Get-NetFirewallProfile`                                 | per-profile `enabled` + `defaultInboundAction` ∈ {`ALLOW`, `BLOCK`, `UNKNOWN`}                                 |
| BitLocker      | `Get-BitLockerVolume`                                    | system-drive booleans + data-drive counts (`dataDriveCount`, `encryptedDataDriveCount`, `protectedDataDriveCount`, `suspendedDriveCount`) |

All four sources run inside a single PowerShell process under
`-NoProfile -NonInteractive` with a pinned script and a 30-second
deadline. The script is reviewed once and embedded in the build;
no payload-supplied substitution, no `Invoke-Expression`, no
shell. `netsh` is intentionally NOT used (AG-035 PowerShell-only
pattern; Codex 019e74b5 iter-0 must-fix #7).

### 13.5 Failure-mode contract (Codex 019e74c3 iter-1 absorb)

- **No-evidence fail-closed guard.** A `null` / `{}` PowerShell
  payload now triggers a `NO_EVIDENCE` probe error before
  `probeComplete` is derived; backend never sees "ran but probed
  nothing" as `probeComplete=true` (MF-2).
- **Source enum allowlist.** PowerShell error sources are mapped
  through `normalizeSecuritySource` — only `defender`,
  `securityCenter`, `firewall`, `bitlocker`, `powershell` are
  honoured. Unknown / blank / lower-cased `securitycenter` collapse
  to the `powershell` catch-all so the typed enum surface is never
  violated (MF-1).
- **SecurityCenter2 explicit failure detection.** The
  `Get-CimInstance root\SecurityCenter2 AntiVirusProduct` call uses
  `-ErrorAction Stop` so namespace-missing / access-denied / CIM
  failure paths throw to the catch block and emit
  `ACCESS_DENIED` / `CMDLET_UNAVAILABLE` / `POWERSHELL_FAILED` —
  distinct from "cmdlet succeeded with zero products"
  (`nonMicrosoftAvPresent=false`, `avProductCount=0`) (MF-3).
- **Summary control-char normalization.** `boundSummary` strips
  NUL / BEL / ESC / DEL etc. and folds CR/LF/TAB to single spaces
  (in addition to the 200-char cap) so downstream consumers
  (audit log, UI, alerting) cannot be tripped by stray control
  bytes in error summaries.

### 13.6 Security invariants

- **Read-only argv pin.** Pinned argv:
  `powershell.exe -NoProfile -NonInteractive -Command <pinned script>`.
  Payload bits cannot reach the PowerShell invocation; they only
  flip the opt-in.
- **No identifier leak.** The PowerShell script's `ConvertTo-Json`
  output is an allowlist `PSCustomObject` — drive letters,
  mountpoints, volume GUIDs, key protectors, recovery passwords,
  AV vendor display names, AV install paths, and firewall rule
  names are NEVER built into the output. The Go-side normalizer
  only consumes the allowlisted fields and drops anything else.
- **Bounded summaries.** Source error summaries are capped at 200
  characters; raw exception dumps and registry / CIM values never
  reach `probeErrors[*].summary`.
- **Tri-state honored.** A failed cmdlet leaves the matching
  nullable field at `null` and appends a typed `probeErrors[*]`
  entry. The agent never fabricates a `false` value to fill the
  shape.
- **Posture, never remediation.** There is no remediation surface
  in AG-031. The backend / operator decides what to do with the
  posture readout.

### 13.7 Known v1 exclusions (planned for future PRs or out of scope)

- **EDR / MDE telemetry posture.** Microsoft Defender for Endpoint
  onboarding state, sensor health, organization id — deferred to
  a dedicated AG-039 EDR posture probe (Sprint C scope).
- **Application Control / WDAC / AppLocker policy state.** Deferred
  to AG-040 (Sprint C).
- **Credential Guard / HVCI / VBS attestation.** Deferred to
  AG-041 (Sprint D).
- **Drive identifier surfacing.** Out of scope — drive letters,
  GUIDs, recovery passwords are a HARD BOUNDARY.
- **Third-party AV vendor enumeration.** SecurityCenter2 returns a
  count + presence boolean only; the `displayName` field is read
  to derive `nonMicrosoftAvPresent` but is NEVER passed to the
  wire payload.

---

## 14. AG-032 — Local Administrators Alias Direct Membership (Faz 22.5.2 posture quartet)

The local administrators inventory probe answers the question
"who is a direct member of the local Built-in Administrators
alias (S-1-5-32-544) right now?" — without ever modifying
group membership and without leaking principal identity to the
wire.

### 14.1 Scope (HARD BOUNDARY)

The probe is strictly **read-only** and strictly **identity-suppressing**:

- It NEVER modifies group membership (no `Add-LocalGroupMember`,
  no `Remove-LocalGroupMember`, no `net localgroup` mutation, no
  `NetLocalGroupAdd*` syscall).
- It NEVER expands transitive domain group / Entra group
  membership. AG-032 reports **direct members of the local
  Built-in Administrators alias only**.
- It NEVER evaluates user-rights assignments (e.g.
  `SeBackupPrivilege`, `SeDebugPrivilege`), service ACLs,
  scheduled tasks, or other admin-equivalent privilege paths.
- It NEVER emits raw SID bytes, full SID string, SID family /
  authority / sub-authority breakdown, SID relative-ID (RID),
  domain SID prefix, account name, display name, description,
  principal path, UPN, or domain name on the wire.

`directMemberCount` is the **direct membership** count; it MUST
NOT be read as "effective administrator count" since transitive
group expansion and other privilege paths are not evaluated.

### 14.2 Opt-in payload bit

`COLLECT_INVENTORY` accepts the opt-in bit:

```json
{
  "type": "COLLECT_INVENTORY",
  "payload": { "includeLocalAdminGroup": true }
}
```

Default = `false`. Heartbeat / auto-enroll never opt in; the
AG-025H lightweight contract stays cheap.

### 14.3 Wire-safe result payload

`Snapshot.localAdminGroup` is omitted unless the caller opted in.
When present:

```json
{
  "localAdminGroup": {
    "schemaVersion": 1,
    "supported": true,
    "probeComplete": true,
    "directMemberCount": 5,
    "localUserCount": 1,
    "localGroupCount": 0,
    "domainUserCount": 0,
    "domainGroupCount": 1,
    "domainComputerCount": 0,
    "builtinAliasCount": 0,
    "serviceSidCount": 1,
    "wellKnownPrivilegedCount": 1,
    "broadWellKnownCount": 0,
    "cloudPrincipalCount": 1,
    "capabilityCount": 0,
    "unknownCount": 0,
    "hasDomainScopedPrincipal": true,
    "hasBroadWellKnownPrincipal": false,
    "hasCloudPrincipal": true,
    "hasNonBuiltinLocalUser": true,
    "members": [
      {"kind":"localUser","isLocalScoped":true,"isDomainScoped":false,"isPrivilegedBuiltinAlias":false,"isBroadWellKnown":false,"isCloudPrincipal":false},
      {"kind":"domainGroup","isLocalScoped":false,"isDomainScoped":true,"isPrivilegedBuiltinAlias":false,"isBroadWellKnown":false,"isCloudPrincipal":false},
      {"kind":"wellKnownPrivileged","isLocalScoped":false,"isDomainScoped":false,"isPrivilegedBuiltinAlias":false,"isBroadWellKnown":false,"isCloudPrincipal":false},
      {"kind":"serviceSid","isLocalScoped":false,"isDomainScoped":false,"isPrivilegedBuiltinAlias":false,"isBroadWellKnown":false,"isCloudPrincipal":false},
      {"kind":"cloudPrincipal","isLocalScoped":false,"isDomainScoped":false,"isPrivilegedBuiltinAlias":false,"isBroadWellKnown":false,"isCloudPrincipal":true}
    ],
    "membersTruncated": false,
    "maxMembers": 256,
    "sourceUsed": "netapi",
    "probeDurationMs": 42
  }
}
```

**Members contract**: `members` ALWAYS serializes as a JSON array
(never `null`). Empty enumeration is `"members": []`. Failure
paths also serialize as `[]` so consumers never have to defend
against `members: null`.

**Member cap**: `members` length is bounded by `maxMembers`
(default 256). If `directMemberCount > maxMembers`, the slice
is truncated to the cap and `membersTruncated: true` is set.
**Counts cover the full enumeration** even when truncated.

### 14.4 Classifier precedence

Each enumerated SID matches **exactly one** Kind via the following
ordered precedence (first match wins):

| Step | Match | Kind | Bool flag |
|------|-------|------|-----------|
| 1 | `S-1-5-32-544` (self-loop), `-547`, `-548`, `-549`, `-551` | `builtinAlias` | `isPrivilegedBuiltinAlias=true` |
| 2 | `S-1-5-32-545`, `-546`, `-555` (Users / Guests / Remote Desktop Users) | `broadWellKnown` | `isBroadWellKnown=true` |
| 2 (cont.) | `S-1-1-0` (Everyone), `S-1-5-{2,4,7,11}` (Network/Interactive/Anonymous/Authenticated Users) | `broadWellKnown` | `isBroadWellKnown=true` |
| 3 | `S-1-5-{18,19,20}` (LocalSystem / LocalService / NetworkService) | `wellKnownPrivileged` | — |
| 4 | `S-1-5-80-*`, `S-1-5-83-*` | `serviceSid` | — |
| 5 | `S-1-15-2-*` (AppContainer), `S-1-15-3-*` (capability) | `capability` | — |
| 6 | `S-1-12-1-*` (MSA / Entra) | `cloudPrincipal` | `isCloudPrincipal=true` |
| 7 | Any other `S-1-5-32-*` | `builtinAlias` | `isPrivilegedBuiltinAlias=false` |
| 8 | `S-1-5-21-<machine-prefix>-*` (machine domain) + SID_NAME_USE | `localUser` / `localGroup` / `unknown` | `isLocalScoped=true` |
| 9 | `S-1-5-21-<not-this-machine>-*` (domain) + SID_NAME_USE | `domainUser` / `domainGroup` / `domainComputer` / `unknown` | `isDomainScoped=true` |
| 10 | Anything else | `unknown` | — |

If LookupAccountSid fails for an S-1-5-21-* member, the member
becomes `Kind=unknown` with the scope booleans set according to
which step matched the prefix (Codex iter-1 MF-5 absorb: no
guessing user/group/computer from RID alone).

### 14.5 Source ordering

| Order | Source | Description |
|-------|--------|-------------|
| 1 (primary) | `netapi` | `NetLocalGroupGetMembers` level 0 (SID-only) targeting the localized Administrators alias resolved from `CreateWellKnownSid(WinBuiltinAdministratorsSid)`. SIDs classified in-place per page; no pointer escapes its NetAPI buffer (lifetime-safe). |
| 2 (fallback) | `powershellLocalAccounts` | `Get-LocalGroup -SID 'S-1-5-32-544' \| Get-LocalGroupMember -ErrorAction Stop` with a scalar SID allowlist (only `$_.SID.Value` serialized; never the `SecurityIdentifier` object). |
| 3 (last-resort) | `wmiGroupUser` | v1 stub returns `CMDLET_UNAVAILABLE`. Future runner can land without schema change. |

`sourceUsed` records which source produced the final readout. If
all three fail, `sourceUsed="none"` and `probeErrors[]` contains
the failure trail from each attempt.

**Fallback success semantics** (Codex iter-1 MF-3 absorb): when a
fallback source succeeds, the failures of earlier sources are NOT
added to `probeErrors[]` — `probeErrors[]` holds
terminal/incomplete-evidence failures only, not telemetry.

### 14.6 Failure-mode contract

- **NetAPI buffer lifetime**: each `LOCALGROUP_MEMBERS_INFO_0.lgrmi0_sid`
  pointer is consumed by the in-place classifier BEFORE
  `NetApiBufferFree` runs on its containing page. No SID pointer
  outlives its buffer (Codex iter-3 MF-1 absorb).
- **Invalid buffer guard**: an entry slice is only created from a
  page when the API status is success / ERROR_MORE_DATA /
  NERR_BufTooSmall AND the buffer is non-nil AND `entriesRead > 0`
  (Codex iter-3 MF-2 absorb).
- **Machine SID resolution failure**: when `NetUserModalsGet`
  level 2 fails to return the local SAM/account-domain SID, an
  `MACHINE_SID_RESOLUTION_FAILED` probe error is appended with
  `source=none` (Codex iter-2 MF-5 absorb), `probeComplete=false`,
  and S-1-5-21-* members degrade to coarse scope: classifier
  cannot prove `isLocalScoped` vs `isDomainScoped` reliably, so
  both default `false`.
- **NO_EVIDENCE fail-closed**: a successful PowerShell parse of
  `null` / `{}` triggers a `NO_EVIDENCE` probe error before
  `probeComplete` is derived (mirroring AG-031 MF-2).
- **Error summaries** are bounded static phrases (capped 200
  chars, control-char normalized). Raw Win32 status codes,
  account names, SIDs, and domain paths NEVER appear in
  summary text (Codex iter-3 MF-3 absorb).

### 14.7 Security invariants

- **Read-only**: only enumeration cmdlets / syscalls appear in
  source: `NetLocalGroupGetMembers`, `NetUserModalsGet`,
  `Get-LocalGroup`, `Get-LocalGroupMember`. No
  `Add-/Remove-/Set-/Enable-/Disable-/New-` cmdlets, no
  group-mutation syscall.
- **Pinned argv**: `powershell.exe -NoProfile -NonInteractive
  -Command <pinned script>` for the fallback path. No
  payload-supplied substitution, no `Invoke-Expression`. The
  script body is reviewed and embedded at build time.
- **Identifier suppression**: see §14.1 HARD BOUNDARY. The wire
  carries only Kind enum + bool flags + counts. The localized
  alias name resolved from `CreateWellKnownSid` is process-local
  only and never reaches log / summary / JSON / audit trail.
- **Bounded member array**: `maxMembers=256` cap with explicit
  `membersTruncated` flag; counts continue to cover the full
  enumeration.
- **Posture, never remediation**: no remediation surface in
  AG-032. The backend / operator decides what to do with the
  posture readout.

### 14.8 Known v1 exclusions

- **Transitive group expansion**: an admin who is a member via
  a nested local or domain group is reported as the group's Kind,
  not as a `localUser` / `domainUser`. Full transitive expansion
  is out of scope for v1.
- **Effective admin equivalence**: user-rights assignments
  (e.g. `SeBackupPrivilege`), service ACLs, scheduled tasks
  running as SYSTEM, and similar admin-equivalent privilege paths
  are out of scope.
- **Per-principal drilldown**: the wire never carries the
  specific principal identity. Drilldown for remediation requires
  a separate explicitly-authorized API call (future scope, not
  AG-032).
- **WMI fallback runner**: v1 ships a stub for the third source;
  if NetAPI + PowerShell both fail, `sourceUsed=none`. A real
  WMI runner can land without schema change.
- **BitLocker / Defender / Firewall**: those are AG-031 scope.

---

## 15. AG-033 — Device Health Snapshot (Faz 22.5.2 posture quartet, final item)

The device health probe answers "is this endpoint healthy enough to
receive a software deployment right now?" — fixed-disk free %,
physical memory utilization %, system uptime + last boot, and a
commit/page-file summary. Read-only point-in-time Win32 syscalls; no
PowerShell, no WMI, no performance-counter sampling.

### 15.1 Relationship to AG-035

- **AG-035** = raw hardware INVENTORY snapshot (static facts:
  total RAM, disk free bytes, last boot timestamp).
- **AG-033** = deployment-readiness health DERIVATION snapshot
  (percentages, warning booleans, uptime duration).

AG-033 has **no runtime dependency** on AG-035: the backend can
request `includeDeviceHealth=true` with `includeHardware=false`.

### 15.2 Opt-in payload bit

```json
{ "type": "COLLECT_INVENTORY", "payload": { "includeDeviceHealth": true } }
```

Default = `false`. Heartbeat / auto-enroll never opt in.

### 15.3 Wire-safe result payload

```json
{
  "deviceHealth": {
    "schemaVersion": 1,
    "supported": true,
    "probeComplete": true,
    "fixedDisks": [
      {"driveLetter":"C:","totalBytes":511000000000,"freeBytes":256000000000,"freePercent":50,"lowDiskWarning":false}
    ],
    "fixedDiskCount": 1,
    "fixedDisksTruncated": false,
    "maxFixedDisks": 64,
    "memory": {
      "totalPhysicalBytes": 17179869184,
      "availableBytes": 8589934592,
      "usedPercent": 50,
      "highPressureWarning": false,
      "commitLimitBytes": 34359738368,
      "commitUsedBytes": 12884901888
    },
    "uptime": {
      "lastBootEpochSec": 1717000000,
      "uptimeSeconds": 259200,
      "uptimeDays": 3,
      "longUptimeWarning": false
    },
    "anyLowDisk": false,
    "sourceUsed": "win32",
    "probeDurationMs": 4
  }
}
```

- `fixedDisks` ALWAYS serializes as `[]` (never null). `fixedDiskCount`
  is the pre-truncation observed count; `anyLowDisk` is OR'd over the
  full pre-truncation enumeration; `fixedDisksTruncated` + `maxFixedDisks`
  (64) bound the slice.
- `freeBytes` is `freeBytesAvailableToCaller` (what the agent's
  LocalSystem context can actually write — the right denominator for
  a "can this install succeed?" gate).
- `lastBootEpochSec` is unix seconds (NOT a local-time string) to
  avoid leaking timezone/locale.
- `commitLimitBytes` / `commitUsedBytes` are a MEMORYSTATUSEX
  approximation (ullTotalPageFile / ullAvailPageFile), NOT exact
  per-pagefile or per-process accounting.

### 15.4 Sources + thresholds

| Source | Syscall | Surfaces |
|--------|---------|----------|
| Disk | `GetLogicalDrives` + `GetDriveType` (filter `DRIVE_FIXED`) + `GetDiskFreeSpaceEx` | per-volume drive letter + total + freeToCaller + free% |
| Memory | `GlobalMemoryStatusEx` (dwLength set) | total/avail phys + dwMemoryLoad (usedPercent) + commit limit/used |
| Uptime | `DurationSinceBoot` (`GetTickCount64`, uint64 — no 49.7-day rollover) | uptimeSeconds + derived lastBootEpoch + uptimeDays |

Thresholds (const, **not** payload-configurable):

| Constant | Value | Effect |
|----------|-------|--------|
| `LowDiskPercentThreshold` | 10 | `freePercent < 10` → `lowDiskWarning` |
| `LowDiskBytesThreshold` | 2 GiB | `freeBytes < 2GiB` → `lowDiskWarning` |
| `HighMemoryUsedPercentThreshold` | 90 | `usedPercent > 90` → `highPressureWarning` |
| `LongUptimeDaysThreshold` | 30 | `uptimeDays > 30` → `longUptimeWarning` |

The backend receives the raw bytes/days too, so it can re-derive
different thresholds without an agent change.

### 15.5 Failure-mode contract

- **Per-volume failure**: `GetDiskFreeSpaceEx` failure for a volume →
  `DISK_ENUM_FAILED` probe error + the volume is skipped (NOT emitted
  as a zero-byte "healthy" row).
- **Memory failure / zero total**: `GlobalMemoryStatusEx` failure OR
  `ullTotalPhys==0` → `MEMORY_QUERY_FAILED` + `probeComplete=false`;
  memory struct stays zero (not emitted as healthy).
- **Uptime failure / clock skew**: non-positive duration →
  `UPTIME_QUERY_FAILED`; implausible derived boot epoch (future or
  ≤0) → `BOOT_TIME_FAILED`; either flips `probeComplete=false`.
- **No-evidence sentinel**: the aggregate `NO_EVIDENCE` +
  `sourceUsed=none` fires ONLY when ALL THREE sources came back
  empty together (`fixedDiskCount == 0` AND
  `memory.totalPhysicalBytes == 0` AND `uptime.uptimeSeconds == 0`).
  A host with zero fixed disks but valid memory + uptime does NOT
  trip the aggregate sentinel; instead the **backend deployment
  gate** must treat `fixedDiskCount == 0` as not-install-ready on
  its own (see §15.7 / the deployment-gate guidance), since the
  agent cannot prove install-target free space without at least one
  fixed volume. (Codex 019e7500 post-impl clarification: the agent
  emits the all-empty aggregate sentinel; the zero-disk-only gate
  is a backend-side policy, not an agent `NO_EVIDENCE`.)
- `probeComplete` is `true` iff `probeErrors` is empty. A
  `supported=true` + `probeComplete=false` result MUST NOT be read
  as deployment-ready. Likewise a `probeComplete=true` result with
  `fixedDiskCount == 0` MUST NOT be read as install-ready by the
  backend gate.

### 15.6 Security invariants

- **Read-only point-in-time syscalls**: no `Get-Counter`, no
  continuous sampling, no per-process enumeration, no WMI
  perfcounter polling ("no performance-counter spam" boundary).
- **Identifier suppression**: only the drive letter (validated
  `^[A-Z]:$` uppercase) reaches the wire. Volume labels, serial
  numbers, file-system types, mount paths, volume GUIDs, and full
  paths are NEVER surfaced. The `X:\` form is used only as the
  syscall argument, never emitted.
- **No payload-configurable policy**: the payload carries only the
  `includeDeviceHealth` opt-in bit; thresholds and source selection
  are not payload-controllable.
- **Bounded summaries**: error summaries are static phrases (200
  char cap conceptually; no raw syscall errno dump, no long path).
- **Overflow-guarded casts**: byte counts are clamped on the
  uint64→int64 conversion so a pathological value never wraps
  negative.

### 15.7 Known v1 exclusions

- **CPU utilization / load**: deliberately out of scope (that is
  the performance-counter territory the plan forbids).
- **Per-process memory / disk**: out of scope.
- **Removable / network / RAM-disk volumes**: only `DRIVE_FIXED`
  is enumerated.
- **SMART / disk-hardware health**: out of scope (AG-033 is
  free-space + utilization, not drive-failure prediction).
- **Per-pagefile breakdown**: only the MEMORYSTATUSEX commit
  summary is surfaced, not per-pagefile detail.
