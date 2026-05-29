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
   - `KEY=value` where KEY ∈ {`LICENSE`, `LICENSEKEY`, `SERIAL`,
     `ACTIVATION`, `ACTIVATIONKEY`, `APIKEY`, `APIKEYS`,
     `ACCESSTOKEN`, `REFRESHTOKEN`, `BEARER`, `OAUTHTOKEN`} —
     case-insensitive, both bare and quoted values, KEY name
     preserved (`LICENSEKEY=[REDACTED]`).
   - `?token=…` / `?api_key=…` / `?access_token=…` /
     `?refresh_token=…` / `?secret=…` / `?bearer=…` — first or
     follow-on (`&key=`) parameter position, value masked up to next
     `&` / whitespace / end-of-string.
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
