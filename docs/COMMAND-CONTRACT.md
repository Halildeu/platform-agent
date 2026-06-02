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
the catalog's detection rule. Supported detection rule types:
`WINGET_PACKAGE` (CONFIRM_ONLY under Session-0 — §11.3b) and
`REGISTRY_UNINSTALL` (AUTHORITATIVE — §11.3c). Any unimplemented rule
type is rejected fail-closed BEFORE mutation.

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
1. validate detectionRule (type ∈ {WINGET_PACKAGE, REGISTRY_UNINSTALL} +
   type-specific fields — mirrors backend validator)
   else FAILED_UNSUPPORTED_DETECTION_RULE (no mutation)

2. validate argsPolicyPreset ∈ {DEFAULT, VENDOR_RECOMMENDED_WINGET_NO_UPGRADE}
   else FAILED_UNSUPPORTED_ARGS_POLICY (no mutation)

3. locator() locates winget.exe
   else FAILED_UNSUPPORTED_PLATFORM (no mutation)

4. egressVerify() re-runs AG-026A SourceEgressPreflight
   if !ready → FAILED_EGRESS (no mutation)

5. pre-detect via detection probe (reliability-keyed — see §11.3b/§11.3c)
   • present + versionPredicate satisfied → SUCCEEDED_NOOP
   • present + versionPredicate fails    → FAILED_PREEXISTING_VERSION_CONFLICT
                                            (no silent upgrade)
   • not present                          → proceed
   • AUTHORITATIVE detector probe error  → FAIL-CLOSED before install
     (REGISTRY_UNINSTALL); CONFIRM_ONLY (winget) probe error → proceed

6. run winget install (30-min hard cap; timeout → process-tree kill via
   `taskkill /F /T /PID` fallback; killStrategy field carries audit
   evidence)

6a. the winget install exit code is the AUTHORITY for installed-state
    (winget list is unreliable under Session-0 — see §11.3b); base status:
   • 0                                    → SUCCEEDED (reboot flag → REBOOT_REQUIRED)
   • 3010                                 → SUCCEEDED_REBOOT_REQUIRED
   • 0x8A150061 (already installed /      → SUCCEEDED_NOOP
     no applicable upgrade)
   • any other non-zero                   → FAILED_INSTALL (winget_exit_<n>)
   exitCode is retained on the result for audit.

7. post-verify is RELIABILITY-KEYED (see §11.3b/§11.3c):
   • positive + versionPredicate ok    → keep base status; attach matched version
   • positive + version mismatch       → FAILED_VERIFICATION
                                          (post_verify_version_predicate_failed)
   • miss / error (CONFIRM_ONLY, winget) → postVerification.status=INCONCLUSIVE;
                                          keep base status for LATEST/no predicate;
                                          versioned + no proof → FAILED_VERIFICATION
                                          (post_verify_inconclusive_version_required)
   • miss / error (AUTHORITATIVE, registry) → FAILED_VERIFICATION, status=NOT_SATISFIED
                                          (post_verify_not_satisfied / _probe_error /
                                          detection_rule_ambiguous_match)
```

### 11.3b Install-state authority vs detection probe (AG-027)

**winget is an install provider, not a reliable inventory provider under
Session-0.** LIVE evidence (7-Zip first-install pilot, HALILKOOLUB735)
proved that under the **SYSTEM Session-0 service context** `winget list`
cannot reliably enumerate installed packages — it returns a clean
no-match even when the package IS installed — independent of `--source`
(both the source-scoped and no-source ARP attempts miss). `winget
install`, by contrast, reports installed-state reliably (e.g. exit
`0x8A150061` "already installed"). Therefore `winget list` MUST NOT be the
verification authority; the winget INSTALL exit code is.

**Authority model (step 6a).** The install exit code decides the base
status: `0` → SUCCEEDED, `3010` → SUCCEEDED_REBOOT_REQUIRED, `0x8A150061`
(UPDATE_NOT_APPLICABLE) → SUCCEEDED_NOOP, any other non-zero →
FAILED_INSTALL. `exitCode` is retained on the result for audit. The
signed/unsigned HRESULT representations of `0x8A150061` (2316632161 /
-1978335135) are normalized via `uint32()`.

**The detection probe (`ProbeViaWingetList`)** is shared by pre-detect and
post-verify and answers "is `<packageId>` installed?" with two attempts:
1. **Source-scoped (preferred):** `winget list --id <pkg> --exact --source
   winget ...` → `detectionMethod = winget_list_source`.
2. **No-source fallback (on a MISS):** drops `--source winget` (ARP query)
   → `detectionMethod = winget_list_no_source_fallback`. Helps
   non-Session-0 contexts where only the source correlation fails; under
   Session-0 both attempts miss (handled by the authority model, not by
   failing). A "miss" is a non-zero winget exit OR a clean exit parsed
   not-satisfied; a hard failure (launch failure / timeout) bubbles up.
   Both attempts require an **exact package-id match** (no fuzzy
   display-name): a positive result is PRESENCE / identity evidence, not
   source-provenance evidence. Source trust stays in the INSTALL path
   (step 6 keeps `--source winget`).

**Pre-detect — best-effort optimization.** A positive pre-detect
short-circuits (predicate ok → SUCCEEDED_NOOP; predicate mismatch →
FAILED_PREEXISTING_VERSION_CONFLICT). A miss OR a probe error is NOT fatal
— the install path is idempotent (`--no-upgrade`), so we proceed.

**Post-verify — confirm-only.** It upgrades evidence but never downgrades
a clean install exit on a winget-list miss:
- **Positive** (Satisfied): reliable. Attach the matched version; a
  positive version-predicate mismatch is an authoritative contradiction →
  FAILED_VERIFICATION / `post_verify_version_predicate_failed`.
- **Miss / error / timeout**: INCONCLUSIVE. `winget list` could neither
  confirm nor deny. The base install-exit status stands; the caveat is
  carried on `postVerification.status = INCONCLUSIVE` +
  `reasonCode = winget_list_session0_enumeration_unreliable` — never as a
  `failedReasonCode` on a SUCCEEDED result. EXCEPTION: a versioned
  predicate (EXACT/MINIMUM/RANGE) needs a concrete installed version to
  verify; with no version evidence it fails closed (strict v1) →
  FAILED_VERIFICATION / `post_verify_inconclusive_version_required`.

`detectionMethod` (and `status`/`reasonCode` on post-verify) are recorded
for audit / debug.

**Durable Session-0 detection:** `REGISTRY_UNINSTALL` (§11.3c) is the
AUTHORITATIVE, Session-0-reliable detector for ARP/registry-shaped state;
`FILE_EXISTS` / `FILE_SHA256` / `FILE_VERSION` (§11.3d, Path C1 — Codex
019e893a) are AUTHORITATIVE, Session-0-reliable detectors for binary-on-disk
state. The agent re-validates every rule fail-closed before any IO,
mirroring the backend `DetectionRuleValidator`. A winget package id alone
is NOT a reliable installed-state detector under Session-0 (CONFIRM_ONLY).

### 11.3c REGISTRY_UNINSTALL — authoritative Session-0 detection (AG-detect)

`winget list` is unreliable under Session-0 (§11.3b), so WINGET_PACKAGE
detection is CONFIRM_ONLY. The **ARP (Add/Remove Programs) registry** IS
readable under SYSTEM Session-0, so a `REGISTRY_UNINSTALL` rule is an
**AUTHORITATIVE** detector: a post-verify miss IS a real denial.

**Rule fields** (additive; the agent re-validates fail-closed, mirroring
the backend `DetectionRuleValidator`):
- `productCode` — MSI `{GUID}`. Primary, precise: a case-insensitive ARP
  subkey-name match. When present, name/publisher are ignored.
- else **DisplayName fallback**: `displayName` + `displayNameMatch`
  (`EXACT|PREFIX|CONTAINS|GLOB`) + `publisher` + `publisherMatch`
  (`EXACT|CONTAINS`). Matching is case-insensitive; GLOB honours only `*`
  and `?` (NO regex). `publisher` is REQUIRED for the fallback unless
  `allowPublisherMissing` is set with an `EXACT` `displayName` (avoids
  "7-Zip"/"Zoom"/"Teams" false positives).

**Matching**: both `HKLM\…\Uninstall` and `HKLM\WOW6432Node\…\Uninstall`
are enumerated (machine scope; HKCU is out of scope for SYSTEM). Entries
without a `DisplayName` are skipped; raw `UninstallString` is never read.
32/64-bit duplicates of the same `(DisplayName, Publisher, DisplayVersion)`
dedupe to one. **Multiple DISTINCT matches → ambiguous** (never a silent
first-match): pre-detect → `detection_rule_ambiguous_match` fail-close;
post-verify → `FAILED_VERIFICATION`. `matchedVersion` = `DisplayVersion`.

**Reliability-keyed authority** (`postVerification.authority`):
| ruleType | authority | pre-detect probe error | post-verify miss/error |
|---|---|---|---|
| `WINGET_PACKAGE` | `CONFIRM_ONLY` | proceed (best-effort) | `INCONCLUSIVE`, keep base exit (§11.3b) |
| `REGISTRY_UNINSTALL` | `AUTHORITATIVE` | **fail-closed BEFORE install** | `FAILED_VERIFICATION` (`post_verify_not_satisfied` / `…_probe_error` / `detection_rule_ambiguous_match`) |

A positive probe is `SATISFIED` for both; a positive version-predicate
mismatch downgrades for both. `detectionMethod=registry_uninstall`.

**Security**: read-only native registry API (no shell); strings
trimmed/control-stripped/length-capped before the wire; enumeration capped;
the package-id↔install-target identity check applies only to
`WINGET_PACKAGE`.

**Follow-ups**: bounded post-verify retry (absorb installers that write ARP
slightly after exit). `FILE_*` rule types LANDED in §11.3d (Path C1,
Codex 019e893a).

### 11.3d FILE_EXISTS / FILE_SHA256 / FILE_VERSION (Path C1, AG-detect)

Three additional AUTHORITATIVE Session-0 detectors for binary-on-disk
state, shipped via Path C1 (Codex 019e893a AGREE Opsiyon C). All three
read the device filesystem under LocalSystem (reliable in Session-0,
no UAC interception, no per-user view), so a post-verify miss IS a
real denial.

**Shared rule fields** (validated fail-closed BEFORE any IO):

- `path` — absolute Windows path of the form `<DRIVE>:\...`. Path-safety
  guards reject **every** documented injection vector:
  - relative segments (`.`, `..`, embedded or at-start)
  - env-var expansion (`%FOO%`, `$env:FOO`)
  - Windows device namespaces (`\\?\`, `\\.\`)
  - UNC paths (`\\server\share\...`)
  - paths without a drive letter
  - NUL byte or any control character
- The agent never writes the file (read-only IO).

**Rule type-specific fields**:

- `FILE_EXISTS` — `path` only. Satisfied=true when the path resolves to
  an existing regular file. A path resolving to a directory is operator
  authoring error (fail-loud, not denial).
- `FILE_SHA256` — `path` + `expectedSha256` (lowercase hex, exactly 64
  chars). Streams the file through SHA-256 with a hard size cap
  (`maxHashBytes` per-rule override, default `FileMaxHashBytes` =
  512 MiB) and a 30-second deadline. A file larger than the cap or a
  digest mismatch yields Satisfied=false. The cap protects the agent
  from being wedged on attacker-controlled multi-GB files.
- `FILE_VERSION` — `path` + `versionPredicate` (`EXACT` /
  `MINIMUM` / `RANGE` / `LATEST`, same semantics as WinGet post-verify)
  + optional `fileVersionField` (`FILE_VERSION` default, or
  `PRODUCT_VERSION` for installers that intentionally keep
  FileVersion lagging). Reads PE VersionInfo via Win32 API
  (`GetFileVersionInfoW` + `VerQueryValueW`) — NOT via PowerShell
  shell-out, to avoid (a) SYSTEM-context PowerShell launch fragility,
  (b) audit smell from leaking the path into a child command line, and
  (c) shell-parser exposure. Non-Windows platforms return
  `FAILED_UNSUPPORTED_PLATFORM` (mirrors the AG-027 install_winget
  cross-platform stub pattern).

**Audit method label**: `file_exists` / `file_sha256` / `file_version`
on `PreDetectResult.DetectionMethod` and `PostVerificationResult.DetectionMethod`.

**HARD RULE No Fake Work**: every detector returns a deterministic
Satisfied bool + DetectionMethod + an error path that maps to the
canonical AG-027 failure-final-statuses. There is no silent
"satisfied=false because we don't know" branch — unknown errors
surface explicitly so the executor maps them to
`FAILED_INTERNAL` (not `FAILED_VERIFICATION` which would
mis-attribute the cause).

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
- ~~**Detection rules beyond `WINGET_PACKAGE`**~~ — LANDED.
  `REGISTRY_UNINSTALL` (§11.3c), `FILE_EXISTS` / `FILE_SHA256` /
  `FILE_VERSION` (§11.3d, Path C1, Codex 019e893a) are all
  AUTHORITATIVE Session-0 detectors. The fail-closed v1 boundary now
  applies only to **unknown** rule types. Remaining FILE_*
  follow-ups: Windows-tag PE fixture tests (RT-AG-027-F2), translation
  block fallback hardening for vendor binaries that use uncommon
  codepages (RT-AG-027-F3).
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

## 16. AG-037 — Windows Update / Hotfix Posture (Faz 22.5 quick-wins)

### 16.1 Scope

Read-only probe surfacing installed hotfix history + pending update
queue counts + Windows Update agent health for a fleet-wide patch
posture view. The probe NEVER triggers a `wuauclt /detectnow`,
`Install-WindowsUpdate`, `sconfig` reboot, service start/stop/enable/
disable, or any policy mutation. Authoritative source is WUA COM
(`Microsoft.Update.Session.CreateUpdateSearcher`) with `Get-HotFix`
as a deliberately narrow installed-only fallback when WUA's
QueryHistory returns empty.

Backend uses this via `COLLECT_INVENTORY{includeHotfixPosture:true}`
when a patch posture evaluation is being prepared (the AG-025H
lightweight default never opts in, so heartbeat / auto-enroll
remain cheap).

### 16.2 Payload opt-in

```jsonc
{
  "type": "COLLECT_INVENTORY",
  "payload": {
    "includeHotfixPosture": true
  }
}
```

`includeHotfixPosture` is `bool`, default `false`. Default
`COLLECT_INVENTORY` payload does NOT include hotfix posture data; the
caller must explicitly request the probe.

### 16.3 Result wire shape (`details.inventory.hotfixPosture`)

Allowlist projection. Adding a field is a contract bump.

```jsonc
{
  "schemaVersion": 1,
  "supported": true,
  "probeComplete": true,
  "collectedAt": "2026-06-01T12:34:56Z",
  "probeDurationMs": 410,
  "installedSourceUsed": "wua",
  "installedHotfixes": [
    {
      "kbId": "KB5034122",
      "installedOn": "2026-01-15T00:00:00Z",
      "description": "Security Update for Microsoft Windows"
    }
  ],
  "installedCount": 1,
  "installedTruncated": false,
  "pendingSourceUsed": "wua",
  "pendingUpdates": [
    {
      "kbIds": ["KB5036899"],
      "primaryCategory": "SECURITY",
      "severity": "CRITICAL"
    }
  ],
  "pendingByCategory": [
    { "category": "SECURITY", "count": 1 }
  ],
  "pendingTotalCount": 1,
  "pendingTruncated": false,
  "healthSourceUsed": "service",
  "agentHealth": {
    "wuaServiceState": "RUNNING",
    "bitsServiceState": "RUNNING",
    "lastDetectAt": "2026-05-31T08:00:00Z",
    "lastInstallAt": "2026-05-30T22:00:00Z",
    "autoUpdatePolicyEnabled": true,
    "autoUpdateEffectiveEnabled": true,
    "notificationLevel": "4"
  },
  "probeErrors": []
}
```

### 16.4 Hard boundaries

- **Read-only.** No `Install-WindowsUpdate`, no `wuauclt /detectnow`,
  no service mutation, no policy write.
- **Pinned PowerShell + WUA COM.** Primary authority. Native Go COM
  / `go-ole` is intentionally NOT used (binding complexity is too
  high for the v1 surface).
- **`Get-HotFix` fallback is installed-only.** It does NOT include
  `Install-Module`, MSI-installed patches, or AppX — never use it as
  a pending-update substitute. When WUA Search fails, pending
  updates surface as `pendingSourceUsed="none"` + a typed probe
  error; do NOT silently report `pendingTotalCount=0`.
- **Service-state is a typed enum** (`RUNNING|STOPPED|DISABLED|
  UNKNOWN`). A `*bool` would conflate Stopped vs Disabled and erase
  the operator action ("re-enable service" vs "start service").
- **Caps.** `MaxInstalledHotfixes=512`; `MaxPendingUpdates=20`. Pre-
  truncation counts are surfaced (`installedCount`,
  `pendingTotalCount`); category rollup (`pendingByCategory`) is
  surfaced even when the per-item list is capped so the operator
  sees the full distribution.
- **Allowlist projection.** Per-hotfix exactly
  `{kbId, installedOn, description}`. Per-pending-item exactly
  `{kbIds, primaryCategory, severity}` — v1 deliberately does NOT
  ship the raw update Title (operator-visible noise + leak vector).

### 16.5 Wire field type contract

- `installedOn` is `*time.Time` (RFC-3339 UTC) — `null` allowed when
  the source did not provide a parseable date.
- `kbIds` is `[]string` (empty array permitted when WUA reports no
  `KBArticleIDs`).
- `primaryCategory` is one of `SECURITY|DEFINITION|CRITICAL|
  IMPORTANT|DRIVER|UPDATE_ROLLUP|FEATURE_PACK|SERVICE_PACK|OPTIONAL|
  TOOLS|UNCATEGORIZED`. Multi-category updates are reduced via
  deterministic precedence (security > definition > critical >
  important > driver > rollup > feature pack > service pack >
  optional > tools > uncategorized).
- `severity` is one of `CRITICAL|IMPORTANT|MODERATE|LOW|UNSPECIFIED`
  (MSRC ratings; `UNSPECIFIED` for non-security updates).
- `wuaServiceState` and `bitsServiceState` are
  `RUNNING|STOPPED|DISABLED|UNKNOWN`.
- `autoUpdatePolicyEnabled`/`autoUpdateEffectiveEnabled` are `*bool`
  — `null` allowed when the registry path is unreadable.
- `notificationLevel` mirrors the `AUOptions` registry value
  (`1`/`2`/`3`/`4`); empty string when registry absent.

### 16.6 Probe error codes

```
UNSUPPORTED_PLATFORM     non-Windows runtime stub
ACCESS_DENIED            elevation / token missing
COM_FAILED               Microsoft.Update.Session.* failed
WSUS_UNREACHABLE         remote WSUS server unreachable
POWERSHELL_MISSING       powershell.exe not in PATH
POWERSHELL_TIMEOUT       script exceeded 45s budget
POWERSHELL_FAILED        non-zero exit / unexpected stderr
POWERSHELL_EMPTY_OUTPUT  empty stdout (would mask "no data" as success)
POWERSHELL_PARSE_ERROR   JSON unmarshal failed
REGISTRY_UNAVAILABLE     WU registry keys absent
SERVICE_QUERY_FAILED     SCM Get-Service failed
NO_EVIDENCE              fallback path could not produce a snapshot
```

A `probeErrors[]` entry flips `probeComplete=false`. Partial paths
(e.g. installed via Get-HotFix fallback while pending fails on COM)
still surface what they could collect — the operator can render
"evidence incomplete; installed-fallback OK; pending unknown".

### 16.7 Source attribution (`sourceUsed`)

Each section attributes the authoritative source it actually queried:

- `installedSourceUsed`: `wua` (QueryHistory primary) | `getHotfix`
  (PowerShell fallback) | `none` (probe failed before any source).
- `pendingSourceUsed`: `wua` (Search; no fallback) | `none`.
- `healthSourceUsed`: composite — typically `service` (SCM) +
  `registry` (timestamps + AU policy); the dominant authority is
  reported.

A `getHotfix` installed list with a `none` pending list is a normal
fail-closed shape that the operator can act on.

### 16.8 Known v1 exclusions

- **Product code / MSI GUID / supersedence chain**: never on wire.
- **Account name / `InstalledBy` / install client app ID**: never
  on wire.
- **Raw update Title in pending items**: deliberately omitted in v1
  (the `kbIds` correlation handle plus `primaryCategory`+`severity`
  classification is enough for posture rendering).
- **Driver-only hotfixes**: included if the category resolves to
  `DRIVER`; AG-037 does NOT filter them out.
- **Hot-patch (Hotpatch) update support**: out of scope; tracked
  separately.
- **Last reboot for update / pending reboot for update**:
  cross-references with AG-030 pending-reboot; not duplicated here.
- **CVE enrichment**: out of scope — backend MAY join `kbId` against
  a CVE database; the agent does NOT ship CVE metadata.

### 16.9 Backend ingest path (separate slice)

This contract describes the AGENT side. The backend ingest path is
a separate slice (V22 migration adding `endpoint_hotfix_posture_*`
tables + `AdminEndpointHotfixPostureController` GET endpoints) that
will be tracked under its own PR; the agent block above is the
exact wire shape the backend will need to deserialize.


## 20. AG-041 — Application Control / WDAC + AppLocker Policy State (Faz 22.5 Sprint C)

### 20.1 Scope

Read-only Application-Control posture probe. Reports two orthogonal facets:

- **WDAC** (Windows Defender Application Control / kernel-mode)
  — operational mode + bounded capability evidence + active CIP policy
  count + legacy SIPolicy presence + multi-policy mode bit.
- **AppLocker** (user-mode SrpV2 policy enforcement)
  — per-rule-collection enforcement mode (Exe / Dll / Script / Msi / Appx)
  + AppIDSvc state + startup mode + presence.

Numbering disambiguation: AG-040 = startup-apps + exposure summary
(NOT Application Control). Codex `019e83a6` iter-1 P0 #1 absorb: V25
+ AG-040 lane already taken by startup-exposure work; Application
Control is AG-041 + V26 (backend migration).

### 20.2 HARD BOUNDARY (do NOT widen)

- NO PowerShell (`gpresult`, `Get-AppLockerPolicy`, etc.)
- NO WMI/CIM (`Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard`)
- NO event log query (audit-log content is operator-policy data)
- NO process / executable enumeration
- NO policy file contents (XML / CIP)
- NO policy file names / IDs / GUIDs / hashes
- NO AppLocker rule lists / rule counts (single enforcement enum per collection)
- NO publisher / signer thumbprint enumeration
- NO full registry export — bounded to specific allowlisted keys + values
- NO arbitrary filesystem scan — bounded to `CIPolicies\Active\*.cip` count + `SIPolicy.p7b` stat

Source-of-truth scalars: registry under `HKLM\SYSTEM\CurrentControlSet\Control\CI`,
`HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\<collection>\EnforcementMode`,
SCM `AppIDSvc` query (same pattern as AG-039), and bounded filesystem
metadata at `C:\Windows\System32\CodeIntegrity\`.

### 20.3 WDAC Mode Derivation (Conservative — Codex 019e83ce iter-1 P0 #2)

```
OFF      ← Queryable=true AND no DecisionCriticalReadFailed AND
            ExplicitAudit!=true AND ExplicitEnforce!=true AND
            ActiveCipPolicyCount=0 AND LegacySipolicyPresent=false

AUDIT    ← Queryable=true AND ExplicitAudit=true (explicit safe scalar)

ENFORCE  ← Queryable=true AND ExplicitEnforce=true (highest priority;
            safety-prioritised when both explicit somehow read true)

UNKNOWN  ← all other cases (the DOMINANT return — capability evidence
            like boot enforcement / multi-policy mode bits / driver
            blocklist are NEVER used to infer AUDIT/ENFORCE)
```

v1 implementation MAY leave `ExplicitAudit` / `ExplicitEnforce` at nil
and emit UNKNOWN dominant. Future iter that identifies a confirmed,
version-defensible canonical registry scalar can land the explicit
detection without contract changes.

### 20.4 AppLocker per-collection mapping (Strict — Codex iter-1 P1 #5)

For each collection `<C>` in {Exe, Dll, Script, Msi, Appx} at
`HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\<C>\EnforcementMode`:

| Registry state | Wire enum |
|---|---|
| Key/value missing OR DWORD 0 | `NOT_CONFIGURED` |
| DWORD 1 | `AUDIT_ONLY` |
| DWORD 2 | `ENFORCE` |
| Non-DWORD type OR DWORD other | `UNKNOWN` + `APPLOCKER_KEY_UNREADABLE` probe error (source=`appLocker`) |
| Permission denied | `UNKNOWN` + `REGISTRY_DENIED` probe error (source=`appLocker`) |

`AppIDSvc` (the AppLocker enforcement service) is reported redundantly
in this probe via SCM `OpenSCManagerW` + `OpenServiceW` (no PowerShell)
because the AG-039 6-service allowlist intentionally excludes it. Reuses
shared `ServiceState` + `StartupMode` enums from AG-039.

### 20.5 Wire shape v1

```json
{
  "schemaVersion": 1,
  "supported": true,
  "probeComplete": true,
  "wdacQueryable": true,
  "appLockerQueryable": true,
  "wdacMode": "UNKNOWN",
  "wdacBootEnforcementPresent": true,
  "wdacActiveCipPolicyCount": 0,
  "wdacLegacySipolicyPresent": false,
  "wdacMultiPolicyMode": true,
  "appLockerExeRule": "NOT_CONFIGURED",
  "appLockerDllRule": "NOT_CONFIGURED",
  "appLockerScriptRule": "NOT_CONFIGURED",
  "appLockerMsiRule": "NOT_CONFIGURED",
  "appLockerAppxRule": "NOT_CONFIGURED",
  "appLockerAppIdSvcState": "STOPPED",
  "appLockerAppIdSvcStartup": "MANUAL",
  "appLockerAppIdSvcPresent": true,
  "probeDurationMs": 47,
  "probeErrors": []
}
```

Wire key STABILITY (Codex iter-2 #2 absorb): pointer evidence fields
(`wdacBootEnforcementPresent`, `wdacActiveCipPolicyCount`,
`wdacLegacySipolicyPresent`, `wdacMultiPolicyMode`,
`appLockerAppIdSvcPresent`) drop `omitempty` so the keys appear with
explicit JSON `null` when evidence is unknown. `probeErrors` is
initialized to `[]` (empty slice) rather than `null` for the same
stability contract.

### 20.6 ProbeErrors

Bounded enum + bounded summary. Each entry:

```json
{
  "code": "APPLOCKER_KEY_UNREADABLE",
  "source": "appLocker",
  "summary": "Exe: permission denied"
}
```

**Codes** (allowlisted):
- `NO_EVIDENCE` — overall probe failed (non-Windows runtime, or all reads denied)
- `REGISTRY_DENIED` — registry key permission denied
- `FILESYSTEM_DENIED` — filesystem metadata read denied (CIPolicies dir / SIPolicy stat)
- `CIP_POLICIES_DIR_UNREADABLE` — `CIPolicies\Active` enumeration failed
- `APPLOCKER_KEY_UNREADABLE` — SrpV2 collection EnforcementMode read failed
- `APP_ID_SVC_QUERY_FAILED` — SCM query for AppIDSvc failed
- `WDAC_SCALAR_UNREADABLE` — DeviceGuard / CI scalar read failed
- `PROBE_ERRORS_TRUNCATED` — final sentinel emitted when MaxAppControlProbeErrors=16 cap is hit (so consumers KNOW data was dropped rather than silently inferring "no errors")

**Source** enum (Codex iter-1 P1 #4): `wdac | appLocker | filesystem`.

**Summary** ≤200 chars, CRLF-stripped.

### 20.7 Operator trigger

Payload bit: `includeAppControl: true`.

```
COLLECT_INVENTORY
  payload:
    includeAppControl: true
```

The agent executor reads via `boolPayload(command.Payload, "includeAppControl")`.
The web `IslemlerTab` default COLLECT_INVENTORY payload should add this bit
in the web PR (the agent PR doesn't touch it — agent-first land contract).

### 20.8 Backend ingest path (separate PR — V26 migration)

This contract describes the AGENT side. The backend ingest path is a
separate slice (V26 migration adding `endpoint_app_control_snapshots` +
`endpoint_app_control_probe_errors` tables + `AdminEndpointAppControlController`
GET endpoint) that will be tracked under its own PR; the agent block above
is the exact wire shape the backend will need to deserialize.

