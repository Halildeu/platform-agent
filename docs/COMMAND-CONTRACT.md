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
plan-time kilit sart):

```text
1. install / upgrade / uninstall / source add|remove|update|reset
   subcommand'lari HIC calistirilmaz; package fixed-argv `show` ve
   `source list` disinda winget yardimi cagrilamaz.
2. Package id `7zip.7zip` (FixedPackageQueryID) hard-coded; payload
   override edilemez (override denenirse readiness `probeError` ile
   reddedilir).
3. Egress hostname listesi (DefaultEgressTargets) hard-coded; payload
   ile arbitrary URL/host gonderilemez.
4. Approved catalog client / unauthorized software detection / install
   execution AG-026A scope'unda DEGIL — sirayla BE-020, BE-023/BE-025,
   AG-027 sorumlu.
5. Source argument (URL), source error reason, proxy URL ve egress
   error reason serbest metni `security.RedactSoftwareString` (proxy
   userinfo `url.User=nil` ile ek olarak strip edilir) ile sanitize
   edilir — user path, SID, JWT, license-shaped string, embedded
   credential payload'a raw girmez.
6. winget LocalSystem'da `source list` veya `show` icin fail dondurursa
   readiness `PASS/WARN/BLOCK` sinyali uretir; implementation failure
   degildir (`probeError` veya per-row `errorReason` ile rapor edilir,
   agent exit code degismez).
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
