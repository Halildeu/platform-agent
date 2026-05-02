# Platform Agent Repo Structure

Bu belge `platform-agent` reposunun ana klasor yapisini ve her klasorun
sorumlulugunu tanimlar.

-------------------------------------------------------------------------------
## 1. Ust Seviye Repo Haritasi
-------------------------------------------------------------------------------

Agent projesi uc ayri repo modelinin agent ayagidir:

```text
/Users/halilkocoglu/Documents/platform-backend
  Backend servisleri.
  Yeni servis: endpoint-admin-service

/Users/halilkocoglu/Documents/platform-web
  Frontend/MFE uygulamalari.
  Yeni MFE: mfe-endpoint-admin

/Users/halilkocoglu/Documents/platform-agent
  Go endpoint agent.
  Windows service ve macOS launchd daemon olarak calisir.
```

Bu repo backend veya web kodu tasimaz. Yalniz agent runtime, installer,
platform adapter ve agent dokumanlarini tasir.

-------------------------------------------------------------------------------
## 2. Agent Repo Ana Klasorleri
-------------------------------------------------------------------------------

Hedef klasor yapisi:

```text
platform-agent/
  cmd/
    endpoint-agent/
      main.go

  internal/
    app/
    config/
    logging/
    protocol/
    enrollment/
    heartbeat/
    commands/
    inventory/
    users/
    files/
    security/
    state/
    updates/
    platform/
      windows/
      macos/
    collectors/
      basic/
      osquery/

  installers/
    windows/
    macos/

  deployments/
    gpo/
    intune/
    sccm/
    jamf/

  docs/
    REPO-STRUCTURE.md
    COMMAND-CONTRACT.md
    SECURITY-MODEL.md
    BACKEND-WEB-INTEGRATION.md
    LOGGING.md
    ROADMAP.md
    TRACKING-ROADMAP.md
    TESTING-STRATEGY.md
    LOCAL-SETUP.md

  scripts/
    dev/
    build/
    test/
```

-------------------------------------------------------------------------------
## 3. Klasor Sorumluluklari
-------------------------------------------------------------------------------

| Klasor | Sorumluluk |
|---|---|
| `cmd/endpoint-agent` | Agent binary entrypoint. |
| `internal/app` | Agent lifecycle, scheduler, graceful shutdown. |
| `internal/config` | Config load, env/file/default merge. |
| `internal/logging` | Structured log, redaction, log rotation hook. |
| `internal/protocol` | Backend API DTO'lari ve HTTP client contract. |
| `internal/enrollment` | Ilk kayit, enrollment token exchange, agent identity. |
| `internal/heartbeat` | Online/offline sinyali, jitter/backoff. |
| `internal/commands` | Command polling, validation, dispatch, result sender. |
| `internal/inventory` | OS-neutral inventory domain modeli. |
| `internal/users` | OS-neutral local user domain modeli. |
| `internal/files` | Path whitelist, home/Desktop/Documents resolver. |
| `internal/security` | Token store, HMAC signing, payload validation, no-secret log guard. |
| `internal/state` | Agent online/offline/degraded state machine. |
| `internal/updates` | Version check, update manifest parsing, later auto-update flow. |
| `internal/platform/windows` | Windows executor: service, PowerShell wrapper, local users. |
| `internal/platform/macos` | macOS executor: launchd, system_profiler, dscl, paths. |
| `internal/collectors/basic` | Built-in lightweight inventory collector. |
| `internal/collectors/osquery` | V2 osquery integration adapter. |
| `installers/windows` | Windows service install/uninstall, MSI/PowerShell assets. |
| `installers/macos` | launchd plist, pkg/install.sh assets. |
| `deployments/gpo` | GPO startup script examples and rollout notes. |
| `deployments/intune` | Intune Win32 packaging notes. |
| `deployments/sccm` | SCCM/MECM deployment notes. |
| `deployments/jamf` | macOS Jamf/MDM packaging notes. |
| `scripts` | Local build/test helpers. |

-------------------------------------------------------------------------------
## 4. Platform Ilkeleri
-------------------------------------------------------------------------------

Komut isimleri OS'e gomulu olmaz:

```text
Dogru: DISABLE_LOCAL_USER
Yanlis: DISABLE_WINDOWS_USER
```

Path modeli OS'e gore agent adapter tarafinda cozulur:

```text
Windows: C:\Users\{username}\Desktop
macOS:   /Users/{username}/Desktop
```

Backend yalniz capability gorur:

```text
WINDOWS agent -> RESET_LOCAL_USER_PASSWORD destekleyebilir
MACOS agent   -> ilk fazda UNSUPPORTED donebilir
```

Linux:

```text
MVP kapsaminda degil.
Klasor yapisi ileride `internal/platform/linux` eklenebilecek sekilde
tasarlanir; bugun Windows-first ve macOS-ready ilerlenir.
```

-------------------------------------------------------------------------------
## 5. Ilk Kod Fazinda Olusturulacak Minimum Paketler
-------------------------------------------------------------------------------

Ilk Go POC icin:

```text
cmd/endpoint-agent/main.go
internal/config
internal/protocol
internal/enrollment
internal/heartbeat
internal/commands
internal/state
internal/security
internal/platform/windows
```

Ilk POC komutlari:

```text
COLLECT_INVENTORY
LIST_LOCAL_USERS
GET_LOGGED_IN_USER
GET_USER_HOME_PATHS
DISABLE_LOCAL_USER
ENABLE_LOCAL_USER
```

Password reset POC'a eklenmeden once log redaction ve payload validation
tamamlanir.

-------------------------------------------------------------------------------
## 6. Backend/Web Baglantisi
-------------------------------------------------------------------------------

Backend repo:

```text
/Users/halilkocoglu/Documents/platform-backend/endpoint-admin-service
```

Backend API prefix:

```text
/api/v1/endpoint-agent
/api/v1/endpoint-admin
```

Web repo:

```text
/Users/halilkocoglu/Documents/platform-web/apps/mfe-endpoint-admin
```

Web route:

```text
/admin/endpoints
```

-------------------------------------------------------------------------------
## 7. Notlar
-------------------------------------------------------------------------------

- `platform-agent` icinde backend veya web artifact tutulmaz.
- AD/GPO/SCCM/Intune entegrasyonlari agent repo icinde yalniz deployment
  dokumani/script asset'i olarak yer alir; merkezi API `platform-backend`
  icindedir.
- macOS sayisi az olsa da klasor yapisi macOS adapter'i bastan tasir; bu,
  ileride backend/web rewrite riskini azaltir.
