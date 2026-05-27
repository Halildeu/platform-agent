# platform-agent

`platform-agent`, endpoint yonetim urununun Windows/macOS agent reposudur.

> **Visibility**: PRIVATE (pre-prod). Faz 22.3 stable + Authenticode signing + audit hash-chain + IT pilot live olduktan sonra public visibility kullanici karariyla yeniden degerlendirilir.
> **License**: Apache License 2.0 (bkz `LICENSE`).
> **Status**: Faz 22.1 Lab tier hazirligi. Detaylar `docs/TRACKING-ROADMAP.md`.

Ana platform yerlesimi (4-component, 4 repo — `Halildeu/platform-k8s-gitops` `docs/adr/0012-EA-endpoint-admin-governance-charter.md`):

```text
Halildeu/platform-backend         endpoint-admin-service/    (REST API, Go)
Halildeu/platform-web              apps/mfe-endpoint-admin/   (admin portal MFE)
Halildeu/platform-agent            (BU REPO — Windows/macOS agent, Go)
Halildeu/platform-k8s-gitops       kustomize/base/apps/endpoint-admin-service/  (manifest)
```

Lokal yerlesim:

```text
/Users/halilkocoglu/Documents/platform-backend
  endpoint-admin-service burada.

/Users/halilkocoglu/Documents/platform-web
  mfe-endpoint-admin burada.

/Users/halilkocoglu/Documents/platform-agent
  Go tabanli endpoint agent burada.

/Users/halilkocoglu/Documents/platform-k8s-gitops
  Runtime manifest + GitOps governance.
```

Ilk hedef Windows endpoint'lerdir. Tasarim macOS agent eklenebilecek sekilde
platform-neutral tutulur.

Detayli klasor yapisi:

- `docs/REPO-STRUCTURE.md`
- `docs/COMMAND-CONTRACT.md`
- `docs/SECURITY-MODEL.md`
- `docs/BACKEND-WEB-INTEGRATION.md`
- `docs/LOGGING.md`
- `docs/ROADMAP.md`
- `docs/TRACKING-ROADMAP.md`
- `docs/TESTING-STRATEGY.md`
- `docs/LOCAL-SETUP.md`

Temel kararlar:

- Agent dili: Go
- Ilk platform: Windows 10/11 x64
- Gelecek platform: macOS Intel/Apple Silicon
- Backend ile iletisim: outbound HTTPS polling
- Komut modeli: whitelist + capability
- Raw shell: kapali
- Inventory V2 adayi: osquery

Ilk kod iskeleti:

- command type ve capability DTO'lari
- command claim validation
- HMAC request signing helpers
- secret redaction helpers
- file path whitelist guardrail helpers
- offline/degraded state tracker
- enrollment, heartbeat, command polling ve result submit client'i
- mock backend ile MVP agent loop testi
- Windows service install/start/stop/status/uninstall wrapper
- file logger + Windows Event Log source + write-time secret redaction

Lokal calistirma:

```bash
export ENDPOINT_AGENT_API_URL=http://127.0.0.1:8080/api/v1/endpoint-agent
export ENDPOINT_AGENT_ENROLLMENT_TOKEN=<token>
go run ./cmd/endpoint-agent --once
```

Enrolled agent icin:

```bash
export ENDPOINT_AGENT_ID=<agent-id>
export ENDPOINT_AGENT_SECRET=<agent-secret>
export ENDPOINT_AGENT_INSTALL_ID=<install-id>
go run ./cmd/endpoint-agent --once
```

Lokal test ve build:

```bash
./scripts/test/local.sh
./scripts/build/local.sh
./scripts/build/windows-package.sh
```

Windows service komutlari:

```powershell
.\endpoint-agent.exe service install
.\endpoint-agent.exe service start
.\endpoint-agent.exe service status
.\endpoint-agent.exe service stop
.\endpoint-agent.exe service uninstall
```

Windows local user read-only diagnostik:

```powershell
.\endpoint-agent.exe diagnose local-users
```

Windows yazilim envanteri ve WinGet hazirligi diagnostik (AG-025/AG-026):

```powershell
.\endpoint-agent.exe diagnose software   # HKLM + WOW6432Node, sanitized
.\endpoint-agent.exe diagnose winget     # winget.exe path + version + systemContextReady
```

`diagnose software` yalnizca okur — install/uninstall/upgrade yok.
`diagnose winget` yalnizca `winget --version` cagirir; `install`,
`search`, `source` veya `upgrade` cagrilmaz.

## License

Bu proje Apache License 2.0 ile lisanslanmistir. Detaylar `LICENSE` dosyasinda.

## Bagli ADR / charter

- ADR-0012-EA Endpoint Admin Governance Charter:
  `Halildeu/platform-k8s-gitops` `docs/adr/0012-EA-endpoint-admin-governance-charter.md`
- 4-component, 4-repo yapi
- Faz 22.x sub-faz (22.1 Lab → 22.2 IT-owned acik.local → 22.3 Restricted)
- Code signing supply-chain RoT (build-time pipeline; runtime secret degil)
- Initial domain scope: acik.local only (BOREAS / CESS Faz 22 disi)

## Sorumluluklar (4-repo dagilimi)

| Component | Repo | Path |
|---|---|---|
| Backend REST | `Halildeu/platform-backend` | `endpoint-admin-service/` |
| Agent (BU) | `Halildeu/platform-agent` | repo root |
| Admin portal MFE | `Halildeu/platform-web` | `apps/mfe-endpoint-admin/` |
| GitOps manifest | `Halildeu/platform-k8s-gitops` | `kustomize/base/apps/endpoint-admin-service/` |

## Naming convention

- **Repo**: `platform-agent` (genis; ileride macOS/Linux genisleme icin)
- **Binary**: `endpoint-agent.exe` (Windows), `endpoint-agent` (macOS)
- **Windows service**: `EndpointAgent` veya `PlatformEndpointAgent`
