# platform-agent

`platform-agent`, endpoint yonetim urununun Windows/macOS agent reposudur.

Ana platform yerlesimi:

```text
/Users/halilkocoglu/Documents/platform-backend
  endpoint-admin-service burada yer alacak.

/Users/halilkocoglu/Documents/platform-web
  mfe-endpoint-admin burada yer alacak.

/Users/halilkocoglu/Documents/platform-agent
  Go tabanli endpoint agent burada yer alacak.
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
