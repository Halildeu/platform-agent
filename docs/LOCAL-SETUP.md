# Local Setup

Bu belge `platform-agent` icin lokal gelistirme ve dogrulama adimlarini
tanimlar.

-------------------------------------------------------------------------------
## 1. Toolchain
-------------------------------------------------------------------------------

Gerekli minimum araclar:

```text
Go 1.25+
gofmt
go vet
```

Bu makinede Go Homebrew ile kurulmustur:

```bash
brew install go
```

Kurulum kontrolu:

```bash
go version
gofmt -h
```

-------------------------------------------------------------------------------
## 2. Test
-------------------------------------------------------------------------------

Tek komut:

```bash
./scripts/test/local.sh
```

Manuel komutlar:

```bash
gofmt -w ./cmd ./internal
go test ./...
go vet ./...
```

-------------------------------------------------------------------------------
## 3. Build
-------------------------------------------------------------------------------

Tek komut:

```bash
./scripts/build/local.sh
```

Binary:

```text
bin/endpoint-agent
```

Versiyon kontrolu:

```bash
./bin/endpoint-agent --version
```

-------------------------------------------------------------------------------
## 4. Lokal Agent Calistirma
-------------------------------------------------------------------------------

Backend endpoint hazir degilse agent loop calistirilmaz. Mock backend testleri
`go test ./...` icinde vardir.

Gercek backend veya gateway hazir oldugunda:

```bash
export ENDPOINT_AGENT_API_URL=http://127.0.0.1:8080/api/v1/endpoint-agent
export ENDPOINT_AGENT_ENROLLMENT_TOKEN=<token>
./bin/endpoint-agent --once
```

Enrolled agent icin:

```bash
export ENDPOINT_AGENT_API_URL=http://127.0.0.1:8080/api/v1/endpoint-agent
export ENDPOINT_AGENT_ID=<agent-id>
export ENDPOINT_AGENT_SECRET=<agent-secret>
export ENDPOINT_AGENT_INSTALL_ID=<install-id>
./bin/endpoint-agent --once
```

-------------------------------------------------------------------------------
## 5. Windows Build
-------------------------------------------------------------------------------

macOS uzerinden Windows binary uretmek icin:

```bash
./scripts/build/windows.sh
```

Windows service wrapper fazi ayrica tasarlanacaktir. Bu MVP binary simdilik
Windows Service Control Manager ile install/start/stop/status/uninstall
komutlarini destekler. Canli SCM dogrulamasi icin Windows pilot makine gerekir.

Windows service komutlari:

```powershell
.\endpoint-agent.exe service install
.\endpoint-agent.exe service start
.\endpoint-agent.exe service status
.\endpoint-agent.exe service stop
.\endpoint-agent.exe service uninstall
```

Windows paket klasoru:

```bash
./scripts/build/windows-package.sh
```

Detayli Windows notlari:

```text
installers/windows/README.md
```
