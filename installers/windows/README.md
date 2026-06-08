# Windows Installer and Service Commands

Bu dosya `AG-012` Windows service wrapper ve `AG-015` Windows installer asset
icin manuel test komutlarini tanimlar.
Komutlar Windows uzerinde Administrator PowerShell ile calistirilir.

-------------------------------------------------------------------------------
## 1. Binary
-------------------------------------------------------------------------------

macOS uzerinden Windows binary:

```bash
./scripts/build/windows.sh
```

Windows paket klasoru:

```bash
./scripts/build/windows-package.sh
```

Paket ciktisi:

```text
dist/windows/EndpointAgent.zip
dist/windows/EndpointAgent/endpoint-agent.exe
dist/windows/EndpointAgent/bootstrap-package.ps1
dist/windows/EndpointAgent/install.ps1
dist/windows/EndpointAgent/uninstall.ps1
dist/windows/EndpointAgent/README.md
dist/windows/EndpointAgent/SHA256SUMS
```

Pilot ZIP artifact kurulumu — domain/mTLS auto-enroll:

```powershell
$PackageUrl = "https://testai.acik.com/artifacts/endpoint-agent/0.1.0-dev/EndpointAgent.zip"
$ExpectedZipSha256 = "<zip-sha256>"

iwr -UseBasicParsing `
  "https://testai.acik.com/artifacts/endpoint-agent/0.1.0-dev/bootstrap-package.ps1" `
  -OutFile "$env:TEMP\endpoint-agent-bootstrap.ps1"

powershell.exe -ExecutionPolicy Bypass -File "$env:TEMP\endpoint-agent-bootstrap.ps1" `
  -PackageUrl $PackageUrl `
  -ExpectedZipSha256 $ExpectedZipSha256 `
  -AutoEnroll `
  -AutoEnrollApiUrl "https://endpoint-agent-mtls.testai.acik.com/api/v1/endpoint-agent" `
  -AutoEnrollCertSANURIPrefix "adcomputer:" `
  -Start `
  -Force
```

Bu yol token istemez. Makinede AD CS / mTLS client certificate hazir degilse
servis auto-enroll modunda bekler ve HMAC token fallback'e sessiz dusmez.

Pilot ZIP artifact kurulumu — gecici HMAC token fallback:

```powershell
$PackageUrl = "https://testai.acik.com/artifacts/endpoint-agent/0.1.0-dev/EndpointAgent.zip"
$ExpectedZipSha256 = "<zip-sha256>"

iwr -UseBasicParsing `
  "https://testai.acik.com/artifacts/endpoint-agent/0.1.0-dev/bootstrap-package.ps1" `
  -OutFile "$env:TEMP\endpoint-agent-bootstrap.ps1"

powershell.exe -ExecutionPolicy Bypass -File "$env:TEMP\endpoint-agent-bootstrap.ps1" `
  -PackageUrl $PackageUrl `
  -ExpectedZipSha256 $ExpectedZipSha256 `
  -ApiUrl "https://testai.acik.com/api/v1/endpoint-agent" `
  -Start
```

`bootstrap-package.ps1` token'i gizli prompt ile alir; token komut satirina
yazilmaz. Script ZIP hash'ini ve ZIP icindeki `SHA256SUMS` dosyasini dogrular,
sonra `install.ps1` akisini calistirir.

Mevcut enrolled cihazda HMAC credential store varsa bu yol upgrade-preserve
modunda eski credential'i korur. Fresh re-enrollment istiyorsaniz explicit
olarak `-ResetCredentialStore` verin; aksi halde yeni token verilse bile script
fail-fast eder ve eski store'un sessizce kullanilmasini onler:

```powershell
powershell.exe -ExecutionPolicy Bypass -File "$env:TEMP\endpoint-agent-bootstrap.ps1" `
  -PackageUrl $PackageUrl `
  -ExpectedZipSha256 $ExpectedZipSha256 `
  -ApiUrl "https://testai.acik.com/api/v1/endpoint-agent" `
  -ResetCredentialStore `
  -Start `
  -Force
```

Windows uzerinde manuel path:

```powershell
New-Item -ItemType Directory -Force C:\Program Files\EndpointAgent
Copy-Item .\endpoint-agent.exe "C:\Program Files\EndpointAgent\endpoint-agent.exe"
```

-------------------------------------------------------------------------------
## 2. Config
-------------------------------------------------------------------------------

MVP config env uzerinden okunur. Windows service kullanimi icin machine-level
environment variable gerekir:

```powershell
[Environment]::SetEnvironmentVariable("ENDPOINT_AGENT_API_URL", "https://backend.example.local/api/v1/endpoint-agent", "Machine")
[Environment]::SetEnvironmentVariable("ENDPOINT_AGENT_ENROLLMENT_TOKEN", "<token>", "Machine")
```

Enrolled agent icin:

```powershell
[Environment]::SetEnvironmentVariable("ENDPOINT_AGENT_ID", "<agent-id>", "Machine")
[Environment]::SetEnvironmentVariable("ENDPOINT_AGENT_SECRET", "<agent-secret>", "Machine")
[Environment]::SetEnvironmentVariable("ENDPOINT_AGENT_INSTALL_ID", "<install-id>", "Machine")
```

Secret degerleri komut gecmisinde kalabilecegi icin production installer fazinda
Windows Credential Manager veya DPAPI store'a tasinacaktir.

-------------------------------------------------------------------------------
## 3. Logging
-------------------------------------------------------------------------------

Default log path:

```text
C:\ProgramData\EndpointAgent\logs\endpoint-agent.log
```

Override:

```powershell
[Environment]::SetEnvironmentVariable("ENDPOINT_AGENT_LOG_DIR", "C:\ProgramData\EndpointAgent\logs", "Machine")
```

Event Log source default service name ile aynidir:

```text
EndpointAgent
```

Custom service name kullanilirsa Event Log source da custom service name olur.
Log redaction kurallari icin `docs/LOGGING.md` izlenir.

-------------------------------------------------------------------------------
## 4. Service Commands
-------------------------------------------------------------------------------

Installer ile install:

```powershell
.\install.ps1 `
  -ApiUrl "https://backend.example.local/api/v1/endpoint-agent" `
  -EnrollmentToken "<token>" `
  -MaintenanceToken "<one-time-maintenance-token>" `
  -Start
```

Mevcut service'i degistirmek icin:

```powershell
.\install.ps1 -Force -MaintenanceToken "<one-time-maintenance-token>" -Start
```

Mevcut enrolled service'i yeni enrollment token ile fresh enroll etmek icin
`-ResetCredentialStore` zorunludur. Bu flag eski
`C:\ProgramData\EndpointAgent\config\hmac-credential.dpapi` dosyasini
`.bak-<timestamp>` olarak yedekler ve yeni token'in gercek enrollment kaynagi
olmasini saglar:

```powershell
.\install.ps1 `
  -ApiUrl "https://testai.acik.com/api/v1/endpoint-agent" `
  -EnrollmentToken "<token>" `
  -ResetCredentialStore `
  -Force `
  -Start
```

Uninstall:

```powershell
.\uninstall.ps1 -MaintenanceToken "<one-time-maintenance-token>"
```

Config ve loglari da kaldirmak icin:

```powershell
.\uninstall.ps1 -MaintenanceToken "<one-time-maintenance-token>" -RemoveConfig -RemoveLogs
```

-------------------------------------------------------------------------------
## 5. Tamper Protection
-------------------------------------------------------------------------------

Installer default olarak Windows tamper protection hardening uygular:

```text
service delayed-auto-start
service failure action: restart
service SDDL: SYSTEM/Admin full, Authenticated Users read/interrogate only
install/config/log directory ACL: SYSTEM/Admin full
maintenance token hash: ENDPOINT_AGENT_MAINTENANCE_TOKEN_SHA256
```

Maintenance token installer tarafinda hash olarak saklanir. Token degeri loglanmaz
ve config'e plaintext yazilmaz. Token backend hazir olana kadar pilot kurulumda
tek kullanimlik local operasyon token'i olarak verilir; backend geldikten sonra
panelden reason + expiry ile uretilecek.

Hash'i onceden uretip token'i installer komut satirinda kullanmak istemezseniz:

```powershell
.\install.ps1 `
  -MaintenanceTokenHash "<sha256-lowercase-hex>" `
  -Start
```

Stop/uninstall komutlari token hash konfiguru edildiyse token ister:

```powershell
& "C:\Program Files\EndpointAgent\endpoint-agent.exe" service stop --maintenance-token "<token>"
& "C:\Program Files\EndpointAgent\endpoint-agent.exe" service uninstall --maintenance-token "<token>"
```

Development/lab icin hardening kapatilabilir:

```powershell
.\install.ps1 -DisableTamperProtection -Start
```

Parallels/Windows live smoke:

```powershell
.\scripts\test\windows-live.ps1
```

Manual install:

```powershell
& "C:\Program Files\EndpointAgent\endpoint-agent.exe" service install
```

Start:

```powershell
& "C:\Program Files\EndpointAgent\endpoint-agent.exe" service start
```

Status:

```powershell
& "C:\Program Files\EndpointAgent\endpoint-agent.exe" service status
```

Stop:

```powershell
& "C:\Program Files\EndpointAgent\endpoint-agent.exe" service stop --maintenance-token "<token>"
```

Uninstall:

```powershell
& "C:\Program Files\EndpointAgent\endpoint-agent.exe" service uninstall --maintenance-token "<token>"
```

Read-only local user diagnostik:

```powershell
& "C:\Program Files\EndpointAgent\endpoint-agent.exe" diagnose local-users
```

Custom service name:

```powershell
& "C:\Program Files\EndpointAgent\endpoint-agent.exe" service install --name EndpointAgentTest --display-name "Endpoint Agent Test"
```

Installer, custom service name kullaniminda binary'yi SCM tarafinda su internal
argumanla baslatir:

```text
--service-run-name <service-name>
```

Bu arguman manuel calistirma icin degildir; service handler'in Windows SCM ile
dogru service name uzerinden konusmasini saglar.

-------------------------------------------------------------------------------
## 6. Live Verification Checklist
-------------------------------------------------------------------------------

Windows pilot makinede `AG-012` kapatmak icin:

```text
service install ok
service start ok
service status RUNNING
service stop ok
service status STOPPED
service uninstall ok
Windows Event Log source olustu
Agent backend'e heartbeat atti
```

`AG-019` tamper protection icin ek kontroller:

```text
service failure action RESTART
DelayedAutoStart=1
service SDDL Authenticated Users icin SERVICE_STOP vermez
wrong maintenance token ile stop reddedilir
correct maintenance token ile kontrollu stop/uninstall calisir
install/config/log ACL normal kullanici write/delete yetkisi vermez
```
