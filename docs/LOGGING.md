# Logging and Event Log

Bu belge `AG-014` icin agent log path, Windows Event Log source ve redaction
kurallarini tanimlar.

-------------------------------------------------------------------------------
## 1. File Log Path
-------------------------------------------------------------------------------

Default Windows path:

```text
%ProgramData%\EndpointAgent\logs\endpoint-agent.log
```

Default macOS local development path:

```text
~/Library/Logs/EndpointAgent/endpoint-agent.log
```

Path override:

```bash
export ENDPOINT_AGENT_LOG_DIR=/custom/path
```

Windows machine-level override:

```powershell
[Environment]::SetEnvironmentVariable("ENDPOINT_AGENT_LOG_DIR", "C:\ProgramData\EndpointAgent\logs", "Machine")
```

-------------------------------------------------------------------------------
## 2. Windows Event Log Source
-------------------------------------------------------------------------------

Default service/event source:

```text
EndpointAgent
```

Custom service name kullanilirsa Event Log source da ayni isimle kurulur:

```powershell
.\endpoint-agent.exe service install --name EndpointAgentTest
```

Service install source'u olusturur:

```text
eventlog.InstallAsEventCreate(<service-name>, Error|Warning|Info)
```

Service uninstall source'u kaldirir:

```text
eventlog.Remove(<service-name>)
```

Service runtime Event Log'a yalniz lifecycle mesajlari yazar:

```text
service starting
service running
service stopping
service stopped
service runner failed: <redacted error>
```

Command payload, password, token veya agent secret Event Log'a yazilmaz.

-------------------------------------------------------------------------------
## 3. Redaction
-------------------------------------------------------------------------------

File logger write seviyesinde metin redaction uygular. Su key/value alanlari
maskelenir:

```text
authorization
cookie
credential
key
password
secret
signature
token
newPasswordSecret
agentSecret
enrollmentToken
```

Bearer token formatlari da maskelenir:

```text
Authorization=Bearer <redacted>
Bearer <redacted>
```

Redacted value:

```text
<redacted>
```

-------------------------------------------------------------------------------
## 4. Verification
-------------------------------------------------------------------------------

Local test:

```bash
./scripts/test/local.sh
```

Redaction testleri:

```text
internal/security/redact_text_test.go
internal/logging/logger_test.go
```

Windows build:

```bash
./scripts/build/windows.sh
```

Live Windows pilot evidence:

```text
%ProgramData%\EndpointAgent\logs\endpoint-agent.log olusur
Windows Event Log source EndpointAgent olusur
service start/stop lifecycle eventleri gorunur
secret/token/password degerleri loglarda gorunmez
```
