# Agent Testing Strategy

-------------------------------------------------------------------------------
## 1. Test Katmanlari
-------------------------------------------------------------------------------

Unit:

```text
config parsing
command validation
claim/result idempotency
redaction
path whitelist validation
offline state transitions
```

Integration:

```text
mock backend enrollment
heartbeat retry/backoff
command polling
result submit idempotency
```

Platform POC:

```text
Windows inventory
Windows local user list
Windows disable/enable local user
macOS inventory
macOS local user list
```

-------------------------------------------------------------------------------
## 2. Ilk CI Hedefi
-------------------------------------------------------------------------------

Go toolchain kurulduktan sonra minimum komutlar:

```bash
./scripts/test/local.sh
```

Bu script su komutlari calistirir:

```bash
gofmt -w ./cmd ./internal
go test ./...
go vet ./...
```

Windows-specific testler icin:

```text
GitHub Actions windows-latest runner veya lokal Windows pilot runner
```

-------------------------------------------------------------------------------
## 3. Mock Backend
-------------------------------------------------------------------------------

Agent testleri gercek backend beklemez. Mock backend su endpointleri saglar:

```text
/enroll
/heartbeat
/commands/next
/commands/{commandId}/result
```

Mock backend idempotency ve retry davranisini test etmek icin kontrollu hata
senaryolari uretir:

```text
500 retry
401 re-enroll required
timeout
duplicate result
claim expired
unsupported command
```

-------------------------------------------------------------------------------
## 4. No-Secret Assertion
-------------------------------------------------------------------------------

Enrollment, password reset ve signed request testlerinde log ciktilari taranir:

```text
password value yok
token value yok
agentSecret value yok
authorization header yok
signature raw secret yok
```

-------------------------------------------------------------------------------
## 5. Canli POC Siniri
-------------------------------------------------------------------------------

Canli Windows POC icin:

```text
1 pilot Windows endpoint
1 dummy local user
manual install
backend test URL
EDR/antivirus izni
```

Canli AD/GPO deployment bu test stratejisinin sonraki fazidir.

-------------------------------------------------------------------------------
## 6. Software + WinGet Diagnose Smoke (AG-025 / AG-026)
-------------------------------------------------------------------------------

`endpoint-agent diagnose software` HKLM Uninstall hive'larini JSON olarak
stdout'a dump eder; `endpoint-agent diagnose winget` ise `winget.exe`
path + version + `systemContextReady` durumunu rapor eder. Iki komut
ayri olarak akar — slow winget probe registry inventarini bloklamaz
(error isolation).

Parallels Windows 11 reproducer:

```powershell
# 1. Software envanteri — HKLM + WOW6432Node, no shell, no PowerShell
.\endpoint-agent.exe diagnose software | Out-File -Encoding utf8 software.json
Get-Content software.json | ConvertFrom-Json | Select-Object -ExpandProperty apps | Measure-Object

# 2. PII sizinti yok kanit
Select-String -Path software.json -Pattern '@example\.com|S-1-5-21-\d|C:\\Users\\[^\\\[]'
# Bos sonuc PASS

# 3. WinGet readiness
.\endpoint-agent.exe diagnose winget

# 4. LocalSystem context — psexec -s ile servis hesabi simulasyonu
psexec -s -i .\endpoint-agent.exe diagnose winget
# systemContextReady=true/false net rapor edilir; install/search/source YOK
```

Non-Windows runner uzerinde:

```sh
./endpoint-agent diagnose software
# {"supported":false,"reason":"unsupported_os",...} exit 0
./endpoint-agent diagnose winget
# {"supported":false,...} exit 0
```

`COLLECT_INVENTORY` includeSoftware payload arg ile envanter command:

```json
{
  "type": "COLLECT_INVENTORY",
  "payload": { "includeSoftware": true }
}
```

AG-025H lightweight default (`includeSoftware` yok veya false) — payload
`inventory.software` alanini HIC TASIMAZ. Registry enumeration ve WinGet
probe hic calistirilmaz. Heartbeat / auto-enroll bu defaulti kullanir.

`includeSoftware=true` opt-in path ile `inventory.software` blogu aktarilir;
`inventory.software.apps` size cap altinda tasinir (`truncated=true` flag'i
ile rapor).
