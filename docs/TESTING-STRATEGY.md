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
