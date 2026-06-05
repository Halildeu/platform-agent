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

-------------------------------------------------------------------------------
## 7. WinGet Source / Egress Preflight (AG-026A, Faz 22.5)
-------------------------------------------------------------------------------

`endpoint-agent diagnose winget-egress` AG-026A read-only WinGet
source/egress preflight calistirir; `winget source list` (fixed argv),
`winget show --id 7zip.7zip --exact --disable-interactivity` (sabit
package id), ve hard-coded `DefaultEgressTargets` listesine karsi
DNS/TCP/HTTPS reachability probleri uretip JSON olarak stdout'a dump
eder. Exit code probe outcome'una BAGLI DEGIL — error isolation
payload icindeki `probeError` / `packageQuery.errorReason` /
`egress.{dns,tcp,https}[*].errorReason` alanlarinda yasar.

Windows LocalSystem smoke:

```powershell
# Interactive user'da
.\endpoint-agent.exe diagnose winget-egress | Out-File -Encoding utf8 winget-egress.json

# LocalSystem context'inde (msstore source LocalSystem'da farkli davranir;
# bu fark `packageQuery.errorReason` ile rapor edilir, implementation bug
# DEGILDIR).
psexec -s -i .\endpoint-agent.exe diagnose winget-egress | Out-File -Encoding utf8 winget-egress-system.json
```

Non-Windows smoke:

```bash
./endpoint-agent diagnose winget-egress
# {"supported":false,"schemaVersion":1,...}
# Supported=false dondurur; sources / packageQuery / egress trivially empty.
```

PII / secret assertion (parser/proxy/redaction kapsami):

```bash
grep -E '@example\.com|S-1-5-21-\d|C:\\Users\\[^\\\[]|Bearer |Authorization:' winget-egress.json && exit 1 || true
```

COLLECT_INVENTORY backend opt-in:

```json
{
  "type": "COLLECT_INVENTORY",
  "payload": { "includeWinGetEgress": true }
}
```

`includeSoftware` ve `includeWinGetEgress` flag'leri **bagimsiz** opt-in
bit'leridir; backend ikisini birlikte de gonderebilir, ayri ayri da. Hicbiri
verilmediginde AG-025H lightweight default korunur (registry / winget
probe / source-egress preflight HIC calistirilmaz).

AG-026A hard boundary (Codex 019e6b5d plan-time AGREE kilit sart +
019e6b70 iter-1/iter-2 absorb):

```text
1. install / upgrade / uninstall / settings / export / import / hash /
   validate / pin / configure / download / repair / features /
   complete / debug / source mutation komutlari calismaz — 19-verb
   regression belt `TestRunSourceEgressForbiddenSubcommandsNeverInvoked`
   her sub-probe argv'sini denetler. (Asil guvenlik gate fixed argv;
   bu test regression belt.)
2. Package id `7zip.7zip` (FixedPackageQueryID) hard-coded;
   `SourceEgressOptions` uzerinde override alani YOK
   (`TestSourceEgressOptionsHasNoOverrideFields` reflection ile
   PackageID/Targets alanlarinin geri eklenmesini engeller).
3. Argv pinning: `source list` icin tam `["source","list"]`, `show` icin
   `["show","--id",FixedPackageQueryID,"--exact","--disable-interactivity"]`
   (`TestRunSourceEgressFixedSourceListArgv` + `TestRunSourceEgressFixedPackageQueryArgv`).
4. Overall timeout enforcement: root `context.WithTimeout(opts.Timeout)`
   her sub-probe'u clamp eder; per-probe slice 250ms floor ile remaining
   budget'i still-to-run probelar arasinda boler. Hicbir sub-probe stall
   total wall-clock'u opts.Timeout'tan fazla yapamaz
   (`TestRunSourceEgressOverallTimeoutBudgetEnforced` 100ms budget +
   stalled probes -> ProbeDurationMs<=500 + Timeout=true).
5. Source-list failure visibility: `sourceListError` wire field
   (sanitised reason) + overall `timeout` flag flips
   (`TestRunSourceEgressSourceListErrorSurfaced` +
   `TestRunSourceEgressSourceListTimeoutSurfacesOverallTimeout`).
6. PackageQuery Found locale-stable: `err==nil && case-insensitive
   contains FixedPackageQueryID` — Turkish/German/Japanese localized
   "paket bulunamadi" cikilarinda false-positive uretmez
   (`TestRunPackageQueryFoundLocaleStable` 5 case dahil
   `turkish-not-found`).
7. Egress target boundary: `defaultEgressTargets` unexported array;
   `DefaultEgressTargets()` callerlara KOPYA doner
   (`TestDefaultEgressTargetsReturnsCopy`).
8. Redaction: probe error, source list error, source argument, proxy
   URL, package query error, egress error reason hepsi
   `security.RedactSoftwareString` (proxy userinfo `url.User=nil` ile
   ek strip edilir).
9. Non-Windows build: `DetectSourceEgress` Supported=false doner,
   hicbir probe calistirilmaz (`source_egress_other_test.go`).
```

-------------------------------------------------------------------------------
## 8. Signed Self-Update Live Smoke (AG-029, Faz 22.5)
-------------------------------------------------------------------------------

AG-029 acceptance is not covered by source tests alone. The live Windows
evidence runbook is `docs/AG-029-self-update-live-smoke.md`.

Minimum acceptance evidence:

```text
1. backend-issued UPDATE_AGENT result reports STAGED_ACTIVATION_READY
2. endpoint-agent self-update preflight returns path-free READY
3. endpoint-agent self-update activate returns path-free ACTIVATED
4. EndpointAgent service is running after activation
5. next backend heartbeat reports AgentVersion == targetVersion
6. audit/result rows correlate to the original command id and actor
7. tampered staged binary preflight fails closed with HASH_MISMATCH
```

If backend command-create PR4 is not available yet, only the source-slice
preflight/activation readiness mode may be used. That mode must not be used to
claim backend catalog, maker-checker, production rollout, or domain-wide
self-update readiness.
