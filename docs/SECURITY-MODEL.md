# Agent Security Model

-------------------------------------------------------------------------------
## 1. Guvenlik Ilkeleri
-------------------------------------------------------------------------------

- Raw shell yok.
- Whitelist command var.
- HTTPS zorunlu.
- Enrollment token sureli ve tek kullanimlik.
- Agent secret OS secret store'da saklanir.
- Hassas komutlardan once HMAC-signed request devreye alinir.
- Password, token, private key ve secret loglanmaz.
- Hassas komutlarda `reason` zorunludur.
- Command result audit'e gider.

-------------------------------------------------------------------------------
## 2. Agent Identity
-------------------------------------------------------------------------------

Enrollment akisi:

```text
1. Admin backend panelden enrollment token olusturur.
2. Agent installer bu token ile calisir.
3. Agent backend'e enroll olur.
4. Backend agentId + agentSecret verir.
5. Enrollment token tekrar kullanilamaz.
6. Sonraki istekler agent identity ile imzalanir/dogrulanir.
```

Ilk read-only POC'ta token-based auth yeterlidir. `RESET_LOCAL_USER_PASSWORD`,
`DISABLE_LOCAL_USER`, `ENABLE_LOCAL_USER` gibi state-changing komutlardan once
HMAC-signed request zorunlu hale getirilir. mTLS daha sonraki hardening fazidir.

Request signing minimumu:

```text
X-Agent-Id
X-Agent-Timestamp
X-Agent-Nonce
X-Agent-Signature
```

Replay guard:

```text
nonce cache TTL: 10 dakika
timestamp skew: 5 dakika
signature body hash'i kapsar
```

-------------------------------------------------------------------------------
## 3. OS Secret Store
-------------------------------------------------------------------------------

Windows:

```text
DPAPI veya Windows Credential Manager
```

macOS:

```text
Keychain
```

Secret dosyada plain text tutulmaz.

-------------------------------------------------------------------------------
## 4. Command Guardrail
-------------------------------------------------------------------------------

Agent command dispatch su kurallari uygular:

```text
type enum mu?
payload schema gecerli mi?
capability destekliyor mu?
reason gerekli mi?
timeout var mi?
path whitelist icinde mi?
secret alanlari logdan temizleniyor mu?
```

Bu kontrollerden biri gecmezse command calismaz.

-------------------------------------------------------------------------------
## 5. Secret Redaction
-------------------------------------------------------------------------------

Loglama default-deny calisir:

```text
yalniz explicit safe field'lar loglanir
bilinmeyen payload alanlari default redacted kabul edilir
```

Redact edilecek alan pattern'leri:

```text
password
secret
token
key
credential
authorization
cookie
signature
newPasswordSecret
agentSecret
enrollmentToken
```

Payload log formatinda secret degerleri su sekilde gorunur:

```text
<redacted>
```

Password reset, enrollment ve agent auth testleri redaction assertion icermelidir.

File logger write seviyesinde text redaction uygular. Log path ve Windows Event
Log source icin `docs/LOGGING.md` izlenir.

-------------------------------------------------------------------------------
## 6. Rate Limit ve Abuse Guardrail
-------------------------------------------------------------------------------

Backend tarafinda uygulanacak minimum limitler:

```text
per-endpoint sensitive command: 5 / 10 dakika
per-actor sensitive command: 20 / saat
bulk disable/password reset: explicit approval gerektirir
same user password reset: cooldown zorunlu
```

Agent tarafinda:

```text
ayni anda tek command
command timeout zorunlu
unsupported command calismaz, result UNSUPPORTED doner
```

-------------------------------------------------------------------------------
## 7. File Access Guardrail
-------------------------------------------------------------------------------

MVP path whitelist:

```text
Windows:
C:\Users\{username}\Desktop
C:\Users\{username}\Documents
C:\Users\{username}\Downloads

macOS:
/Users/{username}/Desktop
/Users/{username}/Documents
/Users/{username}/Downloads
```

Kapali alanlar:

```text
C:\
C:\Windows
C:\Program Files
C:\Users\*\AppData
/
/System
/Library
/private
```

Path dogrulama sirasi:

```text
1. username canonical local user snapshot'tan resolve edilir
2. requested relative path normalize edilir
3. `..`, absolute path injection ve drive override reddedilir
4. symlink/junction resolve edilir
5. resolved path whitelist root altinda mi tekrar kontrol edilir
6. dosya boyutu ve extension policy uygulanir
7. audit log yazilir
```

Windows junction/reparse point ve macOS symlink kontrolleri platform adapter
icinde yapilir.

-------------------------------------------------------------------------------
## 8. Deployment Security
-------------------------------------------------------------------------------

Windows:

```text
GPO/SCCM/Intune ile pilot grup uzerinden dagitim.
Ilk pilot 2-5 endpoint.
EDR/antivirus allowlist IT ile dogrulanir.
```

macOS:

```text
MDM/Jamf/Intune/pkg dagitimi.
Code signing ve notarization V2 kapsaminda.
TCC/PPPC izinleri ayrica tasarlanir.
```

-------------------------------------------------------------------------------
## 9. Tamper Protection
-------------------------------------------------------------------------------

Bu bolum son kullanicinin agent'i normal yollardan kaldiramamasi, durduramamasi
veya gorev yoneticisinden kapatamamasi icin kurumsal tamper protection modelini
tanimlar. Hedef gizlenmek degil; gorunur, audit edilebilir ve IT tarafindan
yonetilebilir bir koruma katmani kurmaktir.

Temel ilke:

```text
standart kullanici agent'i durduramaz, silemez, config degistiremez
local admin yetkisi olan kullaniciya karsi mutlak garanti verilmez
local admin riski MDM/GPO/EDR/WDAC ve audit ile azaltilir
IT icin break-glass uninstall/maintenance yolu vardir
```

Windows MVP guardrail:

```text
service LocalSystem olarak calisir
service auto-start ve delayed-auto-start olur
service stop/delete/configure yetkileri kisitli SDDL ile sertlestirilir
service failure action restart olarak ayarlanir
installer/config/binary klasorleri Program Files/ProgramData altinda ACL ile korunur
uninstall normal kullaniciya kapali olur
uninstall veya maintenance mode backend one-time token + local admin gerektirir
service stop denemesi, uninstall denemesi ve dosya/config degisikligi audit edilir
heartbeat kesilirse backend endpoint'i degraded/offline olarak isaretler
```

Windows ileri seviye guardrail:

```text
Intune/GPO/SCCM ile required app olarak yeniden kurulum/remediation
WDAC veya AppLocker ile yalniz imzali agent binary calisir
EDR/AV allowlist + tamper policy IT ile koordine edilir
LAPS/JIT admin ile kalici local admin yetkisi kaldirilir
opsiyonel watchdog scheduled task veya companion health check
Windows Event Log 7035/7036/7040/7045 ve agent audit correlation
```

Task Manager gercegi:

```text
standart kullanici LocalSystem service process'ini kapatamaz
local admin Task Manager veya servis araclariyla zorlayabilir
PPL/protected process seviyesi Microsoft imzali anti-malware/ELAM sinifi ister
MVP icin PPL hedeflenmez; enterprise policy + audit + remediation hedeflenir
```

macOS guardrail:

```text
LaunchDaemon root:wheel olarak /Library/LaunchDaemons altinda kurulur
binary ve config /Library/Application Support/EndpointAgent altinda root ACL ile korunur
KeepAlive enabled olur
standart kullanici unload/remove yapamaz
admin kullanici sudo ile mudahele edebilir; MDM/Jamf/Intune remediation gerekir
uninstall signed package + backend maintenance token veya MDM command ile yapilir
```

Rakip urunlerde gorulen ortak desenler:

```text
tamper protection toggle veya policy
uninstall password/token
signed agent + protected install directory
auto-restart/health monitor
MDM/GPO/SCCM required deployment
EDR/AV tamper protection
offline/disabled agent alert
break-glass procedure
```

Yasak yaklasimlar:

```text
process veya dosya gizleme
rootkit/kernel hook ile saklanma
EDR/AV atlatma
adminin haberi olmadan persistence
uninstall yolunu tamamen yok etme
```

-------------------------------------------------------------------------------
## 10. Audit
-------------------------------------------------------------------------------

Audit minimum alanlari:

```text
actor
endpointId
hostname
osFamily
commandType
targetUsername
reason
status
startedAt
finishedAt
summary
```

Audit log password, token veya secret degeri tasimaz.

-------------------------------------------------------------------------------
## 11. EDR / Antivirus
-------------------------------------------------------------------------------

Pilot oncesi IT ile dogrulanacak alanlar:

```text
binary path allowlist
publisher/code signing beklentisi
PowerShell child process monitoring
service install behavior
network egress destination
log path
```

Ilk Windows POC raw shell calistirmasa bile kontrollu PowerShell wrapper
kullanacagi icin EDR sinyali dogurabilir. Bu davranis pilot kapsaminda
gizlenmez; IT ile allowlist ve audit notu uzerinden ilerlenir.
