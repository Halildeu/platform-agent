# Backend/Web Integration Plan

Bu belge agent reposunda tutulur; backend ve web kodunun kendisi kendi
repolarinda gelistirilir.

-------------------------------------------------------------------------------
## 1. Repo Sinirlari
-------------------------------------------------------------------------------

```text
/Users/halilkocoglu/Documents/platform-backend
  endpoint-admin-service
  agent enrollment, endpoint inventory, command queue, audit, RBAC gateway

/Users/halilkocoglu/Documents/platform-web
  apps/mfe-endpoint-admin
  endpoint list/detail, command picker, enrollment token UI, audit views

/Users/halilkocoglu/Documents/platform-agent
  Go endpoint agent
  Windows service, macOS launchd daemon, local OS operations
```

Agent repo backend veya web artifact uretmez. Agent sozlesmeleri ve deployment
notlari burada tutulur; merkezi API ve UI ayri repolardadir.

-------------------------------------------------------------------------------
## 2. Backend Servis Hedefi
-------------------------------------------------------------------------------

Backend servisi:

```text
platform-backend/endpoint-admin-service
```

API prefixleri:

```text
/api/v1/endpoint-admin
/api/v1/endpoint-agent
```

Minimum backend sorumluluklari:

```text
endpoint registry
agent enrollment token
agent identity ve HMAC verification
heartbeat ingestion
inventory snapshots
command queue
command claim/result idempotency
audit log
admin RBAC enforcement
rate limit
```

Admin kullanicilar platform auth/RBAC ile girer. Agent kimligi ayri tutulur;
agent requestleri user session token ile calismaz.

-------------------------------------------------------------------------------
## 3. Web MFE Hedefi
-------------------------------------------------------------------------------

Web uygulamasi:

```text
platform-web/apps/mfe-endpoint-admin
```

Shell route:

```text
/admin/endpoints
```

Ilk ekranlar:

```text
Endpoint list
Endpoint detail
Inventory tab
Users tab
Files tab
Commands tab
Audit tab
Enrollment token modal
```

UI kuralı:

```text
freeform shell command yok
yalniz backend'in sundugu command picker var
reason zorunlu komutlarda form reason ister
password/secret alanlari UI log veya audit detayinda gosterilmez
```

-------------------------------------------------------------------------------
## 4. Permission Model
-------------------------------------------------------------------------------

Onerilen permission isimleri:

```text
ENDPOINT_ADMIN_VIEW
ENDPOINT_ADMIN_EXECUTE
ENDPOINT_ADMIN_ENROLL
ENDPOINT_ADMIN_AUDIT
```

Ilk entegrasyonda backend bu izinleri platform auth katmanindan okur. OpenFGA
tuple yazimlari endpoint-admin-service icinden dogrudan yapilmaz; mevcut
permission-service pattern'i izlenir.

-------------------------------------------------------------------------------
## 5. Komut Akisi
-------------------------------------------------------------------------------

```text
1. Admin web uzerinden endpoint secer.
2. Web backend'e command create istegi atar.
3. Backend RBAC + rate limit + payload validation yapar.
4. Backend command'i QUEUED yazar.
5. Agent outbound polling ile command'i claim eder.
6. Agent local validation + capability check yapar.
7. Agent sonucu backend'e commandId + claimId + attemptNumber ile yollar.
8. Backend idempotent result kaydi ve audit uretir.
9. Web command status ve audit'i gosterir.
```

State-changing komutlardan once HMAC signed request backend tarafinda aktif
olmalidir.

-------------------------------------------------------------------------------
## 6. Deployment Entegrasyon Fazlari
-------------------------------------------------------------------------------

MVP:

```text
manual Windows install
enrollment token
read-only inventory
local user list
```

Pilot:

```text
Windows service install
GPO startup script dokumani
Intune/SCCM paket notlari
EDR/antivirus allowlist dogrulamasi
```

Later:

```text
AD discovery
bulk rollout dashboard
macOS pkg/Jamf/MDM
agent update manifest
osquery inventory
```

-------------------------------------------------------------------------------
## 7. Ilk Backend/Web Is Sirası
-------------------------------------------------------------------------------

1. Backend'te `endpoint-admin-service` modulu acilir.
2. Flyway ile endpoint, agent identity, command queue, audit tablolari eklenir.
3. Agent API mock contract'i ve HMAC verifier eklenir.
4. Web'te `mfe-endpoint-admin` acilir.
5. Web mock API ile endpoint list/detail ve command picker cikar.
6. Backend/web entegrasyonu real API ile baglanir.
7. Agent simulator backend'e enroll/heartbeat/command result yollar.
