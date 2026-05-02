# Backend Service Plan

Bu belge `platform-backend` reposuna eklenecek endpoint yonetim backend
servisi icin takip edilebilir uygulama planidir. Kodun kendisi
`/Users/halilkocoglu/Documents/platform-backend` altinda gelistirilecek; bu
belge agent/web/backend sozlesmesini ayni yerde takip etmek icin agent
reposunda tutulur.

-------------------------------------------------------------------------------
## 1. Inceleme Ozeti
-------------------------------------------------------------------------------

Backend repo:

```text
/Users/halilkocoglu/Documents/platform-backend
```

Mevcut repo durumu:

```text
branch: codex/be-001-endpoint-admin-service-platform-backend
HEAD: e9d8fd3 feat: add endpoint admin service
remote: origin/codex/be-001-endpoint-admin-service-platform-backend
untracked: .claude/
```

`.claude/` bu calisma kapsaminda sahiplenilmedi ve dokunulmadi. Backend
servisi `endpoint-admin-service/` altinda gelistiriliyor ve backend branch'e
commitlenip push edildi.

Mevcut servis kalibi:

```text
Spring Boot 3.5.6
Java 21
Maven module per service
local/dev profile permitAll veya dev auth fallback
k8s profile: Eureka kapali, K8s svc DNS, actuator management port 8081
Flyway migration
PostgreSQL datasource
Dockerfile per service
GHCR image matrix
```

Root parent `pom.xml` icindeki moduller:

```text
common-auth
discovery-server
api-gateway
auth-service
permission-service
user-service
variant-service
core-data-service
report-service
```

`schema-service` repo icinde var ama root parent reactor'a dahil degil; CI'da
ayri build ediliyor. Yeni `endpoint-admin-service` root reactor'a eklendi.

Runtime manifest otoritesi:

```text
/Users/halilkocoglu/Documents/platform-k8s-gitops
```

Backend source repo image uretir; K8s deployment/config/gateway runtime
desired-state GitOps repo tarafinda takip edilir.

-------------------------------------------------------------------------------
## 2. Hedef Servis Kontrati
-------------------------------------------------------------------------------

Servis adi:

```text
endpoint-admin-service
```

Backend path:

```text
/Users/halilkocoglu/Documents/platform-backend/endpoint-admin-service
```

Java package:

```text
com.example.endpointadmin
```

Spring application name:

```text
endpoint-admin-service
```

Port kontrati:

```text
local app port: 8096
k8s container app port: 8096
k8s management port: 8081
```

PostgreSQL schema:

```text
endpoint_admin_service
```

API prefixleri:

```text
servis ici mevcut prefixler:
/api/v1/agent
/api/v1/admin

gateway hedef prefixleri:
/api/v1/endpoint-agent
/api/v1/endpoint-admin
```

Agent endpointleri kullanici JWT'si tasimaz. Agent kimligi ayri tutulur ve
HMAC-signed request ile dogrulanir. Admin endpointleri platform user auth/RBAC
ile korunur.

BE-010 ile gateway eslemesi netlesti: `/api/v1/endpoint-agent/**`
servis icinde `/api/v1/agent/**` yuzeyine, `/api/v1/endpoint-admin/**`
servis icinde `/api/v1/admin/**` yuzeyine rewrite edilir.

-------------------------------------------------------------------------------
## 3. Kritik Mimari Kararlar
-------------------------------------------------------------------------------

| Alan | Karar | Gerekce |
|---|---|---|
| Servis siniri | Ayri `endpoint-admin-service` | Agent, endpoint, command queue ve audit yuzeyi domain olarak ayrilir. |
| Agent auth | HMAC signed request | Agent user JWT kullanmayacak; outbound polling modeliyle kendi kimligi var. |
| Admin auth | Mevcut JWT + OpenFGA/RBAC pattern | Web admin kullanicilari mevcut platform auth zincirine baglanir. |
| Gateway | Agent route permitAll, servis ici HMAC | Non-local gateway default JWT ister; agent route icin permitAll gerekir. |
| Secret storage | Encrypted agent secret + hash | HMAC verify icin secret recover edilebilir olmali; raw secret loglanmaz. |
| Replay guard | DB backed nonce table | Multi-replica servis durumunda in-memory nonce cache yetersiz kalir. |
| Command queue | DB transaction + claim TTL | Agent polling icin atomic claim ve idempotent result gerekir. |
| Raw shell | Yasak | Agent sadece whitelist command type calistirir. |
| Password reset | Bloklu | RBAC, HMAC, audit integrity, destructive saga ve pilot gate olmadan acilmaz. |
| Tamper protection | Kurumsal policy + audit | Standart kullanici durduramaz/kaldiramaz; local admin riski MDM/GPO/EDR ile azaltilir. |
| Identity source | Local/AD/M365 ayri track | Local SAM, AD/LDAPS ve Microsoft Graph/M365 farkli yetki, audit ve failure modeline sahiptir. |
| Live evidence | Up/Functional/Secured ayri kanit | Pod/binary ayakta olmak, contract calismak ve yetki enforce edilmek farkli gate'lerdir. |
| Audit integrity | Append-only/hash-chain | Destructive admin aksiyonlarinda audit kaydi sonradan sessizce degistirilemez olmalidir. |
| Destructive saga | Partial failure state modeli | State-changing komutlarda retry, timeout, rollback veya manual-review state'i tanimlanir. |
| KVKK | Retention + veri envanteri | Identity, local user, inventory ve audit verileri icin saklama/silme politikasi gerekir. |

-------------------------------------------------------------------------------
## 4. Veri Modeli Taslagi
-------------------------------------------------------------------------------

Ilk Flyway seti asagidaki tablolari hedefler:

| Tablo | Amac |
|---|---|
| `endpoint_enrollment_tokens` | Tek kullanimlik, sureli enrollment token kaydi. |
| `endpoint_agents` | Agent identity, install id, encrypted secret, status, version. |
| `endpoints` | Makine kimligi, hostname, OS, arch, state, last seen. |
| `endpoint_heartbeats` | Son heartbeat snapshot'i ve opsiyonel tarihce. |
| `endpoint_inventory_snapshots` | Inventory payload versioned snapshot. |
| `endpoint_local_users` | Son local user snapshot'i; read-only veri. |
| `endpoint_commands` | Admin tarafindan olusturulan command queue. |
| `endpoint_command_results` | Agent result payload'i ve idempotency kaydi. |
| `endpoint_audit_events` | Actor, endpoint, command, reason, status audit. |
| `endpoint_agent_nonces` | HMAC replay guard icin nonce TTL ve unique guard. |

Minimum enumlar:

```text
endpoint_status: ACTIVE, DEGRADED, OFFLINE, RETIRED
agent_status: PENDING, ACTIVE, REVOKED
command_status: QUEUED, CLAIMED, RUNNING, SUCCEEDED, FAILED, UNSUPPORTED, EXPIRED, CANCELLED
command_type: COLLECT_INVENTORY, LIST_LOCAL_USERS, GET_LOGGED_IN_USER,
              GET_USER_HOME_PATHS, DISABLE_LOCAL_USER, ENABLE_LOCAL_USER,
              RESET_LOCAL_USER_PASSWORD, LIST_ALLOWED_DIRECTORY
```

`RESET_LOCAL_USER_PASSWORD` yalniz local Windows SAM hesabini hedefler. Domain
ve M365/Entra password reset ayni command type ile acilmaz; ileride
`RESET_DOMAIN_USER_PASSWORD` ve `RESET_M365_USER_PASSWORD` gibi ayri command
type, capability, RBAC, audit ve connector tasarimi gerekir.

Password reset ve file access command type'lari ilk modelde enum olarak
tanimlanabilir ama backend policy ile bloklu kalir.

-------------------------------------------------------------------------------
## 5. Adim Adim Is Plani
-------------------------------------------------------------------------------

| ID | Adim | Durum | Bagimlilik | Dosya alani | Acceptance criteria | Evidence |
|---|---|---|---|---|---|---|
| BE-000 | Repo guard ve branch hazirligi | `DONE` | Mevcut modified/untracked degisikliklerin korunmasi | backend git state | Branch netlesir, bize ait olmayan degisiklikler revert edilmez. | `git status --short`, branch `codex/be-001-endpoint-admin-service-platform-backend`; `.claude/` dokunulmadi. |
| BE-001 | Servis scaffold | `DONE` | BE-000 | `endpoint-admin-service`, root `pom.xml` | Spring Boot app, package yapisi, actuator health, test context ayaga kalkar. | `./mvnw -q -DskipTests test-compile` PASS. |
| BE-002 | Config, profiles, Dockerfile, CI | `DONE` | BE-001 | `application.yml`, `application-k8s.yml`, Dockerfile, workflows | local/k8s config mevcut servislerle uyumlu; CI image matrix servisi icerir. | `endpoint-admin-service/Dockerfile`, `.github/workflows/ci-image-push.yml`, `.github/workflows/ci-mvn-check.yml`, `./mvnw -q -DskipTests -pl endpoint-admin-service package` PASS, `docker build -f endpoint-admin-service/Dockerfile -t endpoint-admin-service:be-002 .` PASS, `docker run --rm --entrypoint id endpoint-admin-service:be-002 -u` -> `1000`, `./mvnw -q -DskipTests verify` PASS, `./mvnw -q -DskipTests test-compile` PASS. |
| BE-003 | Flyway ve JPA model | `DONE` | BE-001 | `db/migration`, model, repository | Endpoint, agent, token, command, result, audit, nonce tablolari migration ile gelir. | `V1__endpoint_admin_baseline.sql`, `V2__endpoint_admin_domain.sql`, `EndpointDomainRepositoryTest`, `./mvnw -q -pl endpoint-admin-service test` PASS. |
| BE-004 | HMAC verification foundation | `DONE` | BE-003 | security package | Timestamp skew, nonce replay, body hash, signature ve agent status dogrulanir. | `HmacDeviceCredentialProviderTest`, `DeviceCredentialAuthenticationFilterTest`, `./mvnw -q -pl endpoint-admin-service test` PASS. |
| BE-005 | Enrollment API | `DONE` | BE-003 | `/api/v1/agent/enrollments/consume`, admin token API | Admin token uretir; agent token ile enroll olur; token tek kullanimliktir; secret sadece enroll response'ta doner. | `AdminEndpointEnrollmentControllerTest`, `AgentEnrollmentControllerTest`, `EndpointEnrollmentServiceTest`, `./mvnw -q -pl endpoint-admin-service test` PASS. |
| BE-006 | Heartbeat, inventory, users snapshot | `DONE` | BE-004, BE-005 | agent controller/service | Signed heartbeat endpoint state, capabilities, inventory ve local user snapshot kaydeder. | `AgentHeartbeatControllerTest`, `EndpointHeartbeatServiceTest`, `./mvnw -q -pl endpoint-admin-service test` PASS, `./mvnw -q -DskipTests test-compile` PASS. |
| BE-007 | Command queue claim/result | `DONE` | BE-004, BE-006 | command controller/service/repository | Agent authenticated device icin `QUEUED` veya claim TTL'i dolmus `DELIVERED` komutu claim eder; result submit idempotent calisir; claim TTL vardir. | `AgentCommandControllerTest`, `EndpointAgentCommandServiceTest`, `./mvnw -q -pl endpoint-admin-service test` PASS, `./mvnw -q -DskipTests test-compile` PASS, `git diff --check` PASS. |
| BE-008 | Admin API | `DONE` | BE-003, BE-007 | `/api/v1/admin/**` | Endpoint list/detail, command create/list/detail status, command result status ve audit list endpointleri calisir; hassas command type'lar bu adimda bloklu kalir. | `AdminEndpointCommandControllerTest`, `AdminEndpointAuditControllerTest`, `EndpointAdminCommandServiceTest`, `./mvnw -q -pl endpoint-admin-service test` PASS, `./mvnw -q -DskipTests test-compile` PASS, `git diff --check` PASS. |
| BE-009 | RBAC/OpenFGA entegrasyonu | `IN_PROGRESS` | BE-008 | security/config/permission integration | Admin API, `ENDPOINT_ADMIN` module uzerinde `viewer/manager` relation ayrimi ile enforce edilir; read endpoint'ler viewer, write endpoint'ler manager ister; local/dev fallback kontrolludur. | `common-auth` dependency, `OpenFgaAuthzConfig`, `EndpointAdminRequireModuleInterceptor`, `EndpointAdminWebMvcConfig`, controller `@RequireModule` annotation'lari, endpoint-admin Dockerfile common-auth install pattern'i. `AdminEndpointAuthorizationSecurityTest`, `EndpointAdminAuthorizationAnnotationTest`; `./mvnw -q -pl endpoint-admin-service -Dtest=AdminEndpointAuthorizationSecurityTest,EndpointAdminAuthorizationAnnotationTest test` PASS, `./mvnw -q -pl endpoint-admin-service test` PASS, `docker build -f endpoint-admin-service/Dockerfile -t endpoint-admin-service:be-009 .` PASS. Acik gate: OpenFGA store/model tuple seed + k8s live smoke. |
| BE-010 | Gateway route | `DONE` | BE-005, BE-008 | `api-gateway` config + GitOps follow-up | `/api/v1/endpoint-agent/**` gateway'de JWT'siz servise gider; `/api/v1/endpoint-admin/**` authenticated kalir. | `SecurityConfig` endpoint-agent permitAll, `application-k8s.yml` endpoint route'lari, GitOps `api-gateway-config` semantic route parity; live test route indexleri `18/19/20`. `./mvnw -q -pl api-gateway -Dtest=GatewaySecurityTest test` PASS, `./mvnw -q -pl api-gateway test` PASS, `kubectl kustomize kustomize/overlays/test` PASS, `kubectl kustomize kustomize/overlays/prod` PASS. |
| BE-011 | Agent live integration smoke | `TODO` | BE-006, BE-007, agent config | backend + platform-agent | Agent enroll/heartbeat/command poll/result backend'e real API ile gider. | Local/Parallels smoke |
| BE-012 | GitOps handoff | `IN_PROGRESS` | BE-002, BE-010 | platform-k8s-gitops | Deployment, Service, ConfigMap, ExternalSecret, ServiceMonitor, overlay image refs planlanir. | Backend commit `e9d8fd3` push edildi; workflow run `25066885496` ile endpoint-admin image uretildi, digest `sha256:05692ae314db4268a85870872318dc876e5606d028824511e770b807c2225b16`. `kustomize/base/apps/endpoint-admin-service/` manifest paketi, test overlay resource baglantisi, endpoint-admin digest pin, dormant prod patch'leri, `bootstrap/preflight-endpoint-admin-service.sh`, `bootstrap/apply-endpoint-admin-test-runtime.sh`, `docs/endpoint-admin-service-gitops-handoff.md`; test `endpoint_admin` DB + `endpoint_admin_service` schema, test Vault path/policy, `ExternalSecret/endpoint-admin-service-secrets Ready=True/SecretSynced`. `IMAGE_TAG=sha-e9d8fd3 ./bootstrap/preflight-endpoint-admin-service.sh` -> `failures=0 warnings=2`. `apply-runtime` selective apply -> Deployment `0/0`, PDB `minAvailable=0`, ServiceMonitor CRD yoklugu nedeniyle skip. Son `scale-smoke` -> Deployment `1/1`, live spec digest ref, imageID `...@sha256:05692ae314db4268a85870872318dc876e5606d028824511e770b807c2225b16`, endpoint registered `10.44.3.208:8096,10.44.3.208:8081`, direct service health `200`, no-auth agent/admin/status `401`. Gateway route drift reconcile edildi: live route indexleri `18/19/20`, api-gateway workflow run `25072953272`, live spec + pod imageID `...@sha256:6bd9ed83a9fbba3498b953e8ad301a23ca307f7cf6148323e9017b63b7c4f06a`; public smoke endpoint-agent `401 DEVICE_CREDENTIAL_MISSING`, admin/status `401 JWT token zorunludur`, regression `theme=200`, no-token `variants=401`. Shared base/prod aktivasyonu ayri gate. |
| BE-013 | Maintenance/uninstall token | `IN_PROGRESS` | BE-005, BE-009 | admin API + agent API | Agent stop/uninstall/maintenance icin hash-only, expiry'li, one-time token akisi vardir; token create/list/detail/revoke admin API, consume agent API ile calisir; consume sadece token'a bagli device tarafindan yapilir ve audit event olusur. | `EndpointMaintenanceTokenService`, `AdminMaintenanceTokenController`, `AgentMaintenanceTokenController`, `V3__endpoint_admin_maintenance_tokens.sql`; `EndpointMaintenanceTokenServiceTest`, `AdminMaintenanceTokenControllerTest`, `AgentMaintenanceTokenControllerTest`; `./mvnw -q -pl endpoint-admin-service -Dtest=EndpointMaintenanceTokenServiceTest,AdminMaintenanceTokenControllerTest,AgentMaintenanceTokenControllerTest test` PASS. Acik gate: BE-009 OpenFGA live config, image/GitOps/live smoke. |
| BE-014 | Tamper/offline audit | `TODO` | BE-006, BE-013 | audit/service | Service stop, uninstall attempt, heartbeat loss, revoked agent ve remediation olaylari auditlenir. | Audit controller tests |
| BE-015 | Endpoint identity compliance API | `TODO` | AG-021, AG-022, ID-001 | endpoint/admin API | Endpoint'in Local/AD/Entra/Hybrid join durumu, tenant/domain bilgisi ve logged-in identity sinifi admin API'de read-only gorunur. | Controller/service tests |
| BE-016 | Audit integrity hash-chain | `TODO` | BE-008, BE-013 | audit/model/migration | Audit event'ler append-only/hash-chain veya WORM uyumlu kanitla degistirilemezlik yuzeyi kazanir. | Migration + audit integrity tests |
| BE-017 | Destructive command saga/rollback | `TODO` | BE-016, OPS-001 | command/audit/service | State-changing komutlarda pre-check, reason, idempotency, partial failure state ve rollback/manual-review yolu tanimlanir. | Command saga tests |
| BE-018A | AD/M365 password reset connector design | `TODO` | ID-001, ID-002, IT-005, IT-007 | design docs + connector boundary | Graph API, LDAPS, service account, multi-domain, writeback, VPN/cached credential failure mode'lari tasarim gate'inde netlesir; kod yazilmaz. | Design review notes |
| BE-018B | AD/M365 password reset connector implementation | `BLOCKED` | BE-018A, BE-016, BE-017, IT pilot gates | connector/service | Tasarim mutabakati, RBAC/audit/saga/pilot gate kaniti olmadan baslamaz. | Yok |
| BE-019 | KVKK data retention enforcement | `TODO` | COMP-001, IT-009 | migration/jobs/config | Inventory, local user, identity ve audit verileri icin retention, anonimlestirme/silme ve export politikasi uygulanir. | Retention job tests |

-------------------------------------------------------------------------------
## 6. Servis Klasor Yapisi
-------------------------------------------------------------------------------

Onerilen backend servis yapisi:

```text
endpoint-admin-service/
  Dockerfile
  pom.xml
  src/
    main/
      java/com/example/endpointadmin/
        EndpointAdminServiceApplication.java
        config/
        security/
          AgentHmacAuthenticationFilter.java
          AgentPrincipal.java
          SecurityConfig.java
          SecurityConfigLocal.java
        enrollment/
          EnrollmentAdminController.java
          AgentEnrollmentController.java
          EnrollmentService.java
          EnrollmentToken.java
          AgentIdentity.java
        endpoint/
          EndpointAdminController.java
          EndpointService.java
          Endpoint.java
          EndpointRepository.java
        heartbeat/
          HeartbeatController.java
          HeartbeatService.java
        command/
          CommandAdminController.java
          AgentCommandController.java
          CommandService.java
          EndpointCommand.java
          EndpointCommandResult.java
        audit/
          EndpointAuditEvent.java
          EndpointAuditService.java
        dto/
      resources/
        application.properties
        application-local.properties
        application-k8s.yml
        application-test.yml
        db/migration/
          V1__endpoint_admin_baseline.sql
          V2__agent_identity_and_enrollment.sql
          V3__command_queue_and_results.sql
          V4__endpoint_audit_events.sql
    test/
      java/com/example/endpointadmin/
```

Paketler domain bazli tutulacak; command, enrollment, endpoint ve audit ayni
servis icinde ayrilacak. Ortak security util'leri servis disina tasinmayacak;
benzer ihtiyac ikinci serviste dogarsa `common-auth` tartisilir.

-------------------------------------------------------------------------------
## 7. Gateway ve Guvenlik Notlari
-------------------------------------------------------------------------------

Mevcut non-local gateway su anda `.anyExchange().authenticated()` kullanir.
Bu nedenle agent route icin gateway security config'te asagidaki ayrim gerekir:

```text
permitAll:
  POST /api/v1/endpoint-agent/enroll
  POST /api/v1/endpoint-agent/heartbeat
  POST /api/v1/endpoint-agent/inventory
  POST /api/v1/endpoint-agent/users/snapshot
  GET  /api/v1/endpoint-agent/commands/next
  POST /api/v1/endpoint-agent/commands/*/result

authenticated:
  /api/v1/endpoint-admin/**
```

Bu permitAll, anonim guvenlik anlamina gelmez. Agent endpointleri servis icinde
HMAC filter'dan gecmedikce 401 doner. Enrollment endpointinde tek kullanimlik
token dogrulanir.

K8s tarafinda `platform-k8s-gitops` configmap'i gateway route'larini env ile
override ediyor. Source repo `application-k8s.yml` ile GitOps configmap'i
ayni anda guncellenmeli; aksi halde source ve runtime drift olusur.

-------------------------------------------------------------------------------
## 8. Test Stratejisi
-------------------------------------------------------------------------------

Minimum test seti:

```text
1. Unit: HMAC canonical string, body hash, timestamp skew, nonce replay.
2. Unit: token hash/encryption, one-time enrollment token.
3. Repository/Flyway: migration schema ve unique constraints.
4. Service: command claim TTL ve idempotent result.
5. Controller: agent endpoints signed/unsigned response.
6. Controller: admin endpoints local/dev ve JWT profile guard.
7. Gateway: endpoint-agent route JWT'siz downstream'e gider.
8. Agent integration: Go agent mock veya real backend ile enroll/heartbeat/poll/result.
9. Live gate: Up, Functional ve Secured kanitlari ayri toplanir.
```

Build guard:

```bash
./mvnw -q -DskipTests -pl endpoint-admin-service -am test-compile
./mvnw -q -DskipTests -pl endpoint-admin-service -am verify
./mvnw -q -pl endpoint-admin-service test
./mvnw -q -DskipTests test-compile
```

Riskli adimlarda ilgili servis testleri `-DskipTests` olmadan calistirilir.

-------------------------------------------------------------------------------
## 9. Riskler ve Blokajlar
-------------------------------------------------------------------------------

| Risk | Etki | Onlem |
|---|---|---|
| `.claude/` untracked kalir | Kullanici/Claude calismasi bozulabilir | Bu klasore dokunma, stage/revert etme. |
| Gateway/GitOps hatti eksik kalir | Image uretimi hazir olsa bile runtime route/deployment olmaz | BE-010 gateway route ve BE-012 GitOps handoff ayri evidence ile kapatilacak. |
| Gateway agent route JWT isterse | Agent backend'e ulasamaz | `/api/v1/endpoint-agent/**` gateway permitAll + servis HMAC. |
| HMAC secret plaintext saklanirsa | Credential riski | Encrypted secret + hash; secret loglanmaz. |
| Nonce in-memory olursa | Multi-replica replay guard zayiflar | DB unique nonce tablosu kullan. |
| Command claim atomic degilse | Ayni command iki agent tarafindan alinabilir | Agent claim path'i device-scoped `findClaimCandidatesForDevice` + `PESSIMISTIC_WRITE` ile calisir. |
| Native batch claim metodu device-scoped degil | Agent claim flow'unda kullanilirsa baska cihazin command'i alinabilir | `claimDeliverableBatch` BE-007 scope disi; ileride device-scoped PG/Testcontainers kanitiyla ele alinacak. |
| Sensitive command erken acilirsa | Guvenlik ve audit riski | BE-008 admin create path'i simdilik `COLLECT_INVENTORY` ile sinirli; password reset/file access bloklu kalir. |
| GitOps route/source drift | Test/prod davranisi source'tan farkli olur | BE-012 ile GitOps handoff ayri evidence ister. |
| Local admin agent'i zorla durdurursa | Endpoint korumasi atlatilabilir | Local admin kaldirma, LAPS/JIT admin, MDM remediation, EDR tamper policy ve backend offline alert. |
| Imzasiz binary pilot'a giderse | EDR false positive, IT guven kaybi | SEC-001/SEC-002 code signing ve timestamp pilot oncesi gate olur. |
| Audit kaydi degistirilebilirse | Forensic ve KVKK/SOC2 kanit yuzeyi zayiflar | BE-016 hash-chain/WORM yuzeyi destructive komutlardan once ele alinir. |
| Domain password reset local reset ile karisirsa | Yetki modeli uyumsuzlugu, lockout ve sync gecikmesi riski | BE-015/ID-001/ID-002 ile identity source ayrimi yapilmadan connector acilmaz. |
| Cached credential senaryosu atlanirsa | Kullanici VPN disinda yeni sifreyle login olamaz veya eski cache davranisi belirsiz kalir | IT-007 altinda VPN, WHfB, BitLocker ve writeback etkileri incelenir. |

-------------------------------------------------------------------------------
## 10. Ilk Uygulama Sirasi
-------------------------------------------------------------------------------

Guvenli foundation kaniti var; guncel teknik sira artik paralel track olarak
takip edilir:

```text
Track A - Backend live gates:
  1. BE-009 OpenFGA store/model tuple seed + k8s live Up/Functional/Secured.
  2. BE-013 maintenance/uninstall token image + GitOps/live Up/Functional/Secured.
  3. BE-011 agent live integration smoke.

Track B - Identity read-only:
  1. AG-021 Windows identity inventory.
  2. AG-022 logged-in identity classification.
  3. ID-001/ID-002 discovery ve sync matrix.
  4. BE-015 endpoint identity compliance API.

Track C - Web:
  1. WEB-001 MFE scaffold.
  2. WEB-006 enrollment token UI.
  3. WEB-009 maintenance controls.

Track D - Pilot readiness:
  1. SEC-001/SEC-002 signing.
  2. AUDIT-001/AUDIT-002 audit integrity.
  3. COMP-001 data inventory.
  4. IT-001/IT-003/IT-006 pilot gates.
```

Bu turda password reset, file browse/download/upload ve AD islemleri acilmaz.
Maintenance token API'si ve endpoint-admin RBAC icin lokal backend kod/test kaniti var.
Siradaki backend hedefi, OpenFGA store/model tuple seed ve k8s live
Up/Functional/Secured kanitini uretmek, ardindan BE-013 image/GitOps/live
kapisina tasimaktir.
