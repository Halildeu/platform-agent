# Endpoint Platform Tracking Roadmap

Bu belge endpoint yonetim urunu icin takip edilebilir ana yol haritasidir.
`ROADMAP.md` faz ozetidir; bu belge aktif takip, durum ve kanit yuzeyidir.

-------------------------------------------------------------------------------
## 1. Durum Etiketleri
-------------------------------------------------------------------------------

| Durum | Anlam |
|---|---|
| `DONE` | Kod/dokuman tamamlandi ve kanit komutu ya da dosya referansi var. |
| `IN_PROGRESS` | Aktif calisiliyor, kabul kriteri henuz kapanmadi. |
| `TODO` | Baslanmadi. |
| `BLOCKED` | Teknik veya operasyonel bagimlilik bekliyor. |
| `WAITING_IT` | IT/ortam/hesap/pilot makine bilgisi bekliyor. |
| `RISK` | Baslanabilir ama guvenlik, rollout veya dogrulama riski var. |

Kapanis kurali:

```text
DONE yazmak icin acceptance criteria + evidence zorunludur.
```

Ileriye donuk live gate kurali:

```text
BE/AG/WEB/IT live smoke islerinde tek "smoke gecti" satiri yetmez.
Her live gate icin Up, Functional ve Secured kaniti ayri yazilir.
```

-------------------------------------------------------------------------------
## 2. Anlik Ozet
-------------------------------------------------------------------------------

| Alan | Durum | Not |
|---|---|---|
| Agent repo bootstrap | `DONE` | Go repo, klasor yapisi, docs ve local scripts hazir. |
| Agent MVP loop | `DONE` | Enroll, signed heartbeat, signed command poll, signed result submit testli. |
| Agent security base | `DONE` | HMAC helper, redaction, path guardrail, offline state tracker testli. |
| Windows service | `DONE` | SCM install/start/status/stop/uninstall Parallels Windows 11 uzerinde dogrulandi. |
| Windows local user adapter | `DONE` | Read-only local user list Parallels Windows 11 uzerinde dogrulandi. |
| Windows event/log path | `DONE` | File log path, Event Log source ve write-time redaction testli. |
| Password reset (local) | `BLOCKED` | RBAC/HMAC/audit + destructive saga + pilot gate olmadan acilmayacak. Domain/M365 reset ayri track. |
| Identity / M365 / domain ayrimi | `TODO` | Local Windows account, AD domain account ve Entra/M365 account ayrimi henuz modele alinmadi. |
| Code signing | `TODO` | Windows Authenticode sertifika, timestamp ve imzali build pipeline henuz yok; IT pilot oncesi gate. |
| Audit integrity | `TODO` | Audit kayitlari icin hash-chain/WORM/append-only kanit henuz yok. |
| KVKK / veri envanteri | `TODO` | Agent'in topladigi kisisel veri kategorileri, retention ve silme politikasi henuz ayrilastirilmadi. |
| Destructive command saga | `TODO` | Disable/enable/password/file/maintenance gibi state-changing komutlar icin partial failure/rollback modeli henuz yok. |
| Agent tamper protection | `IN_PROGRESS` | Windows installer/service hardening tamamlandi; remediation/policy entegrasyonu `AG-020` ve `IT-006` kapsaminda. |
| Backend service | `IN_PROGRESS` | `endpoint-admin-service` acildi; scaffold, DB model, enrollment, HMAC agent auth, heartbeat API, command claim/result API, admin command/status/audit API, maintenance token API, OpenFGA tabanli admin RBAC guard, Dockerfile/CI image matrix ve gateway route testli. Backend branch push edildi ve GHCR image `sha-e9d8fd3` kanitlandi. GitOps test overlay resource + digest image pin eklendi; test DB/Vault/ExternalSecret gate'leri gecti. Direct test runtime smoke `Deployment 1/1`, imageID digest ve direct service `200/401` kaniti verdi. Gateway route drift reconcile edildi; api-gateway digest image rollout ve public endpoint-agent/admin/status smoke kaniti alindi. Shared base/prod inactive kalir. Maintenance token ve RBAC kod/test kaniti lokal backend seviyesinde var; OpenFGA store/model live config, image/GitOps kaniti ayri gate. |
| Web MFE | `TODO` | `platform-web/apps/mfe-endpoint-admin` henuz acilmadi. |
| Windows installer asset | `DONE` | Package, install, start, stop, uninstall ve cleanup Parallels Windows 11 uzerinde dogrulandi. |
| IT pilot/deployment | `WAITING_IT` | Windows pilot host, deployment yontemi ve EDR allowlist gerekir. |

-------------------------------------------------------------------------------
## 3. Agent Is Kalemleri
-------------------------------------------------------------------------------

| ID | Is | Durum | Acceptance criteria | Evidence |
|---|---|---|---|---|
| AG-001 | Go repo ve klasor yapisi | `DONE` | `cmd`, `internal`, `docs`, `scripts`, `installers`, `deployments` var. | `git status`, `docs/REPO-STRUCTURE.md` |
| AG-002 | Local setup ve build scriptleri | `DONE` | Tek komutla test ve build calisiyor. | `./scripts/test/local.sh`, `./scripts/build/local.sh` |
| AG-003 | Command contract | `DONE` | Whitelist command type, claim, idempotency ve forbidden raw shell dokumante. | `docs/COMMAND-CONTRACT.md` |
| AG-004 | HMAC signing helper | `DONE` | Request body degisirse signature verify fail oluyor. | `internal/security/signature_test.go` |
| AG-005 | Secret redaction | `DONE` | password/token/secret/key alanlari recursive redacted. | `internal/security/redact_test.go` |
| AG-006 | Path whitelist guardrail | `DONE` | `..`, drive override ve sibling prefix reddediliyor. | `internal/files/whitelist_test.go` |
| AG-007 | Offline/degraded state tracker | `DONE` | 3 hata degraded, 10 hata offline, success online. | `internal/state/state_test.go` |
| AG-008 | Agent MVP loop | `DONE` | Enroll, signed heartbeat, signed command poll, execute, signed result submit. | `internal/app/runner_test.go` |
| AG-009 | Basic inventory command | `DONE` | `COLLECT_INVENTORY` command result uretiyor. | `internal/commands/executor_test.go` |
| AG-010 | Logged-in user/home path commands | `DONE` | Runtime current user ve home paths result uretiyor. | `internal/users/current.go`, `internal/commands/executor.go` |
| AG-011 | Windows binary cross-build | `DONE` | macOS uzerinden `endpoint-agent.exe` uretilebiliyor. | `GOOS=windows GOARCH=amd64 go build ...` |
| AG-012 | Windows service wrapper | `DONE` | Install/uninstall/status/start/stop komutlari Windows SCM ile calisir. | `scripts/test/windows-live.ps1` Parallels Windows 11: install ok, start ok, status RUNNING, stop ok, status STOPPED, uninstall ok. |
| AG-013 | Windows local user adapter | `DONE` | Local users read-only listelenir. | `scripts/test/windows-live.ps1` Parallels Windows 11: `diagnose local-users` Administrator, DefaultAccount, Guest, WDAGUtilityAccount, halilkocoglu listesi dondu. **Note (2026-05-21 capability coherence)**: `DISABLE_LOCAL_USER` / `ENABLE_LOCAL_USER` capability `internal/inventory/inventory.go` raporundan kaldırıldı çünkü `internal/commands/executor.go` switch'inde adapter henüz yoktu; false advertising kapatıldı. Source-fixed via regression test `TestRuntimeCapabilitiesAllDispatchable` (executor coherence guard). **Verified 2026-05-24** (platform-agent#8): fresh Parallels Windows 11 (HALILKOOLUB735) live smoke `scripts/test/windows-live.ps1` full pass — install → service RUNNING → tamper protection + SDDL configured → event log source verified → read-only local users diagnostic 5 user JSON (Administrator/DefaultAccount/Guest/WDAGUtilityAccount disabled + halilkocoglu enabled) → log path `C:\ProgramData\EndpointAgentCodexTest\logs\endpoint-agent.log` → maintenance token stop + uninstall → service removed clean + install dir + log dir + env vars cleared. Build SHA256 `53a45b637147145025b68c5ab1235ae6e6ee491cef9f6925f83a61fb7fb42669` (main HEAD `2e49f8b` post BE-011 wire reconciliation). Capability list post-fix: `COLLECT_INVENTORY, GET_LOGGED_IN_USER, GET_USER_HOME_PATHS, LIST_LOCAL_USERS` (Windows only) — `DISABLE_LOCAL_USER`/`ENABLE_LOCAL_USER` correctly absent. Adapter implementasyonu ayrı board issue olarak takip edilecek; adapter geldiğinde capability listesine geri eklenecek. |
| AG-014 | Windows event/log path | `DONE` | Agent log path ve event source belirlenir, secret loglanmaz. | `docs/LOGGING.md`, `internal/logging/logger_test.go`, `internal/security/redact_text_test.go`, `./scripts/test/local.sh`, `./scripts/build/windows.sh` |
| AG-015 | Windows installer asset | `DONE` | Manual install script ve uninstall script rollbackable olur. | `scripts/test/windows-live.ps1` Parallels Windows 11: pre-clean, install -Start, status, log check, uninstall -RemoveConfig -RemoveLogs tamamlandi. |
| AG-016 | Password reset local adapter | `BLOCKED` | Backend RBAC/HMAC/audit + Windows pilot olmadan acilmaz. | Yok |
| AG-017 | File access adapter | `RISK` | Sadece Desktop/Documents/Downloads whitelist, symlink/junction kontrolu ile. | Yok |
| AG-018 | Update manifest check | `TODO` | Agent backend'den version/update manifest okuyabilir. | Yok |
| AG-019 | Windows tamper protection | `DONE` | Service ACL/SDDL, failure action restart, protected install/config ACL, uninstall token flow tasarlanir ve Windows testinde dogrulanir. | `./scripts/test/local.sh` PASS. `./scripts/build/windows-package.sh` PASS. `scripts/test/windows-live.ps1` Parallels Windows 11: service delayed-auto-start, failure action RESTART, SDDL Authenticated Users icin SERVICE_STOP yok, wrong maintenance token stop reddedildi, correct maintenance token stop/uninstall ok, install/config/log ACL hardening uygulandi, cleanup ok. |
| AG-020 | Agent health remediation hooks | `TODO` | Intune/GPO/SCCM veya scheduled remediation ile stopped/missing agent tekrar ayaga kaldirilabilir. | Yok |
| AG-021 | Windows identity inventory | `TODO` | Agent `dsregcmd /status`, domain/workgroup, tenant/device id, join state ve VPN/domain reachability bilgisini read-only toplar. | Yok |
| AG-022 | Logged-in identity classification | `TODO` | Son/current user LOCAL, DOMAIN veya ENTRA olarak siniflanir; UPN, SID ve domain bilgisi secret/log sizintisi olmadan raporlanir. | Yok |
| AG-023 | Domain user adapter read-only | `TODO` | Domain ortaminda kullanici status/list sorgusu read-only ve capability-gated calisir; password reset acmaz. | Yok |
| AG-024 | Signed update manifest verification | `TODO` | Agent update manifest imzasini dogrular; imzasiz veya digest uyusmayan update reddedilir. | Yok |

-------------------------------------------------------------------------------
## 4. Backend Is Kalemleri
-------------------------------------------------------------------------------

Backend repo:

```text
/Users/halilkocoglu/Documents/platform-backend
```

| ID | Is | Durum | Acceptance criteria | Evidence |
|---|---|---|---|---|
| BE-000 | Repo guard ve branch hazirligi | `DONE` | Backend branch hazirlanir, bize ait olmayan degisiklikler korunur. | Branch `codex/be-001-endpoint-admin-service-platform-backend`; `.claude/` dokunulmadi. |
| BE-001 | `endpoint-admin-service` scaffold | `DONE` | Spring Boot module root `pom.xml` icine eklenir. | `platform-backend/endpoint-admin-service`, root `pom.xml`, `./mvnw -q -DskipTests test-compile` PASS. |
| BE-002 | Config, profiles, Dockerfile, CI | `DONE` | local/k8s config, Dockerfile ve CI image matrix mevcut servislerle uyumlu olur. | `endpoint-admin-service/Dockerfile`, `.github/workflows/ci-image-push.yml`, `.github/workflows/ci-mvn-check.yml`, `./mvnw -q -DskipTests -pl endpoint-admin-service package` PASS, `docker build -f endpoint-admin-service/Dockerfile -t endpoint-admin-service:be-002 .` PASS, `docker run --rm --entrypoint id endpoint-admin-service:be-002 -u` -> `1000`, `./mvnw -q -DskipTests verify` PASS, `./mvnw -q -DskipTests test-compile` PASS. |
| BE-003 | DB migration ve JPA model | `DONE` | endpoint, agent identity, command queue, command result, audit tablolari Flyway ile gelir. | `V1__endpoint_admin_baseline.sql`, `V2__endpoint_admin_domain.sql`, `EndpointDomainRepositoryTest`, `./mvnw -q -pl endpoint-admin-service test` PASS. |
| BE-004 | HMAC verifier | `DONE` | Timestamp skew, nonce replay, body hash ve signature dogrulanir. | `HmacDeviceCredentialProviderTest`, `DeviceCredentialAuthenticationFilterTest`, nonce cleanup job, `./mvnw -q -pl endpoint-admin-service test` PASS. |
| BE-005 | Agent enrollment API | `DONE` | Tek kullanimlik enrollment token ile agent credential uretilir. | `AdminEndpointEnrollmentControllerTest`, `AgentEnrollmentControllerTest`, `EndpointEnrollmentServiceTest`, `./mvnw -q -pl endpoint-admin-service test` PASS. |
| BE-006 | Heartbeat API | `DONE` | Agent state, capabilities, version ve lastSeen kaydedilir. | `AgentHeartbeatControllerTest`, `EndpointHeartbeatServiceTest`, `./mvnw -q -pl endpoint-admin-service test` PASS, `./mvnw -q -DskipTests test-compile` PASS. |
| BE-007 | Command queue claim/result | `DONE` | Agent authenticated device icin `QUEUED` veya claim TTL'i dolmus `DELIVERED` komutu claim eder; result submit idempotent calisir. | `AgentCommandControllerTest`, `EndpointAgentCommandServiceTest`, `./mvnw -q -pl endpoint-admin-service test` PASS, `./mvnw -q -DskipTests test-compile` PASS, `git diff --check` PASS. |
| BE-008 | Admin endpoint API | `DONE` | Endpoint list/detail, command create/list/detail status, command result status ve audit list endpointleri calisir; hassas command type'lar bu adimda bloklu kalir. | `AdminEndpointCommandControllerTest`, `AdminEndpointAuditControllerTest`, `EndpointAdminCommandServiceTest`, `./mvnw -q -pl endpoint-admin-service test` PASS, `./mvnw -q -DskipTests test-compile` PASS, `git diff --check` PASS. |
| BE-009 | RBAC/OpenFGA integration | `IN_PROGRESS` | Admin API, `ENDPOINT_ADMIN` module uzerinde `viewer/manager` relation ayrimi ile enforce edilir; local/dev davranisi bozulmaz, k8s OpenFGA config env ile acilir. | `common-auth` dependency, `OpenFgaAuthzConfig`, `EndpointAdminRequireModuleInterceptor`, `EndpointAdminWebMvcConfig`, controller `@RequireModule` annotation'lari, endpoint-admin Dockerfile common-auth install pattern'i. `AdminEndpointAuthorizationSecurityTest`, `EndpointAdminAuthorizationAnnotationTest`; `./mvnw -q -pl endpoint-admin-service -Dtest=AdminEndpointAuthorizationSecurityTest,EndpointAdminAuthorizationAnnotationTest test` PASS, `./mvnw -q -pl endpoint-admin-service test` PASS, `docker build -f endpoint-admin-service/Dockerfile -t endpoint-admin-service:be-009 .` PASS. Acik gate: OpenFGA store/model tuple seed + k8s live smoke. |
| BE-010 | Gateway route | `DONE` | `/api/v1/endpoint-admin/**` ve `/api/v1/endpoint-agent/**` route olur. | `api-gateway` `SecurityConfig` endpoint-agent permitAll, `application-k8s.yml` endpoint route'lari, GitOps `api-gateway-config` semantic route parity; live test route indexleri `18/19/20`. `./mvnw -q -pl api-gateway -Dtest=GatewaySecurityTest test` PASS, `./mvnw -q -pl api-gateway test` PASS, `kubectl kustomize kustomize/overlays/test` PASS, `kubectl kustomize kustomize/overlays/prod` PASS. |
| BE-011 | Agent live integration smoke | `TODO` | Agent enroll/heartbeat/command poll/result backend'e real API ile gider. | Yok |
| BE-012 | GitOps handoff | `IN_PROGRESS` | Deployment, Service, ConfigMap, ExternalSecret, ServiceMonitor planlanir. | Backend commit `e9d8fd3` push edildi; workflow run `25066885496` ile endpoint-admin image uretildi, digest `sha256:05692ae314db4268a85870872318dc876e5606d028824511e770b807c2225b16`. `platform-k8s-gitops/kustomize/base/apps/endpoint-admin-service/` manifest paketi, test overlay resource baglantisi, endpoint-admin digest pin, dormant prod patch'leri, `bootstrap/preflight-endpoint-admin-service.sh`, `bootstrap/apply-endpoint-admin-test-runtime.sh`, `docs/endpoint-admin-service-gitops-handoff.md`; test `endpoint_admin` DB + `endpoint_admin_service` schema, test Vault path/policy, `ExternalSecret/endpoint-admin-service-secrets Ready=True/SecretSynced`. `IMAGE_TAG=sha-e9d8fd3 ./bootstrap/preflight-endpoint-admin-service.sh` -> `failures=0 warnings=2`. `apply-runtime` selective apply -> Deployment `0/0`, PDB `minAvailable=0`, ServiceMonitor CRD yoklugu nedeniyle skip. Son `scale-smoke` -> Deployment `1/1`, live spec digest ref, imageID `...@sha256:05692ae314db4268a85870872318dc876e5606d028824511e770b807c2225b16`, endpoint registered `10.44.3.208:8096,10.44.3.208:8081`, direct service health `200`, no-auth agent/admin/status `401`. Gateway route drift reconcile edildi: live route indexleri `18/19/20`, api-gateway workflow run `25072953272`, live spec + pod imageID `...@sha256:6bd9ed83a9fbba3498b953e8ad301a23ca307f7cf6148323e9017b63b7c4f06a`; public smoke endpoint-agent `401 DEVICE_CREDENTIAL_MISSING`, admin/status `401 JWT token zorunludur`, regression `theme=200`, no-token `variants=401`. Shared base/prod aktivasyonu ayri gate. |
| BE-013 | Maintenance/uninstall token API | `IN_PROGRESS` | Agent stop/uninstall sadece auditli one-time maintenance token ile yetkilendirilir; admin create/list/detail/revoke ve agent consume akislari hash-only token, expiry, device match ve audit event ile calisir. | `EndpointMaintenanceTokenService`, `AdminMaintenanceTokenController`, `AgentMaintenanceTokenController`, `V3__endpoint_admin_maintenance_tokens.sql`; `EndpointMaintenanceTokenServiceTest`, `AdminMaintenanceTokenControllerTest`, `AgentMaintenanceTokenControllerTest`; `./mvnw -q -pl endpoint-admin-service -Dtest=EndpointMaintenanceTokenServiceTest,AdminMaintenanceTokenControllerTest,AgentMaintenanceTokenControllerTest test` PASS. Acik gate: BE-009 OpenFGA live config, image/GitOps/live smoke. |
| BE-014 | Tamper/offline audit | `TODO` | Service stop, uninstall attempt, heartbeat loss ve agent revoked olaylari audit/alert olur. | Yok |
| BE-015 | Endpoint identity compliance API | `TODO` | Endpoint'in Local/AD/Entra/Hybrid join durumu, tenant/domain bilgisi ve logged-in identity sinifi admin API'de read-only gorunur. | Yok |
| BE-016 | Audit integrity hash-chain | `TODO` | Audit event'ler append-only/hash-chain veya WORM uyumlu kanitla degistirilemezlik yuzeyi kazanir. | Yok |
| BE-017 | Destructive command saga/rollback | `TODO` | State-changing komutlarda pre-check, reason, idempotency, partial failure state ve rollback/manual-review yolu tanimlanir. | Yok |
| BE-018A | AD/M365 password reset connector design | `TODO` | Graph API, LDAPS, service account, multi-domain, writeback, VPN/cached credential failure mode'lari tasarim gate'inde netlesir; kod yazilmaz. | Yok |
| BE-018B | AD/M365 password reset connector implementation | `BLOCKED` | BE-018A tasarim mutabakati, RBAC/audit/saga/pilot gate kaniti olmadan baslamaz. | Yok |
| BE-019 | KVKK data retention enforcement | `TODO` | Inventory, local user, identity ve audit verileri icin retention, anonimlestirme/silme ve export politikasi uygulanir. | Yok |

-------------------------------------------------------------------------------
## 5. Web Is Kalemleri
-------------------------------------------------------------------------------

Web repo:

```text
/Users/halilkocoglu/Documents/platform-web
```

| ID | Is | Durum | Acceptance criteria | Evidence |
|---|---|---|---|---|
| WEB-001 | `mfe-endpoint-admin` scaffold | `IN_PROGRESS` | Vite/MF app olusur, shell remote olarak taninir. **Source-ready**: `platform-web/origin/main apps/mfe-endpoint-admin/` 26 dosya; `package.json`, `vite.config.ts`, `index.html`, `bootstrap.tsx`. Runtime route acceptance backend canonical main + D29-EA Secured gate sonrası. | `platform-web` PR #287 `fe-001 reapply — devices + audit + build-time-omit shell wiring`; `git ls-tree -r origin/main apps/mfe-endpoint-admin \| wc -l = 26`. |
| WEB-002 | Shell route | `IN_PROGRESS` | `/admin/endpoints` route'u protected olarak acilir. **Source-ready**: `apps/mfe-endpoint-admin/src/app/router/EndpointAdminRouter.tsx`. Runtime route flag enable acceptance backend canonical main + Secured sonrası. | `platform-web/origin/main` source mevcut; runtime gated. |
| WEB-003 | Endpoint list | `IN_PROGRESS` | Hostname, OS, state, lastSeen, agent version listelenir. **Source-ready**: `apps/mfe-endpoint-admin/src/pages/devices/EndpointDevicesPage.tsx` + test. Runtime acceptance backend canonical main + Secured sonrası. | `platform-web/origin/main` source mevcut; runtime gated. |
| WEB-004 | Endpoint detail tabs | `IN_PROGRESS` | Inventory, Users, Files, Commands, Audit tablari var. **Source-ready (partial)**: `apps/mfe-endpoint-admin/src/pages/audit/EndpointAuditPage.tsx` + `EndpointStatusPage.tsx`; tüm tab inventarına ulaşmak için detail surface tamamlanması pending. Runtime acceptance backend canonical main + Secured sonrası. | `platform-web/origin/main` partial source mevcut; runtime gated. |
| WEB-005 | Command picker | `IN_PROGRESS` | Freeform command yok; yalniz whitelist action form'lari var. **Source-ready (partial)**: `apps/mfe-endpoint-admin/src/app/services/endpointAdminApi.ts` API surface + entity types; command picker UI deepening pending. Runtime acceptance backend canonical main + Secured sonrası. | `platform-web/origin/main` partial source mevcut; runtime gated. |
| WEB-006 | Enrollment token UI | `TODO` | Token uretilir, expiry ve tek kullanim bilgisi gosterilir. | Yok |
| WEB-007 | Audit view | `TODO` | Actor, endpoint, command, reason, status ve zaman bilgisi gorunur. | Yok |
| WEB-008 | i18n | `TODO` | TR/EN key'leri ortak dict pattern'ine eklenir. | Yok |
| WEB-009 | Agent maintenance controls | `TODO` | Yetkili admin maintenance/uninstall token uretir; reason ve expiry zorunludur. | Yok |
| WEB-010 | Identity compliance panel | `TODO` | Endpoint list/detail ekraninda Local/AD/Entra/Hybrid join, domain, tenant ve login identity uyumlulugu gorunur; aksiyon butonu yoktur. | Yok |

-------------------------------------------------------------------------------
## 6. Identity / Microsoft 365 Is Kalemleri
-------------------------------------------------------------------------------

Bu paket, kullanici mail sifresi ile bilgisayar giris sifresini ayni hale
getirme hedefini dogru sinirlara ayirir. Bu alanda sifre degistirme kodu,
read-only discovery ve uyumluluk raporu gelmeden acilmaz.

| ID | Is | Durum | Acceptance criteria | Evidence |
|---|---|---|---|---|
| ID-001 | Multi-domain identity discovery | `TODO` | AD domain, NetBIOS, forest, tenant, mail domain ve cihaz join tipleri tek matriste ayrilir. | Yok |
| ID-002 | AD/Entra/M365 sync matrix | `TODO` | PHS/PTA/Federation, password writeback, SSPR, Hybrid Join ve WHfB durumu IT bilgisiyle dokumante edilir. | Yok |
| ID-003 | Cached credential/offline scenario matrix | `TODO` | VPN yokken domain cached credential, BitLocker recovery, WHfB PIN ve MFA reset etkileri senaryolastirilir. | Yok |
| ID-004 | Password reset connector decision gate | `TODO` | Local SAM, AD/LDAPS ve Graph/M365 connector'lari icin yetki, audit, rate limit ve rollback karar tablosu cikmadan implementation acilmaz. | Yok |

-------------------------------------------------------------------------------
## 7. Security / Audit / Compliance / Ops Gate Is Kalemleri
-------------------------------------------------------------------------------

| ID | Is | Durum | Acceptance criteria | Evidence |
|---|---|---|---|---|
| SEC-001 | Windows code signing certificate | `TODO` | Authenticode sertifika tipi, private key saklama modeli ve imza yetkilisi netlesir. | Yok |
| SEC-002 | Signing + timestamp pipeline | `TODO` | Windows binary/installer imzalanir, timestamp alir ve digest/signature kaniti CI veya release notuna yazilir. | Yok |
| SEC-003 | Update signature verification | `TODO` | Agent update manifest ve binary digest/imza dogrulamasini zorunlu kilar. | Yok |
| AUDIT-001 | Append-only audit storage | `TODO` | Audit kayitlari admin tarafindan bile sessizce silinemez/degistirilemez; storage stratejisi secilir. | Yok |
| AUDIT-002 | Command integrity receipts | `TODO` | Komut istegi, actor, agent receipt ve result hash/signature zinciriyle iliskilenir. | Yok |
| AUDIT-003 | Destructive action pre/post snapshot | `TODO` | Disable/enable/password/file/maintenance aksiyonlarinda uygun pre/post snapshot veya neden yok bilgisi auditlenir. | Yok |
| COMP-001 | Data inventory + DPIA | `TODO` | Agent/backend tarafindan toplanan kisisel veri kategorileri, amac, saklama suresi ve erisim rolu dokumante edilir. | Yok |
| COMP-002 | Pilot user notice and approval | `TODO` | IT pilot kapsaminda kullanici bilgilendirme/onay metni ve kurum ici onay yuzeyi netlesir. | Yok |
| OPS-001 | Destructive command saga policy | `TODO` | Her state-changing komut icin retry, timeout, compensation, manual-review ve alert state'leri tanimlanir. | Yok |

-------------------------------------------------------------------------------
## 8. IT ve Pilot Is Kalemleri
-------------------------------------------------------------------------------

| ID | Is | Durum | Acceptance criteria | Evidence |
|---|---|---|---|---|
| IT-001 | Pilot Windows endpoint | `WAITING_IT` | 1 test Windows 10/11 x64 makine ve dummy local user hazir. | Yok |
| IT-002 | Deployment yontemi | `WAITING_IT` | Manual/GPO/Intune/SCCM pilot yontemi secildi. | Yok |
| IT-003 | EDR/AV allowlist | `WAITING_IT` | Binary path, publisher/signing ve network egress IT ile onaylandi. | Yok |
| IT-004 | Backend test URL | `TODO` | Agent'in outbound HTTPS ile erisecegi test endpoint var. | Yok |
| IT-005 | AD service account | `TODO` | AD islemleri icin ayri service account ve yetki modeli tasarlanir. | Yok |
| IT-006 | Tamper protection policy | `WAITING_IT` | Intune/GPO/SCCM required app, EDR tamper policy, WDAC/AppLocker ve local admin modeli netlesir. | Yok |
| IT-007 | Password writeback/VPN/WHfB assessment | `TODO` | SSPR writeback, Always On/Pre-logon VPN, cached credential, BitLocker ve WHfB etkileri IT ile degerlendirilir. | Yok |
| IT-008 | Hybrid Join / Intune / Autopilot pilot plan | `TODO` | Mevcut cihazlar icin format gerektirmeyen Hybrid Join/Intune yolu ve yeni cihazlar icin Autopilot yolu ayrilir. | Yok |
| IT-009 | KVKK/DPO operational approval | `TODO` | Pilot veri toplama kapsami, veri saklama suresi ve sorumlu ekip icin kurum ici onay alinir. | Yok |

-------------------------------------------------------------------------------
## 9. Oncelik Sirasi
-------------------------------------------------------------------------------

Siradaki isler tek seri liste degil; paralel ama gate'li track olarak takip
edilir. Live gate'lerde Up, Functional ve Secured kaniti ayri tutulur.

| Track | Siradaki isler | Gate |
|---|---|---|
| A - Backend live gates | `BE-009` OpenFGA live, `BE-013` maintenance token live, `BE-011` agent live integration | Up + Functional + Secured kaniti |
| B - Identity read-only | `AG-021`, `AG-022`, `ID-001`, `ID-002`, `BE-015`, `WEB-010` | Sifre reset aksiyonu yok; sadece envanter/rapor |
| C - Web MFE | `WEB-001`, `WEB-006`, `WEB-009` | Mock contract ile baslayabilir; backend contract drift kontrolu gerekir |
| D - Pilot readiness | `SEC-001`, `SEC-002`, `AUDIT-001`, `AUDIT-002`, `COMP-001`, `IT-001`, `IT-003`, `IT-006` | IT pilot oncesi imza, audit ve EDR/MDM yuzeyi |
| E - Password reset / file access | `OPS-001`, `BE-017`, `AG-016`, `BE-018A`, `BE-018B`, `AG-017` | RBAC, audit integrity, saga, pilot ve identity discovery olmadan acilmaz |

En yakin 1-3 uygulama hedefi:

1. `BE-009` OpenFGA store/model tuple seed + k8s live Up/Functional/Secured kaniti.
2. `BE-013` maintenance/uninstall token image + GitOps/live Up/Functional/Secured kaniti.
3. `AG-021` Windows identity inventory tasarim/kod veya `WEB-001` MFE scaffold; hangisi daha az dis bagimlilikliyse once alinir.

Password reset ve file access su anda oncelik degil. Bu iki islem identity
discovery, RBAC, audit integrity, destructive saga ve pilot gate kanitlari
gelmeden acilmaz.

-------------------------------------------------------------------------------
## 10. Haftalik Takip Rutini
-------------------------------------------------------------------------------

Her calisma sonunda:

```text
1. Degisen is kaleminin status'u guncellenir.
2. DONE icin evidence satiri doldurulur.
3. Yeni risk/blokaj varsa ilgili tabloya eklenir.
4. `./scripts/test/local.sh` veya ilgili repo testi calistirilir.
5. Sonraki 1-3 is kalemi net yazilir.
6. Kullaniciya kisa sonuc raporu verilir.
```

Agent icin minimum evidence komutlari:

```bash
./scripts/test/local.sh
./scripts/build/local.sh
./scripts/build/windows.sh
```

-------------------------------------------------------------------------------
## 11. Kisa Sonuc Raporu Formati
-------------------------------------------------------------------------------

Her isten sonra kullaniciya en fazla 5 satirlik sonuc raporu verilir:

```text
Is: <ID ve kisa ad>
Durum: <DONE/IN_PROGRESS/BLOCKED>
Degisenler: <ana dosya veya modul>
Kanit: <calisan test/komut veya neden calismadi>
Siradaki: <1 net adim>
```

Uzun aciklama yalniz risk, hata veya kullanici karar ihtiyaci varsa eklenir.
