# Platform Agent Roadmap

Bu belge faz ozetidir. Aktif takip, durum, kabul kriteri ve kanit icin
`docs/TRACKING-ROADMAP.md` kullanilir.

-------------------------------------------------------------------------------
## Faz 1 - Scaffold ve Simulator
-------------------------------------------------------------------------------

- Go repo iskeleti.
- Config, logging, protocol paketleri.
- Mock backend ile enrollment.
- Heartbeat.
- Command polling.
- `UNSUPPORTED` result modeli.
- Unit test iskeleti.
- Mock backend integration testi.
- Command claim/idempotency contract testi.

-------------------------------------------------------------------------------
## Faz 1.5 - Security Contract Hardening
-------------------------------------------------------------------------------

- HMAC-signed request tasarimi.
- Secret redaction testi.
- Offline state machine.
- Path traversal guardrail testi.
- Sensitive command rate limit beklentisi.
- Agent version check ve update manifest tasarimi.

-------------------------------------------------------------------------------
## Faz 2 - Windows POC
-------------------------------------------------------------------------------

- Windows service install/uninstall.
- Windows service tamper protection tasarimi.
- Basic inventory.
- Local user list.
- Logged-in user.
- Home/Desktop/Documents path resolver.
- Disable/enable local user.
- Windows CI veya lokal Windows runner test plani.
- EDR/antivirus pilot checklist.

-------------------------------------------------------------------------------
## Faz 3 - Backend/Web Entegrasyonu
-------------------------------------------------------------------------------

- `platform-backend/endpoint-admin-service`.
- `platform-web/apps/mfe-endpoint-admin`.
- Agent enrollment token UI.
- Endpoint list/detail.
- Command queue + audit.

-------------------------------------------------------------------------------
## Faz 3.5 - Pilot Readiness, Identity Discovery ve Audit Integrity
-------------------------------------------------------------------------------

- Windows Authenticode code signing ve timestamp pipeline.
- Agent update manifest imza/digest dogrulama tasarimi.
- Audit event hash-chain veya append-only storage stratejisi.
- Identity discovery read-only: Local/AD/Entra/Hybrid join sinifi.
- KVKK veri envanteri, retention ve pilot bilgilendirme notlari.
- D29 kanit disiplini: live islerde Up, Functional ve Secured kanitlari ayri.

-------------------------------------------------------------------------------
## Faz 4 - Local Password Reset ve File Path
-------------------------------------------------------------------------------

- HMAC signed request aktif.
- Local password reset command (SAM-only).
- Secret redaction tests.
- Reason required enforcement.
- Desktop/Documents/Downloads whitelist.
- Destructive command saga/rollback policy.

Domain ve M365/Entra password reset bu fazda acilmaz; ayri tasarim gate'i ister.

-------------------------------------------------------------------------------
## Faz 4.5 - Domain ve M365 Password Reset Tasarimi
-------------------------------------------------------------------------------

- Multi-domain discovery ve AD/Entra/M365 sync matrix.
- AD service account, LDAPS ve delegated permission tasarimi.
- Microsoft Graph app registration, admin consent ve role siniri.
- SSPR/password writeback, VPN, cached credential, BitLocker ve WHfB etkileri.
- `BE-018A` tasarim mutabakati olmadan connector implementation acilmaz.

-------------------------------------------------------------------------------
## Faz 5 - AD ve Deployment
-------------------------------------------------------------------------------

- AD discovery backend tarafinda.
- GPO startup script dokumani.
- SCCM/Intune paket notlari.
- Required app/remediation policy ile agent kaldirma-durdurma korumasi.
- Backend maintenance/uninstall token.
- Pilot rollout dashboard.
- Agent version check ve manual update flow.
- Rollbackable installer/uninstaller.

-------------------------------------------------------------------------------
## Faz 6 - osquery V2
-------------------------------------------------------------------------------

- osquery adapter.
- Installed software inventory.
- Process/service inventory.
- Compliance query packs.

-------------------------------------------------------------------------------
## Faz 7 - macOS
-------------------------------------------------------------------------------

- macOS launchd daemon.
- Inventory.
- Local user list.
- Home/Desktop/Documents path resolver.
- MDM/Jamf/Intune deployment notlari.

-------------------------------------------------------------------------------
## Faz 8 - Hardening
-------------------------------------------------------------------------------

- macOS notarization.
- WDAC/AppLocker/EDR tamper protection entegrasyonu.
- Agent auto-update implementasyonu.
- mTLS veya signed request.
- SIEM/audit export.
