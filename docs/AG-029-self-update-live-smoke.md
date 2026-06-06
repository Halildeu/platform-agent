# AG-029 Self-Update Live Smoke Runbook

This runbook defines the evidence needed before AG-029 signed self-update can
be treated as accepted on a real Windows endpoint. It is intentionally stricter
than a green CI run: CI proves source behavior; this runbook proves the
service can stage, preflight, activate, and come back with the expected
version.

## 1. Scope boundary

AG-029 is a two-phase update:

1. `UPDATE_AGENT` command stages a candidate binary and posts a backend result.
2. A local activation helper runs only after the result has been posted.

The staging command result must never claim activation. Activation evidence is
separate and is proved by local preflight/activation output plus a later agent
heartbeat or update-state record.

Current PR #59 provides the agent-side source surface for staging,
preflight, activation helper, rollback-on-activation-failure, and the CLI
entry points:

```text
endpoint-agent self-update preflight --staging-id <id>
endpoint-agent self-update activate   --staging-id <id>
endpoint-agent self-update status     --staging-id <id>
```

The full backend-issued live chain requires the backend command-create surface
from platform-backend PR #489 (BE-032) to be merged and deployed. That PR adds
the dedicated release-catalog-bound `UPDATE_AGENT` dispatch endpoint; this
runbook must not use the generic command endpoint for self-update.

PR #59 also adds an opt-in service wiring switch:

```text
ENDPOINT_AGENT_SELF_UPDATE_AUTO_ACTIVATE=true
ENDPOINT_AGENT_SELF_UPDATE_ACTIVATION_TIMEOUT=2m
```

The Windows installer can write this opt-in plus the rest of the AG-029 local
trust policy into the service-specific Environment regkey:

```powershell
.\install.ps1 `
  -SelfUpdateEnabled `
  -SelfUpdateAllowedHosts "github.com,objects.githubusercontent.com" `
  -SelfUpdateSignerThumbprints "<thumbprint>" `
  -SelfUpdateMaxSeenVersion "0.1.0" `
  -SelfUpdateAutoActivate `
  -Start
```

With this switch enabled, the runner starts a separate
`endpoint-agent self-update activate ...` helper only after the staging result
has been posted to the backend. The intermediate
`ACTIVATION_HELPER_STARTED` outcome is not acceptance evidence. A green smoke
still requires the path-free activation outcome, the `EndpointAgent` service
running after activation, and backend heartbeat/update-state proof with
`AgentVersion == targetVersion`.

## 2. Required environment

Run on an IT-owned or lab-owned Windows 11 endpoint where the operator is
allowed to stop/start the `EndpointAgent` service.

Required:

- elevated PowerShell
- `EndpointAgent` service installed and running
- current `endpoint-agent.exe` path known
- target `endpoint-agent.exe` artifact signed by an allowed signer policy
- backend endpoint reachable over HTTPS for the full-chain mode
- no raw bearer token, password, private key, webhook URL, or HMAC secret in
  captured logs

Recommended evidence directory:

```powershell
$EvidenceRoot = "C:\ProgramData\EndpointAgentEvidence\AG029"
New-Item -ItemType Directory -Force -Path $EvidenceRoot | Out-Null
```

## 3. Evidence matrix

| Gate | Evidence | Accept condition |
|---|---|---|
| Source provenance | PR / commit / artifact SHA256 / signature signer | Artifact maps to reviewed source and signer is expected |
| Service baseline | service status + current version | `EndpointAgent` running before staging |
| Staging result | backend command result `details.update` | `stageStatus=STAGED_ACTIVATION_READY`; includes opaque `stagingId` + `activationPlanId`; no filesystem path |
| Preflight | `self-update preflight` JSON | `status=READY`, `currentBinaryPresent=true`, `stagedBinaryVerified=true`; no filesystem path |
| Helper launch | runner log or helper-start outcome | Optional `ACTIVATION_HELPER_STARTED`; support evidence only, not green acceptance |
| Activation | `self-update activate` JSON | `status=ACTIVATED`, `serviceRunningVerified=true`, `evidencePersisted=true`, or a reviewed rollback status; no filesystem path |
| Durable activation evidence | local `activation-outcome.json` | Same bounded activation status, `serviceRunningVerified` value, and `evidencePersisted=true` persisted in staging dir; no filesystem path |
| Post-activation service | service state + process | service running after activation |
| Backend acceptance | heartbeat or update-state | `AgentVersion == targetVersion` after activation |
| Audit | command/audit rows | request, staging result, activation/update-state and actor evidence correlated |
| Negative guard | tamper / bad staging id | preflight fails closed (`HASH_MISMATCH` or `STAGING_IO_FAILED`) |

## 4. Mode A: full backend-issued chain

Use this mode only after the backend BE-031/BE-032 command-create surface is
merged and deployed. Current source references:

- BE-031: `POST /api/v1/admin/endpoint-agent-update-releases`
- BE-031: `POST /api/v1/admin/endpoint-agent-update-releases/{releaseId}/approve`
- BE-032: `POST /api/v1/admin/endpoint-devices/{deviceId}/agent-updates`

The old generic command endpoints are intentionally out of scope for
self-update. A smoke that creates `UPDATE_AGENT` through
`/endpoint-commands` or `/endpoint-devices/{deviceId}/commands` is invalid.

### 4.1 Baseline

```powershell
$Agent = "C:\Program Files\EndpointAgent\endpoint-agent.exe"
& $Agent --version | Tee-Object -FilePath "$EvidenceRoot\01-version-before.txt"
Get-Service EndpointAgent | Format-List * |
  Out-File -Encoding utf8 "$EvidenceRoot\02-service-before.txt"
Get-FileHash $Agent -Algorithm SHA256 |
  Out-File -Encoding utf8 "$EvidenceRoot\03-current-hash-before.txt"
```

### 4.2 Release catalog seed and approval

Create or update an agent update release catalog row before dispatch. The
release row is where URL, hash, signer and signing-tier evidence lives. The
device dispatch request must not carry those trust fields.

Example request body for `POST /api/v1/admin/endpoint-agent-update-releases`:

```json
{
  "releaseId": "endpoint-agent-1.2.3",
  "channel": "PILOT",
  "targetVersion": "1.2.3",
  "binaryUrl": "https://approved.example.invalid/releases/endpoint-agent.exe",
  "manifestUrl": "https://approved.example.invalid/releases/endpoint-agent.json",
  "sha256": "<64 lowercase or uppercase hex chars>",
  "sha512": "<128 lowercase or uppercase hex chars, optional>",
  "signerThumbprint": "<allowed signer thumbprint>",
  "signingTier": "TRUSTED_SIGNED",
  "maxBytes": 104857600,
  "releaseNotes": "AG-029 live smoke candidate"
}
```

Approval is maker-checker. The approver must be a different manager subject
from the creator:

```text
POST /api/v1/admin/endpoint-agent-update-releases/endpoint-agent-1.2.3/approve
```

Reject the smoke if:

- the release remains `DRAFT`,
- `enabled=false`,
- creator and approver are the same subject,
- `signingTier=LAB_ONLY_EVIDENCE` is used for a domain-wide or production
  self-update claim,
- the release URL, signer or hash differs from the artifact provenance.

### 4.3 Backend command issue

Create an `UPDATE_AGENT` command from the approved backend release catalog.
The admin request must not carry a raw URL or raw installer argument. It should
select a catalog release/channel/ring and a target version.

BE-032 request body for
`POST /api/v1/admin/endpoint-devices/{deviceId}/agent-updates`:

```json
{
  "releaseId": "endpoint-agent-1.2.3",
  "idempotencyKey": "ag029-smoke-001",
  "reason": "AG-029 live self-update smoke",
  "requiredDeploymentRing": "PILOT",
  "notBefore": "2026-06-06T10:00:00Z",
  "expiresAt": "2026-06-06T11:00:00Z"
}
```

`idempotencyKey`, `requiredDeploymentRing`, `notBefore` and `expiresAt` can be
omitted when the smoke needs immediate dispatch, but `releaseId` and `reason`
are required. The backend resolves the trust-sensitive fields from the approved
release catalog. The request must not contain `binaryUrl`, `claimedSha256`,
`claimedSignerThumbprint`, `signingTier`, raw PowerShell, raw installer args or
a caller-supplied payload map.

Expected backend command payload shape after catalog resolution:

```json
{
  "type": "UPDATE_AGENT",
  "payload": {
    "binaryUrl": "https://approved.example.invalid/releases/endpoint-agent.exe",
    "targetVersion": "1.2.3",
    "claimedSha256": "<sha256>",
    "claimedSignerThumbprint": "<thumbprint>",
    "signingTier": "TRUSTED"
  }
}
```

The agent is still the authority for hash, signer, URL policy, tier policy,
and version policy. Backend claims are evidence, not trust authority.

### 4.3A Backend trust-field fail-closed preflight

Before issuing the real update command, prove that the deployed BE-032
dedicated dispatch endpoint rejects caller-supplied trust material. This is a
required negative preflight for the live smoke, not an optional security note.

Send a deliberately invalid request to
`POST /api/v1/admin/endpoint-devices/{deviceId}/agent-updates` that includes
catalog-controlled fields in the dispatch body:

```json
{
  "releaseId": "endpoint-agent-1.2.3",
  "idempotencyKey": "ag029-negative-trust-fields-001",
  "reason": "AG-029 negative trust-field preflight",
  "binaryUrl": "https://attacker.example.invalid/endpoint-agent.exe",
  "claimedSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "claimedSignerThumbprint": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
  "signingTier": "TRUSTED"
}
```

Expected result:

```text
HTTP 400
```

Reject the smoke if this request returns `200`, `201`, creates an
`UPDATE_AGENT` command, or reaches service dispatch. The BE-032 source guard
for this condition is the
`createAgentUpdateRejectsCallerSuppliedTrustFields` controller regression test;
the live environment still has to prove the deployed endpoint is carrying the
same guard before the positive self-update command is allowed.

### 4.4 Wait for staged result

Poll the backend command result until it reports:

```json
{
  "details": {
    "update": {
      "stageStatus": "STAGED_ACTIVATION_READY",
      "stagingId": "<opaque-id>",
      "activationPlanId": "<opaque-id>",
      "targetVersion": "1.2.3",
      "actualSha256": "<sha256>",
      "actualSignerThumbprint": "<thumbprint>",
      "signingTier": "TRUSTED"
    }
  }
}
```

Save this JSON as:

```powershell
"<redacted command result json>" |
  Out-File -Encoding utf8 "$EvidenceRoot\04-staging-result-redacted.json"
```

Reject the smoke if the result contains a local filesystem path such as
`C:\ProgramData\EndpointAgent\updates\...`.

### 4.5 Activation preflight

```powershell
$StagingId = "<stagingId-from-command-result>"
& $Agent self-update preflight --staging-id $StagingId |
  Tee-Object -FilePath "$EvidenceRoot\05-preflight.json"
```

Accept only:

```json
{
  "status": "READY",
  "currentBinaryPresent": true,
  "stagedBinaryVerified": true
}
```

Reject if `05-preflight.json` contains `C:\`, `Program Files`, or
`ProgramData`.

### 4.6 Activation

The activation command stops/starts the service. Run it from an elevated shell
or a service-safe helper process, not from inside the running service process.

```powershell
& $Agent self-update activate --staging-id $StagingId --timeout 2m |
  Tee-Object -FilePath "$EvidenceRoot\06-activation.json"
```

Accept only `status=ACTIVATED`, `serviceRunningVerified=true`, and
`evidencePersisted=true` for the primary green path. If the outcome is
`ROLLED_BACK`, attach the JSON and service logs; treat it as rollback evidence,
not as a successful update.

The activation helper also persists a local-only path-free evidence file in the
staging directory:

```powershell
& $Agent self-update status --staging-id $StagingId |
  Tee-Object -FilePath "$EvidenceRoot\06b-activation-outcome.json"
```

`06b-activation-outcome.json` must carry the same bounded `status` family,
`serviceRunningVerified` value, and `evidencePersisted=true` as
`06-activation.json` and must not contain `C:\`, `Program Files`, or
`ProgramData`. The status command reads the local activation outcome by opaque
staging id so the operator does not need to copy a `ProgramData` path into the
evidence bundle. This file is support evidence only; it does not replace the
post-activation service + backend heartbeat acceptance gates.

### 4.7 Post-activation proof

```powershell
Start-Sleep -Seconds 10
Get-Service EndpointAgent | Format-List * |
  Out-File -Encoding utf8 "$EvidenceRoot\07-service-after.txt"
& $Agent --version | Tee-Object -FilePath "$EvidenceRoot\08-version-after.txt"
Get-FileHash $Agent -Algorithm SHA256 |
  Out-File -Encoding utf8 "$EvidenceRoot\09-current-hash-after.txt"
```

Then prove backend acceptance:

- latest heartbeat is after activation time
- heartbeat reports `AgentVersion == targetVersion`
- no repeated crash/restart loop
- audit/result rows correlate to the original command id

## 5. Mode B: source-slice local activation readiness

Use this mode only while PR #59 is still before the backend PR4 surface. It is
not a full live acceptance substitute; it proves that an already-created local
activation plan can be preflighted and activated with path-free evidence.

Required starting point:

- a valid staging directory exists
- `activation-plan.json` was created by the AG-029 staging flow
- `staged-endpoint-agent.exe` hashes to the plan
- the current binary in the plan exists

Commands:

```powershell
$Agent = "C:\Program Files\EndpointAgent\endpoint-agent.exe"
$StagingId = "<opaque-staging-id>"
& $Agent self-update preflight --staging-id $StagingId |
  Tee-Object -FilePath "$EvidenceRoot\source-slice-preflight.json"
& $Agent self-update activate --staging-id $StagingId --timeout 2m |
  Tee-Object -FilePath "$EvidenceRoot\source-slice-activation.json"
& $Agent self-update status --staging-id $StagingId |
  Tee-Object -FilePath "$EvidenceRoot\source-slice-activation-outcome.json"
```

This mode must be reported as source-slice evidence only. Do not use it to
claim backend command issuance, maker-checker, release catalog, or production
rollout readiness.

## 6. Negative smoke

Run at least one fail-closed check before accepting live activation.

Tampered staged binary:

```powershell
$StagedBinary = "C:\ProgramData\EndpointAgent\updates\<stagingId>\staged-endpoint-agent.exe"
Add-Content -Path $StagedBinary -Value "tamper"
& $Agent self-update preflight --staging-id $StagingId |
  Tee-Object -FilePath "$EvidenceRoot\10-preflight-tamper.json"
```

Accept only:

```json
{
  "status": "FAILED",
  "errorCode": "HASH_MISMATCH"
}
```

Invalid staging id:

```powershell
& $Agent self-update preflight --staging-id "..\escape" |
  Tee-Object -FilePath "$EvidenceRoot\11-preflight-invalid-id.json"
```

Accept only a failed status and a bounded reason. The output must not reveal a
local path.

## 7. No-secret and no-path assertions

Run these checks on every captured JSON artifact:

```powershell
Select-String -Path "$EvidenceRoot\*.json" `
  -Pattern "Bearer |Authorization:|password|private key|BEGIN .* KEY|C:\\Users\\|ProgramData\\EndpointAgent\\updates|Program Files\\EndpointAgent"
```

Expected result: no matches. If there are matches, redact the evidence and
open a source follow-up; do not publish the raw artifact.

## 8. Acceptance wording

Allowed:

- "AG-029 staging source path is verified."
- "AG-029 preflight/activation helper produced path-free stdout and persisted outcome evidence."
- "AG-029 full backend-issued live smoke passed on device `<hostname>`."

Not allowed unless all gates above are present:

- "self-update is production-ready"
- "domain-wide rollout is ready"
- "all devices can update themselves"
- "backend claims prove binary trust"
