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
```

The full backend-issued live chain still requires the backend command-create
surface described in platform-agent issue #55 PR4.

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
| Activation | `self-update activate` JSON | `status=ACTIVATED` or a reviewed rollback status; no filesystem path |
| Durable activation evidence | local `activation-outcome.json` | Same bounded activation status persisted in staging dir; no filesystem path |
| Post-activation service | service state + process | service running after activation |
| Backend acceptance | heartbeat or update-state | `AgentVersion == targetVersion` after activation |
| Audit | command/audit rows | request, staging result, activation/update-state and actor evidence correlated |
| Negative guard | tamper / bad staging id | preflight fails closed (`HASH_MISMATCH` or `STAGING_IO_FAILED`) |

## 4. Mode A: full backend-issued chain

Use this mode after the backend PR4 command-create surface exists.

### 4.1 Baseline

```powershell
$Agent = "C:\Program Files\EndpointAgent\endpoint-agent.exe"
& $Agent --version | Tee-Object -FilePath "$EvidenceRoot\01-version-before.txt"
Get-Service EndpointAgent | Format-List * |
  Out-File -Encoding utf8 "$EvidenceRoot\02-service-before.txt"
Get-FileHash $Agent -Algorithm SHA256 |
  Out-File -Encoding utf8 "$EvidenceRoot\03-current-hash-before.txt"
```

### 4.2 Backend command issue

Create an `UPDATE_AGENT` command from the approved backend release catalog.
The admin request must not carry a raw URL or raw installer argument. It should
select a catalog release/channel/ring and a target version.

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

### 4.3 Wait for staged result

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

### 4.4 Activation preflight

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

### 4.5 Activation

The activation command stops/starts the service. Run it from an elevated shell
or a service-safe helper process, not from inside the running service process.

```powershell
& $Agent self-update activate --staging-id $StagingId --timeout 2m |
  Tee-Object -FilePath "$EvidenceRoot\06-activation.json"
```

Accept only `status=ACTIVATED` for the primary green path. If the outcome is
`ROLLED_BACK`, attach the JSON and service logs; treat it as rollback evidence,
not as a successful update.

The activation helper also persists a local-only path-free evidence file in the
staging directory:

```powershell
$OutcomePath = Join-Path $env:ProgramData "EndpointAgent\updates\$StagingId\activation-outcome.json"
Copy-Item $OutcomePath "$EvidenceRoot\06b-activation-outcome.json"
```

`06b-activation-outcome.json` must carry the same bounded `status` family as
`06-activation.json` and must not contain `C:\`, `Program Files`, or
`ProgramData`. This file is support evidence only; it does not replace the
post-activation service + backend heartbeat acceptance gates.

### 4.6 Post-activation proof

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
$OutcomePath = Join-Path $env:ProgramData "EndpointAgent\updates\$StagingId\activation-outcome.json"
Copy-Item $OutcomePath "$EvidenceRoot\source-slice-activation-outcome.json"
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
