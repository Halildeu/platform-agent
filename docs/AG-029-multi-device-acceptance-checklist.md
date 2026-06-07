# AG-029 Multi-Device Acceptance Checklist

Bu checklist Faz 22 / 22.5 agent self-update kabul kanitini cihaz-cihaz
toplamak icindir. Su an executable lab cihazi local Parallels Windows 11'dir;
diger bilgisayarlar bu checklist uzerinden daha sonra toplu kosulacaktir.

Bu belge tamamlanma iddiasi degildir. Her cihaz icin ayri kanit alinir; eksik
veya fail olan cihazlar Faz 22 genel kabulunu otomatik tamamlanmis yapmaz.

-------------------------------------------------------------------------------
## 1. Boundary
-------------------------------------------------------------------------------

Allowed:

```text
- Local Parallels Windows 11 smoke
- IT tarafindan onaylanan Windows 10/11 x64 cihazlarda agent install/update smoke
- Approved release catalog + UPDATE_AGENT dispatch
- Non-secret evidence: commandId, releaseId, version, sha256, signer thumbprint,
  service state, heartbeat timestamp, sanitized logs
```

Forbidden:

```text
- Raw PowerShell / raw shell command surface as product behavior
- Arbitrary binary URL from admin payload
- Catalog disi software/update
- Secret/JWT/token/password value capture
- Production/domain-wide rollout claim from a single lab device
- Closes/Fixes language for umbrella Faz 22 issue
```

-------------------------------------------------------------------------------
## 2. Device Matrix
-------------------------------------------------------------------------------

| Device | Owner | Join type | Role | Status | Evidence |
|---|---|---|---|---|---|
| HALILKOOLUB735 | dev lab | Parallels / non-domain | local executable lab | PASS | PR #74: AG-029 self-update 0.1.1-lab.3 -> 0.1.2-lab.2 |
| TBD-DEVICE-01 | TBD | TBD | batch target | PENDING_BATCH | Fill before batch run |
| TBD-DEVICE-02 | TBD | TBD | batch target | PENDING_BATCH | Fill before batch run |

Status vocabulary:

```text
PENDING_BATCH   not run yet
PASS            all gates in Section 4 passed
WARN            accepted with documented non-blocking caveat
FAIL            one or more required gates failed
SKIPPED         intentionally not in this batch
```

-------------------------------------------------------------------------------
## 3. Per-Device Preflight
-------------------------------------------------------------------------------

Run before dispatching UPDATE_AGENT:

```text
[ ] Device owner / operator approval recorded.
[ ] Device hostname and deviceId identified.
[ ] Join type recorded: WORKGROUP / DOMAIN / ENTRA / UNKNOWN.
[ ] EndpointAgent service is installed and RUNNING.
[ ] Current agent version captured.
[ ] Backend heartbeat shows the same device ONLINE.
[ ] Approved release exists in backend release catalog.
[ ] Negative trust-field preflight returns HTTP 400 when binaryUrl/hash/signer
    are supplied directly to the dispatch endpoint.
[ ] Local signer policy allows only the expected signer thumbprint.
[ ] No raw secret value is copied into notes, shell history, PR body, or logs.
```

-------------------------------------------------------------------------------
## 4. Required Acceptance Gates
-------------------------------------------------------------------------------

Each device needs all gates below:

```text
[ ] G1 - Release catalog create/approve path works.
[ ] G2 - UPDATE_AGENT dispatch returns HTTP 200.
[ ] G3 - Agent claims the command.
[ ] G4 - Stage result reaches SUCCEEDED with STAGED_ACTIVATION_READY.
[ ] G5 - actualSha256 equals the served target binary sha256.
[ ] G6 - actualSignerThumbprint equals the approved signer thumbprint.
[ ] G7 - Activation replaces the running service binary.
[ ] G8 - EndpointAgent service is RUNNING after activation.
[ ] G9 - endpoint-agent --version reports targetVersion.
[ ] G10 - Backend heartbeat records agent_version == targetVersion.
[ ] G11 - High-water file records the activated targetVersion.
[ ] G12 - Sanitized logs show no raw token/password/authorization header.
```

PASS evidence bundle per device:

```text
deviceId:
hostname:
oldVersion:
targetVersion:
releaseId:
commandId:
stageStatus:
actualSha256:
actualSignerThumbprint:
servicePidAfterActivation:
installedSha256:
targetSha256:
backendHeartbeatUpdatedAt:
logRedactionCheck:
operator:
runAt:
```

-------------------------------------------------------------------------------
## 5. Known PASS Baseline — Local Parallels W11
-------------------------------------------------------------------------------

Local Parallels Windows 11 smoke after PR #74 fix:

```text
deviceId: d0efb00a-681a-4e32-b7de-a27ef94f2977
hostname: HALILKOOLUB735
commandId: f34f9c58-c0d6-4948-bb18-ba1415e2224a
oldVersion: 0.1.1-lab.3
targetVersion: 0.1.2-lab.2
stageStatus: STAGED_ACTIVATION_READY
command terminal status: SUCCEEDED
actualSha256: 51d0e58fb4101ab6216e96d10f1a5ae6ab25d10621336c0072dd9cd188010c7c
actualSignerThumbprint: FD4887BF9A679FE65E1C9F2D5C0C624F8AC8161E1FCA9220B3A19BC6E8EF188B
service after activation: RUNNING
endpoint-agent --version: endpoint-agent 0.1.2-lab.2
installedSha256 == targetSha256: PASS
backend heartbeat: HALILKOOLUB735 | 0.1.2-lab.2 | ONLINE | 2026-06-07 01:24:30Z
```

Root-cause fixed by PR #74:

```text
Stager kept the os.CreateTemp handle open while Authenticode verification
spawned a Windows external process. Windows rejected the verifier read with a
sharing violation and the command surfaced as SIGNATURE_INVALID. The fix closes
the temp file after Sync() and before Verifier.Verify(ctx, tmpPath).
```

-------------------------------------------------------------------------------
## 6. Batch Completion Rule
-------------------------------------------------------------------------------

The batch is acceptable only when:

```text
[ ] Every planned device in Section 2 is PASS or explicitly SKIPPED.
[ ] Every FAIL has a root cause, owner, and follow-up issue/PR.
[ ] At least one non-local-lab device is PASS before any wider rollout claim.
[ ] No production/domain-wide rollout claim is made from lab-only evidence.
[ ] A final evidence roll-up is attached to the relevant board item / PR body.
```

Until this rule passes, the correct wording is:

```text
AG-029 local Parallels self-update smoke PASS; multi-device acceptance pending.
```
