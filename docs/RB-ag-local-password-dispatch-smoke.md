# RB — CHANGE_LOCAL_PASSWORD backend→agent dispatch smoke (operator-gated)

> **Status**: helper/runbook source-side. Live acceptance requires two real
> operator-owned admin identities, supplied as `curl -K` config files.
>
> **Boundary**: this is **local SAM password** only. It does not reset an
> Active Directory, Entra ID, or M365 password, and it does not update cached
> domain credentials while a device is off-domain.

## What this proves

This smoke exercises the complete dedicated local password command path:

1. Backend creates `CHANGE_LOCAL_PASSWORD` through
   `/api/v1/endpoint-admin/endpoint-devices/{deviceId}/local-password-changes`.
2. Backend returns a one-time password to the proposer once, but the helper
   redacts it before writing evidence.
3. Second admin approves the pending command.
4. Agent polls, claims the secret payload once, changes the local SAM password,
   and posts terminal result.
5. Backend reports terminal `SUCCEEDED` and no password material appears in
   command result/audit evidence.

## What it does not prove

- Domain password reset or cached domain credential sync.
- Pre-logon VPN or DC reachability.
- Production pilot readiness for IT-owned domain devices.
- User-facing recovery UX. This smoke is a dispatch and safety proof only.

## Operator-owned auth config files

Do not paste JWTs into the terminal command. The operator should write two
distinct admin identities into `curl -K` files:

```bash
printf 'header = "Authorization: Bearer %s"\n' "$J_PROPOSER" > /tmp/kc_proposer.cfg
printf 'header = "Authorization: Bearer %s"\n' "$J_APPROVER" > /tmp/kc_approver.cfg
chmod 600 /tmp/kc_proposer.cfg /tmp/kc_approver.cfg
```

The proposer and approver must be different people/service identities. The
helper verifies file mode but cannot prove identity separation by itself; keep
that check in the acceptance note.

## Recommended local test account

Use a synthetic account, not a real user account:

- default username: `ea-recovery-smoke`
- do not add it to the local Administrators group
- remove it after the smoke if it was created only for evidence

The helper can create and clean up that local user through Parallels without
printing generated password material:

```bash
scripts/test/ag42-local-password-dispatch-smoke.sh \
  --device-id "$DEVICE_ID" \
  --proposer-config /tmp/kc_proposer.cfg \
  --approver-config /tmp/kc_approver.cfg \
  --parallels-vm "Windows 11" \
  --create-test-user \
  --cleanup-test-user
```

For an already existing synthetic user, omit `--create-test-user` and
`--cleanup-test-user`:

```bash
scripts/test/ag42-local-password-dispatch-smoke.sh \
  --device-id "$DEVICE_ID" \
  --proposer-config /tmp/kc_proposer.cfg \
  --approver-config /tmp/kc_approver.cfg \
  --target-username ea-recovery-smoke \
  --parallels-vm "Windows 11"
```

## Expected result

- backend command reaches terminal `SUCCEEDED`;
- Parallels `net user <target>` before/after differs, showing local SAM state
  changed;
- `report.json` and `report.md` are written under `tmp/ag42-local-password-*`;
- post-write secret scan passes;
- evidence contains no raw JWT, no backend one-time password, and no local
  password material.

## Failure interpretation

| Symptom | Meaning |
|---|---|
| HTTP 401/403 before create | proposer config lacks valid admin JWT / OpenFGA permission |
| HTTP 403 on approval | approver lacks permission or maker-checker identity separation failed |
| terminal `FAILED` | agent rejected payload or Windows local SAM mutation failed |
| VM before/after unchanged | command did not mutate the target local account |
| secret scan failure | evidence redaction regression; do not publish artifacts |

## Two-device and 24h soak boundary

This helper completes the code/runbook side. Two-device repetition and 24h soak
remain operator evidence collection and can use the same command with different
`--device-id` values.
