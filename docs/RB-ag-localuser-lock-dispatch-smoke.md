# RB — LOCK_USER_LOGIN command-specific backend→agent dispatch smoke (operator-gated)

> **Status**: `NOT RUN` — blocked on two real admin JWTs / operator-owned identity
> provisioning. This is an **operator-gated live-acceptance follow-up**, NOT a
> code/security blocker.
>
> **Authority**: admin JWT minting / credential handling is the **operator boundary**
> (Codex `019dd409`; agent credential/token prohibition). The agent writes this
> runbook and runs the dispatch *only* if the operator supplies the two JWTs in a
> way that keeps tokens out of the agent transcript (e.g. `curl -K` config files).

## What is already PASS (do not re-litigate)
- **Windows guard semantics live-verified on a real SAM** (prlctl, NT AUTHORITY\SYSTEM):
  nested-only local admin caught by the recursive Administrators flatten
  (`inFlattened=true, inDirect=false`); last-enabled-admin facts (`others=0` → DENY);
  built-in Administrator RID 500 refused; non-admin excluded. (#84, PRs #85/#86/#89/#90.)
- **Guarded `origin/main` agent binary deployed and polling healthy** on the test VM
  (SHA `fecdca39…`, device `d0efb00a-681a-4e32-b7de-a27ef94f2977`, `mode=hmac`).
- **Generic dual-control command path previously proven** by the AG-028 uninstall
  maker-checker E2E (propose/approve/dispatch/result).

## What this smoke adds (the LOCK-specific glue, currently NOT RUN)
Command-type allowlist (`admin-creatable-types`), payload shape, post-approval
queue/poll delivery, agent executor routing for `LOCK_USER_LOGIN`, and `FAILED`
status/summary/detail propagation back to the backend (and web). Low-probability
glue/regression risk only — **no known guard-safety gap**.

## When this becomes mandatory (run it before any of these)
- Lock/unlock UX is opened to real operators in production.
- Runtime capabilities advertise lock/unlock and the feature is announced "ready".
- The backend command schema, command-type allowlist, approval pipeline, agent
  polling/status ingest, or executor routing changes.
- Audit/compliance requires button-to-agent evidence.

## The smoke (no SAM-write risk — targets the already-disabled built-in Administrator)
Targeting `Administrator` means the RID guard refuses it (RID 500) and, even if a
guard regressed, the account is already disabled — so there is **zero** real
SAM-write risk, while still exercising the full dispatch glue + dual-control.

1. **Operator** mints two DISTINCT admin JWTs (proposer ≠ approver), each with the
   endpoint-admin command role + OpenFGA relations, and writes them to
   `-K` config files on the machine where the dispatch runs (tokens never echoed):
   ```
   printf 'header = "Authorization: Bearer %s"\n' "$J_PROPOSER" > /tmp/kc_proposer.cfg && chmod 600 /tmp/kc_proposer.cfg
   printf 'header = "Authorization: Bearer %s"\n' "$J_APPROVER" > /tmp/kc_approver.cfg && chmod 600 /tmp/kc_approver.cfg
   ```
2. **Propose** (proposer): `POST /api/v1/endpoint-admin/endpoint-devices/{deviceId}/commands`
   body `{"commandType":"LOCK_USER_LOGIN","reason":"RID-guard dispatch smoke","idempotencyKey":"lock-smoke-1","payload":{"username":"Administrator"}}`.
3. **Approve** (approver ≠ proposer): `POST /api/v1/endpoint-admin/endpoint-commands/{commandId}/approval`.
4. **Agent** (guarded binary) polls `/commands/next`, executes, the RID guard refuses,
   posts a `FAILED` result.
5. **Expected**:
   - backend command status `FAILED`, summary/detail = reserved-RID refusal;
   - agent log shows the refusal;
   - `net user Administrator` on the VM shows the account **unchanged** (still disabled,
     no SAM write).

This single negative smoke proves dual-control (approver ≠ issuer), the LOCK-specific
dispatch glue, and `FAILED` propagation — with no real SAM-write risk.

## Cross-AI
Plan + closure framing: Codex (OpenAI) thread `019ea1a2`. Implementer: Claude (Anthropic).
