# AG-029 — Signed Self-Update Threat Model (Faz 22.5)

> Status: **PR0 (pure policy core)**. Cross-AI plan consensus: Codex thread
> `019e94fd` REVISE→AGREE (ready_for_impl PR0). This document is the
> authority for the trust boundary; the `internal/selfupdate` package
> implements + tests the decisions described here. No code in PR0 downloads,
> verifies, mutates, or restarts anything — PR0 is decision logic only.

## 1. Goal & non-goals

**Goal.** Let the backend command a Windows agent to replace its own binary
with a newer, integrity-verified release, **without** an operator present, and
**without** the agent ever trusting the backend as the integrity authority.

**Non-goals (v1).** Rollback/downgrade (a separate, narrower, maker-checker
command), cross-platform self-update (Windows-only; other platforms return
`POLICY_UNSUPPORTED_PLATFORM`), and unattended lab-tier updates (refused).

## 2. Trust model — the backend is NOT the authority

The UPDATE_AGENT payload is resolved by the backend from a **trusted release
catalog** (the admin selects `releaseId|channel/ring + targetVersion`; the
backend fills in the URL + claims). But on the agent side:

| Payload field | Role |
|---|---|
| `binaryUrl` | candidate source, re-checked against a **local URL policy** |
| `claimedSha256` | **audit evidence only**; the agent recomputes the real hash |
| `claimedSignerThumbprint` | **audit evidence only**; never an authority |
| `acceptLabOnlySigning` | **ignored** as authority; lab consent is local-only |
| `signingTier` | classification; trust is decided by local policy |

The **authority** is the agent's **local signer-policy allowlist** (an
install-time secure config). The agent independently (PR1): recomputes the
SHA256 of the staged bytes, verifies the Authenticode chain + Code-Signing
EKU, extracts the **actual** signer thumbprint, and checks
`actual ∈ local allowlist`. A compromised backend (or admin command path) that
ships a *self-consistent* malicious payload — its own binary, its own hash,
its own thumbprint — still fails, because the malicious signer is not in the
agent's local allowlist (`SIGNER_NOT_ALLOWED`).

**Catalog authority.** Backend-supplied, catalog-derived claims are evidence.
An *optional* local release catalog may be an authority **only if** its
signature verifies against a local catalog trust root. An **unsigned** GitHub
release manifest is never an agent authority.

## 3. Signer-policy rotation

The local allowlist must not become a permanent lock-in when the signing cert
rotates, **and** must not be expandable by the backend:

- AG-029 v1 does **not** widen the trust anchor at runtime.
- A new signer is added only via (a) a transitional release **signed by an
  already-allowlisted signer**, or (b) a separate local/admin-controlled
  signer-policy update flow — never by a payload proposing a new thumbprint.
- `EvaluateSignerPolicy` consumes the **verified** thumbprint only; the
  payload's claimed thumbprint is not an input.

## 4. Tier policy

`TRUSTED` is the only production-accepted tier. `LAB_ONLY_EVIDENCE` (the
ephemeral self-signed cert the release pipeline produces) is **refused** for
unattended self-update unless **both**: a **local** opt-in is present
(install-time config / test build) **and** the host is non-domain-joined —
mirroring the install-time guardrail, but **without** honoring the payload's
`acceptLabOnlySigning`. Unknown tiers are treated as untrusted.

## 5. Authenticode timestamp semantics

- **Timestamped** signature → the cert need only have been valid **at signing
  time** (a correctly-signed older release stays acceptable after the signing
  cert expires).
- **Untimestamped** signature → the cert must be valid at the **current** time.
- `TRUSTED` additionally requires a validating chain. All tiers require the
  Code-Signing EKU.

This removes the "expired-cert, correctly-signed release" ambiguity.

## 6. Version policy

Enforced **locally**, fail-closed: unparseable current/target/maxSeen →
`POLICY_VERSION_UNPARSEABLE` (never treated as `0`); `target ≤ maxSeen` →
`POLICY_VERSION_REPLAY` (anti-replay of old signed releases via a persisted
monotonic high-water mark); `target == current` → noop; `target < current` →
`POLICY_VERSION_DOWNGRADE`. SemVer 2.0.0 precedence is implemented + pinned by
the spec's canonical example chain (dependency-free, because the comparator is
a security boundary). The capability layer (PR2) may additionally require the
**current** version to be a clean release before advertising self-update.

## 7. URL policy

HTTPS-only (no scheme downgrade), no userinfo, ASCII host only (IDN must be
pre-encoded to punycode by the catalog — the agent refuses Unicode rather than
normalizing it), no IP-literal host, port empty/443, exact host allowlist (no
substring/suffix matching). **Every** redirect hop is re-checked under the
same policy, with a hard hop cap.

## 8. Two-phase lifecycle (staging never reports activation)

`Execute()` (the staging command) can only ever know the **staging** outcome,
because activation happens **after** the staging command's result POST has
already succeeded. Therefore:

- `stageStatus` ∈ `{STAGED_ACTIVATION_READY, NOOP_ALREADY_CURRENT, FAILED_STAGE}`
  — the only thing the command result carries.
- `activationStatus` ∈ `{ACTIVATED, ROLLED_BACK, PENDING_REBOOT, ACTIVATION_FAILED}`
  — reported **later** via the new agent's heartbeat / a dedicated
  update-state evidence surface (PR3), **never** inside the staging result.
- Activation mechanism (PR3): download to a protected staging dir → verify →
  result POST → **post-result** helper stops the service, side-by-side
  activates (swap `ImagePath`/atomic replace via helper), starts the service,
  rolls back on start-failure. **Not** rename-over-running-exe;
  `MoveFileEx(DELAY_UNTIL_REBOOT)` only as a fallback ⇒ `PENDING_REBOOT`,
  never `SUCCEEDED`. **Acceptance** = the new agent's heartbeat reporting
  `AgentVersion == targetVersion`, closed server-side.

The DPAPI-persisted HMAC credential is **never touched** by staging or
activation; PR3 adds a pre-activation **credential preflight** (readable +
matches the current credential id) so the new binary can re-enroll-free start.

## 9. Wire minimization

`details.update` carries opaque handles (`stagingId`, `activationPlanId`) +
bounded evidence (`targetVersion`, `actualSha256`, `actualSignerThumbprint`,
`signingTier`, bounded `reason`) — **never** the local staging path, which
stays in local logs only.

## 10. Bounded error taxonomy (staging phase)

`POLICY_UNSUPPORTED_PLATFORM`, `POLICY_LAB_TIER_REFUSED`,
`POLICY_VERSION_DOWNGRADE`, `POLICY_VERSION_REPLAY`,
`POLICY_VERSION_UNPARSEABLE`, `POLICY_URL_REJECTED`, `DOWNLOAD_FAILED`,
`DOWNLOAD_TOO_LARGE`, `HASH_MISMATCH`, `SIGNATURE_INVALID`,
`SIGNER_NOT_ALLOWED`, `CATALOG_MISMATCH`, `CREDENTIAL_PREFLIGHT_FAILED`,
`STAGING_IO_FAILED`, `ACTIVATION_PLAN_WRITE_FAILED`. The set is closed (pinned
by `TestErrorCodeSetStable`); a backend mirror may reject any code outside it.

## 11. PR sequence

- **PR0** (this) — pure policy core + threat model + tests. No mutation, no capability.
- **PR1** — Windows Authenticode verifier + SHA256 streaming cap + protected staging dir (DACL) + non-Windows stub. Trusted-only default.
- **PR2** — executor wire `CommandUpdateAgent` + `RequiresReason` + capability (policy-aware) + structured results. No process kill.
- **PR3** — activation helper / post-result restart + rollback + pending-reboot fallback + DPAPI preflight + live Windows service tests.
- **PR4** — backend command-create (maker-checker, release-catalog-sourced payload, capability+freshness, policy+audit).
- **PR5** — docs (COMMAND-CONTRACT §UPDATE_AGENT + TESTING-STRATEGY + signing runbook) + Parallels VM live acceptance.

Tracking: platform-agent issue **#55**.
