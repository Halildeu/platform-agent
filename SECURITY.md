# Security Policy

`platform-agent` is the Windows endpoint-management agent for the platform
fleet: device enrollment, inventory, signed self-update, software install/
uninstall, and the Faz 22.6 remote-access bridge client harness. Because the
agent runs with high privilege on managed endpoints, we take its security
posture seriously and welcome coordinated disclosure.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Use GitHub's private vulnerability reporting (the **Security** tab → **Report a
vulnerability**) for this repository. If that is unavailable to you, contact the
maintainer through the account profile and request a private channel before
sharing any details.

Please include: affected version/commit, a minimal reproduction, the impact you
believe it has, and any suggested remediation. Do **not** test against live
production endpoints or fleets — a local build or an isolated VM is sufficient
to demonstrate agent-side issues.

We aim to acknowledge a report within a few business days and to agree a
disclosure timeline with you. Please give us a reasonable window to ship a fix
before any public discussion.

## Supported versions

This is pre-production software under active development. Security fixes target
the latest `main` and the most recent signed release. Older builds are not
maintained — the signed self-update path is designed to move endpoints forward.

## Security model — what is, and is not, secret

The agent's trust model is **signing/identity based, not source-secrecy based**
(Kerckhoffs-compatible). Publishing this source does not weaken it:

- **Self-update** verifies an Authenticode signature and a configured signer
  thumbprint allowlist before activating any binary. The private signing key
  lives in protected infrastructure, never in this repo.
- **Enrollment / heartbeat / command** requests are HMAC-signed with a
  device credential issued at enrollment. The credential and its secret are
  provisioned to the endpoint, never committed here.
- The **remote-access bridge** (Faz 22.6) is **disabled by default**
  (`ENDPOINT_AGENT_REMOTE_BRIDGE_ENABLED=false`), **outbound-only**, and the
  agent only ever **verifies** broker-issued operation permits (ECDSA P-256);
  it cannot mint authorization. The broker holds the private permit-signing
  key. The interactive pilot is attended-only and owner-gated; this repo
  contains **no** screen-capture or PTY execution (that is a later,
  owner-pilot-gated milestone). At runtime, mTLS client identity binds the
  transport.

Intentionally **not** secret: the wire protocols, message framing, enrollment
and self-update flow structure, and the bridge client state machine. Knowing
the protocol does not grant the signing keys, the device HMAC secret, the
broker permit-signing key, or the mTLS identity — those are the actual trust
anchors.

If you find a way to **forge** a signed update, an enrollment credential, or an
operation permit; to **bypass** the signer-thumbprint / freshness / device-
binding checks; or a side-channel (timing/oracle/nonce) that materially weakens
any of the above — that is exactly the class of report we want.

## Hardening notes for operators

- Keep `ENDPOINT_AGENT_REMOTE_BRIDGE_ENABLED` unset/false unless you are part of
  an explicitly authorized pilot.
- `ENDPOINT_AGENT_REMOTE_BRIDGE_INSECURE_PLAINTEXT` and lab-only signing
  (`ENDPOINT_AGENT_SELF_UPDATE_ALLOW_LAB_ONLY_SIGNING`) are for development
  only — never enable them on production installs.
- Lab-signed release artifacts are evidence-only and must not be treated as
  production-trusted; production installs require the trusted (internal-CA)
  signing path.
