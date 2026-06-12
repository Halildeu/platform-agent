# Contributing to platform-agent

`platform-agent` is the Windows endpoint-management agent for the platform
fleet. It is developed in the open alongside the rest of the platform; this
guide covers how changes land.

## Ground rules

- **Security issues do not go in public issues or PRs.** Follow
  [SECURITY.md](SECURITY.md) for coordinated disclosure.
- **Never commit a real secret.** No device credentials, HMAC keys, signing
  keys/PFX, tokens, enrollment tokens, maintenance tokens, or production
  hostnames. CI runs gitleaks on every push; tests that need secret-*shaped*
  data use the obvious fakes already established in
  `internal/security/redact_*_test.go` (and are allowlisted in
  `.gitleaks.toml`).
- **No production endpoints in reproductions or tests.** Use a local build or
  an isolated VM. Test data (IPs, MACs, UPNs, serials) must be synthetic.

## Development

```sh
go build ./...
go vet ./...
go test ./... -race          # the full suite is expected green
GOOS=windows GOARCH=amd64 go vet ./...   # Windows build tags must vet too
```

Windows-only code paths build under `//go:build windows`; the Linux job
exercises the non-Windows stubs and the platform-agnostic code, and a separate
Windows job runs the Windows build. Keep both green.

The remote-bridge protobuf code under `internal/remotebridge/pb` is generated
and committed; CI is intentionally protoc-free. Regenerate only via
`scripts/proto/generate.sh` (pinned toolchain) and never hand-edit field
numbers — they are frozen by the wire contract on the broker side.

## Pull requests

- Branch from `main`; keep PRs focused.
- The PR description must include the **Boundary declaration (ADR-0011 §2.3)**
  block — CI enforces it (BG-EA-1 gate).
- Changes are reviewed before merge; CI must be green (a red required *or*
  advisory check blocks merge — fix it, do not bypass it).
- A change that touches a Windows-only path should describe how it was
  exercised (the Windows CI job, a VM smoke, or why a unit test is sufficient);
  redact any logs you attach.

## What lands where

The broker/policy/recording/permit-signing side of the remote-access bridge
lives in the backend service repository, not here. This repo owns the
**agent/client** side: enrollment, inventory, self-update, install/uninstall,
and the outbound bridge transport harness. New capabilities that belong to the
broker's authority do not go in the agent.
