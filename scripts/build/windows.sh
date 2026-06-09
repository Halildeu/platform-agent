#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

mkdir -p bin
# Default to a COMMIT-DISTINCT version so a local/script build never reports the
# static "0.1.0-dev" sentinel (which made every untagged build indistinguishable
# in the UI "Ajan Sürümü"). ENDPOINT_AGENT_VERSION still wins for explicit
# overrides; a tagged release passes the tag. `git describe --tags` is avoided
# on purpose (archive/* cleanup tags pollute it) — a short SHA is unambiguous.
# The `g` prefix keeps the SHA a SAFE ALPHANUMERIC SemVer identifier: a bare
# all-numeric leading-zero SHA (e.g. 0123456) is rejected by strict SemVer and
# the agent's own self-update policy parses the running version (Codex 019eac32).
_sha="$(git rev-parse --short HEAD 2>/dev/null || echo nogit)"
version="${ENDPOINT_AGENT_VERSION:-0.1.0-dev.g${_sha}}"
syso="$(./scripts/build/windows-versioninfo.sh "$version")"
cleanup() {
  rm -f "$syso"
}
trap cleanup EXIT

GOOS=windows GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -X platform-agent/internal/config.BuildVersion=$version" \
  -o bin/endpoint-agent.exe ./cmd/endpoint-agent
ls -lh bin/endpoint-agent.exe
