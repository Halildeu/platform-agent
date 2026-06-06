#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

mkdir -p bin
version="${ENDPOINT_AGENT_VERSION:-0.1.0-dev}"
syso="$(./scripts/build/windows-versioninfo.sh "$version")"
cleanup() {
  rm -f "$syso"
}
trap cleanup EXIT

GOOS=windows GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -X platform-agent/internal/config.BuildVersion=$version" \
  -o bin/endpoint-agent.exe ./cmd/endpoint-agent
ls -lh bin/endpoint-agent.exe
