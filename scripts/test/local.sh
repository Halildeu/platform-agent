#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

./scripts/test/windows-installer-encoding.sh
./scripts/test/release-policy-contract.sh
gofmt -w ./cmd ./internal
go test ./...
go vet ./...
