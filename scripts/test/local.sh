#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

gofmt -w ./cmd ./internal
go test ./...
go vet ./...
