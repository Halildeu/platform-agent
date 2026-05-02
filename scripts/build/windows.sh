#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

mkdir -p bin
GOOS=windows GOARCH=amd64 go build -o bin/endpoint-agent.exe ./cmd/endpoint-agent
ls -lh bin/endpoint-agent.exe
