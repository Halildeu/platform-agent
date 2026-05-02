#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

mkdir -p bin
go build -o bin/endpoint-agent ./cmd/endpoint-agent
./bin/endpoint-agent --version
