#!/usr/bin/env bash
# Faz 22.6 T-3 — regenerate internal/remotebridge/pb from the VENDORED proto.
#
# The proto's source of truth is platform-backend
# endpoint-admin-service/src/main/proto/remote_bridge.proto (T-2a, frozen
# field numbers). The vendored copy here adds ONLY the go_package option.
# Generated code is COMMITTED so CI stays protoc-free; the wire shape is
# pinned by internal/remotebridge/pb/descriptor_guard_test.go, which fails
# on any regeneration that drifts the contract.
#
# Pinned toolchain (bump deliberately, never implicitly):
#   protoc            >= 29 (brew install protobuf; built with libprotoc 35.0)
#   protoc-gen-go     v1.36.10
#   protoc-gen-go-grpc v1.5.1
set -euo pipefail
cd "$(dirname "$0")/../.."

go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.10
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1

PATH="$PATH:$(go env GOPATH)/bin" protoc \
  -I internal/remotebridge/proto \
  --go_out=. --go_opt=module=platform-agent \
  --go-grpc_out=. --go-grpc_opt=module=platform-agent \
  internal/remotebridge/proto/remote_bridge.proto

echo "regenerated internal/remotebridge/pb — run: go test ./internal/remotebridge/..."
