#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

version="${1:-${ENDPOINT_AGENT_VERSION:-0.1.0-dev}}"
out_prefix="${2:-cmd/endpoint-agent/endpoint_agent_version}"
config_path="cmd/endpoint-agent/winres/winres.json"

if [ ! -f "$config_path" ]; then
  echo "windows version resource config not found: $config_path" >&2
  exit 2
fi

rm -f "${out_prefix}"_windows_*.syso

go run github.com/tc-hib/go-winres@v0.3.3 make \
  --in "$config_path" \
  --out "$out_prefix" \
  --arch amd64 \
  --file-version "$version" \
  --product-version "$version" >/dev/null

syso="${out_prefix}_windows_amd64.syso"
if [ ! -s "$syso" ]; then
  echo "windows version resource was not generated: $syso" >&2
  exit 2
fi

printf '%s\n' "$syso"
