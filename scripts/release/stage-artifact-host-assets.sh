#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

dist_dir="${1:-dist}"
assets_dir="${2:-deploy/artifact-host/build-assets}"

fail() {
  echo "::error::$*" >&2
  exit 1
}

require_file() {
  local path="$1"
  [ -f "$path" ] || fail "required artifact missing: $path"
}

sha256_file() {
  shasum -a 256 "$1" | awk '{print tolower($1)}'
}

normalize_sha() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

manifest="$dist_dir/release-manifest.json"
require_file "$dist_dir/endpoint-agent.exe"
require_file "$dist_dir/bootstrap-package.ps1"
require_file "$dist_dir/install.ps1"
require_file "$dist_dir/uninstall.ps1"
require_file "$dist_dir/windows/EndpointAgent.zip"
require_file "$dist_dir/windows/EndpointAgent.zip.sha256"
require_file "$manifest"

jq -e '.assets | type == "array" and length > 0' "$manifest" >/dev/null \
  || fail "release-manifest.json must contain a non-empty assets array"

rm -rf "$assets_dir"
mkdir -p "$assets_dir"

cp "$dist_dir/endpoint-agent.exe" "$assets_dir/"
cp "$dist_dir/bootstrap-package.ps1" "$assets_dir/"
cp "$dist_dir/install.ps1" "$assets_dir/"
cp "$dist_dir/uninstall.ps1" "$assets_dir/"
cp "$dist_dir/windows/EndpointAgent.zip" "$assets_dir/"
cp "$dist_dir/windows/EndpointAgent.zip.sha256" "$assets_dir/"
cp "$manifest" "$assets_dir/"

zip_sha="$(sha256_file "$assets_dir/EndpointAgent.zip")"
zip_sha_file="$(awk 'NF {print tolower($1); exit}' "$assets_dir/EndpointAgent.zip.sha256")"
[ "$zip_sha" = "$zip_sha_file" ] \
  || fail "EndpointAgent.zip.sha256 ($zip_sha_file) does not match served EndpointAgent.zip ($zip_sha)"

manifest_zip_sha="$(jq -r '.endpoint_agent_zip_sha256 // empty' "$manifest" | tr '[:upper:]' '[:lower:]')"
[ "$manifest_zip_sha" = "$zip_sha" ] \
  || fail "release-manifest endpoint_agent_zip_sha256 ($manifest_zip_sha) does not match served EndpointAgent.zip ($zip_sha)"

manifest_exe_sha="$(jq -r '.endpoint_agent_sha256 // empty' "$manifest" | tr '[:upper:]' '[:lower:]')"
exe_sha="$(sha256_file "$assets_dir/endpoint-agent.exe")"
[ "$manifest_exe_sha" = "$exe_sha" ] \
  || fail "release-manifest endpoint_agent_sha256 ($manifest_exe_sha) does not match served endpoint-agent.exe ($exe_sha)"

while IFS=$'\t' read -r name expected_sha; do
  case "$name" in
    ""|*/*|*..*) fail "unsafe release-manifest asset name: $name" ;;
  esac
  require_file "$assets_dir/$name"
  actual_sha="$(sha256_file "$assets_dir/$name")"
  expected_sha="$(normalize_sha "$expected_sha")"
  [ "$actual_sha" = "$expected_sha" ] \
    || fail "release-manifest asset sha mismatch for $name: manifest=$expected_sha served=$actual_sha"
done < <(jq -r '.assets[] | [.name, .sha256] | @tsv' "$manifest")

(
  cd "$assets_dir"
  shasum -a 256 \
    endpoint-agent.exe bootstrap-package.ps1 install.ps1 uninstall.ps1 \
    EndpointAgent.zip EndpointAgent.zip.sha256 release-manifest.json \
    > SHA256SUMS
)

echo "artifact-host assets staged and verified in $assets_dir"
