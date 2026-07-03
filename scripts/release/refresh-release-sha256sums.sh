#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

dist_dir="${1:-dist}"
output="${2:-$dist_dir/SHA256SUMS}"

fail() {
  echo "::error::$*" >&2
  exit 1
}

require_file() {
  local path="$1"
  [ -f "$path" ] || fail "required release artifact missing: $path"
}

sha_line() {
  local path="$1"
  local asset_name="$2"
  require_file "$path"
  printf '%s  %s\n' "$(shasum -a 256 "$path" | awk '{print tolower($1)}')" "$asset_name"
}

command -v jq >/dev/null 2>&1 || fail "jq is required"

require_file "$dist_dir/endpoint-agent.exe"
require_file "$dist_dir/bootstrap-package.ps1"
require_file "$dist_dir/install.ps1"
require_file "$dist_dir/uninstall.ps1"
require_file "$dist_dir/windows/EndpointAgent.zip"
require_file "$dist_dir/windows/EndpointAgent.zip.sha256"
require_file "$dist_dir/release-manifest.json"

attestation_assets="$(
  jq -r '
    if (.remote_bridge_attestation? | type == "object") then
      .remote_bridge_attestation.evidence_file,
      .remote_bridge_attestation.summary_file
    else
      empty
    end
  ' "$dist_dir/release-manifest.json"
)"
while IFS= read -r asset; do
  [ -n "$asset" ] || continue
  case "$asset" in
    ""|*/*|*..*) fail "unsafe remote_bridge_attestation asset name: $asset" ;;
  esac
  require_file "$dist_dir/$asset"
done <<< "$attestation_assets"

mkdir -p "$(dirname "$output")"
tmp="$output.tmp"
{
  sha_line "$dist_dir/endpoint-agent.exe" "endpoint-agent.exe"
  sha_line "$dist_dir/bootstrap-package.ps1" "bootstrap-package.ps1"
  sha_line "$dist_dir/install.ps1" "install.ps1"
  sha_line "$dist_dir/uninstall.ps1" "uninstall.ps1"
  sha_line "$dist_dir/windows/EndpointAgent.zip" "EndpointAgent.zip"
  sha_line "$dist_dir/windows/EndpointAgent.zip.sha256" "EndpointAgent.zip.sha256"
  while IFS= read -r asset; do
    [ -n "$asset" ] || continue
    sha_line "$dist_dir/$asset" "$asset"
  done <<< "$attestation_assets"
  sha_line "$dist_dir/release-manifest.json" "release-manifest.json"
} > "$tmp"
mv "$tmp" "$output"

echo "release SHA256SUMS refreshed in $output"
