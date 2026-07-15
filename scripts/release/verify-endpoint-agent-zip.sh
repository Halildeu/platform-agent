#!/usr/bin/env bash
set -euo pipefail

zip_path=""
release_dir=""

fail() {
  echo "verify-endpoint-agent-zip: $*" >&2
  exit 1
}

usage() {
  cat <<'USAGE'
Usage:
  scripts/release/verify-endpoint-agent-zip.sh --zip PATH --release-dir DIR

Verifies the strict signed EndpointAgent.zip payload, its internal SHA256SUMS,
and the byte identity of the binary and provenance files with loose release
assets. Packaged PowerShell files are intentionally BOM-normalized and are
therefore covered by the internal hashes rather than loose-asset byte parity.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --zip)
      zip_path="${2:-}"; shift 2 ;;
    --release-dir)
      release_dir="${2:-}"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      fail "unknown argument: $1" ;;
  esac
done

command -v unzip >/dev/null 2>&1 || fail "unzip is required"
command -v shasum >/dev/null 2>&1 || fail "shasum is required"
[ -f "$zip_path" ] || fail "ZIP not found: $zip_path"
[ -d "$release_dir" ] || fail "release directory not found: $release_dir"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

zip_entries="$tmp/entries.txt"
expected_zip_entries="$tmp/entries.expected.txt"
unzip -Z1 "$zip_path" | LC_ALL=C sort > "$zip_entries"
printf '%s\n' \
  README.md \
  SHA256SUMS \
  bootstrap-package.ps1 \
  endpoint-agent.exe \
  install.ps1 \
  remote-bridge-attestation-evidence-summary.json \
  remote-bridge-attestation-evidence.b64 \
  uninstall.ps1 \
  | LC_ALL=C sort > "$expected_zip_entries"
cmp -s "$zip_entries" "$expected_zip_entries" \
  || fail "EndpointAgent.zip contents differ from the strict release package contract"

package_dir="$tmp/package"
mkdir "$package_dir"
unzip -q "$zip_path" -d "$package_dir"

expected_sum_names="$tmp/sum-names.expected.txt"
actual_sum_names="$tmp/sum-names.txt"
printf '%s\n' \
  README.md \
  bootstrap-package.ps1 \
  endpoint-agent.exe \
  install.ps1 \
  remote-bridge-attestation-evidence-summary.json \
  remote-bridge-attestation-evidence.b64 \
  uninstall.ps1 \
  | LC_ALL=C sort > "$expected_sum_names"
awk '
  NF != 2 || $1 !~ /^[0-9a-fA-F]{64}$/ || $2 ~ /(^\/|\/|\\|\.\.)/ { exit 1 }
  { print $2 }
' "$package_dir/SHA256SUMS" | LC_ALL=C sort > "$actual_sum_names" \
  || fail "EndpointAgent.zip SHA256SUMS has an invalid line or unsafe path"
cmp -s "$actual_sum_names" "$expected_sum_names" \
  || fail "EndpointAgent.zip SHA256SUMS does not cover the exact package payload"
(
  cd "$package_dir"
  shasum -a 256 -c SHA256SUMS >/dev/null
) || fail "EndpointAgent.zip internal SHA256SUMS verification failed"

for bound_asset in \
  endpoint-agent.exe \
  remote-bridge-attestation-evidence.b64 \
  remote-bridge-attestation-evidence-summary.json
do
  [ -f "$release_dir/$bound_asset" ] \
    || fail "published release asset missing for ZIP binding: $bound_asset"
  cmp -s "$package_dir/$bound_asset" "$release_dir/$bound_asset" \
    || fail "EndpointAgent.zip $bound_asset differs from the published release asset"
done

echo "EndpointAgent.zip strict package verification pass"
