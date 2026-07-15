#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

fail() {
  echo "windows-package-attestation-contract: $*" >&2
  exit 1
}

command -v unzip >/dev/null 2>&1 || fail "unzip is required"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

repo="$tmp/repo"
mkdir -p "$repo/scripts/build" "$repo/installers/windows" "$repo/dist"
cp scripts/build/windows-package.sh "$repo/scripts/build/windows-package.sh"
mkdir -p "$repo/scripts/release"
cp scripts/release/verify-endpoint-agent-zip.sh "$repo/scripts/release/verify-endpoint-agent-zip.sh"
printf 'package readme\n' > "$repo/installers/windows/README.md"

printf 'signed endpoint binary\n' > "$repo/dist/endpoint-agent.exe"
printf 'bootstrap\n' > "$repo/dist/bootstrap-package.ps1"
printf 'install\n' > "$repo/dist/install.ps1"
printf 'uninstall\n' > "$repo/dist/uninstall.ps1"
printf 'c2lnbmVkLXByb3ZlbmFuY2U=\n' > "$repo/dist/remote-bridge-attestation-evidence.b64"
printf '{"signature_present":true,"private_key_included":false}\n' \
  > "$repo/dist/remote-bridge-attestation-evidence-summary.json"

(
  cd "$repo"
  PREBUILT_EXE=dist/endpoint-agent.exe \
    PACKAGE_REQUIRE_REMOTE_BRIDGE_ATTESTATION=true \
    ./scripts/build/windows-package.sh >/dev/null
)

package="$repo/dist/windows/EndpointAgent"
zip_path="$repo/dist/windows/EndpointAgent.zip"
for required in \
  endpoint-agent.exe \
  bootstrap-package.ps1 \
  install.ps1 \
  uninstall.ps1 \
  README.md \
  remote-bridge-attestation-evidence.b64 \
  remote-bridge-attestation-evidence-summary.json \
  SHA256SUMS
do
  [ -f "$package/$required" ] || fail "release package missing $required"
  unzip -Z1 "$zip_path" | grep -Fx "$required" >/dev/null \
    || fail "release ZIP missing $required"
done

(
  cd "$package"
  shasum -a 256 -c SHA256SUMS >/dev/null
)
grep -Eq '^[0-9a-fA-F]{64}[[:space:]]+remote-bridge-attestation-evidence\.b64$' "$package/SHA256SUMS" \
  || fail "SHA256SUMS does not cover signed attestation evidence"
grep -Eq '^[0-9a-fA-F]{64}[[:space:]]+remote-bridge-attestation-evidence-summary\.json$' "$package/SHA256SUMS" \
  || fail "SHA256SUMS does not cover attestation evidence summary"

(
  cd "$repo"
  ./scripts/release/verify-endpoint-agent-zip.sh \
    --zip dist/windows/EndpointAgent.zip \
    --release-dir dist >/dev/null
)

cp "$repo/dist/remote-bridge-attestation-evidence.b64" "$tmp/original-evidence.b64"
printf 'dGFtcGVyZWQ=\n' > "$repo/dist/remote-bridge-attestation-evidence.b64"
if (
  cd "$repo"
  ./scripts/release/verify-endpoint-agent-zip.sh \
    --zip dist/windows/EndpointAgent.zip \
    --release-dir dist
) >"$tmp/tampered-loose-asset.out" 2>"$tmp/tampered-loose-asset.err"; then
  fail "ZIP verifier accepted mismatched loose attestation evidence"
fi
grep -F "differs from the published release asset" "$tmp/tampered-loose-asset.err" >/dev/null \
  || fail "ZIP verifier mismatch failure did not explain the binding violation"
cp "$tmp/original-evidence.b64" "$repo/dist/remote-bridge-attestation-evidence.b64"

rm "$repo/dist/remote-bridge-attestation-evidence.b64"
if (
  cd "$repo"
  PREBUILT_EXE=dist/endpoint-agent.exe \
    PACKAGE_REQUIRE_REMOTE_BRIDGE_ATTESTATION=true \
    ./scripts/build/windows-package.sh
) >"$tmp/missing-evidence.out" 2>"$tmp/missing-evidence.err"; then
  fail "trusted PREBUILT_EXE packaging passed without signed attestation evidence"
fi
grep -F "signed remote-bridge attestation evidence not found for trusted packaging" "$tmp/missing-evidence.err" >/dev/null \
  || fail "missing-evidence failure did not explain the release contract"

rm "$repo/dist/remote-bridge-attestation-evidence-summary.json"
(
  cd "$repo"
  PREBUILT_EXE=dist/endpoint-agent.exe ./scripts/build/windows-package.sh >/dev/null
)
[ ! -e "$repo/dist/windows/EndpointAgent/remote-bridge-attestation-evidence.b64" ] \
  || fail "lab package unexpectedly retained trusted remote-bridge evidence"

echo "windows package attestation contract PASS"
