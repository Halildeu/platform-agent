#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

policy="config/faz22-6-endpoint-agent-release-policy.v1.json"
repo="${GITHUB_REPOSITORY:-}"
tag="${TAG:-}"
expect_source_commit=""
expect_previous_release=""
expect_release_class=""

fail() {
  echo "::error::$*" >&2
  exit 1
}

usage() {
  cat <<'USAGE'
Usage:
  scripts/release/verify-published-release.sh --repo OWNER/REPO --tag v0.3.0 [--policy PATH] [lineage expectations]

Verifies the GitHub Release archive after publish: required assets, SHA256SUMS,
release-manifest.json policy contract, EndpointAgent.zip hash, and artifact-host
image digest parity.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --policy)
      policy="${2:-}"; shift 2 ;;
    --repo)
      repo="${2:-}"; shift 2 ;;
    --tag)
      tag="${2:-}"; shift 2 ;;
    --source-commit)
      expect_source_commit="${2:-}"; shift 2 ;;
    --previous-release)
      expect_previous_release="${2:-}"; shift 2 ;;
    --release-class)
      expect_release_class="${2:-}"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      fail "unknown argument: $1" ;;
  esac
done

command -v gh >/dev/null 2>&1 || fail "gh is required"
command -v jq >/dev/null 2>&1 || fail "jq is required"
[ -n "$repo" ] || fail "--repo is required"
[ -n "$tag" ] || fail "--tag is required"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "tag must be clean semver: $tag"
[ -f "$policy" ] || fail "release policy missing: $policy"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

gh release view "$tag" --repo "$repo" >/dev/null || fail "GitHub release is not visible: $repo@$tag"
gh release download "$tag" --repo "$repo" --dir "$tmp" --clobber

required_assets=(
  endpoint-agent.exe
  bootstrap-package.ps1
  install.ps1
  uninstall.ps1
  SHA256SUMS
  release-manifest.json
  EndpointAgent.zip
  EndpointAgent.zip.sha256
  remote-bridge-attestation-evidence.b64
  remote-bridge-attestation-evidence-summary.json
)
for asset in "${required_assets[@]}"; do
  [ -f "$tmp/$asset" ] || fail "published release missing asset: $asset"
done

while read -r expected name extra; do
  [ -z "${expected:-}" ] && continue
  [ -z "${extra:-}" ] || fail "invalid SHA256SUMS line has extra fields for $name"
  [[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] || fail "invalid SHA256SUMS hash for $name"
  case "$name" in
    ""|*/*|*..*) fail "unsafe SHA256SUMS asset name: $name" ;;
  esac
  [ -f "$tmp/$name" ] || fail "SHA256SUMS references missing asset: $name"
  actual="$(shasum -a 256 "$tmp/$name" | awk '{print tolower($1)}')"
  expected="$(printf '%s' "$expected" | tr '[:upper:]' '[:lower:]')"
  [ "$actual" = "$expected" ] || fail "SHA256SUMS mismatch for $name: expected=$expected actual=$actual"
done < "$tmp/SHA256SUMS"

zip_sha="$(shasum -a 256 "$tmp/EndpointAgent.zip" | awk '{print tolower($1)}')"
zip_sha_file="$(awk 'NF {print tolower($1); exit}' "$tmp/EndpointAgent.zip.sha256")"
[ "$zip_sha" = "$zip_sha_file" ] \
  || fail "EndpointAgent.zip.sha256 ($zip_sha_file) does not match EndpointAgent.zip ($zip_sha)"

scripts/release/verify-endpoint-agent-zip.sh \
  --zip "$tmp/EndpointAgent.zip" \
  --release-dir "$tmp"

manifest_tag="$(jq -er '.release_tag' "$tmp/release-manifest.json")"
[ "$manifest_tag" = "$tag" ] || fail "release-manifest release_tag $manifest_tag != $tag"

scripts/release/validate-release-manifest.sh \
  --policy "$policy" \
  --manifest "$tmp/release-manifest.json" \
  --dist-dir "$tmp" \
  --tag "$tag" \
  --source-commit "$expect_source_commit" \
  --previous-release "$expect_previous_release" \
  --release-class "$expect_release_class"

artifact_host_digest="$(jq -er '.artifact_host_digest' "$tmp/release-manifest.json")"
artifact_host_image_ref="$(jq -er '.artifact_host_image_ref' "$tmp/release-manifest.json")"
command -v docker >/dev/null 2>&1 || fail "docker is required to verify artifact_host_image_ref registry digest"
registry_digest="$(
  docker buildx imagetools inspect "$artifact_host_image_ref" \
    | awk '/^Digest:/ {print $2; exit}'
)"
[ -n "$registry_digest" ] || fail "could not resolve registry digest for $artifact_host_image_ref"
[ "$registry_digest" = "$artifact_host_digest" ] \
  || fail "registry digest $registry_digest != manifest artifact_host_digest $artifact_host_digest"

echo "published release archive verification pass: $repo@$tag"
