#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

policy="config/faz22-6-endpoint-agent-release-policy.v1.json"
manifest="dist/release-manifest.json"
dist_dir=""
expect_tag=""
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
  scripts/release/validate-release-manifest.sh [options]

Options:
  --policy PATH                 Release policy JSON.
  --manifest PATH               release-manifest.json path.
  --dist-dir DIR                Optional artifact directory; verifies files/hashes when present.
  --tag TAG                     Optional expected release_tag.
  --source-commit SHA           Optional expected source_commit.
  --previous-release TAG        Optional expected previous_release.
  --release-class CLASS         Optional expected release_class.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --policy)
      policy="${2:-}"; shift 2 ;;
    --manifest)
      manifest="${2:-}"; shift 2 ;;
    --dist-dir)
      dist_dir="${2:-}"; shift 2 ;;
    --tag)
      expect_tag="${2:-}"; shift 2 ;;
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

command -v jq >/dev/null 2>&1 || fail "jq is required"
[ -f "$policy" ] || fail "release policy missing: $policy"
[ -f "$manifest" ] || fail "release manifest missing: $manifest"

jq -e . "$policy" >/dev/null || fail "release policy is not valid JSON: $policy"
jq -e . "$manifest" >/dev/null || fail "release manifest is not valid JSON: $manifest"

required_fields="$(jq -c '.release_manifest_required_fields' "$policy")"
jq -e --argjson required "$required_fields" '
  . as $m | all($required[]; . as $key | ($m | has($key)) and $m[$key] != null and (($m[$key] | tostring | length) > 0))
' "$manifest" >/dev/null || {
  missing="$(jq -r --argjson required "$required_fields" '
    . as $m | [$required[] | . as $key | select((($m | has($key)) | not) or $m[$key] == null or (($m[$key] | tostring | length) == 0))] | join(", ")
  ' "$manifest")"
  fail "release manifest missing required field(s): $missing"
}

field() {
  jq -er --arg key "$1" '.[$key]' "$manifest"
}

assert_eq() {
  local name="$1" expected="$2" actual="$3"
  [ -z "$expected" ] || [ "$expected" = "$actual" ] \
    || fail "$name mismatch: expected '$expected', got '$actual'"
}

source_commit="$(field source_commit | tr '[:upper:]' '[:lower:]')"
workflow_run_id="$(field workflow_run_id)"
release_tag="$(field release_tag)"
release_class="$(field release_class)"
endpoint_agent_sha256="$(field endpoint_agent_sha256 | tr '[:upper:]' '[:lower:]')"
endpoint_agent_zip_sha256="$(field endpoint_agent_zip_sha256 | tr '[:upper:]' '[:lower:]')"
signer_thumbprint="$(field signer_thumbprint | tr '[:upper:]' '[:lower:]')"
signing_tier="$(field signing_tier)"
artifact_host_digest="$(field artifact_host_digest)"
artifact_host_image_ref="$(field artifact_host_image_ref)"
previous_release="$(field previous_release)"

[[ "$source_commit" =~ ^[0-9a-f]{40}$ ]] || fail "source_commit must be 40 lowercase hex after normalization"
[[ "$workflow_run_id" =~ ^[0-9]+$ ]] || fail "workflow_run_id must be numeric"
[[ "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "release_tag must be clean semver tag"
jq -e --arg rc "$release_class" '.release_train_policy.allowed_release_classes | index($rc) != null' "$policy" >/dev/null \
  || fail "release_class '$release_class' is not policy-allowed"
[[ "$endpoint_agent_sha256" =~ ^[0-9a-f]{64}$ ]] || fail "endpoint_agent_sha256 must be 64 hex"
[[ "$endpoint_agent_zip_sha256" =~ ^[0-9a-f]{64}$ ]] || fail "endpoint_agent_zip_sha256 must be 64 hex"
[[ "$signer_thumbprint" =~ ^[0-9a-f]{40}$ ]] || fail "signer_thumbprint must be 40 hex"
[ "$signing_tier" = "trusted-internal-ca" ] || fail "signing_tier must be trusted-internal-ca for trusted EXE releases"
[[ "$artifact_host_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "artifact_host_digest must be sha256:<64 lowercase hex>"
[[ "$previous_release" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "previous_release must be clean semver tag"
[ "$previous_release" != "$release_tag" ] || fail "previous_release cannot equal release_tag"
case "$artifact_host_image_ref" in
  *@sha256:*) ;;
  *) fail "artifact_host_image_ref must include @sha256 digest: $artifact_host_image_ref" ;;
esac
ref_digest="${artifact_host_image_ref##*@}"
[ "$ref_digest" = "$artifact_host_digest" ] \
  || fail "artifact_host_image_ref digest $ref_digest != artifact_host_digest $artifact_host_digest"

jq -e '.assets | type == "array" and length > 0' "$manifest" >/dev/null \
  || fail "release manifest must contain a non-empty assets array"

jq -e '
  .remote_bridge_attestation as $a
  | ($a | type == "object")
  and ($a.evidence_file == "remote-bridge-attestation-evidence.b64")
  and ($a.summary_file == "remote-bridge-attestation-evidence-summary.json")
  and ($a.binary_digest == .endpoint_agent_sha256)
  and (($a.evidence_sha256 // "") | test("^[0-9a-f]{64}$"))
  and (($a.summary_sha256 // "") | test("^[0-9a-f]{64}$"))
  and (($a.builder_id // "") | length > 0)
  and (($a.policy_hash // "") | length > 0)
  and (($a.signature_algorithm // "") | length > 0)
  and ($a.private_key_included == false)
' "$manifest" >/dev/null || fail "release manifest remote_bridge_attestation is missing or invalid"

jq -e '
  .remote_bridge_attestation as $a
  | any(.assets[]; .name == $a.evidence_file and .sha256 == $a.evidence_sha256)
  and any(.assets[]; .name == $a.summary_file and .sha256 == $a.summary_sha256)
' "$manifest" >/dev/null || fail "remote_bridge_attestation files must be declared in assets with matching sha256"

assert_eq release_tag "$expect_tag" "$release_tag"
assert_eq source_commit "$(printf '%s' "$expect_source_commit" | tr '[:upper:]' '[:lower:]')" "$source_commit"
assert_eq previous_release "$expect_previous_release" "$previous_release"
assert_eq release_class "$expect_release_class" "$release_class"

asset_path() {
  local name="$1"
  if [ -z "$dist_dir" ]; then
    return 1
  fi
  if [ -f "$dist_dir/$name" ]; then
    printf '%s/%s\n' "$dist_dir" "$name"
    return 0
  fi
  if [ -f "$dist_dir/windows/$name" ]; then
    printf '%s/windows/%s\n' "$dist_dir" "$name"
    return 0
  fi
  return 1
}

if [ -n "$dist_dir" ]; then
  [ -d "$dist_dir" ] || fail "dist-dir does not exist: $dist_dir"
  while IFS=$'\t' read -r name expected_sha; do
    case "$name" in
      ""|*/*|*..*) fail "unsafe asset name in manifest: $name" ;;
    esac
    expected_sha="$(printf '%s' "$expected_sha" | tr '[:upper:]' '[:lower:]')"
    [[ "$expected_sha" =~ ^[0-9a-f]{64}$ ]] || fail "asset $name sha256 is not 64 hex"
    path="$(asset_path "$name")" || fail "manifest asset missing from dist-dir: $name"
    actual_sha="$(shasum -a 256 "$path" | awk '{print tolower($1)}')"
    [ "$actual_sha" = "$expected_sha" ] \
      || fail "manifest asset sha mismatch for $name: manifest=$expected_sha actual=$actual_sha"
  done < <(jq -r '.assets[] | [.name, .sha256] | @tsv' "$manifest")
fi

echo "release manifest policy validation pass: $manifest"
