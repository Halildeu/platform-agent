#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

policy="config/faz22-6-endpoint-agent-release-policy.v1.json"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail() {
  echo "release-policy-contract: $*" >&2
  exit 1
}

sha_file() {
  shasum -a 256 "$1" | awk '{print tolower($1)}'
}

expect_fail() {
  local name="$1"
  shift
  if "$@" >"$tmp/${name}.out" 2>"$tmp/${name}.err"; then
    cat "$tmp/${name}.out" >&2
    cat "$tmp/${name}.err" >&2
    fail "expected failure but command passed: $name"
  fi
}

command -v jq >/dev/null 2>&1 || fail "jq is required"
[ -f "$policy" ] || fail "policy missing: $policy"

dist="$tmp/dist"
mkdir -p "$dist/windows"
printf 'exe\n' > "$dist/endpoint-agent.exe"
printf 'bootstrap\n' > "$dist/bootstrap-package.ps1"
printf 'install\n' > "$dist/install.ps1"
printf 'uninstall\n' > "$dist/uninstall.ps1"
printf 'zip\n' > "$dist/windows/EndpointAgent.zip"
printf '%s  EndpointAgent.zip\n' "$(sha_file "$dist/windows/EndpointAgent.zip")" > "$dist/windows/EndpointAgent.zip.sha256"
printf 'test-remote-bridge-attestation-evidence\n' > "$dist/remote-bridge-attestation-evidence.b64"
cat > "$dist/remote-bridge-attestation-evidence-summary.json" <<'JSON'
{
  "schema_version": 1,
  "artifact": "remote-bridge-attestation-evidence.b64",
  "signature_present": true,
  "private_key_included": false,
  "raw_private_key_logged": false
}
JSON

exe_sha="$(sha_file "$dist/endpoint-agent.exe")"
bootstrap_sha="$(sha_file "$dist/bootstrap-package.ps1")"
install_sha="$(sha_file "$dist/install.ps1")"
uninstall_sha="$(sha_file "$dist/uninstall.ps1")"
zip_sha="$(sha_file "$dist/windows/EndpointAgent.zip")"
attestation_evidence_sha="$(sha_file "$dist/remote-bridge-attestation-evidence.b64")"
attestation_summary_sha="$(sha_file "$dist/remote-bridge-attestation-evidence-summary.json")"

jq -n \
  --arg source_commit "10361a60ca8ca1fb4c6efe3823b433297e16ae3a" \
  --arg workflow_run_id "1782280001" \
  --arg release_tag "v0.3.0" \
  --arg release_class "rollout-candidate" \
  --arg endpoint_agent_sha256 "$exe_sha" \
  --arg endpoint_agent_zip_sha256 "$zip_sha" \
  --arg signer_thumbprint "D68F4F530137EB65CE44E3405E82B46205E753E5" \
  --arg signing_tier "trusted-internal-ca" \
  --arg artifact_host_digest "sha256:36a81cb89294ef7f4d09350ab9f92a955b65b8132ba5330fcf1dcb7e365ab3e2" \
  --arg previous_release "v0.2.28" \
  --arg bootstrap_sha "$bootstrap_sha" \
  --arg install_sha "$install_sha" \
  --arg uninstall_sha "$uninstall_sha" \
  --arg attestation_evidence_sha "$attestation_evidence_sha" \
  --arg attestation_summary_sha "$attestation_summary_sha" \
  '{
    schema_version: 1,
    source_commit: $source_commit,
    workflow_run_id: $workflow_run_id,
    release_tag: $release_tag,
    release_class: $release_class,
    endpoint_agent_sha256: $endpoint_agent_sha256,
    endpoint_agent_zip_sha256: $endpoint_agent_zip_sha256,
    signer_thumbprint: $signer_thumbprint,
    signing_tier: $signing_tier,
    trust_scope: "installer-imported-internal-ca",
    publicly_trusted: false,
    artifact_host_digest: $artifact_host_digest,
    artifact_host_image: "ghcr.io/halildeu/platform-agent-artifacts:v0.3.0",
    artifact_host_image_ref: ("ghcr.io/halildeu/platform-agent-artifacts:v0.3.0@" + $artifact_host_digest),
    previous_release: $previous_release,
    remote_bridge_attestation: {
      evidence_file: "remote-bridge-attestation-evidence.b64",
      evidence_sha256: $attestation_evidence_sha,
      summary_file: "remote-bridge-attestation-evidence-summary.json",
      summary_sha256: $attestation_summary_sha,
      binary_digest: $endpoint_agent_sha256,
      builder_id: "faz22-agent-builder@acik",
      policy_hash: "faz22-remote-bridge-policy-v1",
      signature_algorithm: "SHA256withECDSA",
      private_key_included: false
    },
    assets: [
      {name: "endpoint-agent.exe", sha256: $endpoint_agent_sha256},
      {name: "bootstrap-package.ps1", sha256: $bootstrap_sha},
      {name: "install.ps1", sha256: $install_sha},
      {name: "uninstall.ps1", sha256: $uninstall_sha},
      {name: "EndpointAgent.zip", sha256: $endpoint_agent_zip_sha256},
      {name: "remote-bridge-attestation-evidence.b64", sha256: $attestation_evidence_sha},
      {name: "remote-bridge-attestation-evidence-summary.json", sha256: $attestation_summary_sha}
    ]
  }' > "$dist/release-manifest.json"

scripts/release/validate-release-manifest.sh \
  --policy "$policy" \
  --manifest "$dist/release-manifest.json" \
  --dist-dir "$dist" \
  --tag v0.3.0 \
  --source-commit 10361a60ca8ca1fb4c6efe3823b433297e16ae3a \
  --previous-release v0.2.28 \
  --release-class rollout-candidate

jq 'del(.source_commit)' "$dist/release-manifest.json" > "$tmp/missing-source.json"
expect_fail missing-source scripts/release/validate-release-manifest.sh --policy "$policy" --manifest "$tmp/missing-source.json"

jq '.artifact_host_digest = "sha256:not-a-digest"' "$dist/release-manifest.json" > "$tmp/bad-digest.json"
expect_fail bad-digest scripts/release/validate-release-manifest.sh --policy "$policy" --manifest "$tmp/bad-digest.json"

jq 'del(.artifact_host_image_ref)' "$dist/release-manifest.json" > "$tmp/missing-image-ref.json"
expect_fail missing-image-ref scripts/release/validate-release-manifest.sh --policy "$policy" --manifest "$tmp/missing-image-ref.json"

jq '.artifact_host_image_ref = "ghcr.io/halildeu/platform-agent-artifacts:v0.3.0@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' "$dist/release-manifest.json" > "$tmp/bad-image-ref-digest.json"
expect_fail bad-image-ref-digest scripts/release/validate-release-manifest.sh --policy "$policy" --manifest "$tmp/bad-image-ref-digest.json"

repo="$tmp/repo"
mkdir "$repo"
git -C "$repo" init -q
git -C "$repo" config user.email release-policy-test@example.invalid
git -C "$repo" config user.name release-policy-test
printf 'root\n' > "$repo/README.md"
git -C "$repo" add README.md
git -C "$repo" commit -q -m root
for patch in 24 25 26 27 28; do
  printf 'v0.2.%s\n' "$patch" >> "$repo/train.txt"
  git -C "$repo" add train.txt
  git -C "$repo" commit -q -m "release v0.2.$patch"
  git -C "$repo" tag "v0.2.$patch"
done
printf 'v0.3.0\n' >> "$repo/train.txt"
git -C "$repo" add train.txt
git -C "$repo" commit -q -m "release v0.3.0"
git -C "$repo" tag v0.3.0
cp "$policy" "$repo/policy.json"

(
  cd "$repo"
  RELEASE_POLICY_REPO_ROOT="$repo" "$OLDPWD/scripts/release/check-release-lineage-policy.sh" \
    --policy "$repo/policy.json" \
    --tag v0.3.0 \
    --release-class rollout-candidate
)

(
  cd "$repo"
  expect_fail frozen-minor env RELEASE_POLICY_REPO_ROOT="$repo" "$OLDPWD/scripts/release/check-release-lineage-policy.sh" \
    --policy "$repo/policy.json" \
    --tag v0.2.29 \
    --release-class rollout-candidate
)

(
  cd "$repo"
  expect_fail production-class env RELEASE_POLICY_REPO_ROOT="$repo" "$OLDPWD/scripts/release/check-release-lineage-policy.sh" \
    --policy "$repo/policy.json" \
    --tag v0.3.0 \
    --release-class production-candidate
)

echo "release policy contract tests passed"
