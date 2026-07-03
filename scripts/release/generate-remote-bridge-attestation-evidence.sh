#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

binary_digest=""
builder_id=""
policy_hash=""
private_key_pem=""
public_key_pem=""
out_dir="dist"
signature_algorithm="SHA256withECDSA"

fail() {
  echo "::error::$*" >&2
  exit 1
}

usage() {
  cat <<'USAGE'
Usage:
  scripts/release/generate-remote-bridge-attestation-evidence.sh [options]

Options:
  --binary-digest HEX          Signed endpoint-agent.exe SHA-256 digest.
  --builder-id ID              Expected remote-bridge builder id.
  --policy-hash HASH           Expected remote-bridge SLSA policy hash.
  --private-key-pem PATH       PEM private key used only for signing.
  --public-key-pem PATH        Optional PEM public key for self-verification.
  --out-dir DIR                Output directory (default: dist).
  --signature-algorithm ALG    Summary metadata (default: SHA256withECDSA).
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --binary-digest)
      binary_digest="${2:-}"; shift 2 ;;
    --builder-id)
      builder_id="${2:-}"; shift 2 ;;
    --policy-hash)
      policy_hash="${2:-}"; shift 2 ;;
    --private-key-pem)
      private_key_pem="${2:-}"; shift 2 ;;
    --public-key-pem)
      public_key_pem="${2:-}"; shift 2 ;;
    --out-dir)
      out_dir="${2:-}"; shift 2 ;;
    --signature-algorithm)
      signature_algorithm="${2:-}"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      fail "unknown argument: $1" ;;
  esac
done

[ -n "$binary_digest" ] || fail "--binary-digest is required"
[ -n "$builder_id" ] || fail "--builder-id is required"
[ -n "$policy_hash" ] || fail "--policy-hash is required"
[ -n "$private_key_pem" ] || fail "--private-key-pem is required"
[[ "$binary_digest" =~ ^[0-9a-fA-F]{64}$ ]] || fail "--binary-digest must be 64 hex chars"
[ -f "$private_key_pem" ] || fail "private key PEM missing: $private_key_pem"
if [ -n "$public_key_pem" ] && [ ! -f "$public_key_pem" ]; then
  fail "public key PEM missing: $public_key_pem"
fi

command -v openssl >/dev/null 2>&1 || fail "openssl is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"

mkdir -p "$out_dir"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

canonical="$tmp/canonical-provenance.bin"
signature="$tmp/predicate-signature.der"
evidence_plain="$tmp/remote-bridge-attestation-evidence.txt"
evidence_b64="$out_dir/remote-bridge-attestation-evidence.b64"
summary="$out_dir/remote-bridge-attestation-evidence-summary.json"

BINARY_DIGEST="$(printf '%s' "$binary_digest" | tr '[:upper:]' '[:lower:]')" \
BUILDER_ID="$builder_id" \
POLICY_HASH="$policy_hash" \
CANONICAL_OUT="$canonical" \
python3 - <<'PY'
import os
import struct

fields = [
    os.environ["BINARY_DIGEST"],
    os.environ["BUILDER_ID"],
    os.environ["POLICY_HASH"],
]
with open(os.environ["CANONICAL_OUT"], "wb") as out:
    for field in fields:
        data = field.encode("utf-8")
        out.write(struct.pack(">I", len(data)))
        out.write(data)
PY

openssl dgst -sha256 -sign "$private_key_pem" -out "$signature" "$canonical"
signature_b64="$(base64 < "$signature" | tr -d '\n')"
printf '%s|%s|%s|%s' \
  "$(printf '%s' "$binary_digest" | tr '[:upper:]' '[:lower:]')" \
  "$builder_id" \
  "$policy_hash" \
  "$signature_b64" > "$evidence_plain"
base64 < "$evidence_plain" | tr -d '\n' > "$evidence_b64"
printf '\n' >> "$evidence_b64"

verification_result="not_run"
public_key_sha256=""
if [ -n "$public_key_pem" ]; then
  public_key_sha256="$(shasum -a 256 "$public_key_pem" | awk '{print tolower($1)}')"
  if openssl dgst -sha256 -verify "$public_key_pem" -signature "$signature" "$canonical" >/dev/null 2>&1; then
    verification_result="verified"
  else
    verification_result="failed"
    fail "generated remote-bridge attestation signature did not verify with public key"
  fi
fi

evidence_sha256="$(shasum -a 256 "$evidence_b64" | awk '{print tolower($1)}')"
signature_sha256="$(shasum -a 256 "$signature" | awk '{print tolower($1)}')"

BINARY_DIGEST="$(printf '%s' "$binary_digest" | tr '[:upper:]' '[:lower:]')" \
BUILDER_ID="$builder_id" \
POLICY_HASH="$policy_hash" \
SIGNATURE_ALGORITHM="$signature_algorithm" \
SIGNATURE_SHA256="$signature_sha256" \
EVIDENCE_SHA256="$evidence_sha256" \
PUBLIC_KEY_SHA256="$public_key_sha256" \
VERIFICATION_RESULT="$verification_result" \
SUMMARY_OUT="$summary" \
python3 - <<'PY'
import json
import os

summary = {
    "schema_version": 1,
    "artifact": "remote-bridge-attestation-evidence.b64",
    "binary_digest": os.environ["BINARY_DIGEST"],
    "builder_id": os.environ["BUILDER_ID"],
    "policy_hash": os.environ["POLICY_HASH"],
    "signature_algorithm": os.environ["SIGNATURE_ALGORITHM"],
    "signature_sha256": os.environ["SIGNATURE_SHA256"],
    "signature_present": True,
    "evidence_sha256": os.environ["EVIDENCE_SHA256"],
    "public_key_sha256": os.environ["PUBLIC_KEY_SHA256"],
    "public_key_verification": os.environ["VERIFICATION_RESULT"],
    "private_key_included": False,
    "raw_private_key_logged": False,
}
with open(os.environ["SUMMARY_OUT"], "w", encoding="utf-8") as out:
    json.dump(summary, out, indent=2, sort_keys=False)
    out.write("\n")
PY

echo "remote-bridge attestation evidence generated: $evidence_b64"
echo "remote-bridge attestation evidence summary: $summary"
