#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

wrapper="scripts/codesign/codesign-sign.sh"

require() {
  grep -qF "$1" "$wrapper" \
    || { echo "codesign wrapper contract missing: $1" >&2; exit 1; }
}

for marker in \
  'SIGCHECK="$("$OSSLSIGNCODE" verify -in "$IN_R" 2>&1 || true)"' \
  "grep -qE '^Signature Index:'" \
  'grep -qF "No signature found"' \
  'grep -qF "MSI file has no signature"' \
  '[ "$EXT" = "msi" ]' \
  "could not prove that input is unsigned" \
  "grep -qi \"is timestamped\"" \
  "grep -qE '^[[:space:]]*Timestamp time:'" \
  "grep -q \"Timestamp Server Signature verification: ok\"" \
  "grep -qE '^[[:space:]]*Countersignatures:'" \
  "signature NOT timestamped"
do
  require "$marker"
done

if grep -qF '"$OSSLSIGNCODE" extract-signature' "$wrapper"; then
  echo "codesign wrapper must not use osslsigncode 2.8 extract-signature on unsigned PE input" >&2
  exit 1
fi

echo "codesign wrapper osslsigncode 2.8 contract PASS"
