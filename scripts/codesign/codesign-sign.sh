#!/usr/bin/env bash
# =============================================================================
# AG-018 — sudoers-pinned Authenticode signing wrapper (runs AS `codesign` user).
#
# The self-hosted runner user (`gh-runner`) can NEVER read the leaf private key.
# It may only invoke THIS wrapper via a pinned sudoers rule:
#   gh-runner ALL=(codesign) NOPASSWD: /usr/local/bin/codesign-sign
# The wrapper signs ONE caller-provided Windows binary (MSI or PE: .exe/.dll) and
# writes ONE output of the same type. The key stays 0400 codesign:codesign and is
# read only inside this process.
#
# Hardening (Codex 019eb0dd + 019eb20c):
#   - exactly two positional args: <in> <out>; nothing else accepted
#   - both paths confined to an allowed work root (no path traversal / abs escape)
#   - input is a regular file with a .msi/.exe/.dll extension AND a matching magic
#     byte (PE "MZ" / MSI OLE2) so a misnamed input can't be signed; out matches ext
#   - osslsigncode is the only signing binary; pinned absolute path
#   - timestamp is REQUIRED (fail-closed: no TSA reply => no signature => exit!=0)
#   - re-verify with osslsigncode before returning; refuse double-sign
#   - root-owned, mode 0755, intended to be `chattr +i` (immutable) after install
#
# Manifest custody (written by the workflow, not here):
#   key_custody=host-fs-restricted  vault_backed=false  wrapper_required=true
# =============================================================================
set -euo pipefail

OSSLSIGNCODE="/usr/bin/osslsigncode"
LEAF_KEY="/etc/codesign/leaf/leaf.key"
LEAF_CRT="/etc/codesign/leaf/leaf.crt"
ROOT_CRT="/etc/codesign/root/root.crt"
TSA_URL="${CODESIGN_TIMESTAMP_URL:-http://timestamp.digicert.com}"
WORK_ROOT="${CODESIGN_WORK_ROOT:-/var/lib/codesign/work}"   # runner stages files here

# group-readable output so the runner (shared `codesign` group on the work dir)
# can pick up the signed MSI; the private key stays 0400 owner-only regardless.
umask 002

die() { echo "codesign-sign: $*" >&2; exit 1; }

# --- strict arg contract -----------------------------------------------------
[ "$#" -eq 2 ] || die "usage: codesign-sign <in.{msi,exe,dll}> <out.same-ext> (got $# args)"
IN="$1"; OUT="$2"

# --- path confinement (resolve, then assert under WORK_ROOT) ------------------
canon() { readlink -m -- "$1"; }   # -m: don't require existence (out may be new)
IN_R="$(canon "$IN")"; OUT_R="$(canon "$OUT")"
WORK_R="$(canon "$WORK_ROOT")"
case "$IN_R/"  in "$WORK_R"/*) : ;; *) die "input escapes work root: $IN_R" ;; esac
case "$OUT_R/" in "$WORK_R"/*) : ;; *) die "output escapes work root: $OUT_R" ;; esac
[ "$IN_R" != "$OUT_R" ] || die "in and out must differ"
# Accept Windows MSI or PE (.exe/.dll); in and out must share the extension.
case "$IN_R"  in *.msi) EXT=msi ;; *.exe) EXT=exe ;; *.dll) EXT=dll ;; *) die "input must be .msi/.exe/.dll" ;; esac
case "$OUT_R" in *."$EXT") : ;; *) die "output extension must match input (.$EXT)" ;; esac
[ -f "$IN_R" ] || die "input not a regular file: $IN_R"
# Magic-byte type check so a misnamed input can't be signed (Codex 019eb20c):
#   PE (.exe/.dll) starts with "MZ" (4D5A); MSI is an OLE2 compound (D0CF11E0...).
MAGIC="$(head -c 8 "$IN_R" | xxd -p 2>/dev/null | head -c 16)"
case "$EXT" in
  exe|dll) case "$MAGIC" in 4d5a*) : ;; *) die "input .$EXT is not a PE binary (magic=$MAGIC)" ;; esac ;;
  msi)     case "$MAGIC" in d0cf11e0a1b11ae1) : ;; *) die "input .msi is not an OLE2/MSI (magic=$MAGIC)" ;; esac ;;
esac
[ -d "$(dirname "$OUT_R")" ] || die "output dir missing: $(dirname "$OUT_R")"
[ ! -e "$OUT_R" ] || die "output already exists (refusing overwrite): $OUT_R"

# --- refuse double-sign ------------------------------------------------------
# Detect signature PRESENCE, not chain validity. osslsigncode 2.8 can segfault
# while extract-signature probes an unsigned PE, so classify the bounded verify
# output instead: a signature index proves the input is signed; the exact
# unsigned marker permits signing; every other result fails closed.
SIGCHECK="$("$OSSLSIGNCODE" verify -in "$IN_R" 2>&1 || true)"
if printf '%s\n' "$SIGCHECK" | grep -qE '^Signature Index:'; then
  die "input already carries a signature (sign-last violated upstream)"
fi
printf '%s\n' "$SIGCHECK" | grep -qF "No signature found" \
  || die "could not prove that input is unsigned (sign-last check indeterminate)"
unset SIGCHECK

# --- toolchain + key sanity --------------------------------------------------
[ -x "$OSSLSIGNCODE" ]   || die "osslsigncode missing at $OSSLSIGNCODE"
[ -r "$LEAF_KEY" ]       || die "leaf key unreadable (run as codesign user?)"
[ -r "$LEAF_CRT" ]       || die "leaf cert unreadable"
[ -r "$ROOT_CRT" ]       || die "root cert unreadable"
case "$TSA_URL" in http://*|https://*) : ;; *) die "bad TSA url: $TSA_URL" ;; esac

# --- sign (timestamp REQUIRED — fail-closed) ---------------------------------
# -ts uses RFC3161; if the TSA is unreachable osslsigncode exits non-zero and
# set -e aborts BEFORE any output exists. No unsigned/un-timestamped artifact.
"$OSSLSIGNCODE" sign \
  -certs "$LEAF_CRT" -key "$LEAF_KEY" \
  -ac "$ROOT_CRT" \
  -h sha256 \
  -ts "$TSA_URL" \
  -in "$IN_R" -out "$OUT_R" \
  || die "osslsigncode sign failed (TSA unreachable, leaf key/cert unreadable, or output dir not group-writable => fail-closed, no output)"

# --- self-verify before returning -------------------------------------------
# Verify the leaf chain against OUR root (exit 0) and assert the RFC3161 timestamp
# is present in the output. We deliberately do NOT pass -TSA-CAfile here: on
# osslsigncode 2.2 that path raises a false "certificate is not yet valid" while
# validating the TSA's own chain. The TSA chain is validated authoritatively on
# Windows by `signtool verify /pa` in the verify-windows gate — host-side we only
# assert (a) our leaf chains to our root and (b) a timestamp was actually applied
# (fail-closed: an un-timestamped signature is rejected).
VOUT="$("$OSSLSIGNCODE" verify -CAfile "$ROOT_CRT" -in "$OUT_R" 2>&1)" \
  || { rm -f "$OUT_R"; die "post-sign chain verify failed — output removed"; }
echo "$VOUT" | grep -q "Signature verification: ok" \
  || { rm -f "$OUT_R"; die "signature not OK against internal root — output removed"; }
if echo "$VOUT" | grep -qi "is timestamped"; then
  :
elif echo "$VOUT" | grep -qE '^[[:space:]]*Timestamp time:' &&
     echo "$VOUT" | grep -q "Timestamp Server Signature verification: ok" &&
     echo "$VOUT" | grep -qE '^[[:space:]]*Countersignatures:'; then
  :
else
  rm -f "$OUT_R"
  die "signature NOT timestamped (fail-closed) — output removed"
fi

echo "codesign-sign: OK  in=$IN_R  out=$OUT_R  tsa=$TSA_URL"
