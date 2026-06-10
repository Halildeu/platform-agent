#!/usr/bin/env bash
# =============================================================================
# AG-018 — sudoers-pinned Authenticode signing wrapper (runs AS `codesign` user).
#
# The self-hosted runner user (`gh-runner`) can NEVER read the leaf private key.
# It may only invoke THIS wrapper via a pinned sudoers rule:
#   gh-runner ALL=(codesign) NOPASSWD: /usr/local/bin/codesign-sign
# The wrapper signs ONE caller-provided MSI and writes ONE output MSI. The key
# stays 0400 codesign:codesign and is read only inside this process.
#
# Hardening (Codex 019eb0dd):
#   - exactly two positional args: <in.msi> <out.msi>; nothing else accepted
#   - both paths confined to an allowed work root (no path traversal / abs escape)
#   - input must be a regular file ending .msi; output dir must already exist
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
[ "$#" -eq 2 ] || die "usage: codesign-sign <in.msi> <out.msi> (got $# args)"
IN="$1"; OUT="$2"

# --- path confinement (resolve, then assert under WORK_ROOT) ------------------
canon() { readlink -m -- "$1"; }   # -m: don't require existence (out may be new)
IN_R="$(canon "$IN")"; OUT_R="$(canon "$OUT")"
WORK_R="$(canon "$WORK_ROOT")"
case "$IN_R/"  in "$WORK_R"/*) : ;; *) die "input escapes work root: $IN_R" ;; esac
case "$OUT_R/" in "$WORK_R"/*) : ;; *) die "output escapes work root: $OUT_R" ;; esac
[ "$IN_R" != "$OUT_R" ] || die "in and out must differ"
case "$IN_R"  in *.msi) : ;; *) die "input must be .msi" ;; esac
case "$OUT_R" in *.msi) : ;; *) die "output must be .msi" ;; esac
[ -f "$IN_R" ] || die "input not a regular file: $IN_R"
[ -d "$(dirname "$OUT_R")" ] || die "output dir missing: $(dirname "$OUT_R")"
[ ! -e "$OUT_R" ] || die "output already exists (refusing overwrite): $OUT_R"

# --- refuse double-sign ------------------------------------------------------
# Detect signature PRESENCE, not chain validity: a signed-but-untrusted input
# fails `verify` (non-zero) for the SAME reason an unsigned file does, so the
# verify exit code can't distinguish them. `extract-signature` can: it exits 0
# only when a signature is actually present (unsigned => non-zero). Sign-last
# means our input must be unsigned.
# extract-signature needs a NON-EXISTENT real output path: it refuses /dev/null
# AND it refuses to overwrite an existing file (so plain `mktemp`, which creates
# the file, makes it always fail and mask a present signature). Use a temp DIR
# and a fresh name inside it.
_SIGDIR="$(mktemp -d)"
if "$OSSLSIGNCODE" extract-signature -in "$IN_R" -out "$_SIGDIR/sig.p7" >/dev/null 2>&1; then
  rm -rf "$_SIGDIR"
  die "input already carries a signature (sign-last violated upstream)"
fi
rm -rf "$_SIGDIR"

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
echo "$VOUT" | grep -qi "is timestamped" \
  || { rm -f "$OUT_R"; die "signature NOT timestamped (fail-closed) — output removed"; }

echo "codesign-sign: OK  in=$IN_R  out=$OUT_R  tsa=$TSA_URL"
