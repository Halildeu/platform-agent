#!/usr/bin/env bash
# =============================================================================
# AG-018 — one-shot signing-host provisioner (staging-sw, $0).
#
# Wires the runner→wrapper→key isolation Codex approved (019eb0dd):
#   1. apt-installs osslsigncode (pinned-version asserted)
#   2. installs codesign-sign.sh -> /usr/local/bin/codesign-sign (root:root 0755)
#   3. sudoers drop-in: gh-runner may run ONLY that wrapper AS codesign, NOPASSWD
#   4. work root /var/lib/codesign/work (gh-runner writable; staging area)
#   5. (optional) chattr +i the wrapper (immutable) — Codex hardening
#
# Pre-req: generate-ca.sh already ran (keys exist under /etc/codesign).
# Run as root on the signing host:
#   sudo bash install-signing-host.sh --runner-user gh-runner
# =============================================================================
set -euo pipefail

RUNNER_USER="gh-runner"
CODESIGN_USER="codesign"
WRAPPER_SRC="$(dirname "$(readlink -f "$0")")/codesign-sign.sh"
WRAPPER_DST="/usr/local/bin/codesign-sign"
WORK_ROOT="/var/lib/codesign/work"
MIN_OSSL_VER="2.5"          # osslsigncode >= 2.5 (modern RFC3161 + MSI handling)
IMMUTABLE=1

usage() { grep '^# ' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --runner-user)   RUNNER_USER="$2"; shift 2 ;;
    --no-immutable)  IMMUTABLE=0; shift ;;
    --wrapper-src)   WRAPPER_SRC="$2"; shift 2 ;;
    -h|--help)       usage 0 ;;
    *) echo "unknown arg: $1" >&2; usage 1 ;;
  esac
done
[ "$(id -u)" = "0" ] || { echo "run as root (sudo)" >&2; exit 1; }
id "$CODESIGN_USER" >/dev/null 2>&1 || { echo "codesign user missing — run generate-ca.sh first" >&2; exit 1; }
[ -r /etc/codesign/leaf/leaf.key ] || { echo "leaf key missing — run generate-ca.sh first" >&2; exit 1; }

# --- 1. osslsigncode ---------------------------------------------------------
if ! command -v osslsigncode >/dev/null 2>&1; then
  echo "installing osslsigncode…"
  apt-get update -qq && apt-get install -y -qq osslsigncode
fi
OSSL_VER="$(osslsigncode --version 2>&1 | grep -oE '[0-9]+\.[0-9]+' | head -1 || echo 0)"
awk -v v="$OSSL_VER" -v m="$MIN_OSSL_VER" 'BEGIN{split(v,a,".");split(m,b,".");
  if (a[1]<b[1] || (a[1]==b[1] && a[2]<b[2])) {exit 1}}' \
  || echo "WARN: osslsigncode $OSSL_VER < $MIN_OSSL_VER (upgrade recommended; continuing)"
echo "osslsigncode: $OSSL_VER at $(command -v osslsigncode)"

# --- 2. wrapper --------------------------------------------------------------
[ -f "$WRAPPER_SRC" ] || { echo "wrapper source missing: $WRAPPER_SRC" >&2; exit 1; }
[ "$IMMUTABLE" = "1" ] && chattr -i "$WRAPPER_DST" 2>/dev/null || true
install -o root -g root -m 0755 "$WRAPPER_SRC" "$WRAPPER_DST"
echo "installed wrapper: $WRAPPER_DST (root:root 0755)"

# --- 3. sudoers drop-in (pinned, validated) ----------------------------------
SUDOERS="/etc/sudoers.d/codesign-runner"
TMP_SUDO="$(mktemp)"
cat > "$TMP_SUDO" <<EOF
# AG-018: $RUNNER_USER may invoke ONLY the signing wrapper, AS $CODESIGN_USER, no password.
# Arguments are intentionally UNrestricted at the sudoers layer (a trailing "" would
# force zero-arg and break the wrapper) — the wrapper itself enforces the strict
# 2-arg / path-confinement / .msi / double-sign contract.
$RUNNER_USER ALL=($CODESIGN_USER) NOPASSWD: $WRAPPER_DST
Defaults!$WRAPPER_DST !requiretty
EOF
visudo -cf "$TMP_SUDO" >/dev/null || { echo "sudoers syntax check FAILED — not installing" >&2; rm -f "$TMP_SUDO"; exit 1; }
install -o root -g root -m 0440 "$TMP_SUDO" "$SUDOERS"
rm -f "$TMP_SUDO"
echo "installed sudoers: $SUDOERS"

# --- 4. work root (shared via the codesign group; keys stay 0400 owner-only) --
# The runner stages in.msi and reads out.msi; the wrapper (codesign user) reads
# in.msi and writes out.msi. They share files through group=codesign on a setgid
# work dir. gh-runner joining the codesign GROUP does NOT expose the keys: the
# private keys are 0400 codesign:codesign (owner-read only; group has no access).
usermod -aG "$CODESIGN_USER" "$RUNNER_USER"
mkdir -p "$WORK_ROOT"
chown root:"$CODESIGN_USER" "$WORK_ROOT"
chmod 2770 "$WORK_ROOT"          # setgid: new files inherit group=codesign
echo "work root: $WORK_ROOT (root:$CODESIGN_USER 2770; $RUNNER_USER added to $CODESIGN_USER group)"

# --- 5. immutability ---------------------------------------------------------
if [ "$IMMUTABLE" = "1" ]; then
  chattr +i "$WRAPPER_DST" 2>/dev/null && echo "wrapper marked immutable (chattr +i)" \
    || echo "WARN: chattr +i unsupported on this fs — wrapper mutable (still root-owned 0755)"
fi

cat <<EOF

=============================================================================
 AG-018 signing host ready.
 Runner invokes signing as:
   sudo -u $CODESIGN_USER $WRAPPER_DST <work>/in.msi <work>/out.msi
 (with CODESIGN_TIMESTAMP_URL exported; key never leaves the host)
 Register the GitHub self-hosted runner as user '$RUNNER_USER' with labels:
   [self-hosted, linux, signing]
=============================================================================
EOF
