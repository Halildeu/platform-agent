#!/usr/bin/env bash
# =============================================================================
# AG-018 — Internal code-signing CA generator (Linux/OpenSSL, FREE, $0).
#
# Owner decisions (2026-06-10): NO paid services, NO Windows Server / AD CS.
# The Windows endpoint-agent MSI is Authenticode-signed on a self-hosted LINUX
# runner with `osslsigncode`; trust reaches Windows machines via the agent
# installer importing this root (TOFU) — domain-joined AND workgroup boxes alike.
#
# This script builds a 2-tier internal CA on the signing host:
#   Root  "ACIK Internal Code Signing Root CA"  — RSA 4096, 10y, CA:TRUE,
#         pathlen:0 (cannot mint sub-CAs, only end-entity leaves),
#         KeyUsage=keyCertSign,cRLSign, SubjectKeyIdentifier, NO EKU.
#   Leaf  "EndpointAgent CodeSign"              — RSA 3072, 2y, CA:FALSE,
#         KeyUsage=digitalSignature(critical), EKU=codeSigning(critical),
#         SKI+AKI, CRL Distribution Point.
#
# Hardening rationale (Codex 019eb0dd AGREE):
#   - Root EKU intentionally OMITTED (EKU-nesting is inconsistent on Windows;
#     real protection is root key custody + pathlen:0, not a root EKU trick).
#   - pathlen:0 means a leaked root can still mint LEAVES (same custody barrier
#     as signing itself) but never an intermediate CA.
#   - Key custody = host-fs-restricted (pre-prod exception): private keys live
#     0400 under a dedicated `codesign` user; the runner never reads them raw —
#     it calls a sudoers-pinned wrapper. Vault Transit/HSM is a FOLLOW-UP phase.
#
# Idempotent: refuses to overwrite an existing root key unless --force-root
# (forensic-corruption guard); the leaf may be re-issued (--renew-leaf).
#
# Run ON the signing host (staging-sw) as a user with sudo:
#   sudo bash generate-ca.sh --crl-url http://<edge>/codesign/crl.pem
# =============================================================================
set -euo pipefail

CODESIGN_HOME="${CODESIGN_HOME:-/etc/codesign}"
CODESIGN_USER="${CODESIGN_USER:-codesign}"
ROOT_CN="ACIK Internal Code Signing Root CA"
LEAF_CN="EndpointAgent CodeSign"
ROOT_DAYS=3650          # 10y
LEAF_DAYS=730           # 2y
ROOT_BITS=4096
LEAF_BITS=3072
CRL_URL="http://localhost/codesign/crl.pem"
FORCE_ROOT=0
RENEW_LEAF=0
EXPORT_DIR=""           # if set, public .cer/.crt copied here for repo pinning

usage() { grep '^# ' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --crl-url)     CRL_URL="$2"; shift 2 ;;
    --force-root)  FORCE_ROOT=1; shift ;;
    --renew-leaf)  RENEW_LEAF=1; shift ;;
    --export-dir)  EXPORT_DIR="$2"; shift 2 ;;
    --home)        CODESIGN_HOME="$2"; shift 2 ;;
    -h|--help)     usage 0 ;;
    *) echo "unknown arg: $1" >&2; usage 1 ;;
  esac
done

[ "$(id -u)" = "0" ] || { echo "must run as root (sudo) — key files are 0400 root-tree" >&2; exit 1; }

ROOT_DIR="$CODESIGN_HOME/root"
LEAF_DIR="$CODESIGN_HOME/leaf"
ROOT_KEY="$ROOT_DIR/root.key"
ROOT_CRT="$ROOT_DIR/root.crt"
ROOT_SRL="$ROOT_DIR/root.srl"
CRL_PEM="$ROOT_DIR/crl.pem"
LEAF_KEY="$LEAF_DIR/leaf.key"
LEAF_CSR="$LEAF_DIR/leaf.csr"
LEAF_CRT="$LEAF_DIR/leaf.crt"

# --- dedicated system user (no login, no shell) -----------------------------
if ! id "$CODESIGN_USER" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$CODESIGN_USER"
  echo "created system user: $CODESIGN_USER"
fi

umask 077
mkdir -p "$ROOT_DIR" "$LEAF_DIR"

# --- openssl extension configs ----------------------------------------------
ROOT_EXT="$(mktemp)"; LEAF_EXT="$(mktemp)"
trap 'rm -f "$ROOT_EXT" "$LEAF_EXT"' EXIT

cat > "$ROOT_EXT" <<EOF
[req]
distinguished_name = dn
prompt = no
x509_extensions = root_ext
[dn]
CN = ${ROOT_CN}
O  = ACIK
OU = ACIK Build
[root_ext]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

cat > "$LEAF_EXT" <<EOF
[req]
distinguished_name = dn
prompt = no
[dn]
CN = ${LEAF_CN}
O  = ACIK
OU = ACIK Build
[leaf_ext]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, codeSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
crlDistributionPoints = URI:${CRL_URL}
EOF

# --- ROOT --------------------------------------------------------------------
if [ -f "$ROOT_KEY" ] && [ "$FORCE_ROOT" = "0" ]; then
  echo "root key exists — keeping it (pass --force-root to regenerate; forensic guard)"
else
  echo "generating ROOT key + self-signed cert (RSA ${ROOT_BITS}, ${ROOT_DAYS}d)…"
  openssl genrsa -out "$ROOT_KEY" "$ROOT_BITS"
  openssl req -new -x509 -sha256 -days "$ROOT_DAYS" \
    -key "$ROOT_KEY" -out "$ROOT_CRT" \
    -config "$ROOT_EXT" -extensions root_ext
fi

# --- LEAF --------------------------------------------------------------------
if [ -f "$LEAF_KEY" ] && [ "$RENEW_LEAF" = "0" ]; then
  echo "leaf key exists — keeping it (pass --renew-leaf to re-issue)"
else
  echo "generating LEAF key + CSR + root-signed cert (RSA ${LEAF_BITS}, ${LEAF_DAYS}d)…"
  openssl genrsa -out "$LEAF_KEY" "$LEAF_BITS"
  openssl req -new -sha256 -key "$LEAF_KEY" -out "$LEAF_CSR" -config "$LEAF_EXT"
  openssl x509 -req -sha256 -days "$LEAF_DAYS" \
    -in "$LEAF_CSR" -CA "$ROOT_CRT" -CAkey "$ROOT_KEY" \
    -CAcreateserial -CAserial "$ROOT_SRL" \
    -extfile "$LEAF_EXT" -extensions leaf_ext \
    -out "$LEAF_CRT"
fi

# --- CRL (empty, valid) ------------------------------------------------------
# Minimal CA db so `openssl ca -gencrl` works for revocation later.
touch "$ROOT_DIR/index.txt"
[ -f "$ROOT_DIR/crlnumber" ] || echo 1000 > "$ROOT_DIR/crlnumber"
CRL_CNF="$(mktemp)"
cat > "$CRL_CNF" <<EOF
[ca]
default_ca = ca_default
[ca_default]
database = $ROOT_DIR/index.txt
crlnumber = $ROOT_DIR/crlnumber
default_md = sha256
default_crl_days = 180
[crl_ext]
authorityKeyIdentifier = keyid:always
EOF
openssl ca -gencrl -config "$CRL_CNF" -cert "$ROOT_CRT" -keyfile "$ROOT_KEY" \
  -out "$CRL_PEM" 2>/dev/null || echo "(crl gen skipped — non-fatal; CRL DP still pinned in leaf)"
rm -f "$CRL_CNF"

# --- ownership + permissions -------------------------------------------------
chown -R "$CODESIGN_USER":"$CODESIGN_USER" "$CODESIGN_HOME"
chmod 0700 "$ROOT_DIR" "$LEAF_DIR"
chmod 0400 "$ROOT_KEY" "$LEAF_KEY"
chmod 0444 "$ROOT_CRT" "$LEAF_CRT" "$CRL_PEM" 2>/dev/null || true
# root key: only codesign user reads; runner user NEVER touches it
echo "permissions set: keys 0400 owner=$CODESIGN_USER"

# --- DER exports for repo pinning + Windows import --------------------------
DER_ROOT="$ROOT_DIR/root.cer"   # DER, what install.ps1 imports
openssl x509 -in "$ROOT_CRT" -outform DER -out "$DER_ROOT"
chmod 0444 "$DER_ROOT"

ROOT_SHA256="$(openssl x509 -in "$ROOT_CRT" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g')"
LEAF_SHA1="$(openssl x509 -in "$LEAF_CRT" -noout -fingerprint -sha1   | sed 's/.*=//; s/://g')"
LEAF_SHA256="$(openssl x509 -in "$LEAF_CRT" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g')"
LEAF_NOTAFTER="$(openssl x509 -in "$LEAF_CRT" -noout -enddate | sed 's/notAfter=//')"

if [ -n "$EXPORT_DIR" ]; then
  mkdir -p "$EXPORT_DIR"
  cp "$DER_ROOT" "$EXPORT_DIR/acik-codesign-root.cer"
  openssl x509 -in "$ROOT_CRT" -out "$EXPORT_DIR/acik-codesign-root.pem"
  openssl x509 -in "$LEAF_CRT" -out "$EXPORT_DIR/endpointagent-codesign-leaf.pem"
  echo "public certs exported to $EXPORT_DIR (commit these for pinning)"
fi

cat <<EOF

=============================================================================
 AG-018 CA ready — pin values (NON-SECRET; set as repo variables / install pin)
=============================================================================
 CODESIGN_ROOT_CERT_SHA256        = ${ROOT_SHA256}
 CODESIGN_LEAF_THUMBPRINT (SHA1)  = ${LEAF_SHA1}
 CODESIGN_LEAF_SHA256             = ${LEAF_SHA256}
 Leaf notAfter                    = ${LEAF_NOTAFTER}
 Root DER (import source)         = ${DER_ROOT}
=============================================================================
 Private keys (0400 ${CODESIGN_USER}, host-fs-restricted — NEVER leave host):
   ${ROOT_KEY}   (offline; manual leaf renewal only)
   ${LEAF_KEY}   (signing; reached ONLY via sudoers-pinned wrapper)
 Next: install-sign-wrapper.sh to wire the runner→wrapper→key isolation.
=============================================================================
EOF
