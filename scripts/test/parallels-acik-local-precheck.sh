#!/usr/bin/env bash
#
# parallels-acik-local-precheck.sh — Faz 22.2 IT pilot acik.local Gate 0 precheck reproducer
#
# Boundary note — Faz 22.2 IT pilot acik.local Gate 0:
# This script runs non-destructive PowerShell probes inside the local Parallels
# Windows 11 VM (default "Windows 11") via prlctl exec, to verify whether the
# VM can reach the acik.local Active Directory domain controller for IT pilot
# join. It is OPERATOR-PRECONDITION reproducer ONLY:
#   - Requires Mac VPN connected (operator-bound; agent does not connect VPN)
#   - Requires Parallels VM routing/DNS configured (operator-bound;
#     see docs/runbooks/RB-faz22-acik-local-vpn-routing-setup.md)
#   - No credentials, no token, no domain admin password, no JWT, no enrollment
#     token is created, captured, or logged
#   - Output is sanitized (redact filter) + post-write secret scan fail-closed
#   - Read-only DNS/port probes (no `Add-Computer`, no `Set-DnsClient*`,
#     no `Remove-Computer`, no `Stop-Service`, no `Set-Service`)
#
# This is NOT acik.local IT pilot acceptance. It is the Gate 0 reachability
# check before any domain join attempt. Real pilot acceptance requires:
# domain join (operator interactive Get-Credential), EndpointPilot OU, IT-owned
# device, EDR allowlist, trusted signing — all ext-bound (Faz 22.2 operator
# queue per gitops handoff §5 P1 + RB-faz22-endpoint-pilot-it-owned.md §3-§10).
#
# Tracked by: gitops #1037, gitops #1015 IT pilot umbrella, platform-agent #12
# Parallels W11 lab rehearsal companion, gitops PR #1021 + platform-agent PR #10
# WORKGROUP predecessor smoke, Codex strategic 019e5aca.

set -euo pipefail
# IMPORTANT: do NOT enable `set -x` — output stream goes into evidence dir;
# accidental token/credential exposure must be avoided even though this script
# does not handle credentials directly.

readonly VM_NAME="${PARALLELS_VM_NAME:-Windows 11}"
readonly RUN_ID="${RUN_ID:-$(date +%Y%m%d%H%M%S)}"
readonly EVIDENCE_DIR="${EVIDENCE_DIR:-./tmp/acik-local-precheck-${RUN_ID}}"
readonly DOMAIN="${ACIK_LOCAL_DOMAIN:-acik.local}"
readonly TEST_CLUSTER_HOST="${TEST_CLUSTER_HOST:-testai.acik.com}"

mkdir -p "$EVIDENCE_DIR"
readonly LOG="${EVIDENCE_DIR}/run.log"
readonly PRECHECK="${EVIDENCE_DIR}/precheck.txt"

log() {
  printf '%s [acik-local-precheck] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" | tee -a "$LOG"
}

redact() {
  # Stream filter: known credential/token patterns scrubbed before writing to evidence.
  # Same pattern as scripts/test/parallels-windows11-ci.sh — keep in sync.
  sed -E \
    -e 's/(Bearer[[:space:]]+)[A-Za-z0-9._-]+/\1<REDACTED>/g' \
    -e 's/(Authorization:[[:space:]]+)[^[:space:]]+/\1<REDACTED>/g' \
    -e 's/("?(password|token|secret|key|authorization)"?[[:space:]]*[:=][[:space:]]*"?)[^",[:space:]}]+("?)/\1<REDACTED>\3/gi' \
    -e 's/(eyJ[A-Za-z0-9_-]{8,})\.[A-Za-z0-9._-]+/\1.<REDACTED>/g'
}

fail() {
  log "FAIL: $*"
  return 1
}

post_write_secret_scan() {
  # Fail-closed: scan written evidence for residual secrets.
  local hits
  hits=$(grep -rEi 'eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}|Bearer [A-Za-z0-9._-]{20,}|"password"[[:space:]]*:[[:space:]]*"[^"]+"|"token"[[:space:]]*:[[:space:]]*"[^"]+"' "$EVIDENCE_DIR" 2>/dev/null | grep -v "<REDACTED>" || true)
  if [ -n "$hits" ]; then
    log "FAIL: post-write secret scan found residual matches:"
    printf '%s\n' "$hits" | head -5 >&2
    return 1
  fi
  log "post-write secret scan: clean"
}

# === Step 0: preflight ===
log "Step 0: preflight"
log "  VM_NAME=$VM_NAME"
log "  RUN_ID=$RUN_ID"
log "  EVIDENCE_DIR=$EVIDENCE_DIR"
log "  DOMAIN=$DOMAIN"
log "  TEST_CLUSTER_HOST=$TEST_CLUSTER_HOST"

if ! command -v prlctl >/dev/null 2>&1; then
  fail "prlctl not found — Parallels Desktop required on macOS host"
  exit 1
fi
log "  prlctl: $(prlctl --version 2>&1 | head -1)"

if [ "$(uname -s)" != "Darwin" ]; then
  fail "host OS not Darwin — Parallels requires macOS; got $(uname -s)"
  exit 1
fi
log "  host: $(uname -s) $(uname -r)"

if ! prlctl list --all --output name 2>/dev/null | grep -Fxq "$VM_NAME"; then
  fail "VM '$VM_NAME' not found in 'prlctl list --all'"
  exit 1
fi
log "  VM '$VM_NAME' found"

vm_state=$(prlctl status "$VM_NAME" 2>/dev/null | awk '{print $NF}' | head -1)
log "  VM state: $vm_state"

if [ "$vm_state" != "running" ]; then
  log "  starting VM '$VM_NAME'..."
  prlctl start "$VM_NAME" >>"$LOG" 2>&1 || { fail "prlctl start failed"; exit 1; }
  # wait for guest tools ready
  for _ in $(seq 1 30); do
    if prlctl exec "$VM_NAME" cmd /c echo guest-ready 2>/dev/null | grep -q guest-ready; then
      break
    fi
    sleep 2
  done
fi

# === Step 1: VM baseline (hostname, domain, user, IP, DNS, OS) ===
log "Step 1: VM baseline"

prlctl exec "$VM_NAME" powershell -NoProfile -Command "
\$cs = Get-CimInstance Win32_ComputerSystem;
\$os = Get-CimInstance Win32_OperatingSystem;
\$net = Get-NetIPConfiguration | Where-Object { \$_.IPv4DefaultGateway } | Select-Object -First 1;
\$dns = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { \$_.ServerAddresses.Count -gt 0 } | Select-Object -First 1;
[PSCustomObject]@{
  Hostname     = \$env:COMPUTERNAME
  UserName     = \"\$env:USERDOMAIN\\\$env:USERNAME\"
  Domain       = \$cs.Domain
  PartOfDomain = \$cs.PartOfDomain
  Workgroup    = \$cs.Workgroup
  OSCaption    = \$os.Caption
  OSVersion    = \$os.Version
  OSBuild      = \$os.BuildNumber
  IPAddress    = if (\$net) { \$net.IPv4Address.IPAddress } else { '(no default gw)' }
  Interface    = if (\$net) { \$net.InterfaceAlias } else { '(unknown)' }
  DNSServers   = if (\$dns) { (\$dns.ServerAddresses -join ',') } else { '(none)' }
} | ConvertTo-Json
" 2>&1 | redact | tee -a "$PRECHECK"

# === Step 2: dsregcmd /status (domain/AAD join state) ===
log "Step 2: dsregcmd /status (relevant lines)"

prlctl exec "$VM_NAME" cmd /c dsregcmd /status 2>&1 | \
  grep -iE 'AzureAdJoined|EnterpriseJoined|DomainJoined|DeviceName|DomainName|TenantName|WorkplaceJoined' | \
  redact | tee -a "$PRECHECK" || true

# === Step 3: DNS resolve (acik.local + DC SRV records) ===
log "Step 3: DNS resolve probes ($DOMAIN)"

prlctl exec "$VM_NAME" powershell -NoProfile -Command "
foreach (\$name in @('$DOMAIN', '_ldap._tcp.dc._msdcs.$DOMAIN', '_kerberos._tcp.$DOMAIN')) {
  try {
    \$r = Resolve-DnsName -Name \$name -ErrorAction Stop -DnsOnly | Select-Object -First 5;
    \$summary = (\$r | ForEach-Object { \"  - \$(\$_.Name) [\$(\$_.Type)]: \$(\$_.IPAddress)\$(\$_.NameTarget)\" }) -join \"\`n\";
    Write-Host \"[OK] \$name :\";
    Write-Host \$summary;
  } catch {
    Write-Host \"[FAIL] \$name : \$(\$_.Exception.Message)\";
  }
}
" 2>&1 | redact | tee -a "$PRECHECK" || true

# === Step 4: nltest /dsgetdc (DC locator) ===
log "Step 4: nltest /dsgetdc:$DOMAIN"
dc_locate_output=$(prlctl exec "$VM_NAME" cmd /c nltest "/dsgetdc:$DOMAIN" 2>&1 | redact)
echo "$dc_locate_output" | tee -a "$PRECHECK"

# Extract DC FQDN (if any)
dc_fqdn=$(echo "$dc_locate_output" | grep -iE 'DC:.*\\' | sed -E 's/.*DC:[[:space:]]*\\\\([^[:space:]]+).*/\1/' | head -1 || true)
if [ -z "$dc_fqdn" ]; then
  dc_fqdn=$(echo "$dc_locate_output" | grep -iE 'DC Site Name' -B1 | head -1 | awk -F'\\\\\\\\' '{print $2}' | awk '{print $1}' || true)
fi

if [ -n "$dc_fqdn" ]; then
  log "  DC FQDN discovered: $dc_fqdn"
else
  log "  DC FQDN NOT discovered (domain unreachable or DNS fail)"
fi

# === Step 5: TCP port reachability (against DC if discovered, else $DOMAIN as fallback) ===
log "Step 5: TCP port reachability"
probe_target="${dc_fqdn:-$DOMAIN}"
log "  probe target: $probe_target"

prlctl exec "$VM_NAME" powershell -NoProfile -Command "
foreach (\$port in @(53, 88, 135, 389, 445, 464, 636, 3268, 9389)) {
  try {
    \$r = Test-NetConnection -ComputerName '$probe_target' -Port \$port -InformationLevel Quiet -WarningAction SilentlyContinue;
    \$status = if (\$r) { 'PASS' } else { 'FAIL' };
    Write-Host \"  port \$port : \$status\";
  } catch {
    Write-Host \"  port \$port : ERROR \$(\$_.Exception.Message)\";
  }
}
" 2>&1 | redact | tee -a "$PRECHECK" || true

# === Step 6: testai.acik.com:443 baseline ===
log "Step 6: testai.acik.com:443 baseline (public cluster reachability)"
prlctl exec "$VM_NAME" powershell -NoProfile -Command "
\$r = Test-NetConnection -ComputerName '$TEST_CLUSTER_HOST' -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue;
Write-Host \"  $TEST_CLUSTER_HOST:443 : \$( if (\$r) { 'PASS' } else { 'FAIL' } )\";
" 2>&1 | redact | tee -a "$PRECHECK" || true

# === Step 7: Time sync (Kerberos requires < 5 min clock skew) ===
log "Step 7: Time sync (w32tm /query /status)"
prlctl exec "$VM_NAME" cmd /c w32tm /query /status 2>&1 | head -10 | redact | tee -a "$PRECHECK" || true

# === Step 8: Post-write secret scan + summary ===
log "Step 8: post-write secret scan"
post_write_secret_scan || { fail "secret scan failed — evidence quarantined; do NOT upload as artifact"; exit 1; }

log "Step 9: summary"
log "  domain: $DOMAIN"
log "  DC FQDN: ${dc_fqdn:-(unknown — DC unreachable)}"
log "  evidence: $PRECHECK"
log "  run log: $LOG"

# === Pass/fail decision ===
# Pass if:
# - DNS resolve $DOMAIN returns OK (Step 3 [OK] line for $DOMAIN)
# - DC FQDN discovered (Step 4 nltest success)
# - At least port 88 (Kerberos) PASS (Step 5)
dns_ok=$(grep -E "^\[OK\] $DOMAIN" "$PRECHECK" | head -1 || true)
port_88_ok=$(grep -E "port 88 : PASS" "$PRECHECK" | head -1 || true)

if [ -n "$dns_ok" ] && [ -n "$dc_fqdn" ] && [ -n "$port_88_ok" ]; then
  log "GATE 0 RESULT: PASS — pilot smoke phase can proceed (operator action)"
  log ""
  log "Boundary reminder: Gate 0 pass means DC reachability OK. Domain join,"
  log "agent install, and pilot smoke are SEPARATE operator-gated steps with"
  log "their own evidence doc PR (Codex strategic 019e5aca; see runbook"
  log "RB-faz22-endpoint-pilot-it-owned.md §3-§10)."
  exit 0
else
  log "GATE 0 RESULT: FAIL — operator action required before pilot smoke"
  log ""
  log "Likely causes (see RB-faz22-acik-local-vpn-routing-setup.md §6):"
  if [ -z "$dns_ok" ]; then
    log "  - DNS resolve fail for $DOMAIN (VM DNS not corp DNS; or VPN not connected)"
  fi
  if [ -z "$dc_fqdn" ]; then
    log "  - DC locator fail (nltest ERROR_NO_SUCH_DOMAIN; domain unreachable)"
  fi
  if [ -z "$port_88_ok" ]; then
    log "  - Kerberos port 88 not reachable (firewall block or DC down)"
  fi
  log ""
  log "Reproducer: connect Mac VPN, set VM Parallels Bridged mode, configure"
  log "VM DNS to corp DNS IP, rerun this script."
  exit 1
fi
