#!/usr/bin/env bash
#
# parallels-windows11-non-domain-classify.sh — Faz 22.2.A non-domain Windows tier classification helper
#
# Boundary note — Faz 22.2.A non-domain Windows pilot classification:
# This helper runs non-destructive PowerShell probes inside the local Parallels
# Windows 11 VM (default "Windows 11") via prlctl exec, to classify the device
# tier per ADR-0012-EA "22.2 scope amendment" non-domain taxonomy (A1-A4):
#   - A1 Workgroup / standalone
#   - A2 BYOD unmanaged (ownership operator evidence-flagged)
#   - A3 Entra-joined / Azure AD-joined
#   - A4 Workplace-registered only
#
# Operator-precondition reproducer ONLY:
#   - No credentials, no token, no domain admin password
#   - Read-only PowerShell probes (dsregcmd /status + Get-CimInstance Win32_*)
#   - Output sanitized (redact filter) + post-write secret scan fail-closed
#   - Logged-in identity sanitized (UPN hash + SID truncate; never plaintext)
#
# This is NOT a complete pilot acceptance. Real A2 BYOD requires:
#   - Operator consent flow (22-2-byod-consent-template.md)
#   - KVKK data inventory + retention policy (22-2-kvkk-data-inventory.md)
#   - Signed binary distribution (22-2-trusted-signing-onboarding.md)
#   - EDR allowlist coordination
#
# Tracked by: gitops PR #1043 RB-faz22-non-domain-windows-pilot.md §4/§8,
# gitops #1044 A1 multi-VM repeatability board issue, Codex strategic 019e5b38.

set -euo pipefail
# IMPORTANT: do NOT enable `set -x` — token/credential exposure risk.

readonly VM_NAME="${PARALLELS_VM_NAME:-Windows 11}"
readonly RUN_ID="${RUN_ID:-$(date +%Y%m%d%H%M%S)}"
readonly EVIDENCE_DIR="${EVIDENCE_DIR:-./tmp/non-domain-classify-${RUN_ID}}"
readonly OWNERSHIP="${PARALLELS_OWNERSHIP:-corporate}"  # corporate|personal — A2 BYOD için personal

mkdir -p "$EVIDENCE_DIR"
readonly LOG="${EVIDENCE_DIR}/run.log"
readonly CLASSIFY_OUT="${EVIDENCE_DIR}/classification.json"

log() {
  printf '%s [non-domain-classify] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" | tee -a "$LOG"
}

redact() {
  # Stream filter: known credential/token + UPN/SID patterns scrubbed before evidence write.
  # Keeps machine identifiers (hostname, workgroup); hashes/truncates user identifiers.
  sed -E \
    -e 's/(Bearer[[:space:]]+)[A-Za-z0-9._-]+/\1<REDACTED>/g' \
    -e 's/(Authorization:[[:space:]]+)[^[:space:]]+/\1<REDACTED>/g' \
    -e 's/("?(password|token|secret|key|authorization)"?[[:space:]]*[:=][[:space:]]*"?)[^",[:space:]}]+("?)/\1<REDACTED>\3/gi' \
    -e 's/(eyJ[A-Za-z0-9_-]{8,})\.[A-Za-z0-9._-]+/\1.<REDACTED>/g' \
    -e 's/(S-1-5-21-)[0-9-]+(-[0-9]+)/\1***-***-***\2/g'  # SID truncate: keep RID, mask domain SID
}

fail() {
  log "FAIL: $*"
  return 1
}

post_write_secret_scan() {
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
log "  OWNERSHIP=$OWNERSHIP (operator-flagged; A2 BYOD için 'personal')"

command -v prlctl >/dev/null 2>&1 || { fail "prlctl not found — Parallels Desktop required on macOS host"; exit 1; }
[ "$(uname -s)" = "Darwin" ] || { fail "host OS not Darwin"; exit 1; }
prlctl list --all --output name 2>/dev/null | grep -Fxq "$VM_NAME" || { fail "VM '$VM_NAME' not found"; exit 1; }

vm_state=$(prlctl status "$VM_NAME" 2>/dev/null | awk '{print $NF}' | head -1)
[ "$vm_state" = "running" ] || { fail "VM '$VM_NAME' not running (state=$vm_state); start manually first"; exit 1; }
log "  VM '$VM_NAME' running"

# === Step 1: Win32_ComputerSystem (PartOfDomain + Domain + Workgroup + UserName) ===
log "Step 1: Win32_ComputerSystem (domain/workgroup state)"

# UPN/SID hashing performed in PowerShell before output, to avoid plaintext personal data even
# in transit through the redact filter. UPN hash uses SHA256 truncated to first 16 hex chars.
cs_output=$(prlctl exec "$VM_NAME" powershell -NoProfile -Command "
\$cs = Get-CimInstance Win32_ComputerSystem;
\$upnRaw = if (\$env:USERDNSDOMAIN) { \"\$env:USERNAME@\$env:USERDNSDOMAIN\" } else { \$env:USERNAME };
\$upnHash = if (\$upnRaw) { (Get-FileHash -Algorithm SHA256 -InputStream ([System.IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes(\$upnRaw)))).Hash.Substring(0,16).ToLower() } else { '(none)' };
[PSCustomObject]@{
  Hostname        = \$env:COMPUTERNAME
  Domain          = \$cs.Domain
  PartOfDomain    = \$cs.PartOfDomain
  Workgroup       = \$cs.Workgroup
  UserNameMachine = \$env:USERDOMAIN
  UserUPNHash     = \"sha256:\$upnHash\"
  OSCaption       = (Get-CimInstance Win32_OperatingSystem).Caption
  OSVersion       = (Get-CimInstance Win32_OperatingSystem).Version
  OSBuild         = (Get-CimInstance Win32_OperatingSystem).BuildNumber
} | ConvertTo-Json
" 2>&1 | redact)
echo "$cs_output" | tee -a "$LOG" > /dev/null

# Extract fields for classification logic
part_of_domain=$(echo "$cs_output" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("PartOfDomain", "unknown"))' 2>/dev/null || echo "unknown")
log "  PartOfDomain=$part_of_domain"

# === Step 2: dsregcmd /status (AzureAdJoined + WorkplaceJoined + DomainJoined) ===
log "Step 2: dsregcmd /status (AAD/Workplace join state)"

dsreg_output=$(prlctl exec "$VM_NAME" cmd /c dsregcmd /status 2>&1 | redact | grep -iE 'AzureAdJoined|EnterpriseJoined|DomainJoined|DeviceName|TenantName|TenantId|WorkplaceJoined|DeviceId' | head -10 || true)
echo "$dsreg_output" | tee -a "$LOG" > /dev/null

# Tier detection
azure_ad_joined=$(echo "$dsreg_output" | grep -iE '^AzureAdJoined' | awk -F: '{print $2}' | tr -d ' \r\n' | head -1 || echo "NO")
workplace_joined=$(echo "$dsreg_output" | grep -iE '^WorkplaceJoined' | awk -F: '{print $2}' | tr -d ' \r\n' | head -1 || echo "NO")
domain_joined=$(echo "$dsreg_output" | grep -iE '^DomainJoined' | awk -F: '{print $2}' | tr -d ' \r\n' | head -1 || echo "NO")

# Tenant ID hash (if Entra-joined)
tenant_id_hash="(n/a)"
if [ "$azure_ad_joined" = "YES" ]; then
  tenant_raw=$(echo "$dsreg_output" | grep -iE 'TenantId' | awk -F: '{print $2}' | tr -d ' \r\n' | head -1 || echo "")
  if [ -n "$tenant_raw" ]; then
    tenant_id_hash="sha256:$(echo -n "$tenant_raw" | shasum -a 256 | awk '{print substr($1,1,16)}'):${tenant_raw: -4}"
  fi
fi
log "  AzureAdJoined=$azure_ad_joined, WorkplaceJoined=$workplace_joined, DomainJoined=$domain_joined"
log "  TenantIdHash=$tenant_id_hash"

# === Step 3: MDM/Intune enrollment state ===
log "Step 3: MDM/Intune enrollment state probe"

# Set +e so MDM probe fail (common on workgroup) doesn't kill script
set +e
mdm_output=$(prlctl exec "$VM_NAME" powershell -NoProfile -Command "
try {
  \$mdm = Get-CimInstance -Namespace root/cimv2/mdm/dmmap -ClassName MDM_DevDetail_Ext01 -ErrorAction Stop;
  [PSCustomObject]@{
    DeviceClientId = \$mdm.DeviceClientId
    OEMVersion     = \$mdm.OEMVersion
    Enrolled       = \$true
  } | ConvertTo-Json
} catch {
  '{\"Enrolled\":false, \"Reason\":\"MDM_DevDetail_Ext01 not available (workgroup veya non-enrolled)\"}'
}
" 2>&1 | redact)
mdm_rc=$?
set -e

echo "$mdm_output" | tee -a "$LOG" > /dev/null
mdm_enrolled=$(echo "$mdm_output" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("Enrolled", False))' 2>/dev/null || echo "false")
log "  MDM enrolled=$mdm_enrolled (rc=$mdm_rc)"

# === Step 4: Tier classification (decision tree per RB §4.3) ===
log "Step 4: Tier classification"

tier="UNKNOWN"
tier_reason=""

if [ "$part_of_domain" = "True" ] || [ "$part_of_domain" = "true" ]; then
  tier="22.2.B"
  tier_reason="PartOfDomain=true → 22.2.B (B1 Hybrid AAD veya B2 acik.local; bu helper scope dışı)"
elif [ "$azure_ad_joined" = "YES" ]; then
  tier="A3"
  tier_reason="AzureAdJoined=YES, PartOfDomain=false → A3 Entra-joined / Azure AD-joined"
elif [ "$workplace_joined" = "YES" ] && [ "$azure_ad_joined" = "NO" ]; then
  tier="A4"
  tier_reason="WorkplaceJoined=YES, AzureAdJoined=NO, PartOfDomain=false → A4 Workplace-registered only"
elif [ "$part_of_domain" = "False" ] || [ "$part_of_domain" = "false" ]; then
  if [ "$OWNERSHIP" = "personal" ]; then
    tier="A2"
    tier_reason="PartOfDomain=false, ownership=personal → A2 BYOD (consent + KVKK + signed binary mandatory)"
  else
    tier="A1"
    tier_reason="PartOfDomain=false, ownership=corporate (default) → A1 workgroup/standalone"
  fi
else
  tier="UNKNOWN"
  tier_reason="Detection inconclusive — PartOfDomain=$part_of_domain"
fi

log "  Detected tier: $tier"
log "  Reason: $tier_reason"

# === Step 5: Sanitized JSON evidence output ===
log "Step 5: Sanitized JSON evidence output"

cat > "$CLASSIFY_OUT" <<EOF
{
  "run_id": "$RUN_ID",
  "vm_name": "$VM_NAME",
  "tier": "$tier",
  "tier_reason": "$tier_reason",
  "ownership_flag": "$OWNERSHIP",
  "detection_fields": {
    "PartOfDomain": "$part_of_domain",
    "AzureAdJoined": "$azure_ad_joined",
    "WorkplaceJoined": "$workplace_joined",
    "DomainJoined": "$domain_joined",
    "TenantIdHash": "$tenant_id_hash",
    "MdmEnrolled": "$mdm_enrolled"
  },
  "machine_baseline": $(echo "$cs_output" | python3 -m json.tool 2>/dev/null || echo '{}'),
  "boundary": {
    "scope": "A1-A4 non-domain Windows pilot classification only",
    "not_pilot_acceptance": true,
    "agent_action_only": "read-only probes + sanitized JSON output",
    "next_gates": {
      "A2": ["consent flow", "KVKK data inventory", "signed binary", "EDR allowlist"],
      "A3": ["identity classification (AG-021/022 + BE-015)", "signed binary", "EDR allowlist"],
      "A4": ["read-only inventory only", "signed binary"]
    }
  }
}
EOF

cat "$CLASSIFY_OUT" | tee -a "$LOG"
log ""

# === Step 6: Post-write secret scan ===
log "Step 6: post-write secret scan"
post_write_secret_scan || { fail "secret scan failed — evidence quarantined"; exit 1; }

# === Step 7: Summary + exit code ===
log "Step 7: summary"
log "  Detected tier: $tier ($tier_reason)"
log "  Evidence: $CLASSIFY_OUT"
log "  Run log: $LOG"
log ""

case "$tier" in
  A1|A2|A3|A4)
    log "RESULT: PASS — tier $tier classified; next gates per §13.2 RB-faz22-non-domain-windows-pilot.md"
    log ""
    log "Boundary reminder: Classification is NOT pilot acceptance. A2-A4 require"
    log "additional operator gates (consent, KVKK, signed binary, EDR allowlist)."
    exit 0
    ;;
  22.2.B)
    log "RESULT: SCOPE_REDIRECT — VM PartOfDomain=true; 22.2.B acik.local IT pilot scope"
    log "See RB-faz22-endpoint-pilot-it-owned.md for 22.2.B operasyon runbook"
    exit 2
    ;;
  *)
    fail "Detection inconclusive (tier=$tier); manual review required"
    exit 1
    ;;
esac
