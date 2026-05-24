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
#   - Output sanitized (parse-then-hash; raw outputs NOT logged) + post-write
#     secret scan fail-closed (JWT/Bearer/password/token + GUID + UPN + SID)
#   - Logged-in identity sanitized (UPN hash + SID truncate; never plaintext)
#   - Hostname is captured raw for fixture/lab VM; for real A2 BYOD device,
#     OWNERSHIP=byod activates hostname masking (operator policy)
#
# This is NOT a complete pilot acceptance. Real A2 BYOD requires:
#   - Operator consent flow (22-2-byod-consent-template.md)
#   - KVKK data inventory + retention policy (22-2-kvkk-data-inventory.md)
#   - Signed binary distribution (22-2-trusted-signing-onboarding.md)
#   - EDR allowlist coordination
#
# Tracked by: gitops PR #1043 RB-faz22-non-domain-windows-pilot.md §4/§8,
# gitops #1044 A1 multi-VM repeatability board issue, Codex strategic 019e5b38,
# Codex post-impl review 019e5b4e (REVISE iter-1 absorb: dsregcmd whitespace-safe
# parse, PARALLELS_OWNERSHIP byod alias, fail-closed sanitization expansion).

set -euo pipefail
# IMPORTANT: do NOT enable `set -x` — token/credential exposure risk.

readonly VM_NAME="${PARALLELS_VM_NAME:-Windows 11}"
readonly RUN_ID="${RUN_ID:-$(date +%Y%m%d%H%M%S)}"
readonly EVIDENCE_DIR="${EVIDENCE_DIR:-./tmp/non-domain-classify-${RUN_ID}}"
readonly OWNERSHIP_RAW="${PARALLELS_OWNERSHIP:-corporate}"

# Ownership canonicalization (Codex 019e5b4e BLOCKER 2 fix):
# Accept both 'byod' and 'personal' for BYOD; 'corporate' or 'corp' for corp;
# fail explicitly on unknown values rather than silent A1 fallback.
case "$(printf '%s' "$OWNERSHIP_RAW" | tr '[:upper:]' '[:lower:]')" in
  corporate|corp) readonly OWNERSHIP="corporate" ;;
  byod|personal) readonly OWNERSHIP="byod" ;;
  *)
    printf 'FAIL: PARALLELS_OWNERSHIP=%s invalid; must be one of: corporate|corp|byod|personal\n' "$OWNERSHIP_RAW" >&2
    exit 1
    ;;
esac

mkdir -p "$EVIDENCE_DIR"
readonly LOG="${EVIDENCE_DIR}/run.log"
readonly CLASSIFY_OUT="${EVIDENCE_DIR}/classification.json"

log() {
  printf '%s [non-domain-classify] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" | tee -a "$LOG"
}

# Stream filter: known credential/token + UPN/SID patterns scrubbed before evidence write.
# Keeps machine identifiers (hostname, workgroup); hashes/truncates user identifiers.
redact() {
  sed -E \
    -e 's/(Bearer[[:space:]]+)[A-Za-z0-9._-]+/\1<REDACTED>/g' \
    -e 's/(Authorization:[[:space:]]+)[^[:space:]]+/\1<REDACTED>/g' \
    -e 's/("?(password|token|secret|key|authorization)"?[[:space:]]*[:=][[:space:]]*"?)[^",[:space:]}]+("?)/\1<REDACTED>\3/gi' \
    -e 's/(eyJ[A-Za-z0-9_-]{8,})\.[A-Za-z0-9._-]+/\1.<REDACTED>/g' \
    -e 's/(S-1-5-21-)[0-9-]+(-[0-9]+)/\1***-***-***\2/g'
}

# Hash sensitive identifier (TenantId, DeviceId, DeviceClientId): SHA256 truncate to 16 hex.
hash_id() {
  if [ -n "${1:-}" ]; then
    local hash
    hash=$(printf '%s' "$1" | shasum -a 256 | awk '{print substr($1,1,16)}')
    printf 'sha256:%s' "$hash"
  else
    printf '(n/a)'
  fi
}

# Mask name field (TenantName, DeviceName, Hostname for BYOD): first 8 chars + '***'.
mask_name() {
  if [ -n "${1:-}" ]; then
    local len="${#1}"
    if [ "$len" -le 8 ]; then
      printf '%s***' "${1:0:2}"
    else
      printf '%s***' "${1:0:8}"
    fi
  else
    printf '(n/a)'
  fi
}

fail() {
  log "FAIL: $*"
  return 1
}

# Whitespace-safe extractor for "  FieldName : Value" lines from dsregcmd /status output
# (Codex 019e5b4e BLOCKER 1 fix: previous `^FieldName` regex missed leading-whitespace lines).
# (Codex 019e5b4e iter-2 BLOCKER fix: grep no-match must not crash `set -euo pipefail`;
#  A1/workgroup VM normally lacks TenantId/DeviceId/TenantName/DeviceName fields, so
#  empty-return + exit 0 is the safe default. Caller checks for empty string.)
extract_dsreg_field() {
  local field="$1"
  local source="$2"
  local line

  # grep no-match → || true rescues pipeline; head -1 collapses multi-match
  line=$(printf '%s\n' "$source" | grep -iE "^[[:space:]]*${field}[[:space:]]*:" | head -1 || true)

  # Early return on empty (no field found)
  [ -n "$line" ] || { printf ''; return 0; }

  # Extract value after ':' separator
  printf '%s' "$line" | awk -F: '{print $2}' | tr -d ' \r\n'
}

post_write_secret_scan() {
  local hits
  # Expanded patterns (Codex 019e5b4e BLOCKER 3 fix):
  # - Original: JWT, Bearer, password/token JSON values
  # - Added: raw GUID (TenantId/DeviceId leak), email/UPN cleartext, full SID cleartext
  # Whitelist: sha256: hashed values + masked SID (S-1-5-21-***-***-***-NNNN)
  hits=$(grep -rEi \
    -e 'eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}' \
    -e 'Bearer [A-Za-z0-9._-]{20,}' \
    -e '"password"[[:space:]]*:[[:space:]]*"[^"]+"' \
    -e '"token"[[:space:]]*:[[:space:]]*"[^"]+"' \
    -e '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' \
    -e '[a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' \
    -e 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+' \
    "$EVIDENCE_DIR" 2>/dev/null \
    | grep -v "<REDACTED>" \
    | grep -vE 'sha256:[a-f0-9]{16}' \
    | grep -vE 'S-1-5-21-\*{3}-\*{3}-\*{3}-[0-9]+' \
    || true)
  if [ -n "$hits" ]; then
    log "FAIL: post-write secret scan found residual matches (GUID/email/SID/JWT/Bearer not allowed):"
    printf '%s\n' "$hits" | head -5 >&2
    return 1
  fi
  log "post-write secret scan: clean (no JWT/Bearer/password/token/raw-GUID/email/raw-SID)"
}

# === Step 0: preflight ===
log "Step 0: preflight"
log "  VM_NAME=$VM_NAME"
log "  RUN_ID=$RUN_ID"
log "  EVIDENCE_DIR=$EVIDENCE_DIR"
log "  OWNERSHIP=$OWNERSHIP (raw='$OWNERSHIP_RAW' canonicalized; corporate|byod accepted)"

command -v prlctl >/dev/null 2>&1 || { fail "prlctl not found — Parallels Desktop required on macOS host"; exit 1; }
command -v jq >/dev/null 2>&1 || { fail "jq not found — required for safe JSON construction"; exit 1; }
[ "$(uname -s)" = "Darwin" ] || { fail "host OS not Darwin"; exit 1; }
prlctl list --all --output name 2>/dev/null | grep -Fxq "$VM_NAME" || { fail "VM '$VM_NAME' not found"; exit 1; }

vm_state=$(prlctl status "$VM_NAME" 2>/dev/null | awk '{print $NF}' | head -1)
[ "$vm_state" = "running" ] || { fail "VM '$VM_NAME' not running (state=$vm_state); start manually first"; exit 1; }
log "  VM '$VM_NAME' running"

# === Step 1: Win32_ComputerSystem (PartOfDomain + Domain + Workgroup + UserName) ===
log "Step 1: Win32_ComputerSystem (domain/workgroup state)"

# UPN/SID hashing performed in PowerShell before output, to avoid plaintext personal data even
# in transit through the redact filter. UPN hash uses SHA256 truncated to first 16 hex chars.
cs_raw=$(prlctl exec "$VM_NAME" powershell -NoProfile -Command "
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

# Parse Win32 fields safely via jq (fixture VM hostname allowed; BYOD masks below)
part_of_domain=$(printf '%s' "$cs_raw" | jq -r '.PartOfDomain // "unknown"' 2>/dev/null || echo "unknown")
hostname_raw=$(printf '%s' "$cs_raw" | jq -r '.Hostname // ""' 2>/dev/null || echo "")
workgroup_raw=$(printf '%s' "$cs_raw" | jq -r '.Workgroup // ""' 2>/dev/null || echo "")

# Hostname masking for BYOD (Codex 019e5b4e Q3 follow-up: A2 BYOD personal-device hostname risk)
if [ "$OWNERSHIP" = "byod" ]; then
  hostname_output=$(mask_name "$hostname_raw")
  log "  Hostname=$hostname_output (BYOD ownership — masked)"
else
  hostname_output="$hostname_raw"
  log "  Hostname=$hostname_output (corporate/fixture VM — raw allowed)"
fi
log "  PartOfDomain=$part_of_domain"
log "  Workgroup=$workgroup_raw"

# Re-write cs_raw to sanitize hostname if BYOD (for evidence output)
if [ "$OWNERSHIP" = "byod" ]; then
  cs_sanitized=$(printf '%s' "$cs_raw" | jq --arg h "$hostname_output" '.Hostname = $h' 2>/dev/null || echo "$cs_raw")
else
  cs_sanitized="$cs_raw"
fi

# === Step 2: dsregcmd /status (AzureAdJoined + WorkplaceJoined + DomainJoined) ===
log "Step 2: dsregcmd /status (AAD/Workplace join state) — parse + hash sensitive fields"

# Get RAW dsregcmd output (NOT logged — only parsed values logged after sanitization)
dsreg_raw=$(prlctl exec "$VM_NAME" cmd /c dsregcmd /status 2>&1 | head -200)

# Whitespace-safe parse (Codex 019e5b4e BLOCKER 1 fix)
azure_ad_joined=$(extract_dsreg_field "AzureAdJoined" "$dsreg_raw")
workplace_joined=$(extract_dsreg_field "WorkplaceJoined" "$dsreg_raw")
domain_joined=$(extract_dsreg_field "DomainJoined" "$dsreg_raw")
tenant_id_raw=$(extract_dsreg_field "TenantId" "$dsreg_raw")
device_id_raw=$(extract_dsreg_field "DeviceId" "$dsreg_raw")
tenant_name_raw=$(extract_dsreg_field "TenantName" "$dsreg_raw")
device_name_raw=$(extract_dsreg_field "DeviceName" "$dsreg_raw")

# Explicit UNKNOWN when extract fails (Codex 019e5b4e BLOCKER 1 fix: no silent NO fallback)
azure_ad_joined="${azure_ad_joined:-UNKNOWN}"
workplace_joined="${workplace_joined:-UNKNOWN}"
domain_joined="${domain_joined:-UNKNOWN}"

# Hash/mask sensitive identifiers BEFORE any logging
tenant_id_hash=$(hash_id "$tenant_id_raw")
device_id_hash=$(hash_id "$device_id_raw")
tenant_name_mask=$(mask_name "$tenant_name_raw")
device_name_mask=$(mask_name "$device_name_raw")

# Drop dsreg_raw from memory (defensive — prevents accidental logging)
unset dsreg_raw tenant_id_raw device_id_raw tenant_name_raw device_name_raw

log "  AzureAdJoined=$azure_ad_joined, WorkplaceJoined=$workplace_joined, DomainJoined=$domain_joined"
log "  TenantIdHash=$tenant_id_hash"
log "  DeviceIdHash=$device_id_hash"
log "  TenantNameMask=$tenant_name_mask"
log "  DeviceNameMask=$device_name_mask"

# === Step 3: MDM/Intune enrollment state ===
log "Step 3: MDM/Intune enrollment state probe"

# Set +e so MDM probe fail (common on workgroup) doesn't kill script
set +e
mdm_raw=$(prlctl exec "$VM_NAME" powershell -NoProfile -Command "
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
" 2>&1)
mdm_rc=$?
set -e

# Parse MDM fields (NOT logging raw output) + sanitize DeviceClientId before output
mdm_enrolled=$(printf '%s' "$mdm_raw" | jq -r '.Enrolled // false' 2>/dev/null || echo "false")
mdm_device_client_id_raw=$(printf '%s' "$mdm_raw" | jq -r '.DeviceClientId // ""' 2>/dev/null || echo "")
mdm_oem_version=$(printf '%s' "$mdm_raw" | jq -r '.OEMVersion // ""' 2>/dev/null || echo "")
mdm_reason=$(printf '%s' "$mdm_raw" | jq -r '.Reason // ""' 2>/dev/null || echo "")

mdm_device_client_id_hash=$(hash_id "$mdm_device_client_id_raw")

# Drop raw from memory
unset mdm_raw mdm_device_client_id_raw

log "  MDM enrolled=$mdm_enrolled (rc=$mdm_rc)"
log "  MDM DeviceClientIdHash=$mdm_device_client_id_hash"
log "  MDM OEMVersion=$mdm_oem_version"
[ -n "$mdm_reason" ] && log "  MDM Reason=$mdm_reason"

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
  if [ "$OWNERSHIP" = "byod" ]; then
    tier="A2"
    tier_reason="PartOfDomain=false, ownership=byod → A2 BYOD (consent + KVKK + signed binary mandatory)"
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

# === Step 5: Sanitized JSON evidence output (via jq for safe encoding) ===
log "Step 5: Sanitized JSON evidence output"

# Use jq -n to construct JSON safely (Codex 019e5b4e fix-list: heredoc → jq)
jq -n \
  --arg run_id "$RUN_ID" \
  --arg vm_name "$VM_NAME" \
  --arg tier "$tier" \
  --arg tier_reason "$tier_reason" \
  --arg ownership "$OWNERSHIP" \
  --arg part_of_domain "$part_of_domain" \
  --arg azure_ad_joined "$azure_ad_joined" \
  --arg workplace_joined "$workplace_joined" \
  --arg domain_joined "$domain_joined" \
  --arg tenant_id_hash "$tenant_id_hash" \
  --arg device_id_hash "$device_id_hash" \
  --arg tenant_name_mask "$tenant_name_mask" \
  --arg device_name_mask "$device_name_mask" \
  --arg mdm_enrolled "$mdm_enrolled" \
  --arg mdm_device_client_id_hash "$mdm_device_client_id_hash" \
  --arg mdm_oem_version "$mdm_oem_version" \
  --argjson machine_baseline "${cs_sanitized:-null}" \
  '{
    run_id: $run_id,
    vm_name: $vm_name,
    tier: $tier,
    tier_reason: $tier_reason,
    ownership_flag: $ownership,
    detection_fields: {
      PartOfDomain: $part_of_domain,
      AzureAdJoined: $azure_ad_joined,
      WorkplaceJoined: $workplace_joined,
      DomainJoined: $domain_joined,
      TenantIdHash: $tenant_id_hash,
      DeviceIdHash: $device_id_hash,
      TenantNameMask: $tenant_name_mask,
      DeviceNameMask: $device_name_mask,
      MdmEnrolled: $mdm_enrolled,
      MdmDeviceClientIdHash: $mdm_device_client_id_hash,
      MdmOEMVersion: $mdm_oem_version
    },
    machine_baseline: $machine_baseline,
    boundary: {
      scope: "A1-A4 non-domain Windows pilot classification only",
      not_pilot_acceptance: true,
      agent_action_only: "read-only probes + sanitized JSON output (parse-then-hash)",
      sanitization_notes: "TenantId/DeviceId/DeviceClientId: SHA256 truncate 16-char. TenantName/DeviceName: 8-char prefix mask. Hostname: raw for corporate/fixture, masked for BYOD. UPN: SHA256 hash in PowerShell. SID: domain-SID truncate (RID preserved).",
      next_gates: {
        A2: ["consent flow", "KVKK data inventory", "signed binary", "EDR allowlist"],
        A3: ["identity classification (AG-021/022 + BE-015)", "signed binary", "EDR allowlist"],
        A4: ["read-only inventory only", "signed binary"]
      }
    }
  }' > "$CLASSIFY_OUT"

cat "$CLASSIFY_OUT" | tee -a "$LOG"
log ""

# === Step 6: Post-write secret scan ===
log "Step 6: post-write secret scan (expanded patterns)"
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
