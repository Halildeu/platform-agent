#!/usr/bin/env bash
#
# parallels-windows11-ci.sh — Parallels Windows 11 CI pilot rehearsal harness
#
# Boundary note — Parallels W11 CI pilot rehearsal:
# This track runs against local Parallels Windows 11 VM (default name
# "Windows 11") from a self-hosted Mac runner via prlctl. The VM is
# WORKGROUP / PartOfDomain=false unless evidence states otherwise. This is
# a repeatable lab rehearsal only. It is NOT acik.local IT-owned pilot
# acceptance, NOT prod-ready, NOT password-reset-ready, and NOT domain-wide
# rollout-ready. The first backend command is non-destructive COLLECT_INVENTORY
# / inventory_refresh only. No password reset, user disable/enable, file
# access, raw agent shell, production cluster mutation, token logging,
# password logging, or domain admin credential capture is allowed. Real
# acik.local acceptance remains blocked on domain join, EndpointPilot OU
# placement, IT-owned devices, and EDR/allowlist provisioning. GitHub-hosted
# windows-latest runners cannot access this local Parallels VM; CI requires
# a self-hosted Mac runner with labels [self-hosted, macOS, parallels, windows11].
#
# Tracked by: platform-agent #12, gitops #1015 IT pilot umbrella, Codex
# strategic 019e5a95, predecessor manual smoke gitops PR #1021 + platform-
# agent PR #10.

set -euo pipefail
# IMPORTANT: do NOT enable `set -x` — token/credential exposure risk.

readonly VM_NAME="${PARALLELS_VM_NAME:-Windows 11}"
readonly RUN_ID="${GITHUB_RUN_ID:-local-$(date +%Y%m%d%H%M%S)}"
readonly EVIDENCE_DIR="${EVIDENCE_DIR:-./tmp/parallels-w11-ci-${RUN_ID}}"
readonly VM_USER="${PARALLELS_VM_USER:-halilkocoglu}"
# shellcheck disable=SC2034  # reserved for future prlctl exec wrapper timeout
readonly TIMEOUT_SECONDS="${PRLCTL_EXEC_TIMEOUT:-600}"

mkdir -p "$EVIDENCE_DIR"
readonly LOG="${EVIDENCE_DIR}/run.log"
readonly PRECHECK="${EVIDENCE_DIR}/precheck.txt"
readonly SMOKE_OUT="${EVIDENCE_DIR}/windows-live.txt"
readonly BUILD_OUT="${EVIDENCE_DIR}/build.txt"

log() {
  printf '%s [parallels-w11-ci] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" | tee -a "$LOG"
}

redact() {
  # Stream filter: known credential/token patterns scrubbed before writing to evidence.
  sed -E \
    -e 's/(Bearer[[:space:]]+)[A-Za-z0-9._-]+/\1<REDACTED>/g' \
    -e 's/(Authorization:[[:space:]]+)[^[:space:]]+/\1<REDACTED>/g' \
    -e 's/("?(password|token|secret|key|authorization)"?[[:space:]]*[:=][[:space:]]*"?)[^",\s}]+("?)/\1<REDACTED>\3/gi' \
    -e 's/(eyJ[A-Za-z0-9_-]{8,})\.[A-Za-z0-9._-]+/\1.<REDACTED>/g'
}

fail() {
  log "FAIL: $*"
  exit 1
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
log "  VM_USER=$VM_USER"

if ! command -v prlctl >/dev/null 2>&1; then
  fail "prlctl not found — self-hosted Mac runner with Parallels Desktop required"
fi
log "  prlctl: $(prlctl --version 2>&1 | head -1)"

if [ "$(uname -s)" != "Darwin" ]; then
  fail "host OS not Darwin — Parallels requires macOS; got $(uname -s)"
fi
log "  host: $(uname -s) $(uname -r)"

# === Step 1: VM discovery + start ===
log "Step 1: VM discovery + start"
if ! prlctl list --all --output name 2>/dev/null | grep -Fxq "$VM_NAME"; then
  fail "VM '$VM_NAME' not found in 'prlctl list --all'"
fi
log "  VM '$VM_NAME' found"

vm_state=$(prlctl status "$VM_NAME" 2>/dev/null | awk '{print $NF}' | head -1)
log "  initial state: $vm_state"

if [ "$vm_state" != "running" ]; then
  log "  starting VM '$VM_NAME'..."
  prlctl start "$VM_NAME" >>"$LOG" 2>&1 || fail "prlctl start '$VM_NAME' failed"
  # wait for guest tools ready
  for _ in $(seq 1 30); do
    if prlctl exec "$VM_NAME" "cmd /c echo guest-ready" 2>/dev/null | grep -q guest-ready; then
      break
    fi
    sleep 2
  done
fi

# === Step 2: PowerShell pre-check (non-admin OK) ===
log "Step 2: PowerShell pre-check — hostname / domain / PartOfDomain / UserName / backend reachability"
cat >"$EVIDENCE_DIR/precheck.ps1" <<'PSEOF'
$ErrorActionPreference = 'Stop'
$cs = Get-CimInstance Win32_ComputerSystem
[PSCustomObject]@{
  Hostname     = $env:COMPUTERNAME
  UserName     = $env:USERDOMAIN + '\' + $env:USERNAME
  Domain       = $cs.Domain
  PartOfDomain = $cs.PartOfDomain
  Workgroup    = $cs.Workgroup
  OSVersion    = (Get-CimInstance Win32_OperatingSystem).Version
  OSBuild      = (Get-CimInstance Win32_OperatingSystem).BuildNumber
} | ConvertTo-Json -Depth 4

Write-Host "---backend-reachability---"
$client = New-Object System.Net.Sockets.TcpClient
$async = $client.BeginConnect('testai.acik.com', 443, $null, $null)
$reachable = $async.AsyncWaitHandle.WaitOne(3000, $false)
if ($reachable) {
  try {
    $client.EndConnect($async)
  } catch {
    $reachable = $false
  }
}
$client.Close()
[PSCustomObject]@{
  Target    = 'testai.acik.com:443'
  Reachable = [bool]$reachable
} | ConvertTo-Json -Depth 4
PSEOF

# Note: prlctl exec runs as the configured Parallels guest user. For pre-check we use
# default user (no admin required). Credentials must be pre-configured out-of-band;
# this script NEVER passes --user with --password, NEVER logs domain admin credentials.
precheck_ps=$(cat "$EVIDENCE_DIR/precheck.ps1")
prlctl exec "$VM_NAME" powershell -NoProfile -ExecutionPolicy Bypass -Command "$precheck_ps" 2>&1 | redact >"$PRECHECK"
unset precheck_ps
log "  pre-check captured: $PRECHECK"
cat "$PRECHECK" | head -40 | tee -a "$LOG"

# Extract classification (PartOfDomain) for boundary asserts
domain_class=$(grep -E '"PartOfDomain"' "$PRECHECK" | head -1 | awk -F': ' '{print $2}' | tr -d ', \r' || echo "unknown")
log "  domain classification: PartOfDomain=$domain_class"
if [ "$domain_class" = "true" ]; then
  log "  NOTE: VM is domain-joined — evidence doc must capture domain class explicitly; this script does not auto-pivot to acik.local pilot acceptance scope."
else
  log "  classification: WORKGROUP (PartOfDomain=$domain_class) — Parallels W11 CI pilot rehearsal scope"
fi

# === Step 2.5: Non-domain A1-A4 tier classification (optional helper integration) ===
# Codex 019e5b38 Q2 absorb (b): yeni helper script ile A1-A4 detection (RB §4 + §8 decision tree).
# Output: sanitized classification JSON + tier; pilot acceptance gates per RB §13.2.
classify_helper="$(dirname "$0")/parallels-windows11-non-domain-classify.sh"
if [ -x "$classify_helper" ]; then
  log "Step 2.5: non-domain A1-A4 tier classification (helper: $classify_helper)"
  classify_evidence_dir="${EVIDENCE_DIR}/classify"
  mkdir -p "$classify_evidence_dir"
  set +e
  env -i \
    PATH="$PATH" \
    HOME="$HOME" \
    RUN_ID="$RUN_ID" \
    EVIDENCE_DIR="$classify_evidence_dir" \
    PARALLELS_VM_NAME="$VM_NAME" \
    PARALLELS_OWNERSHIP="${PARALLELS_OWNERSHIP:-corporate}" \
    bash "$classify_helper" >>"$LOG" 2>&1
  classify_rc=$?
  set -e
  log "  classification helper exit: $classify_rc (0=PASS, 1=fail, 2=scope_redirect to 22.2.B)"
  if [ -f "$classify_evidence_dir/classification.json" ]; then
    log "  classification evidence: $classify_evidence_dir/classification.json"
  fi
  if [ "$classify_rc" -ne 0 ]; then
    fail "classification helper failed or redirected (rc=$classify_rc; see $classify_evidence_dir) — Parallels W11 CI rehearsal must not false-green"
  fi
else
  log "Step 2.5: classification helper not found (executable expected at $classify_helper); skipping — re-run after platform-agent PR merge"
fi

# === Step 3: agent build/package ===
log "Step 3: agent build/package — ./scripts/build/windows-package.sh"
( cd "$(dirname "$0")/../.." && ./scripts/build/windows-package.sh ) 2>&1 | redact >"$BUILD_OUT"
log "  build complete: $BUILD_OUT"

# Capture SHA256 for evidence
pkg_dir="$(cd "$(dirname "$0")/../.."; pwd)/dist/windows/EndpointAgent"
if [ -f "$pkg_dir/SHA256SUMS" ]; then
  log "  package SHA256:"
  cat "$pkg_dir/SHA256SUMS" | tee -a "$LOG"
  cp "$pkg_dir/SHA256SUMS" "$EVIDENCE_DIR/SHA256SUMS"
fi

# === Step 4: windows-live.ps1 smoke ===
log "Step 4: windows-live.ps1 smoke (admin PowerShell required)"
# Guest path resolution: operator must configure Parallels Shared Folders so the
# checked-out repo root is reachable from the VM. Default assumes the macOS Home
# folder is shared and the repo lives at ~/Documents/platform-agent. Override via
# PARALLELS_GUEST_REPO_PATH env (e.g. "\\\\psf\\platform-agent" or "\\\\Mac\\Home\\path").
# This is OPERATOR-BOUND config — the script does NOT auto-create shared folder mounts
# (would require host-side credentials / sudo). NEVER pass --password.
readonly GUEST_REPO_PATH="${PARALLELS_GUEST_REPO_PATH:-\\\\Mac\\Home\\Documents\\platform-agent}"
readonly GUEST_LIVE_PS1="${GUEST_REPO_PATH}\\scripts\\test\\windows-live.ps1"
log "  guest repo path: $GUEST_REPO_PATH"
log "  guest windows-live.ps1: $GUEST_LIVE_PS1"
log "  invoking windows-live.ps1 via prlctl exec"

# windows-live.ps1 requires Administrator. In the Parallels CI harness, prlctl
# exec normally runs through Parallels Tools with sufficient rights; if that is
# not true, the script's Assert-Administrator check fails loudly with captured
# output. Do NOT spawn a detached/elevated child process here: Start-Process
# -Verb RunAs can return a false green while leaving windows-live.txt empty.
if prlctl exec "$VM_NAME" powershell -NoProfile -ExecutionPolicy Bypass -File "$GUEST_LIVE_PS1" 2>&1 | redact >"$SMOKE_OUT"; then
  log "  smoke output: $SMOKE_OUT ($(wc -l <"$SMOKE_OUT") lines)"
  tail -40 "$SMOKE_OUT" | tee -a "$LOG"
  if [ "$(wc -l <"$SMOKE_OUT")" -eq 0 ]; then
    fail "windows-live.ps1 produced empty output — treating as false-green risk"
  fi
  log "  windows-live.ps1: PASS"
else
  rc=$?
  log "  smoke output: $SMOKE_OUT ($(wc -l <"$SMOKE_OUT") lines)"
  tail -40 "$SMOKE_OUT" | tee -a "$LOG"
  fail "windows-live.ps1 exit code non-zero (rc=$rc; see $SMOKE_OUT) — CI FAIL"
fi

# === Step 5: BE-011 lifecycle smoke (optional hook) ===
log "Step 5: BE-011 lifecycle smoke (optional helper)"
if [ -x "$(dirname "$0")/be011-lifecycle-helper.sh" ]; then
  log "  helper found, invoking"
  bash "$(dirname "$0")/be011-lifecycle-helper.sh" --vm "$VM_NAME" --run-id "$RUN_ID" --evidence "$EVIDENCE_DIR" 2>&1 | redact | tee -a "$LOG"
else
  log "  no helper present at scripts/test/be011-lifecycle-helper.sh — skipping (manual BE-011 flow per gitops PR #1021 §5)"
fi

# === Step 6: post-write secret scan + summary ===
log "Step 6: post-write secret scan"
post_write_secret_scan || fail "secret scan failed — evidence quarantined; do NOT upload as artifact"

log "Step 7: summary"
log "  VM: $VM_NAME (PartOfDomain=$domain_class)"
log "  evidence dir: $EVIDENCE_DIR"
log "  pre-check: $PRECHECK"
log "  build: $BUILD_OUT"
log "  windows-live.ps1: $SMOKE_OUT"
log "  run log: $LOG"
log ""
log "Boundary note: Parallels W11 CI pilot rehearsal — NOT acik.local IT pilot acceptance, NOT prod-ready, NOT domain-wide rollout-ready. First backend command non-destructive COLLECT_INVENTORY / inventory_refresh only."

log "DONE (exit 0)"
exit 0
