#!/usr/bin/env bash
#
# AG-092 / #84 residual #1 — LOCK_USER_LOGIN command-specific dispatch smoke.
#
# This harness consumes operator-owned curl -K auth config files. It must never
# receive raw JWTs as environment variables or command-line arguments.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/test/ag92-lock-dispatch-smoke.sh \
    --device-id <uuid> \
    --proposer-config /secure/kc-proposer.cfg \
    --approver-config /secure/kc-approver.cfg

Options:
  --base-url <url>             External base URL (default: https://testai.acik.com)
  --admin-prefix <path>        Gateway admin prefix (default: /api/v1/endpoint-admin)
  --device-id <uuid>           Endpoint device UUID to target (required)
  --proposer-config <path>     curl -K file for issuer/proposer admin JWT (required)
  --approver-config <path>     curl -K file for second-admin approver JWT (required)
  --target-username <name>     Target account (default: Administrator)
  --reason <text>              Command reason
  --approval-reason <text>     Approval reason
  --idempotency-key <key>      Idempotency key (default: generated)
  --evidence-dir <path>        Evidence output directory (default: tmp/ag92-lock-dispatch-<ts>)
  --timeout-seconds <n>        Poll timeout (default: 180)
  --poll-interval-seconds <n>  Poll interval (default: 5)
  --parallels-vm <name>        Optional VM name; captures before/after 'net user' state
  --skip-result-text-check     Do not require RID/reserved-account refusal text
  -h, --help                   Show this help

Security boundary:
  - Do not pass Bearer tokens directly to this script.
  - Put Authorization headers in chmod 600 curl -K config files.
  - The script does not print config contents and scans written evidence for token leaks.
EOF
}

readonly DEFAULT_REASON="AG-092 RID-guard dispatch smoke"
readonly DEFAULT_APPROVAL_REASON="AG-092 second-admin approval for RID-guard dispatch smoke"

base_url="https://testai.acik.com"
admin_prefix="/api/v1/endpoint-admin"
device_id=""
proposer_config=""
approver_config=""
target_username="Administrator"
reason="$DEFAULT_REASON"
approval_reason="$DEFAULT_APPROVAL_REASON"
idempotency_key="lock-user-login-smoke-$(date -u '+%Y%m%dT%H%M%SZ')"
evidence_dir="tmp/ag92-lock-dispatch-$(date -u '+%Y%m%dT%H%M%SZ')"
timeout_seconds=180
poll_interval_seconds=5
parallels_vm=""
skip_result_text_check=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --base-url)
      base_url="${2:?--base-url requires a value}"
      shift 2
      ;;
    --admin-prefix)
      admin_prefix="${2:?--admin-prefix requires a value}"
      shift 2
      ;;
    --device-id)
      device_id="${2:?--device-id requires a value}"
      shift 2
      ;;
    --proposer-config)
      proposer_config="${2:?--proposer-config requires a value}"
      shift 2
      ;;
    --approver-config)
      approver_config="${2:?--approver-config requires a value}"
      shift 2
      ;;
    --target-username)
      target_username="${2:?--target-username requires a value}"
      shift 2
      ;;
    --reason)
      reason="${2:?--reason requires a value}"
      shift 2
      ;;
    --approval-reason)
      approval_reason="${2:?--approval-reason requires a value}"
      shift 2
      ;;
    --idempotency-key)
      idempotency_key="${2:?--idempotency-key requires a value}"
      shift 2
      ;;
    --evidence-dir)
      evidence_dir="${2:?--evidence-dir requires a value}"
      shift 2
      ;;
    --timeout-seconds)
      timeout_seconds="${2:?--timeout-seconds requires a value}"
      shift 2
      ;;
    --poll-interval-seconds)
      poll_interval_seconds="${2:?--poll-interval-seconds requires a value}"
      shift 2
      ;;
    --parallels-vm)
      parallels_vm="${2:?--parallels-vm requires a value}"
      shift 2
      ;;
    --skip-result-text-check)
      skip_result_text_check=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown argument: %s\n\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

fail() {
  printf '%s [ag92-lock-smoke] FAIL: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2
  exit 1
}

redact() {
  sed -E \
    -e 's/(Bearer[[:space:]]+)[A-Za-z0-9._-]+/\1<REDACTED>/g' \
    -e 's/(Authorization:[[:space:]]*)[^[:space:]]+/\1<REDACTED>/g' \
    -e 's/(eyJ[A-Za-z0-9_-]{8,})\.[A-Za-z0-9._-]+/\1.<REDACTED>/g' \
    -e 's/("?(password|token|secret|key|authorization)"?[[:space:]]*[:=][[:space:]]*"?)[^",[:space:]}]+("?)/\1<REDACTED>\3/gi'
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

stat_mode() {
  if stat -f '%Lp' "$1" >/dev/null 2>&1; then
    stat -f '%Lp' "$1"
  else
    stat -c '%a' "$1"
  fi
}

validate_auth_config() {
  local path="$1"
  local label="$2"

  [ -n "$path" ] || fail "$label config path is required"
  [ -f "$path" ] || fail "$label config file not found: $path"

  local mode
  mode="$(stat_mode "$path")"
  mode="${mode: -3}"
  if [ "${#mode}" -lt 3 ]; then
    fail "$label config file mode could not be parsed: $mode"
  fi
  if [ "${mode:1:1}" != "0" ] || [ "${mode:2:1}" != "0" ]; then
    fail "$label config file must not be group/other-readable (mode=$mode); run chmod 600 '$path'"
  fi
}

curl_json() {
  local config_file="$1"
  local method="$2"
  local url="$3"
  local request_body="${4:-}"
  local response_body="$5"
  local response_meta="$6"

  local http_code
  if [ -n "$request_body" ]; then
    http_code="$(
      curl --silent --show-error --location --max-time 60 \
        --request "$method" \
        -K "$config_file" \
        -H "Content-Type: application/json" \
        --data @"$request_body" \
        --output >(redact >"$response_body") \
        --write-out '%{http_code}' \
        "$url"
    )"
  else
    http_code="$(
      curl --silent --show-error --location --max-time 60 \
        --request "$method" \
        -K "$config_file" \
        --output >(redact >"$response_body") \
        --write-out '%{http_code}' \
        "$url"
    )"
  fi

  jq -n --arg method "$method" --arg url "$url" --arg httpCode "$http_code" \
    '{method:$method,url:$url,httpCode:($httpCode|tonumber)}' >"$response_meta"

  if [ "$http_code" -lt 200 ] || [ "$http_code" -ge 300 ]; then
    printf 'HTTP %s for %s %s\n' "$http_code" "$method" "$url" >&2
    sed -n '1,80p' "$response_body" >&2 || true
    return 22
  fi
}

capture_vm_user_state() {
  local stage="$1"
  local out="$2"

  [ -n "$parallels_vm" ] || return 0
  require_cmd prlctl
  if ! prlctl status "$parallels_vm" >/dev/null 2>&1; then
    fail "Parallels VM not found or inaccessible: $parallels_vm"
  fi
  prlctl exec "$parallels_vm" cmd /c "net user \"$target_username\"" 2>&1 | redact >"$out" \
    || fail "failed to capture '$target_username' state from VM '$parallels_vm' at stage=$stage"
}

post_write_secret_scan() {
  local hits
  hits="$(
    grep -rEi \
      'Bearer [A-Za-z0-9._-]{20,}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}|"(password|token|secret|authorization)"[[:space:]]*:[[:space:]]*"[^"]+"' \
      "$evidence_dir" 2>/dev/null | grep -v '<REDACTED>' || true
  )"
  if [ -n "$hits" ]; then
    printf '%s\n' "$hits" | head -20 >&2
    fail "post-write secret scan found unredacted token-like evidence"
  fi
}

[ -n "$device_id" ] || fail "--device-id is required"
validate_auth_config "$proposer_config" "proposer"
validate_auth_config "$approver_config" "approver"

require_cmd curl
require_cmd jq
require_cmd grep
require_cmd mktemp

mkdir -p "$evidence_dir"
log_file="$evidence_dir/run.log"
report_json="$evidence_dir/report.json"
report_md="$evidence_dir/report.md"

log() {
  printf '%s [ag92-lock-smoke] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" | tee -a "$log_file"
}

base_url="${base_url%/}"
admin_prefix="/${admin_prefix#/}"
admin_prefix="${admin_prefix%/}"
admin_url="${base_url}${admin_prefix}"

log "start"
log "base_url=$base_url"
log "admin_prefix=$admin_prefix"
log "device_id=$device_id"
log "target_username=$target_username"
log "idempotency_key=$idempotency_key"
log "evidence_dir=$evidence_dir"
log "parallels_vm=${parallels_vm:-<not-set>}"

payload_file="$evidence_dir/propose.payload.json"
approval_file="$evidence_dir/approval.payload.json"
propose_body="$evidence_dir/propose.response.json"
propose_meta="$evidence_dir/propose.meta.json"
approve_body="$evidence_dir/approve.response.json"
approve_meta="$evidence_dir/approve.meta.json"
poll_body="$evidence_dir/poll.response.json"
poll_meta="$evidence_dir/poll.meta.json"
vm_before="$evidence_dir/vm-before-net-user.txt"
vm_after="$evidence_dir/vm-after-net-user.txt"

jq -n \
  --arg type "LOCK_USER_LOGIN" \
  --arg idempotencyKey "$idempotency_key" \
  --arg reason "$reason" \
  --arg username "$target_username" \
  '{type:$type,idempotencyKey:$idempotencyKey,reason:$reason,payload:{username:$username}}' \
  >"$payload_file"

jq -n \
  --arg decision "APPROVE" \
  --arg reason "$approval_reason" \
  '{decision:$decision,reason:$reason}' \
  >"$approval_file"

capture_vm_user_state "before" "$vm_before"

create_url="${admin_url}/endpoint-devices/${device_id}/commands"
approve_url=""
get_url=""

log "propose LOCK_USER_LOGIN command"
curl_json "$proposer_config" "POST" "$create_url" "$payload_file" "$propose_body" "$propose_meta"
command_id="$(jq -er '.id // .commandId' "$propose_body")" || fail "could not parse command id from propose response"
approval_status="$(jq -r '.approvalStatus // "UNKNOWN"' "$propose_body")"
status="$(jq -r '.status // "UNKNOWN"' "$propose_body")"
log "proposed command_id=$command_id status=$status approvalStatus=$approval_status"

approve_url="${admin_url}/endpoint-commands/${command_id}/approval"
get_url="${admin_url}/endpoint-commands/${command_id}"

log "approve command with second admin config"
curl_json "$approver_config" "POST" "$approve_url" "$approval_file" "$approve_body" "$approve_meta"
approval_status="$(jq -r '.approvalStatus // "UNKNOWN"' "$approve_body")"
status="$(jq -r '.status // "UNKNOWN"' "$approve_body")"
log "approved command_id=$command_id status=$status approvalStatus=$approval_status"

deadline=$((SECONDS + timeout_seconds))
terminal_status=""
while [ "$SECONDS" -le "$deadline" ]; do
  curl_json "$proposer_config" "GET" "$get_url" "" "$poll_body" "$poll_meta"
  terminal_status="$(jq -r '.status // "UNKNOWN"' "$poll_body")"
  log "poll command_id=$command_id status=$terminal_status"
  case "$terminal_status" in
    FAILED|SUCCEEDED|CANCELLED|EXPIRED|REJECTED)
      break
      ;;
  esac
  sleep "$poll_interval_seconds"
done

if [ "$terminal_status" != "FAILED" ]; then
  fail "expected terminal status FAILED from RID guard; got $terminal_status"
fi

result_text="$(
  jq -r '
    [
      .summary?,
      .detail?,
      .lastError?,
      .errorMessage?,
      .failureReason?,
      .result?.summary?,
      .result?.detail?,
      .result?.errorMessage?,
      .result?.failureReason?,
      .result?.payload?.summary?,
      .result?.payload?.detail?,
      .result?.payload?.errorMessage?,
      .result?.payload?.failureReason?,
      (.resultPayload? | tostring),
      (.result?.payload? | tostring)
    ] | map(select(. != null and . != "")) | join("\n")
  ' "$poll_body"
)"

if [ "$skip_result_text_check" -eq 0 ]; then
  printf '%s\n' "$result_text" | grep -Eiq '(rid|reserved|built.?in|administrator)' \
    || fail "terminal FAILED did not include RID/reserved-account refusal text; inspect $poll_body"
fi

capture_vm_user_state "after" "$vm_after"
if [ -n "$parallels_vm" ]; then
  if ! cmp -s "$vm_before" "$vm_after"; then
    fail "VM '$target_username' state changed between before/after captures"
  fi
  log "VM '$target_username' before/after state unchanged"
fi

jq -n \
  --arg runStarted "$(head -1 "$log_file" | awk '{print $1}')" \
  --arg runFinished "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
  --arg baseUrl "$base_url" \
  --arg adminPrefix "$admin_prefix" \
  --arg deviceId "$device_id" \
  --arg commandId "$command_id" \
  --arg targetUsername "$target_username" \
  --arg idempotencyKey "$idempotency_key" \
  --arg terminalStatus "$terminal_status" \
  --arg evidenceDir "$evidence_dir" \
  --arg vmName "${parallels_vm:-}" \
  --argjson proposer "$(cat "$propose_meta")" \
  --argjson approver "$(cat "$approve_meta")" \
  --argjson poll "$(cat "$poll_meta")" \
  '{
    smoke:"AG-092 LOCK_USER_LOGIN dispatch",
    runStarted:$runStarted,
    runFinished:$runFinished,
    baseUrl:$baseUrl,
    adminPrefix:$adminPrefix,
    deviceId:$deviceId,
    commandId:$commandId,
    targetUsername:$targetUsername,
    idempotencyKey:$idempotencyKey,
    terminalStatus:$terminalStatus,
    vmName:($vmName | select(. != "")),
    endpoints:{propose:$proposer,approve:$approver,poll:$poll},
    evidenceDir:$evidenceDir,
    secretPolicy:"operator JWTs supplied only through curl -K config files; evidence redacted and scanned"
  }' >"$report_json"

{
  printf "# AG-092 LOCK_USER_LOGIN Dispatch Smoke\n\n"
  printf -- "- Device: \`%s\`\n" "$device_id"
  printf -- "- Command: \`%s\`\n" "$command_id"
  printf -- "- Target user: \`%s\`\n" "$target_username"
  printf -- "- Terminal status: \`%s\`\n" "$terminal_status"
  printf -- "- Idempotency key: \`%s\`\n" "$idempotency_key"
  printf -- "- VM before/after check: \`%s\`\n" "$([ -n "$parallels_vm" ] && echo "enabled:$parallels_vm" || echo "not-run")"
  printf -- "- Evidence dir: \`%s\`\n\n" "$evidence_dir"
  printf "No raw JWTs are stored in this evidence directory. Config-file contents are never printed.\n"
} >"$report_md"

post_write_secret_scan
log "PASS command_id=$command_id terminal_status=$terminal_status"
log "report_json=$report_json"
log "report_md=$report_md"
