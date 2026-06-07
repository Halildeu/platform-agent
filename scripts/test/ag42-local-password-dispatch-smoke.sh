#!/usr/bin/env bash
#
# AG-042 — CHANGE_LOCAL_PASSWORD dedicated backend→agent dispatch smoke.
#
# This harness consumes operator-owned curl -K auth config files. It must never
# receive raw JWTs or password material as environment variables or arguments.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/test/ag42-local-password-dispatch-smoke.sh \
    --device-id <uuid> \
    --proposer-config /secure/kc-proposer.cfg \
    --approver-config /secure/kc-approver.cfg

Options:
  --base-url <url>             External base URL (default: https://testai.acik.com)
  --admin-prefix <path>        Gateway admin prefix (default: /api/v1/endpoint-admin)
  --device-id <uuid>           Endpoint device UUID to target (required)
  --proposer-config <path>     curl -K file for issuer/proposer admin JWT (required)
  --approver-config <path>     curl -K file for second-admin approver JWT (required)
  --target-username <name>     Local SAM account to change (default: ea-recovery-smoke)
  --reason <text>              Command reason
  --approval-reason <text>     Approval reason
  --idempotency-key <key>      Idempotency key (default: generated)
  --evidence-dir <path>        Evidence output directory (default: tmp/ag42-local-password-<ts>)
  --timeout-seconds <n>        Poll timeout (default: 240)
  --poll-interval-seconds <n>  Poll interval (default: 5)
  --parallels-vm <name>        Optional VM name; captures before/after 'net user' state
  --create-test-user           Create the target local test account before dispatch
  --cleanup-test-user          Remove the created test account after evidence capture
  -h, --help                   Show this help

Security boundary:
  - Do not pass Bearer tokens or passwords directly to this script.
  - Put Authorization headers in chmod 600 curl -K config files.
  - Use a synthetic local account. Domain, UPN, and built-in account targets are refused.
  - The backend one-time password is redacted before it is written to disk.
  - The script scans written evidence for token/password-like leaks before PASS.
EOF
}

readonly DEFAULT_REASON="AG-042 local password dispatch smoke"
readonly DEFAULT_APPROVAL_REASON="AG-042 second-admin approval for local password dispatch smoke"

base_url="https://testai.acik.com"
admin_prefix="/api/v1/endpoint-admin"
device_id=""
proposer_config=""
approver_config=""
target_username="ea-recovery-smoke"
reason="$DEFAULT_REASON"
approval_reason="$DEFAULT_APPROVAL_REASON"
idempotency_key="local-password-smoke-$(date -u '+%Y%m%dT%H%M%SZ')"
evidence_dir="tmp/ag42-local-password-$(date -u '+%Y%m%dT%H%M%SZ')"
timeout_seconds=240
poll_interval_seconds=5
parallels_vm=""
create_test_user=0
cleanup_test_user=0
created_vm_test_user=0
cleanup_done=0

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
    --create-test-user)
      create_test_user=1
      shift
      ;;
    --cleanup-test-user)
      cleanup_test_user=1
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
  printf '%s [ag42-local-password-smoke] FAIL: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2
  exit 1
}

redact() {
  sed -E \
    -e 's/(Bearer[[:space:]]+)[A-Za-z0-9._-]+/\1<REDACTED>/g' \
    -e 's/(Authorization:[[:space:]]*)[^[:space:]]+/\1<REDACTED>/g' \
    -e 's/(eyJ[A-Za-z0-9_-]{8,})\.[A-Za-z0-9._-]+/\1.<REDACTED>/g' \
    -e 's/("?[A-Za-z0-9_-]*(password|token|secret|authorization)[A-Za-z0-9_-]*"?[[:space:]]*[:=][[:space:]]*"?)[^",[:space:]}]+("?)/\1<REDACTED>\3/gi'
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

validate_target_username() {
  case "$target_username" in
    *\\*|*/*|*@*|*:*|*\"*|*\|*|*\<*|*\>*|*'?'*)
      fail "target username must be a local SAM name, not a domain/UPN/path target: $target_username"
      ;;
  esac
  printf '%s' "$target_username" | grep -Eq '^[A-Za-z0-9._-]{1,64}$' \
    || fail "target username must match ^[A-Za-z0-9._-]{1,64}$ for this smoke"
  case "$(printf '%s' "$target_username" | tr '[:upper:]' '[:lower:]')" in
    administrator|guest|defaultaccount|wdagutilityaccount)
      fail "built-in/reserved local account is refused for password smoke: $target_username"
      ;;
  esac
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

ps_quote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/''/g")"
}

ps_encoded_arg() {
  local script="$1"
  printf '%s' "$script" | iconv -f UTF-8 -t UTF-16LE | base64 | tr -d '\n'
}

run_vm_powershell() {
  local script="$1"
  local out="$2"

  require_cmd prlctl
  require_cmd iconv
  require_cmd base64
  if ! prlctl status "$parallels_vm" >/dev/null 2>&1; then
    fail "Parallels VM not found or inaccessible: $parallels_vm"
  fi

  local encoded
  encoded="$(ps_encoded_arg "\$ProgressPreference = 'SilentlyContinue'
$script")"
  prlctl exec "$parallels_vm" powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand "$encoded" 2>&1 \
    | redact >"$out"
}

create_vm_test_user() {
  [ -n "$parallels_vm" ] || fail "--create-test-user requires --parallels-vm"

  local out="$1"
  local user_ps
  user_ps="$(ps_quote "$target_username")"
  run_vm_powershell "
\$ErrorActionPreference = 'Stop'
\$user = $user_ps
if (Get-LocalUser -Name \$user -ErrorAction SilentlyContinue) {
  throw \"local test user already exists: \$user\"
}
\$chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%'.ToCharArray()
\$bytes = New-Object byte[] 28
\$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
\$rng.GetBytes(\$bytes)
\$plain = -join (\$bytes | ForEach-Object { \$chars[[int]\$_ % \$chars.Length] })
\$secure = ConvertTo-SecureString -String \$plain -AsPlainText -Force
New-LocalUser -Name \$user -Password \$secure -Description 'AG-042 password smoke' | Out-Null
[pscustomobject]@{Username=\$user; Created=\$true; PasswordMaterial='REDACTED'} | ConvertTo-Json -Compress
" "$out"
}

remove_vm_test_user() {
  [ -n "$parallels_vm" ] || return 0

  local out="$1"
  local user_ps
  user_ps="$(ps_quote "$target_username")"
  run_vm_powershell "
\$ErrorActionPreference = 'Stop'
\$user = $user_ps
if (Get-LocalUser -Name \$user -ErrorAction SilentlyContinue) {
  Remove-LocalUser -Name \$user
  [pscustomobject]@{Username=\$user; Removed=\$true} | ConvertTo-Json -Compress
} else {
  [pscustomobject]@{Username=\$user; Removed=\$false; Reason='not-found'} | ConvertTo-Json -Compress
}
" "$out"
}

cleanup_on_exit() {
  local status=$?
  if [ "$status" -ne 0 ] \
    && [ "$cleanup_test_user" -eq 1 ] \
    && [ "$created_vm_test_user" -eq 1 ] \
    && [ "$cleanup_done" -eq 0 ]; then
    remove_vm_test_user "$evidence_dir/vm-cleanup-test-user-on-exit.json" || true
  fi
  exit "$status"
}

capture_vm_user_state() {
  local stage="$1"
  local out="$2"

  [ -n "$parallels_vm" ] || return 0

  local user_ps
  user_ps="$(ps_quote "$target_username")"
  run_vm_powershell "
\$ErrorActionPreference = 'Stop'
\$user = $user_ps
cmd /c \"net user \`\"\$user\`\"\"
if (\$LASTEXITCODE -ne 0) { exit \$LASTEXITCODE }
" "$out" || fail "failed to capture '$target_username' state from VM '$parallels_vm' at stage=$stage"
}

post_write_secret_scan() {
  local hits
  hits="$(
    grep -rEi \
      'Bearer [A-Za-z0-9._-]{20,}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}|"(oneTimePassword|newPassword|password|token|secret|authorization)"[[:space:]]*:[[:space:]]*"[^"]+"' \
      "$evidence_dir" 2>/dev/null | grep -v '<REDACTED>' || true
  )"
  if [ -n "$hits" ]; then
    printf '%s\n' "$hits" | head -20 >&2
    fail "post-write secret scan found unredacted token/password-like evidence"
  fi
}

[ -n "$device_id" ] || fail "--device-id is required"
[ "$cleanup_test_user" -eq 0 ] || [ "$create_test_user" -eq 1 ] \
  || fail "--cleanup-test-user is only allowed together with --create-test-user"

validate_target_username
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
  printf '%s [ag42-local-password-smoke] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" | tee -a "$log_file"
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
log "create_test_user=$create_test_user cleanup_test_user=$cleanup_test_user"

payload_file="$evidence_dir/create-local-password.payload.json"
approval_file="$evidence_dir/approval.payload.json"
create_body="$evidence_dir/create-local-password.response.json"
create_meta="$evidence_dir/create-local-password.meta.json"
approve_body="$evidence_dir/approve.response.json"
approve_meta="$evidence_dir/approve.meta.json"
poll_body="$evidence_dir/poll.response.json"
poll_meta="$evidence_dir/poll.meta.json"
vm_create="$evidence_dir/vm-create-test-user.json"
vm_before="$evidence_dir/vm-before-net-user.txt"
vm_after="$evidence_dir/vm-after-net-user.txt"
vm_cleanup="$evidence_dir/vm-cleanup-test-user.json"

trap cleanup_on_exit EXIT

if [ "$create_test_user" -eq 1 ]; then
  log "create synthetic local test user in Parallels VM"
  create_vm_test_user "$vm_create"
  created_vm_test_user=1
fi

capture_vm_user_state "before" "$vm_before"

jq -n \
  --arg username "$target_username" \
  --arg idempotencyKey "$idempotency_key" \
  --arg reason "$reason" \
  '{username:$username,idempotencyKey:$idempotencyKey,reason:$reason}' \
  >"$payload_file"

jq -n \
  --arg decision "APPROVE" \
  --arg reason "$approval_reason" \
  '{decision:$decision,reason:$reason}' \
  >"$approval_file"

create_url="${admin_url}/endpoint-devices/${device_id}/local-password-changes"

log "create CHANGE_LOCAL_PASSWORD command through dedicated local-password endpoint"
curl_json "$proposer_config" "POST" "$create_url" "$payload_file" "$create_body" "$create_meta"
command_id="$(
  jq -er '.command.id // .command.commandId // .id // .commandId' "$create_body"
)" || fail "could not parse command id from local-password response"
command_type="$(jq -r '.command.type // .command.commandType // .type // .commandType // "UNKNOWN"' "$create_body")"
[ "$command_type" = "CHANGE_LOCAL_PASSWORD" ] \
  || fail "expected CHANGE_LOCAL_PASSWORD command type from dedicated endpoint; got $command_type"
approval_status="$(jq -r '.command.approvalStatus // .approvalStatus // "UNKNOWN"' "$create_body")"
status="$(jq -r '.command.status // .status // "UNKNOWN"' "$create_body")"
log "created command_id=$command_id status=$status approvalStatus=$approval_status"

if jq -e '
  [
    (.oneTimePassword? // empty),
    (.newPassword? // empty)
  ] | map(select(. != "" and . != "<REDACTED>")) | length > 0
' "$create_body" >/dev/null; then
  fail "local-password response evidence contains unredacted password material"
fi

approve_url="${admin_url}/endpoint-commands/${command_id}/approval"
get_url="${admin_url}/endpoint-commands/${command_id}"

log "approve command with second admin config"
curl_json "$approver_config" "POST" "$approve_url" "$approval_file" "$approve_body" "$approve_meta"
approval_status="$(jq -r '.approvalStatus // .command.approvalStatus // "UNKNOWN"' "$approve_body")"
status="$(jq -r '.status // .command.status // "UNKNOWN"' "$approve_body")"
log "approved command_id=$command_id status=$status approvalStatus=$approval_status"

deadline=$((SECONDS + timeout_seconds))
terminal_status=""
while [ "$SECONDS" -le "$deadline" ]; do
  curl_json "$proposer_config" "GET" "$get_url" "" "$poll_body" "$poll_meta"
  terminal_status="$(jq -r '.status // .command.status // "UNKNOWN"' "$poll_body")"
  log "poll command_id=$command_id status=$terminal_status"
  case "$terminal_status" in
    FAILED|SUCCEEDED|CANCELLED|EXPIRED|REJECTED)
      break
      ;;
  esac
  sleep "$poll_interval_seconds"
done

if [ "$terminal_status" != "SUCCEEDED" ]; then
  fail "expected terminal status SUCCEEDED for synthetic local password smoke; got $terminal_status"
fi

result_text="$(
  jq -r '
    [
      .type?,
      .commandType?,
      .summary?,
      .detail?,
      .result?.summary?,
      .result?.detail?,
      (.resultPayload? | tostring)
    ] | map(select(. != null and . != "")) | join("\n")
  ' "$poll_body"
)"

if printf '%s\n' "$result_text" | grep -Eiq '(oneTimePassword|newPassword|password[[:space:]]*[=:]|secret[[:space:]]*[=:])'; then
  fail "terminal result appears to contain password material"
fi

capture_vm_user_state "after" "$vm_after"
if [ -n "$parallels_vm" ]; then
  if cmp -s "$vm_before" "$vm_after"; then
    fail "VM '$target_username' state did not change between before/after captures"
  fi
  log "VM '$target_username' before/after state changed as expected"
fi

if [ "$cleanup_test_user" -eq 1 ]; then
  log "cleanup synthetic local test user"
  remove_vm_test_user "$vm_cleanup"
  cleanup_done=1
fi

jq -n \
  --arg runStarted "$(head -1 "$log_file" | awk '{print $1}')" \
  --arg runFinished "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
  --arg baseUrl "$base_url" \
  --arg adminPrefix "$admin_prefix" \
  --arg deviceId "$device_id" \
  --arg commandId "$command_id" \
  --arg commandType "$command_type" \
  --arg targetUsername "$target_username" \
  --arg idempotencyKey "$idempotency_key" \
  --arg terminalStatus "$terminal_status" \
  --arg evidenceDir "$evidence_dir" \
  --arg vmName "${parallels_vm:-}" \
  --arg createTestUser "$create_test_user" \
  --arg cleanupTestUser "$cleanup_test_user" \
  --argjson createMeta "$(cat "$create_meta")" \
  --argjson approver "$(cat "$approve_meta")" \
  --argjson poll "$(cat "$poll_meta")" \
  '{
    smoke:"AG-042 CHANGE_LOCAL_PASSWORD dispatch",
    runStarted:$runStarted,
    runFinished:$runFinished,
    baseUrl:$baseUrl,
    adminPrefix:$adminPrefix,
    deviceId:$deviceId,
    commandId:$commandId,
    commandType:$commandType,
    targetUsername:$targetUsername,
    idempotencyKey:$idempotencyKey,
    terminalStatus:$terminalStatus,
    vmName:($vmName | select(. != "")),
    createTestUser:($createTestUser == "1"),
    cleanupTestUser:($cleanupTestUser == "1"),
    endpoints:{create:$createMeta,approve:$approver,poll:$poll},
    evidenceDir:$evidenceDir,
    secretPolicy:"operator JWTs supplied only through curl -K config files; backend one-time password is redacted before disk write; evidence scanned"
  }' >"$report_json"

{
  printf "# AG-042 CHANGE_LOCAL_PASSWORD Dispatch Smoke\n\n"
  printf -- "- Device: \`%s\`\n" "$device_id"
  printf -- "- Command: \`%s\`\n" "$command_id"
  printf -- "- Command type: \`%s\`\n" "$command_type"
  printf -- "- Target local user: \`%s\`\n" "$target_username"
  printf -- "- Terminal status: \`%s\`\n" "$terminal_status"
  printf -- "- Idempotency key: \`%s\`\n" "$idempotency_key"
  printf -- "- VM before/after check: \`%s\`\n" "$([ -n "$parallels_vm" ] && echo "enabled:$parallels_vm" || echo "not-run")"
  printf -- "- Synthetic user create/cleanup: \`%s/%s\`\n" "$create_test_user" "$cleanup_test_user"
  printf -- "- Evidence dir: \`%s\`\n\n" "$evidence_dir"
  printf "No raw JWTs, backend one-time passwords, or local password material are stored in this evidence directory.\n"
} >"$report_md"

post_write_secret_scan
log "PASS command_id=$command_id terminal_status=$terminal_status"
log "report_json=$report_json"
log "report_md=$report_md"
