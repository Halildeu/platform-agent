#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
workflow="$repo_root/.github/workflows/release-exe-signed.yml"

require_text() {
  local text="$1"
  grep -Fq -- "$text" "$workflow" \
    || { echo "missing historical recovery guard: $text" >&2; exit 1; }
}

require_text "historical_recovery:"
require_text "historical recovery is workflow_dispatch-only"
require_text ".isImmutable == true"
require_text "immutable manifest does not bind previous_release="
require_text "historical recovery predecessor"
require_text 'echo "previous_release=$predecessor" >&3'
require_text "ref: \${{ needs.classify.outputs.recovery_policy_commit }}"
require_text "current_run_draft_id()"
require_text "multiple current-run drafts matched"
require_text "current-run historical draft release id not found"
require_text "-f make_latest=false"
require_text "historical recovery incorrectly changed Latest"
require_text "Latest regressed from"

echo "historical release recovery workflow static guards pass"
