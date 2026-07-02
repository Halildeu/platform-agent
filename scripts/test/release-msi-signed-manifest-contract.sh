#!/usr/bin/env bash
# Static regression guard for platform-agent#211.
#
# The trusted MSI production manifest must expose the signed MSI at top-level
# msi_file/msi_sha256, while preserving the unsigned build input under an
# explicit unsigned_input object. This script intentionally checks the workflow
# contract because the signing job itself runs only on protected runners.
# Limitation: grep-based static checks can match commented/dead text; the real
# protection remains the runtime PowerShell assertions in release-msi-signed.yml.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKFLOW="$ROOT/.github/workflows/release-msi-signed.yml"

require_grep() {
  local needle="$1" file="$2"
  if ! grep -Fq "$needle" "$file"; then
    echo "missing required contract text: $needle" >&2
    exit 1
  fi
}

require_grep '$unsignedMsiFile = [string]$m.msi_file' "$WORKFLOW"
require_grep '$unsignedMsiSha256 = [string]$m.msi_sha256' "$WORKFLOW"
require_grep 'Add-Member -Force NoteProperty unsigned_input' "$WORKFLOW"
require_grep 'Add-Member -Force NoteProperty msi_file $msiName' "$WORKFLOW"
require_grep 'Add-Member -Force NoteProperty msi_sha256 $msiHash' "$WORKFLOW"
require_grep 'production manifest top-level msi_file' "$WORKFLOW"
require_grep 'production manifest top-level msi_sha256' "$WORKFLOW"
require_grep 'production manifest must preserve unsigned input under unsigned_input' "$WORKFLOW"
require_grep 'unsigned_input.msi_file must differ from top-level signed msi_file' "$WORKFLOW"
require_grep 'unsigned_input.msi_sha256 must differ from top-level signed msi_sha256' "$WORKFLOW"

echo "release-msi-signed-manifest-contract-ok"
