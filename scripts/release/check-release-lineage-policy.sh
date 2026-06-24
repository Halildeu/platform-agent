#!/usr/bin/env bash
set -euo pipefail

script_root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${RELEASE_POLICY_REPO_ROOT:-$script_root}"

policy="config/faz22-6-endpoint-agent-release-policy.v1.json"
tag="${TAG:-}"
release_class="${RELEASE_CLASS:-}"
previous_release="${PREVIOUS_RELEASE:-}"
source_commit="${SOURCE_COMMIT:-}"
github_repo="${GITHUB_REPOSITORY:-}"
enforce_github_rules="${ENFORCE_GITHUB_RULES:-false}"
today="${RELEASE_POLICY_TODAY:-$(date -u +%F)}"
emit_output=""

fail() {
  echo "::error::$*" >&2
  exit 1
}

notice() {
  echo "::notice::$*"
}

usage() {
  cat <<'USAGE'
Usage:
  scripts/release/check-release-lineage-policy.sh --tag v0.3.0 --release-class rollout-candidate [options]

Options:
  --policy PATH              Release policy JSON. Default: config/faz22-6-endpoint-agent-release-policy.v1.json
  --tag TAG                  Clean trusted release tag, for example v0.3.0
  --release-class CLASS      Policy release class, for example rollout-candidate
  --previous-release TAG     Previous clean trusted release. Auto-detected from git tags when omitted.
  --source-commit SHA        Source commit for TAG. Auto-detected from git when omitted.
  --github-repo OWNER/REPO   Repository used for GitHub release/ruleset checks.
  --enforce-github-rules     Fail closed on GitHub release limits, tag rules, and existing release.
  --today YYYY-MM-DD         UTC day for release-count checks. Default: current UTC date.
  --emit-github-output PATH  Append resolved values to a GitHub Actions output file.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --policy)
      policy="${2:-}"; shift 2 ;;
    --tag)
      tag="${2:-}"; shift 2 ;;
    --release-class)
      release_class="${2:-}"; shift 2 ;;
    --previous-release)
      previous_release="${2:-}"; shift 2 ;;
    --source-commit)
      source_commit="${2:-}"; shift 2 ;;
    --github-repo)
      github_repo="${2:-}"; shift 2 ;;
    --enforce-github-rules)
      enforce_github_rules="true"; shift ;;
    --today)
      today="${2:-}"; shift 2 ;;
    --emit-github-output)
      emit_output="${2:-}"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      fail "unknown argument: $1" ;;
  esac
done

command -v jq >/dev/null 2>&1 || fail "jq is required"
command -v git >/dev/null 2>&1 || fail "git is required"
[ -f "$policy" ] || fail "release policy missing: $policy"

policy_status="$(jq -er '.status' "$policy")" || fail "policy status missing"
[ "$policy_status" = "active" ] || fail "release policy is not active: $policy_status"

[ -n "$tag" ] || fail "--tag is required"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || fail "trusted release tag must be clean vMAJOR.MINOR.PATCH: $tag"

if [ -z "$release_class" ]; then
  release_class="rollout-candidate"
fi
jq -e --arg rc "$release_class" '.release_train_policy.allowed_release_classes | index($rc) != null' "$policy" >/dev/null \
  || fail "release_class '$release_class' is not allowed by $policy"

github_required() {
  [ "$enforce_github_rules" = "true" ] || return 1
  command -v gh >/dev/null 2>&1 || fail "gh is required when --enforce-github-rules is set"
  [ -n "$github_repo" ] || fail "--github-repo or GITHUB_REPOSITORY is required when --enforce-github-rules is set"
  return 0
}

check_existing_release_absent() {
  github_required || return 0
  if gh release view "$tag" --repo "$github_repo" >/dev/null 2>&1; then
    fail "GitHub release $github_repo@$tag already exists; trusted release assets are immutable"
  fi
}

check_tag_protection() {
  local required="$1"
  [ "$required" = "true" ] || return 0
  if ! github_required; then
    notice "tag protection check not enforced outside GitHub release gate"
    return 0
  fi

  local rulesets_json legacy_json
  rulesets_json="$(gh api "/repos/$github_repo/rulesets" 2>/dev/null || true)"
  if printf '%s' "$rulesets_json" | jq -e '
      type == "array" and
      any(.[]; .target == "tag" and .enforcement == "active")
    ' >/dev/null 2>&1; then
    return 0
  fi

  legacy_json="$(gh api "/repos/$github_repo/tags/protection" 2>/dev/null || true)"
  if printf '%s' "$legacy_json" | jq -e 'type == "array" and length > 0' >/dev/null 2>&1; then
    return 0
  fi

  fail "require_tag_protection=true but no active tag ruleset or legacy protected tag pattern is visible for $github_repo"
}

daily_trusted_release_count="not_enforced"
check_daily_release_limit() {
  local max="$1"
  [[ "$max" =~ ^[0-9]+$ ]] || fail "max_trusted_releases_per_day is not numeric: $max"
  [ "$max" -gt 0 ] || return 0
  if ! github_required; then
    notice "daily trusted release limit not enforced outside GitHub release gate"
    return 0
  fi
  [[ "$today" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || fail "--today must be YYYY-MM-DD: $today"

  local releases_json
  releases_json="$(gh release list --repo "$github_repo" --limit 100 --json tagName,createdAt,isPrerelease)"
  daily_trusted_release_count="$(
    printf '%s' "$releases_json" \
      | jq -er --arg day "$today" --arg tag "$tag" '
          [
            .[]
            | select(.isPrerelease == false)
            | select(.tagName | test("^v[0-9]+\\.[0-9]+\\.[0-9]+$"))
            | select(.tagName != $tag)
            | select(.createdAt | startswith($day))
          ]
          | length
        '
  )"
  if [ "$daily_trusted_release_count" -ge "$max" ]; then
    fail "daily trusted release limit would be exceeded: existing=$daily_trusted_release_count max=$max day=$today"
  fi
}

frozen_minor="$(jq -er '.release_train_policy.frozen_minor' "$policy")"
next_trusted_minor="$(jq -er '.release_train_policy.next_trusted_minor' "$policy")"
case "$tag" in
  "$frozen_minor".*)
    fail "trusted release tag $tag is on frozen minor $frozen_minor; next trusted minor is $next_trusted_minor"
    ;;
esac
case "$tag" in
  "$next_trusted_minor".*) ;;
  *)
    fail "trusted release tag $tag is outside next_trusted_minor=$next_trusted_minor; update the policy before publishing a different minor"
    ;;
esac

if [ -z "$source_commit" ]; then
  source_commit="$(git rev-list -n1 "$tag" 2>/dev/null || true)"
fi
[ -n "$source_commit" ] || fail "could not resolve source_commit for $tag"
[[ "$source_commit" =~ ^[0-9a-fA-F]{40}$ ]] || fail "source_commit is not a 40-char git SHA: $source_commit"
source_commit="$(printf '%s' "$source_commit" | tr '[:upper:]' '[:lower:]')"

if git show-ref --verify --quiet refs/remotes/origin/main; then
  git merge-base --is-ancestor "$source_commit" origin/main \
    || fail "$tag source_commit $source_commit is not an ancestor of origin/main"
else
  notice "origin/main not present; skipping main-ancestor check in local policy guard"
fi

if [ -z "$previous_release" ]; then
  previous_release="$(
    git tag --list 'v*.*.*' \
      | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' \
      | grep -Fxv "$tag" \
      | sort -V \
      | awk -v target="$tag" '
          BEGIN { prev = "" }
          {
            all[++n] = $0
          }
          END {
            for (i = 1; i <= n; i++) {
              if (all[i] == target) {
                print prev
                exit
              }
              prev = all[i]
            }
            print prev
          }'
  )"
fi
[ -n "$previous_release" ] || fail "could not resolve previous_release before $tag"
[[ "$previous_release" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || fail "previous_release must be clean vMAJOR.MINOR.PATCH: $previous_release"
[ "$previous_release" != "$tag" ] || fail "previous_release cannot equal release tag: $tag"

frozen_series_regex="$(jq -er '.release_train_policy.frozen_train_evidence.series_regex' "$policy")"
frozen_window="$(jq -er '.release_train_policy.frozen_train_evidence.window' "$policy")"
frozen_minimum="$(jq -er '.release_train_policy.frozen_train_evidence.minimum' "$policy")"
[[ "$frozen_window" =~ ^[0-9]+$ ]] || fail "frozen_train_evidence.window is not numeric: $frozen_window"
[[ "$frozen_minimum" =~ ^[0-9]+$ ]] || fail "frozen_train_evidence.minimum is not numeric: $frozen_minimum"

frozen_train_evidence_count="$(
  git tag --list 'v*.*.*' \
    | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' \
    | grep -E "$frozen_series_regex" \
    | sort -V \
    | tail -n "$frozen_window" \
    | wc -l \
    | tr -d ' '
)"
[[ "$frozen_train_evidence_count" =~ ^[0-9]+$ ]] || fail "could not count frozen release train evidence tags"
if [ "$frozen_train_evidence_count" -lt "$frozen_minimum" ]; then
  fail "frozen train evidence guard failed: $frozen_train_evidence_count tags match $frozen_series_regex in last $frozen_window, minimum is $frozen_minimum"
fi

check_existing_release_absent
check_tag_protection "$(jq -er '.release_train_policy.require_tag_protection' "$policy")"
check_daily_release_limit "$(jq -er '.release_train_policy.max_trusted_releases_per_day' "$policy")"

if [ -n "$emit_output" ]; then
  {
    echo "release_class=$release_class"
    echo "previous_release=$previous_release"
    echo "source_commit=$source_commit"
    echo "frozen_train_evidence_count=$frozen_train_evidence_count"
    echo "daily_trusted_release_count=$daily_trusted_release_count"
  } >> "$emit_output"
fi

echo "release lineage policy pass:"
echo "  tag                  = $tag"
echo "  release_class        = $release_class"
echo "  source_commit        = $source_commit"
echo "  previous_release     = $previous_release"
echo "  frozen_train_matches = $frozen_train_evidence_count"
echo "  daily_trusted_count  = $daily_trusted_release_count"
