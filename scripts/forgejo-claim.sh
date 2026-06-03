#!/usr/bin/env bash
# Forgejo claim/release helper for Codex parallel instance safety.
# Operates on the tidefs repo via Forgejo API.
#
# Usage:
#   forgejo-claim.sh claim <issue_number>    Atomically claim an issue
#   forgejo-claim.sh release <issue_number>  Release a claimed issue
#   forgejo-claim.sh scan-stale [hours]      List/auto-release stale claims (default: 24h)
#   forgejo-claim.sh status <issue_number>   Show claim status of an issue
#   forgejo-claim.sh self-check              Validate current worktree claim
#
# Environment variables:
#   FORGEJO_URL       Forgejo base URL (default: http://localhost:3000)
#   FORGEJO_TOKEN     API token (required)
#   FORGEJO_REPO      Repo path as owner/repo (default: forgeadmin/tidefs)
#   WORKTREE_ROOT     Worktree root dir (default: $HOME/tidefs-worktrees)
#   FORGEJO_AUTO_RELEASE  If non-empty, scan-stale auto-releases (default: off)

set -euo pipefail

FORGEJO_URL="${FORGEJO_URL:-http://localhost:3000}"
FORGEJO_TOKEN="${FORGEJO_TOKEN:-}"
FORGEJO_REPO="${FORGEJO_REPO:-forgeadmin/tidefs}"
WORKTREE_ROOT="${WORKTREE_ROOT:-$HOME/tidefs-worktrees}"
FORGEJO_AUTO_RELEASE="${FORGEJO_AUTO_RELEASE:-}"

API_BASE="${FORGEJO_URL}/api/v1/repos/${FORGEJO_REPO}"
CURL_AUTH="Authorization: token ${FORGEJO_TOKEN}"
CT="Content-Type: application/json"

# Label IDs (discovered at startup, cached per session)
LABEL_READY_ID=""
LABEL_CLAIMED_ID=""
LABEL_NEEDS_REVIEW_ID=""

_init_labels() {
    if [ -n "$LABEL_READY_ID" ]; then return 0; fi
    local labels
    labels=$(curl -sf -H "$CURL_AUTH" "${API_BASE}/labels" 2>/dev/null) || {
        echo "ERROR: Failed to fetch labels from ${API_BASE}/labels" >&2
        exit 1
    }
    LABEL_READY_ID=$(echo "$labels" | python3 -c "
import json, sys
for l in json.load(sys.stdin):
    if l['name'] == 'codex:ready': print(l['id']); break
" 2>/dev/null)
    LABEL_CLAIMED_ID=$(echo "$labels" | python3 -c "
import json, sys
for l in json.load(sys.stdin):
    if l['name'] == 'codex:claimed': print(l['id']); break
" 2>/dev/null)
    LABEL_NEEDS_REVIEW_ID=$(echo "$labels" | python3 -c "
import json, sys
for l in json.load(sys.stdin):
    if l['name'] == 'codex:needs-review': print(l['id']); break
" 2>/dev/null)

    if [ -z "$LABEL_READY_ID" ] || [ -z "$LABEL_CLAIMED_ID" ]; then
        echo "ERROR: Could not find codex:ready or codex:claimed label" >&2
        exit 1
    fi
}

_get_issue() {
    local num="$1"
    curl -sf -H "$CURL_AUTH" "${API_BASE}/issues/${num}" 2>/dev/null
}

_get_issue_labels() {
    local num="$1"
    curl -sf -H "$CURL_AUTH" "${API_BASE}/issues/${num}/labels" 2>/dev/null
}

_has_label() {
    local num="$1" label_name="$2"
    _get_issue_labels "$num" | python3 -c "
import json, sys
for l in json.load(sys.stdin):
    if l['name'] == '$label_name':
        sys.exit(0)
sys.exit(1)
" 2>/dev/null
}

_add_label() {
    local num="$1" label_id="$2"
    curl -sf -X POST "${API_BASE}/issues/${num}/labels" \
        -H "$CURL_AUTH" -H "$CT" \
        -d "{\"labels\":[${label_id}]}" >/dev/null 2>&1
}

_remove_label() {
    local num="$1" label_id="$2"
    curl -sf -X DELETE "${API_BASE}/issues/${num}/labels/${label_id}" \
        -H "$CURL_AUTH" >/dev/null 2>&1
}

# Replace all labels atomically using PATCH on the issue
_set_labels() {
    local num="$1"
    shift
    local label_ids="$*"
    local label_array
    label_array=$(echo "$label_ids" | tr ' ' ',')
    local payload="{\"labels\":[${label_array}]}"
    curl -sf -X PATCH "${API_BASE}/issues/${num}" \
        -H "$CURL_AUTH" -H "$CT" -d "$payload" >/dev/null 2>&1
}

_get_current_labels() {
    local num="$1"
    _get_issue "$num" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(','.join(str(l['id']) for l in d['labels']))
" 2>/dev/null
}

_get_issue_updated_at() {
    local num="$1"
    _get_issue "$num" | python3 -c "
import json, sys
print(json.load(sys.stdin)['updated_at'])
" 2>/dev/null
}

_get_hours_since() {
    local iso_date="$1"
    python3 -c "
from datetime import datetime, timezone, timedelta
dt = datetime.fromisoformat('${iso_date}'.replace('Z','+00:00'))
now = datetime.now(timezone.utc)
delta = now - dt
print(int(delta.total_seconds() / 3600))
" 2>/dev/null
}

# ---------------------------------------------------------------------------
# claim <issue_number>
# Atomically add codex:claimed and remove codex:ready.
# Fails if the issue is already claimed or not in ready state.
# ---------------------------------------------------------------------------
cmd_claim() {
    local num="$1"
    _init_labels

    local issue_json
    issue_json=$(_get_issue "$num") || {
        echo "ERROR: Issue #${num} not found" >&2
        exit 1
    }

    local has_ready has_claimed
    has_ready=$(_has_label "$num" "codex:ready" && echo 1 || echo 0)
    has_claimed=$(_has_label "$num" "codex:claimed" && echo 1 || echo 0)

    if [ "$has_claimed" = "1" ]; then
        echo "CONFLICT: Issue #${num} is already claimed by another instance" >&2
        exit 2
    fi
    if [ "$has_ready" = "0" ]; then
        echo "CONFLICT: Issue #${num} is not in ready state (no codex:ready label)" >&2
        exit 2
    fi

    # Atomically: add claimed, remove ready using PATCH
    local current_ids
    current_ids=$(_get_current_labels "$num")
    local new_ids
    new_ids=$(echo "$current_ids" | tr ',' '\n' | grep -v "^${LABEL_READY_ID}$" | paste -sd, -)
    new_ids="${new_ids},${LABEL_CLAIMED_ID}"

    _set_labels "$num" "$new_ids" || {
        echo "ERROR: Failed to update labels for issue #${num}" >&2
        exit 1
    }

    if _has_label "$num" "codex:claimed"; then
        echo "CLAIMED: Issue #${num} is now claimed"
        return 0
    else
        echo "ERROR: Claim verification failed for issue #${num}" >&2
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# release <issue_number>
# Remove codex:claimed, add codex:ready.
# ---------------------------------------------------------------------------
cmd_release() {
    local num="$1"
    _init_labels

    local current_ids
    current_ids=$(_get_current_labels "$num")
    local new_ids
    new_ids=$(echo "$current_ids" | tr ',' '\n' | grep -v "^${LABEL_CLAIMED_ID}$" | paste -sd, -)
    new_ids="${new_ids},${LABEL_READY_ID}"

    _set_labels "$num" "$new_ids" || {
        echo "ERROR: Failed to update labels for issue #${num}" >&2
        exit 1
    }

    if _has_label "$num" "codex:ready"; then
        echo "RELEASED: Issue #${num} is now ready"
        return 0
    else
        echo "ERROR: Release verification failed for issue #${num}" >&2
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# scan-stale [timeout_hours]
# Lists issues with codex:claimed that are older than the timeout.
# With FORGEJO_AUTO_RELEASE=1, auto-releases stale claims.
# ---------------------------------------------------------------------------
cmd_scan_stale() {
    local timeout_hours="${1:-24}"
    _init_labels

    echo "# Scanning for stale claims (timeout: ${timeout_hours}h)..."

    local claim_list
    claim_list=$(curl -sf -H "$CURL_AUTH" \
        "${API_BASE}/issues?state=open&labels=${LABEL_CLAIMED_ID}" 2>/dev/null) || {
        echo "ERROR: Failed to list issues with codex:claimed" >&2
        exit 1
    }

    local count
    count=$(echo "$claim_list" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null)
    echo "# Found ${count} claimed issue(s)"

    if [ "$count" = "0" ]; then
        return 0
    fi

    echo "$claim_list" | python3 -c "
import json, sys
from datetime import datetime, timezone
issues = json.load(sys.stdin)
for i in issues:
    num = i['number']
    updated = i['updated_at']
    title = i['title']
    dt = datetime.fromisoformat(updated.replace('Z','+00:00'))
    now = datetime.now(timezone.utc)
    hours = int((now - dt).total_seconds() / 3600)
    print(f'{num}|{hours}|{title}')
" | while IFS='|' read -r num hours title; do
        if [ "$hours" -gt "$timeout_hours" ]; then
            echo "STALE: Issue #${num} claimed ${hours}h ago — \"${title}\""
            if [ -n "$FORGEJO_AUTO_RELEASE" ]; then
                echo "       Auto-releasing..."
                cmd_release "$num"
            fi
        else
            echo "OK:    Issue #${num} claimed ${hours}h ago — \"${title}\""
        fi
    done
}

# ---------------------------------------------------------------------------
# status <issue_number>
# Show current claim state + worktree mapping.
# ---------------------------------------------------------------------------
cmd_status() {
    local num="$1"
    _init_labels

    local issue_json
    issue_json=$(_get_issue "$num") || {
        echo "ERROR: Issue #${num} not found" >&2
        exit 1
    }

    echo "$issue_json" | python3 -c "
import json, sys
from datetime import datetime, timezone

d = json.load(sys.stdin)
labels = [l['name'] for l in d['labels']]
state = d['state']
title = d['title']
updated = d['updated_at']
created = d['created_at']

dt = datetime.fromisoformat(updated.replace('Z','+00:00'))
now = datetime.now(timezone.utc)
hours = int((now - dt).total_seconds() / 3600)

print(f'Issue #{d[\"number\"]}: {title}')
print(f'  State:   {state}')
print(f'  Labels:  {\", \".join(labels)}')
print(f'  Updated: {updated} ({hours}h ago)')
print(f'  Created: {created}')
"

    # Show worktree info
    local wt_glob="${WORKTREE_ROOT}/issue-${num}-"*
    if compgen -G "$wt_glob" >/dev/null 2>&1; then
        echo "  Worktrees:"
        for wt in $wt_glob; do
            if [ -d "$wt" ]; then
                local br
                br=$(cd "$wt" 2>/dev/null && git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
                echo "    $(basename "$wt") (branch: ${br})"
            fi
        done
    else
        echo "  Worktrees: none found"
    fi
}

# ---------------------------------------------------------------------------
# self-check
# Validate current worktree has a valid Forgejo claim.
# ---------------------------------------------------------------------------
cmd_self_check() {
    _init_labels

    local cwd
    cwd=$(pwd)

    # Detect issue number from cwd
    local issue_num
    issue_num=$(echo "$cwd" | grep -oP "(?<=${WORKTREE_ROOT}/issue-)\d+" || true)
    if [ -z "$issue_num" ]; then
        echo "FAIL: Not running in a tidefs worktree under ${WORKTREE_ROOT}" >&2
        echo "  Current dir: ${cwd}" >&2
        exit 1
    fi

    local wt_match="${WORKTREE_ROOT}/issue-${issue_num}-"*
    local wt_dir
    wt_dir=$(compgen -G "$wt_match" | head -1)
    if [ -z "$wt_dir" ] || [ ! -d "$wt_dir" ]; then
        echo "FAIL: Worktree directory issue-${issue_num}-* not found under ${WORKTREE_ROOT}" >&2
        exit 1
    fi

    # Check branch
    local expected_prefix="codex/issue-${issue_num}-"
    local actual_branch
    actual_branch=$(cd "$wt_dir" && git rev-parse --abbrev-ref HEAD 2>/dev/null) || {
        echo "FAIL: Could not determine branch in ${wt_dir}" >&2
        exit 1
    }

    if [[ "$actual_branch" != "${expected_prefix}"* ]]; then
        echo "FAIL: Branch mismatch" >&2
        echo "  Expected prefix: ${expected_prefix}" >&2
        echo "  Actual:          ${actual_branch}" >&2
        exit 1
    fi

    # Check Forgejo claim
    local has_claimed
    has_claimed=$(_has_label "$issue_num" "codex:claimed" && echo 1 || echo 0)
    if [ "$has_claimed" = "0" ]; then
        echo "FAIL: Issue #${issue_num} is not claimed on Forgejo (no codex:claimed label)" >&2
        exit 1
    fi

    echo "OK: Worktree $(basename "$wt_dir") has valid claim for issue #${issue_num} (branch: ${actual_branch})"
}

# ---------------------------------------------------------------------------
main() {
    if [ -z "$FORGEJO_TOKEN" ]; then
        echo "ERROR: FORGEJO_TOKEN is not set" >&2
        echo "  export FORGEJO_TOKEN='your-token'" >&2
        exit 1
    fi

    local cmd="${1:-}"
    shift || true

    case "$cmd" in
        claim)       cmd_claim "${1:?usage: forgejo-claim.sh claim <issue_number>}" ;;
        release)     cmd_release "${1:?usage: forgejo-claim.sh release <issue_number>}" ;;
        scan-stale|scan) cmd_scan_stale "${1:-24}" ;;
        status)      cmd_status "${1:?usage: forgejo-claim.sh status <issue_number>}" ;;
        self-check|check) cmd_self_check ;;
        *)
            echo "Usage: forgejo-claim.sh {claim|release|scan-stale|status|self-check} [args]" >&2
            exit 1
            ;;
    esac
}

main "$@"
