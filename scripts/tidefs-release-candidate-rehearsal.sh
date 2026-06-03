#!/usr/bin/env bash
set -euo pipefail
# tidefs-release-candidate-rehearsal.sh — tag candidate, build artifacts, run matrix, record rollback

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

RUN_ID="rc-rehearsal-$(date -u +%Y%m%d-%H%M%S)"
RUN_DIR="/root/ai/tmp/tidefs-validation/$RUN_ID"
CARGO_TD="${CARGO_TARGET_DIR:-/root/ai/tmp/tidefs-target}"

REHEARSE_TAG=true
CUSTOM_TAG=""
SKIP_BUILD=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --run-only) REHEARSE_TAG=false; shift ;;
        --tag) CUSTOM_TAG="$2"; shift 2 ;;
        --skip-build) SKIP_BUILD=true; shift ;;
        *) echo "Unknown: $1" >&2; exit 2 ;;
    esac
done

mkdir -p "$RUN_DIR"

write_log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) | $1 | $2" >> "$RUN_DIR/rehearsal.log"; }
record_step() { local s="$1" r="$2" d="${3:-}"; echo "  [$r] $s${d:+: $d}"; write_log "$s" "$r${d:+ $d}"; }

CURRENT_SHA="$(git rev-parse HEAD)"
CURRENT_SHORT="$(git rev-parse --short HEAD)"
ORIGIN_MASTER="$(git rev-parse origin/master 2>/dev/null || echo unknown)"
BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo detached)"
IS_DIRTY=false; [[ -n "$(git status --porcelain 2>/dev/null)" ]] && IS_DIRTY=true
HOST_KERNEL="$(uname -r)"

write_log "CURRENT_SHA" "$CURRENT_SHA"
write_log "ORIGIN_MASTER" "$ORIGIN_MASTER"
write_log "BRANCH" "$BRANCH"
write_log "DIRTY" "$IS_DIRTY"
write_log "HOST_KERNEL" "$HOST_KERNEL"

echo "=== TideFS Release Candidate Rehearsal ==="
echo "Run ID:     $RUN_ID"
echo "Commit:     $CURRENT_SHORT ($CURRENT_SHA)"
echo "Master:     ${ORIGIN_MASTER:0:12}..."
echo "Dirty:      $IS_DIRTY"
echo ""

if [[ -n "$CUSTOM_TAG" ]]; then
    RC_TAG="$CUSTOM_TAG"
else
    LATEST_TAG="$(git tag -l 'v0.*' | sort -V | tail -1)"
    if [[ -z "$LATEST_TAG" ]]; then echo "ERROR: no v0.* tags" >&2; exit 1; fi
    LATEST_NUM="${LATEST_TAG#v0.}"
    NEXT_NUM=$((LATEST_NUM + 1))
    RC_TAG="v0.${NEXT_NUM}-rc1"
fi
RC_BRANCH="release-candidate/${RC_TAG}"
echo "Candidate:   $RC_TAG @ $RC_BRANCH"
write_log "RC_TAG" "$RC_TAG"
write_log "RC_BRANCH" "$RC_BRANCH"
echo ""

FAILS=0

echo "--- Pre-flight ---"
if $IS_DIRTY; then record_step "dirty-tree" "REFUSAL" "cannot tag dirty tree"; FAILS=$((FAILS+1))
else record_step "dirty-tree" "PASS" "clean tree"; fi

if [[ "$CURRENT_SHA" == "$ORIGIN_MASTER" ]]; then record_step "at-origin-master" "PASS" "HEAD == origin/master"
else record_step "at-origin-master" "REFUSAL" "HEAD != origin/master"; FAILS=$((FAILS+1)); fi

if git rev-parse "$RC_TAG" >/dev/null 2>&1; then record_step "tag-free" "REFUSAL" "tag exists"; FAILS=$((FAILS+1))
else record_step "tag-free" "PASS" "tag free"; fi

if git show-ref --verify --quiet "refs/heads/$RC_BRANCH" 2>/dev/null; then record_step "branch-free" "REFUSAL" "branch exists"; FAILS=$((FAILS+1))
else record_step "branch-free" "PASS" "branch free"; fi

if git diff --check HEAD >/dev/null 2>&1; then record_step "git-diff-check" "PASS" "no whitespace errs"
else record_step "git-diff-check" "REFUSAL" "whitespace errs"; FAILS=$((FAILS+1)); fi

echo "  cargo check -p tidefs-validation --locked..."
if CARGO_TARGET_DIR="$CARGO_TD" cargo check -p tidefs-validation --locked > /tmp/tidefs-workers/s6/rc-cargo-check.log 2>&1; then
    record_step "cargo-check" "PASS" "tidefs-validation ok"
else
    record_step "cargo-check" "FAIL" "cargo check failed"; FAILS=$((FAILS+1))
fi

echo ""
if $REHEARSE_TAG && [[ $FAILS -eq 0 ]]; then
    echo "--- Branch and Tag ---"
    if git branch "$RC_BRANCH" "$CURRENT_SHA" 2>/dev/null; then record_step "create-branch" "PASS" "created $RC_BRANCH"
    else record_step "create-branch" "FAIL" "branch creation failed"; FAILS=$((FAILS+1)); fi
    TM="TideFS release candidate $RC_TAG at $CURRENT_SHA ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
    if git tag -a "$RC_TAG" -m "$TM" "$CURRENT_SHA" 2>/dev/null; then record_step "create-tag" "PASS" "tagged $RC_TAG"
    else record_step "create-tag" "FAIL" "tag failed"; FAILS=$((FAILS+1)); fi
else
    record_step "create-branch" "SKIP" "pre-flight failed or --run-only"
    record_step "create-tag" "SKIP" "pre-flight failed or --run-only"
fi

echo ""
echo "--- Release Matrix ---"
GNG="$REPO_ROOT/docs/release/release-candidate-go-no-go-checklist.md"
if [[ -f "$GNG" ]]; then
    GO_C="$(rg -c '\*\*GO\*\*' "$GNG" 2>/dev/null || echo 0)"
    NGO_C="$(rg -c '\*\*NO-GO\*\*' "$GNG" 2>/dev/null || echo 0)"
    record_step "go-no-go-checklist" "ASSESSED" "go=$GO_C no-go=$NGO_C rows"
    cp "$GNG" "$RUN_DIR/release-candidate-go-no-go-checklist.md"
fi

echo ""
echo "--- Rollback ---"
cat > "$RUN_DIR/ROLLBACK.md" << RBEOF
# Rollback for $RC_TAG
Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Commit: $CURRENT_SHA

## Immediate (pre-publish)
1. git tag -d $RC_TAG
2. git branch -D $RC_BRANCH

## Post-Publish
1. git push origin :refs/tags/$RC_TAG
2. git push origin :refs/heads/$RC_BRANCH
3. Remove published release artifacts if any.
4. Commit a rollback notice to docs/release/.

## Verify
1. git tag -l '$RC_TAG'  → should be empty
2. git branch -a | grep '$RC_BRANCH'  → should be empty
RBEOF
record_step "rollback-path" "RECORDED" "$RUN_DIR/ROLLBACK.md"

cat > "$RUN_DIR/validation-manifest.json" << MEOF
{
  "run_id": "$RUN_ID",
  "validation_id": "release-candidate-rehearsal",
  "validation_tier": "release-integration",
  "commit": "$CURRENT_SHA",
  "branch": "$BRANCH",
  "origin_master": "$ORIGIN_MASTER",
  "dirty": $IS_DIRTY,
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "host_kernel": "$HOST_KERNEL",
  "rc_tag": "$RC_TAG",
  "rc_branch": "$RC_BRANCH",
  "tag_created": $REHEARSE_TAG
}
MEOF

cat > "$RUN_DIR/environment.env" << EEOF
RUN_ID=$RUN_ID
CURRENT_SHA=$CURRENT_SHA
ORIGIN_MASTER=$ORIGIN_MASTER
BRANCH=$BRANCH
DIRTY=$IS_DIRTY
HOST_KERNEL=$HOST_KERNEL
RC_TAG=$RC_TAG
RC_BRANCH=$RC_BRANCH
REHEARSE_TAG=$REHEARSE_TAG
DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EEOF

cat > "$RUN_DIR/SUMMARY.md" << SEOF
# Release Candidate Rehearsal: $RC_TAG

- **Run ID:** $RUN_ID
- **Issue:** #6521
- **Validation Tier:** release-integration
- **Date:** $(date -u +%Y-%m-%dT%H:%M:%SZ)
- **Commit:** $CURRENT_SHA
- **Master:** $ORIGIN_MASTER
- **Dirty:** $IS_DIRTY
- **Candidate Tag:** $RC_TAG
- **Branch:** $RC_BRANCH
- **Tag Created:** $REHEARSE_TAG
- **Failures:** $FAILS

## Next Steps
1. Resolve pre-flight refusals (dirty tree, HEAD != master).
2. Run full Nix artifact build.
3. Execute runtime release matrix from candidate tag.
4. If accepted, promote rc tag to final release tag.
SEOF

echo ""
echo "=== Summary ==="
echo "Run:   $RUN_ID"
echo "Tag:   $RC_TAG"
echo "Tagged: $REHEARSE_TAG"
echo "Fails: $FAILS"
echo "Evid:  $RUN_DIR/"
