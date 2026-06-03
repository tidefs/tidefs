#!/usr/bin/env bash
# TideFS QEMU artifact cleanup helper.
# Removes common QEMU runtime artifacts that may leak into the repository
# working tree: disk images, pid files, socket files, and temp directories.
#
# Safe to run manually or from validation scripts. Non-destructive of
# validation output written under /root/ai/tmp/tidefs-validation/ and scripts/ themselves.

set -euo pipefail

repo_root="${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
cd "$repo_root"

cleaned=0
skipped=0

cleanup_pattern() {
  local pattern="$1" label="$2"
  local count=0
  while IFS= read -r -d '' f; do
    # Skip validation output and our own scripts directory
    case "$f" in
      *//root/ai/tmp/tidefs-validation/*) skipped=$((skipped + 1)); continue ;;
      */scripts/*)        skipped=$((skipped + 1)); continue ;;
    esac
    rm -f "$f"
    count=$((count + 1))
  done < <(find . -name "$pattern" -not -path './.git/*' -print0 2>/dev/null || true)
  if [ "$count" -gt 0 ]; then
    printf 'cleaned %d %s file(s)\n' "$count" "$label"
    cleaned=$((cleaned + count))
  fi
}

printf '=== TideFS QEMU artifact cleanup ===\n'
printf 'repo_root: %s\n' "$repo_root"

cleanup_pattern '*.qcow2'  'QEMU disk image'
cleanup_pattern 'qemu.pid' 'QEMU pid'
cleanup_pattern 'qemu.sock' 'QEMU socket'
cleanup_pattern 'nohup.out' 'nohup output'

printf 'done: %d files cleaned, %d skipped (under /root/ai/tmp/tidefs-validation/ or scripts/)\n' "$cleaned" "$skipped"
