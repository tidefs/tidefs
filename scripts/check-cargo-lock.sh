#!/usr/bin/env bash
# check-cargo-lock.sh: detect stale Cargo.lock before it blocks --locked builds.
# Exit 0 when Cargo.lock is consistent with workspace manifests,
# exit 1 with a diagnostic when it's stale.
set -euo pipefail

WS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOCKFILE="$WS_ROOT/Cargo.lock"

if ! [ -f "$LOCKFILE" ]; then
  echo "ERROR: Cargo.lock not found at $LOCKFILE" >&2
  exit 2
fi

# Find all Cargo.toml files excluding target/ directories
mapfile -t toml_files < <(find "$WS_ROOT" -name Cargo.toml -not -path '*/target/*' 2>/dev/null)

# Find the newest Cargo.toml mtime
newest_toml_mtime=0
newest_toml=""
for f in "${toml_files[@]}"; do
  mtime=$(stat -c %Y "$f" 2>/dev/null || echo 0)
  if [ "$mtime" -gt "$newest_toml_mtime" ]; then
    newest_toml_mtime=$mtime
    newest_toml="$f"
  fi
done

lock_mtime=$(stat -c %Y "$LOCKFILE" 2>/dev/null || echo 0)

if [ "$newest_toml_mtime" -gt "$lock_mtime" ]; then
  echo "ERROR: Cargo.lock is stale (older than workspace Cargo.toml manifests)." >&2
  echo "  Newest Cargo.toml: $newest_toml" >&2
  echo "  Cargo.lock:        $LOCKFILE" >&2
  echo "" >&2
  echo "To fix: run 'cargo generate-lockfile' or 'cargo update' in the workspace root." >&2
  exit 1
fi

echo "Cargo.lock is current (newest manifest: $newest_toml)."
exit 0
