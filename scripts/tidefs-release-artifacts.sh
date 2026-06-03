#!/usr/bin/env bash
# TideFS release artifact packaging and checksum generation.
#
# Builds the workspace, produces SHA256 checksums for every built binary,
# and emits a release-manifest.json that links artifacts to the source commit.
#
# Usage:
#   scripts/tidefs-release-artifacts.sh [--out-dir <path>] [--tarball]
#
# Options:
#   --out-dir DIR   Write artifacts and manifest to DIR (default: /tmp/tidefs-release-<version>)
#   --tarball       Create a compressed tarball of the output directory
#   --help          Show this message
#
# Exit codes:
#   0  success
#   1  build or packaging error
#   2  missing dependency

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR=""
DO_TARBALL=false

usage() {
  head -15 "$0" | sed -n 's/^# //p'
  exit 0
}

# --- argument parsing ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --tarball) DO_TARBALL=true; shift ;;
    --help|-h) usage ;;
    *) echo "ERROR: unknown option: $1" >&2; usage ;;
  esac
done

# --- resolve version from Cargo.toml ---
CARGO_TOML="$REPO_ROOT/Cargo.toml"
if ! VERSION=$(sed -n 's/^version *= *"\(.*\)"/\1/p' "$CARGO_TOML" | head -1); then
  echo "ERROR: cannot read version from $CARGO_TOML" >&2
  exit 1
fi
if [[ -z "$VERSION" ]]; then
  echo "ERROR: empty version in $CARGO_TOML" >&2
  exit 1
fi

# --- resolve git commit ---
GIT_COMMIT=$(cd "$REPO_ROOT" && git rev-parse HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH=$(cd "$REPO_ROOT" && git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
GIT_DIRTY=false
if cd "$REPO_ROOT" && ! git diff-index --quiet HEAD -- 2>/dev/null; then
  GIT_DIRTY=true
fi

# --- set up output directory ---
if [[ -z "$OUT_DIR" ]]; then
  OUT_DIR="/tmp/tidefs-release-$VERSION"
fi
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/bin"

BUILD_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "=== TideFS Release Artifacts ==="
echo "  version:       $VERSION"
echo "  commit:        $GIT_COMMIT"
echo "  branch:        $GIT_BRANCH"
echo "  dirty:         $GIT_DIRTY"
echo "  timestamp:     $BUILD_TIMESTAMP"
echo "  output dir:    $OUT_DIR"
echo ""

# --- build workspace via Nix ---
echo "--- Building workspace via nix build .#default ---"
NIX_RESULT=$(cd "$REPO_ROOT" && nix build --no-link --print-out-paths .#default 2>&1) || {
  echo "ERROR: nix build .#default failed" >&2
  echo "$NIX_RESULT" >&2
  exit 1
}
NIX_OUT=$(echo "$NIX_RESULT" | tail -1)
if [[ ! -d "$NIX_OUT/bin" ]]; then
  echo "ERROR: nix build succeeded but no bin/ directory at $NIX_OUT" >&2
  exit 1
fi
echo "  nix store path: $NIX_OUT"

# --- collect binaries and compute checksums ---
CHECKSUMS=()
shopt -s nullglob
for bin_path in "$NIX_OUT/bin/"*; do
  bin_name=$(basename "$bin_path")
  # skip non-regular files
  if [[ ! -f "$bin_path" ]]; then continue; fi

  sha256=$(sha256sum "$bin_path" | awk '{print $1}')
  size_bytes=$(stat -c%s "$bin_path" 2>/dev/null || stat -f%z "$bin_path" 2>/dev/null)

  # Copy binary into output dir for packaging
  cp "$bin_path" "$OUT_DIR/bin/$bin_name"

  CHECKSUMS+=("{\"name\":\"$bin_name\",\"sha256\":\"$sha256\",\"size_bytes\":$size_bytes}")
  echo "  $bin_name  sha256=$sha256  size=$size_bytes"
done

if [[ ${#CHECKSUMS[@]} -eq 0 ]]; then
  echo "ERROR: no binaries found in $NIX_OUT/bin/" >&2
  exit 1
fi

# --- build checksums JSON array ---
CHECKSUM_JSON="["
for i in "${!CHECKSUMS[@]}"; do
  if [[ $i -gt 0 ]]; then CHECKSUM_JSON+=","; fi
  CHECKSUM_JSON+="${CHECKSUMS[$i]}"
done
CHECKSUM_JSON+="]"

# --- write release manifest ---
MANIFEST_PATH="$OUT_DIR/release-manifest.json"
cat > "$MANIFEST_PATH" <<MANIFEST
{
  "tidefs_version": "$VERSION",
  "git_commit": "$GIT_COMMIT",
  "git_branch": "$GIT_BRANCH",
  "git_dirty": $GIT_DIRTY,
  "build_timestamp": "$BUILD_TIMESTAMP",
  "nix_store_path": "$NIX_OUT",
  "binaries": $CHECKSUM_JSON
}
MANIFEST

echo ""
echo "--- Release manifest written to $MANIFEST_PATH ---"

# --- optional tarball ---
if $DO_TARBALL; then
  TARBALL_NAME="tidefs-$VERSION-$(echo "$GIT_COMMIT" | head -c 12).tar.gz"
  TARBALL_PATH="/tmp/$TARBALL_NAME"
  tar -czf "$TARBALL_PATH" -C "$(dirname "$OUT_DIR")" "$(basename "$OUT_DIR")"
  echo "--- Tarball written to $TARBALL_PATH ---"
fi

echo ""
echo "=== Done ==="
