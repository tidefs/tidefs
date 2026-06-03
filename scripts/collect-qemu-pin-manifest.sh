#!/usr/bin/env bash
# Collect a QEMU pin manifest for reproducible validation runs.
#
# Usage:
#   collect-qemu-pin-manifest.sh \
#     --validation-id fuse-fsx-mmap \
#     --kernel /nix/store/...-linux-7.0/bzImage \
#     --initrd /tmp/initrd.img \
#     --output /root/ai/tmp/tidefs-validation/my-run/qemu-pin-manifest.json \
#     [--disk-image /tmp/disk.qcow2] \
#     [--flake-lock ./flake.lock] \
#     [--rebuild-recipe "nix build .#target -L"] \
#     [--nix-derivation /nix/store/...-kernel] \
#     [--commit abc123]
#
# Falls back to using the tidefs-xtask binary from the workspace build,
# or from the Nix package.  If neither is available, emits a minimal
# hand-rolled pin manifest JSON using sha256sum.

set -euo pipefail

VALIDATION_ID=""
KERNEL=""
INITRD=""
DISK_IMAGE=""
FLAKE_LOCK=""
REBUILD_RECIPE=""
OUTPUT=""
COMMIT=""
NIX_DERIVATIONS=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --validation-id) VALIDATION_ID="$2"; shift 2 ;;
    --kernel) KERNEL="$2"; shift 2 ;;
    --initrd) INITRD="$2"; shift 2 ;;
    --disk-image) DISK_IMAGE="$2"; shift 2 ;;
    --flake-lock) FLAKE_LOCK="$2"; shift 2 ;;
    --rebuild-recipe) REBUILD_RECIPE="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    --commit) COMMIT="$2"; shift 2 ;;
    --nix-derivation) NIX_DERIVATIONS+=("$2"); shift 2 ;;
    *) echo "ERROR: unknown option: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$VALIDATION_ID" ] || [ -z "$KERNEL" ] || [ -z "$INITRD" ] || [ -z "$OUTPUT" ]; then
  echo "ERROR: --validation-id, --kernel, --initrd, and --output are required" >&2
  exit 2
fi

# Resolve commit SHA if not provided.
if [ -z "$COMMIT" ]; then
  COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
fi

# Resolve flake.lock if not provided.
if [ -z "$FLAKE_LOCK" ]; then
  for candidate in "./flake.lock" "../flake.lock" "../../flake.lock"; do
    if [ -f "$candidate" ]; then
      FLAKE_LOCK="$candidate"
      break
    fi
  done
fi

# Rebuild recipe default.
if [ -z "$REBUILD_RECIPE" ]; then
  REBUILD_RECIPE="nix build .#packages.x86_64-linux.<target> -L"
fi

mkdir -p "$(dirname "$OUTPUT")"

# Try the xtask binary first.
XTAST_BIN=""
for candidate in \
  "${TIDEFS_PACKAGE:-}/bin/tidefs-xtask" \
  "./result/bin/tidefs-xtask" \
  "$(dirname "$0")/../result/bin/tidefs-xtask" \
  "tidefs-xtask"; do
  if [ -x "$candidate" ] || command -v "$candidate" >/dev/null 2>&1; then
    XTAST_BIN="$candidate"
    break
  fi
done

if [ -n "$XTAST_BIN" ] && [ -f "$FLAKE_LOCK" ]; then
  echo "Using tidefs-xtask to collect pin manifest..."
  XTAST_ARGS=(
    --validation-id "$VALIDATION_ID"
    --kernel "$KERNEL"
    --initrd "$INITRD"
    --flake-lock "$FLAKE_LOCK"
    --rebuild-recipe "$REBUILD_RECIPE"
    --output "$OUTPUT"
    --commit "$COMMIT"
  )
  [ -n "$DISK_IMAGE" ] && XTAST_ARGS+=(--disk-image "$DISK_IMAGE")
  for nd in "${NIX_DERIVATIONS[@]}"; do
    XTAST_ARGS+=(--nix-derivation "$nd")
  done

  if "$XTAST_BIN" collect-qemu-pin-manifest "${XTAST_ARGS[@]}" 2>/dev/null; then
    echo "Pin manifest collected via xtask: $OUTPUT"
    exit 0
  fi
  echo "xtask collection failed; falling back to basic pin manifest."
fi

# Fallback: produce a hand-rolled minimal pin manifest JSON.
KERNEL_SHA256=$(sha256sum "$KERNEL" 2>/dev/null | cut -d' ' -f1 || echo "unknown")
INITRD_SHA256=$(sha256sum "$INITRD" 2>/dev/null | cut -d' ' -f1 || echo "unknown")
KERNEL_SIZE=$(stat -c%s "$KERNEL" 2>/dev/null || echo 0)
INITRD_SIZE=$(stat -c%s "$INITRD" 2>/dev/null || echo 0)

DISK_JSON=""
if [ -n "$DISK_IMAGE" ] && [ -f "$DISK_IMAGE" ]; then
  DISK_SHA256=$(sha256sum "$DISK_IMAGE" 2>/dev/null | cut -d' ' -f1 || echo "unknown")
  DISK_SIZE=$(stat -c%s "$DISK_IMAGE" 2>/dev/null || echo 0)
  DISK_JSON=$(printf '"disk_image": {"path": "%s", "sha256": "%s", "size_bytes": %s, "label": "disk_image"},' "$DISK_IMAGE" "$DISK_SHA256" "$DISK_SIZE")
fi

FLAKE_JSON="{}"
if [ -f "$FLAKE_LOCK" ]; then
  FLAKE_JSON=$(cat "$FLAKE_LOCK" 2>/dev/null || echo "{}")
fi

NIX_DERIV_JSON="[]"
if [ ${#NIX_DERIVATIONS[@]} -gt 0 ]; then
  NIX_DERIV_JSON=$(printf '"%s",' "${NIX_DERIVATIONS[@]}" | sed 's/,$//')
  NIX_DERIV_JSON="[$NIX_DERIV_JSON]"
fi

COLLECTED_AT=$(date -u +%s 2>/dev/null || echo 0)

cat > "$OUTPUT" << JSONEOF
{
  "validation_id": "$VALIDATION_ID",
  "commit": "$COMMIT",
  "collected_at": $COLLECTED_AT,
  "kernel": {
    "path": "$KERNEL",
    "sha256": "$KERNEL_SHA256",
    "size_bytes": $KERNEL_SIZE,
    "label": "kernel"
  },
  "initrd": {
    "path": "$INITRD",
    "sha256": "$INITRD_SHA256",
    "size_bytes": $INITRD_SIZE,
    "label": "initrd"
  },
  $DISK_JSON
  "nix_flake_lock": $FLAKE_JSON,
  "nix_store_derivations": $NIX_DERIV_JSON,
  "rebuild_recipe": "$REBUILD_RECIPE"
}
JSONEOF

echo "Pin manifest collected (fallback): $OUTPUT"
