# TideFS: retired kernel link crash-validation wrapper.
#
# This app intentionally fails closed. The previous wrapper used lazy unmount
# and remount cycles while publishing link crash-consistency rows.
{
  pkgs,
  linuxKernel_7_0 ? null,
}:

pkgs.writeShellScriptBin "tidefs-kmod-link-crash-validation" ''
  set -euo pipefail

  cat <<'EOF'
BLOCKED: kernel link crash-validation wrapper retired.

Required replacement:
- Linux 7.0 QEMU guest with the real kmod-posix-vfs module loaded.
- Link/unlink workload execution against the mounted kernel filesystem.
- Persistent backing storage across an actual hard reset/power-loss cycle before
  any crash-consistency row can pass.

Lazy unmount/remount rows are not crash validation.
EOF
  exit 1
''
