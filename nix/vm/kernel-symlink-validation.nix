# TideFS: retired kernel symlink/readlink validation wrapper.
#
# This app intentionally fails closed. The previous wrapper used lazy unmount
# and remount cycles while publishing symlink crash-consistency rows.
{
  pkgs,
  linuxKernel_7_0 ? null,
}:

pkgs.writeShellScriptBin "tidefs-kmod-symlink-validation" ''
  set -euo pipefail

  cat <<'EOF'
BLOCKED: kernel symlink/readlink validation wrapper retired.

Required replacement:
- Linux 7.0 QEMU guest with the real kmod-posix-vfs module loaded.
- Mounted symlink/readlink helper coverage.
- Persistent backing storage across an actual hard reset/power-loss cycle before
  any crash-consistency row can pass.

Lazy unmount/remount rows are not crash validation.
EOF
  exit 1
''
