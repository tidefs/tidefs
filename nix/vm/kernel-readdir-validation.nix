# TideFS: retired kernel readdir validation wrapper.
#
# This app intentionally fails closed. The previous wrapper used lazy unmount
# and remount cycles while publishing readdir crash-consistency rows.
{
  pkgs,
  linuxKernel_7_0 ? null,
}:

pkgs.writeShellScriptBin "tidefs-kmod-readdir-validation" ''
  set -euo pipefail

  cat <<'EOF'
BLOCKED: kernel readdir validation wrapper retired.

Required replacement:
- Linux 7.0 QEMU guest with the real kmod-posix-vfs module loaded.
- Mounted getdents64/readdir helper coverage with cookie and pagination checks.
- Persistent backing storage across an actual hard reset/power-loss cycle before
  any crash-consistency row can pass.

Lazy unmount/remount rows are not crash validation.
EOF
  exit 1
''
