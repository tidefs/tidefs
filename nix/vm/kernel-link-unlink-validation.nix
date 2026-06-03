# TideFS: retired kernel link/unlink validation wrapper.
#
# This app intentionally fails closed. The previous wrapper mixed mounted
# link/unlink smoke with lazy unmount/remount crash labels.
{
  pkgs,
  linuxKernel_7_0 ? null,
}:

pkgs.writeShellScriptBin "tidefs-kmod-link-unlink-validation" ''
  set -euo pipefail

  cat <<'EOF'
BLOCKED: kernel link/unlink validation wrapper retired.

Required replacement:
- Linux 7.0 QEMU guest with the real kmod-posix-vfs module loaded.
- Mounted link/unlink behavior separated from crash-consistency validation.
- Persistent backing storage across an actual hard reset/power-loss cycle before
  any crash-consistency row can pass.

Lazy unmount/remount rows are not crash validation.
EOF
  exit 1
''
