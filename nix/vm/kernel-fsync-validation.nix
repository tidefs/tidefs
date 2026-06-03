# TideFS: retired kernel fsync validation wrapper.
#
# This app intentionally fails closed. The previous wrapper labelled clean
# unmount/remount persistence as crash-consistency validation.
{
  pkgs,
  linuxKernel_7_0 ? null,
}:

pkgs.writeShellScriptBin "tidefs-kmod-fsync-validation" ''
  set -euo pipefail

  cat <<'EOF'
BLOCKED: kernel fsync validation wrapper retired.

Required replacement:
- Linux 7.0 QEMU guest with the real kmod-posix-vfs module loaded.
- A guest helper that calls fsync(2), fdatasync(2), and syncfs(2) explicitly.
- Persistent backing storage across an actual hard reset/power-loss cycle before
  any crash-consistency row can pass.

Clean unmount/remount rows are not crash validation.
EOF
  exit 1
''
