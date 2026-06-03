# TideFS: retired kernel statfs validation wrapper.
#
# This app intentionally fails closed. The previous wrapper labelled
# unmount/remount persistence as statfs crash-consistency validation.
{
  pkgs,
  linuxKernel_7_0 ? null,
}:

pkgs.writeShellScriptBin "tidefs-kmod-statfs-validation" ''
  set -euo pipefail

  cat <<'EOF'
BLOCKED: kernel statfs validation wrapper retired.

Required replacement:
- Linux 7.0 QEMU guest with the real kmod-posix-vfs module loaded.
- Guest helper coverage for statfs(2), fstatfs(2), statvfs(2), and fstatvfs(2).
- Persistent backing storage across an actual hard reset/power-loss cycle before
  any crash-consistency row can pass.

Clean unmount/remount rows are not crash validation.
EOF
  exit 1
''
