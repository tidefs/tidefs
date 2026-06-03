# TideFS: retired kernel lookup validation wrapper.
#
# This app intentionally fails closed. The previous wrapper used lazy unmount
# and remount cycles while publishing lookup crash-consistency rows.
{
  pkgs,
  linuxKernel_7_0 ? null,
}:

pkgs.writeShellScriptBin "tidefs-kmod-lookup-validation" ''
  set -euo pipefail

  cat <<'EOF'
BLOCKED: kernel lookup validation wrapper retired.

Required replacement:
- Linux 7.0 QEMU guest with the real kmod-posix-vfs module loaded.
- Mounted lookup/create/delete workload validation.
- Persistent backing storage across an actual hard reset/power-loss cycle before
  any crash-consistency row can pass.

Lazy unmount/remount rows are not crash validation.
EOF
  exit 1
''
