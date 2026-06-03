# TideFS: retired kernel pool-import validation wrapper.
#
# This app intentionally fails closed. The previous wrapper used a regular file
# as a simulated block device and labelled lazy unmount/remount cycles as pool
# import crash points.
{
  pkgs,
  linuxKernel_7_0 ? null,
}:

pkgs.writeShellScriptBin "tidefs-kmod-pool-import-validation" ''
  set -euo pipefail

  cat <<'EOF'
BLOCKED: kernel pool-import validation wrapper retired.

Required replacement:
- Linux 7.0 QEMU guest with the real kmod-posix-vfs module loaded.
- Real pool media attached as persistent guest storage.
- Device scan, label read, root select, intent replay, and mount commit
  validationd from the product import path.
- Actual hard reset/power-loss cycles before any crash row can pass.

Regular-file backing and lazy unmount/remount rows are not pool-import crash
validation.
EOF
  exit 1
''
