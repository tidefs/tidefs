# TideFS: retired kernel truncate/ftruncate validation wrapper.
#
# This app intentionally fails closed. The previous wrapper used dd/truncate to
# imitate ftruncate and lazy unmount/remount cycles while publishing crash rows.
{
  pkgs,
  linuxKernel_7_0 ? null,
}:

pkgs.writeShellScriptBin "tidefs-kmod-truncate-validation" ''
  set -euo pipefail

  cat <<'EOF'
BLOCKED: kernel truncate/ftruncate validation wrapper retired.

Required replacement:
- Linux 7.0 QEMU guest with the real kmod-posix-vfs module loaded.
- Guest helper coverage that calls truncate(2) and ftruncate(2) explicitly.
- Persistent backing storage across an actual hard reset/power-loss cycle before
  any crash-consistency row can pass.

dd/truncate substitutions and lazy unmount/remount rows are not production
validation.
EOF
  exit 1
''
