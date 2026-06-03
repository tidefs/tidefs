# TideFS: retired kernel mkdir/rmdir validation wrapper.
#
# This app intentionally fails closed. The previous wrapper published
# crash/concurrency-sounding rows from single-process shell operations.
{
  pkgs,
  linuxKernel_7_0 ? null,
}:

pkgs.writeShellScriptBin "tidefs-kmod-mkdir-rmdir-validation" ''
  set -euo pipefail

  cat <<'EOF'
BLOCKED: kernel mkdir/rmdir validation wrapper retired.

Required replacement:
- Linux 7.0 QEMU guest with the real kmod-posix-vfs module loaded.
- Mounted mkdir/rmdir behavior separated from concurrent and crash validation.
- Real concurrent helper coverage for concurrency claims.
- Persistent backing storage across an actual hard reset/power-loss cycle before
  any crash-consistency row can pass.

Sequential shell collision rows are not concurrent release validation.
EOF
  exit 1
''
