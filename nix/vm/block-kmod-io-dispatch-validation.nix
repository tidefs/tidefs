# TideFS: retired block-kmod I/O dispatch validation wrapper.
#
# This app intentionally fails closed. The previous wrapper mixed real module
# load/read/write smoke with dd/sync "flush", dd "barrier", and module-unload
# "crash" rows. Those rows are not release validation for block I/O ordering or
# crash consistency.
{
  pkgs,
  linuxKernel_7_0 ? null,
}:

pkgs.writeShellScriptBin "tidefs-block-kmod-io-dispatch-validation" ''
  set -euo pipefail

  cat <<'EOF'
BLOCKED: block-kmod I/O dispatch validation wrapper retired.

Required replacement:
- Linux 7.0 QEMU guest with the real tidefs-block-kmod module loaded.
- Real request-queue validation for read, write, flush/FUA, discard, and barriers.
- Persistent backing storage across an actual hard reset/power-loss cycle before
  any crash-consistency row can pass.
- Current-head logs only when the validation comes from that runtime path.

dd/sync/module-unload rows are not production validation.
EOF
  exit 1
''
