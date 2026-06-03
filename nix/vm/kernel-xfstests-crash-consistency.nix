# TideFS: retired kernel xfstests crash-consistency wrapper.
#
# This app intentionally fails closed. The previous wrapper used two initrd
# boots but did not preserve a real guest block device across the boot boundary,
# so it could not prove mounted-kernel crash recovery.
{
  pkgs,
  linuxKernel_7_0 ? null,
}:

pkgs.writeShellScriptBin "tidefs-kernel-xfstests-crash-consistency" ''
  set -euo pipefail

  cat <<'EOF'
BLOCKED: kernel xfstests crash-consistency wrapper retired.

Required replacement:
- Linux 7.0 QEMU guest with the real kmod-posix-vfs module loaded.
- xfstests or xfstests-grade workload against the mounted product filesystem.
- Persistent guest block storage carried across an actual hard reset/power-loss
  cycle before any crash-consistency row can pass.
- Current-head phase logs and environment disclosures.

Two initrd boots without persistent guest media are not crash validation.
EOF
  exit 1
''
