# TideFS: retired kernel performance-budget validation wrapper.
#
# This app intentionally fails closed. The previous wrapper mixed synthetic
# crash point labels with runtime/performance budget language.
{
  pkgs,
  linuxKernel_7_0 ? null,
}:

pkgs.writeShellScriptBin "tidefs-kmod-perf-budget-validation" ''
  set -euo pipefail

  cat <<'EOF'
BLOCKED: kernel performance-budget validation wrapper retired.

Required replacement:
- Linux 7.0 QEMU guest with the real product module loaded.
- Measured performance artifacts with workload envelope, comparator,
  environment profile, KPI vector, and noise policy.
- Persistent backing storage across an actual hard reset/power-loss cycle before
  any crash/recovery budget row can pass.

Synthetic crash-point labels are not production performance validation.
EOF
  exit 1
''
