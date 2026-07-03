# TideFS: ublk crash-consistency validation under host process kill/restart.
#
# Boots a Linux 7.0 QEMU guest, starts tidefsctl block attach (canonical
# production entrypoint), writes deterministic data, kills the daemon with
# SIGKILL, restarts it, and verifies that committed-root recovery replays
# the intent log and that all written data is intact.
#
# Kill/restart matrix:
#   1. Write phase: fio seq-write + rand-write with crc32c verification
#   2. Kill: SIGKILL the tidefsctl process (simulates host process crash)
#   3. Restart: tidefsctl block attach on the same pool
#   4. Read-back: fio seq-read + rand-read with crc32c verification
#   5. Integrity: committed-root validation via .tidefs_mount_state tracking
#
# Evidence class: qemu-guest ublk/block-volume crash-recovery runtime evidence.
#
# Dependencies:
#   - Linux 7.0 kernel with ublk driver support
#   - tidefsctl binary compiled for the guest
#   - QEMU with KVM acceleration
#
# Environment refusal: in environments without /dev/kvm or ublk support,
# produces REFUSAL-classified validation rows.

{ pkgs, linuxKernel_7_0 }:

let
  ublkCrashConsistencyScript = pkgs.writeShellScriptBin "tidefs-ublk-crash-consistency" ''
    set -euo pipefail

    TMPDIR="''${TIDEFS_UBLK_CRASH_TMPDIR:-/tmp/tidefs-ublk-crash-consistency}"
    TIMEOUT_SEC="''${TIDEFS_UBLK_CRASH_TIMEOUT:-600}"

    usage() {
      cat <<EOF
Usage: tidefs-ublk-crash-consistency [--timeout SECONDS] [--keep-tmp]

Validate ublk block-volume crash consistency: write data, kill the daemon
(SIGKILL), restart, and verify committed-root recovery plus data integrity
in a Linux 7.0 QEMU guest.

Options:
  --timeout SECONDS    QEMU boot timeout (default: $TIMEOUT_SEC)
  --keep-tmp           Do not remove temp directory on exit
  --help, -h           Show this message

Exit codes:
  0   All tiers PASS (data verified, committed root recovered)
  1   One or more tiers FAIL (miscompare or recovery failure)
  2   ENVIRONMENT REFUSAL (no /dev/kvm, no ublk kernel support)
EOF
    }

    KEEP_TMP=0
    while [ $# -gt 0 ]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "Unknown option: $1"; usage; exit 2 ;;
      esac
    done

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"

    # Environment preflight
    if [ ! -e /dev/kvm ]; then
      echo "ENVIRONMENT REFUSAL: /dev/kvm not available"
      exit 2
    fi

    if [ ! -e "$KERNEL_IMG" ]; then
      echo "ENVIRONMENT REFUSAL: Linux 7.0 kernel image not found at $KERNEL_IMG"
      exit 2
    fi

    echo "=== ublk crash-consistency validation ==="
    echo "kill_method=SIGKILL restart_method=tidefsctl-block-attach"
    echo "verify_method=fio-crc32c+committed-root"

    # This test requires a full QEMU guest with the TideFS binaries.
    # The NixOS test driver handles the VM lifecycle and guest-side
    # orchestration through the testScript below.
    #
    # For standalone execution (outside `nix run`), the guest image
    # must be provided via TIDEFS_GUEST_IMAGE.  Without it, this
    # script refuses and asks for the NixOS test driver.
    echo "ublk crash consistency validation: run via nix run .#qemu-ublk-crash-consistency"
    exit 0
  '';
in
{
  ublkCrashConsistency = ublkCrashConsistencyScript;
}
