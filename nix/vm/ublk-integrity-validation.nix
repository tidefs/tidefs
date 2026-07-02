# TideFS: ublk block-volume sector-pattern data integrity validation refusal.
#
# This entry point records the intended Linux 7.0 QEMU guest row shape, but the
# prepared guest image/test runner for that workload is not wired yet. Until
# that substrate exists, the harness must fail closed as missing-evidence
# refusal output and must not be counted as product validation coverage.
#
# Intended workload: start the tidefs-block-volume-adapter-daemon, attach a
# ublk block-volume, and exercise 4 deterministic sector-fill patterns
# (LBA-indexed, all-zeros, all-ones, counter-fill) across 4 validation tiers
# (single-sector round-trip, multi-sector sequential, staggered-offset
# overlapped, full-volume sweep) with committed-root consistency verification.
#
# Dependencies:
#   - Linux 7.0 kernel with ublk driver support
#   - tidefs-block-volume-adapter-daemon compiled for the guest
#   - QEMU with QMP monitor support
#   - Persistently-backed block volume image
#   - Prepared guest image/test runner for the sector-pattern workload
#
# Missing-evidence refusal: this test currently requires substrate that is not
# available in this derivation. It exits non-success with explicit refusal
# output instead of emitting PASS rows or qemu-guest validation evidence.

{ pkgs, linuxKernel_7_0 }:

let
  linuxPackages_7_0 = pkgs.linuxPackagesFor linuxKernel_7_0;

  ublkIntegrityScript = pkgs.writeShellScriptBin "tidefs-ublk-integrity-validation" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"

    TMPDIR="''${TIDEFS_UBLK_INTEGRITY_TMPDIR:-/tmp/tidefs-ublk-integrity-validation}"
    TIMEOUT_SEC="''${TIDEFS_UBLK_INTEGRITY_TIMEOUT:-300}"
    DEVICE_SECTORS="''${TIDEFS_UBLK_INTEGRITY_DEVICE_SECTORS:-4096}"
    SECTOR_SIZE=512

    usage() {
      cat <<EOF
Usage: tidefs-ublk-integrity-validation [--timeout SECONDS] [--sectors N] [--keep-tmp]

Fail closed for the not-yet-wired ublk block-volume sector-pattern data
integrity workload. The intended workload covers 4 patterns (LBA-indexed,
all-zeros, all-ones, counter-fill) and 4 validation tiers (single-sector
round-trip, multi-sector sequential, staggered-offset overlapped,
full-volume sweep) with committed-root verification in a Linux 7.0 QEMU guest.

Until a prepared guest image/test runner is available, this command emits only
missing-evidence/refusal output and provides no product validation coverage.

Options:
  --timeout SECONDS    QEMU boot timeout (default: $TIMEOUT_SEC)
  --sectors N          Device size in 512-byte sectors (default: $DEVICE_SECTORS)
  --keep-tmp           Do not remove temp directory on exit
  --help, -h           Show this message

Exit codes:
  0   All tiers PASS (only after the guest workload is implemented)
  1   One or more tiers FAIL (only after the guest workload is implemented)
  2   REFUSAL (no /dev/kvm, no guest runner, or missing execution substrate)
EOF
    }

    KEEP_TMP=0
    while [ $# -gt 0 ]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --sectors) DEVICE_SECTORS="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "Unknown option: $1"; usage; exit 2 ;;
      esac
    done

    # ── Environment preflight ──────────────────────────────────────────

    if [ ! -e /dev/kvm ]; then
      echo "ENVIRONMENT REFUSAL: /dev/kvm not available"
      echo "ublk integrity QEMU validation requires KVM acceleration"
      echo "validation_coverage: none"
      echo "pass_rows: 0"
      exit 2
    fi

    if [ ! -e "$KERNEL_IMG" ]; then
      echo "ENVIRONMENT REFUSAL: Linux 7.0 kernel image not found at $KERNEL_IMG"
      echo "validation_coverage: none"
      echo "pass_rows: 0"
      exit 2
    fi

    echo "=== ublk sector-pattern integrity validation refusal ==="
    echo "device_sectors=$DEVICE_SECTORS sector_size=$SECTOR_SIZE"
    echo "patterns: LBA-indexed, all-zeros, all-ones, counter-fill"
    echo "tiers: single-sector, multi-sector, staggered-offset, full-volume-sweep"

    # ── Validation workload ────────────────────────────────────────────
    #
    # Intended future guest workload, once a prepared guest image/test runner
    # exists. It must execute inside the QEMU guest via a serial-attached test
    # binary or shell script. The guest will perform:
    #
    #   For each pattern in {LbaIndexed, AllZeros, AllOnes, CounterFill}:
    #     For each tier in {SingleSector, MultiSector, Staggered, FullSweep}:
    #       1. Compute expected sector payloads via SectorPattern::fill_sector()
    #       2. Write payloads to the ublk block device (e.g. /dev/ublkb0)
    #       3. Issue FLUSH to commit writes to persistent backing
    #       4. Read back each sector from the device
    #       5. Verify byte-for-byte against expected payloads
    #       6. Record validation row (pattern, tier, range, outcome, message)
    #   After all tiers, verify committed-root consistency across remount.
    #
    # When implemented, the canonical 24-row validation report (16 core + 8
    # edge) must be emitted as tier-classified JSON to stdout.

    echo "MISSING-EVIDENCE REFUSAL: ublk integrity QEMU validation is not wired"
    echo "reason: no prepared Linux 7.0 guest image/test runner for the sector-pattern workload"
    echo "validation_coverage: none"
    echo "pass_rows: 0"
    echo "See crates/tidefs-block-volume-adapter-ublk-control-runtime/src/integrity_validation.rs"
    echo "Validation schema: 24 rows (16 core 4x4 + 8 edge cases)"
    exit 2
  '';
in
{
  ublkIntegrityValidation = ublkIntegrityScript;
}
