# TideFS two-node harness TCP carrier validation inside a QEMU guest.
#
# Nix builds the validation binary, initramfs inputs, and Linux 7.0 kernel.
# The runner launches qemu-system-* as a normal host process so runtime
# validation does not execute inside the Nix build sandbox.

{
  pkgs,
  linuxKernel_7_0,
  tidefsPackage,
}:

let
  twoNodeCarrierValidationScript = pkgs.writeShellScriptBin "tidefs-two-node-carrier-validation" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    LDD_BIN="${pkgs.lib.getBin pkgs.glibc}/bin/ldd"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    GZIP="${pkgs.gzip}/bin/gzip"
    IP_BIN="${pkgs.iproute2}/bin/ip"
    VALIDATION_BIN="${tidefsPackage}/bin/tidefs-two-node-qemu-carrier-validation"

    TMPDIR="''${TIDEFS_TWO_NODE_CARRIER_TMPDIR:-/tmp/tidefs-two-node-carrier-validation}"
    VALIDATION_DIR="''${TIDEFS_TWO_NODE_CARRIER_VALIDATION_DIR:-/tmp/tidefs-validation/two-node-carrier-validation}"
    TIMEOUT_SEC="''${TIDEFS_TWO_NODE_CARRIER_TIMEOUT:-600}"
    KEEP_TMP=0

    usage() {
      cat <<USAGE
Usage: tidefs-two-node-carrier-validation [--timeout SECONDS] [--validation-dir DIR] [--keep-tmp]

Boot Linux 7.0 in QEMU, run the qemu-gated tidefs-two-node-harness live TCP
carrier validation binary, and extract its JSON report.

Options:
  --timeout SECONDS     QEMU boot timeout (default: $TIMEOUT_SEC)
  --validation-dir DIR  Host output directory (default: $VALIDATION_DIR)
  --keep-tmp            Do not remove temporary initramfs workspace
  --help, -h            Show this message
USAGE
    }

    while [ "$#" -gt 0 ]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --validation-dir) VALIDATION_DIR="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO" "$GZIP" "$IP_BIN" "$VALIDATION_BIN"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ENVIRONMENT REFUSAL: dependency not found: $dep" >&2
        exit 2
      fi
    done
    if [ ! -x "$LDD_BIN" ]; then
      LDD_BIN="$(command -v ldd || true)"
    fi
    if [ -z "$LDD_BIN" ] || [ ! -x "$LDD_BIN" ]; then
      echo "ENVIRONMENT REFUSAL: ldd not available for initrd dependency discovery" >&2
      exit 2
    fi

    QEMU_ACCEL=(-cpu qemu64)
    QEMU_ACCEL_LABEL="tcg"
    if [ -e /dev/kvm ]; then
      QEMU_ACCEL=(-enable-kvm -cpu host)
      QEMU_ACCEL_LABEL="kvm"
    fi

    echo "=== TideFS VAL: two-node harness TCP carrier QEMU ==="
    echo "  Kernel:         $KERNEL_IMG"
    echo "  Validation bin: $VALIDATION_BIN"
    echo "  QEMU:           $QEMU_BIN"
    echo "  Accel:          $QEMU_ACCEL_LABEL"
    echo "  Timeout:        ''${TIMEOUT_SEC}s"
    echo "  Validation dir: $VALIDATION_DIR"
    echo ""

    WORK_DIR="$TMPDIR/validation-$$"
    RUN_DIR="$WORK_DIR/initrd"
    QEMU_LOG="$VALIDATION_DIR/qemu.log"
    QEMU_ERR="$VALIDATION_DIR/qemu-stderr.log"
    REPORT_JSON="$VALIDATION_DIR/carrier-report.json"
    SUMMARY_JSON="$VALIDATION_DIR/summary.json"

    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,etc}
    mkdir -p "$VALIDATION_DIR"

    cleanup() {
      if [ "$KEEP_TMP" -eq 1 ]; then
        echo "  Keeping: $WORK_DIR"
      else
        rm -rf "$WORK_DIR"
      fi
    }
    trap cleanup EXIT

    {
      echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      echo "kernel_package=linuxKernel_7_0"
      echo "qemu_accel=$QEMU_ACCEL_LABEL"
      echo "validation_bin=$VALIDATION_BIN"
    } > "$VALIDATION_DIR/environment.txt"

    copy_binary_to_bin() {
      local src="$1"
      local dst="$2"
      cp "$src" "$RUN_DIR/bin/$dst"
      chmod +x "$RUN_DIR/bin/$dst"
    }

    copy_runtime_deps() {
      echo "  Copying exact Nix store runtime dependencies..."
      local deps
      deps=$("$LDD_BIN" "$BUSYBOX" "$IP_BIN" "$VALIDATION_BIN" 2>/dev/null | grep -o '/nix/store/[^ ]*' | sort -u || true)
      for lib in $deps; do
        if [ -f "$lib" ]; then
          local lib_dir
          lib_dir=$(dirname "$lib")
          mkdir -p "$RUN_DIR$lib_dir"
          cp "$lib" "$RUN_DIR$lib" 2>/dev/null || true
        fi
      done

      for binary in "$BUSYBOX" "$IP_BIN" "$VALIDATION_BIN"; do
        local ld_so
        ld_so=$("$LDD_BIN" "$binary" 2>/dev/null | grep -o '/nix/store/[^ ]*ld-linux[^ ]*' | head -1 || true)
        if [ -n "$ld_so" ] && [ -f "$ld_so" ]; then
          local ld_dir
          ld_dir=$(dirname "$ld_so")
          mkdir -p "$RUN_DIR$ld_dir"
          cp "$ld_so" "$RUN_DIR$ld_so" 2>/dev/null || true
          chmod +x "$RUN_DIR$ld_so" 2>/dev/null || true
        fi
      done
    }

    copy_binary_to_bin "$BUSYBOX" busybox
    for applet in sh ls cat echo mount dmesg sleep poweroff mknod mkdir rm \
                    touch find sync head tail cut uname date true false \
                    ifconfig; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done
    copy_binary_to_bin "$IP_BIN" ip
    copy_binary_to_bin "$VALIDATION_BIN" tidefs-two-node-qemu-carrier-validation
    copy_runtime_deps

    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev || true
ip link set lo up 2>/tmp/lo.err || ifconfig lo 127.0.0.1 up 2>>/tmp/lo.err || true

echo "=== TideFS two-node harness TCP carrier validation ==="
echo "kernel=$(uname -r 2>/dev/null || echo unknown)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"
echo ""

KVER=$(uname -r 2>/dev/null || echo unknown)
case "$KVER" in
  7.*) echo "PASS: linux_7_0_kernel $KVER" ;;
  *)   echo "FAIL: linux_7_0_kernel expected Linux 7.0 guest kernel, got $KVER"; poweroff -f ;;
esac

if tidefs-two-node-qemu-carrier-validation > /tmp/carrier-report.out 2>/tmp/carrier-report.err; then
    cat /tmp/carrier-report.out
    echo "PASS: qemu_tcp_carrier_state_transfer"
else
    echo "FAIL: qemu_tcp_carrier_state_transfer"
    cat /tmp/carrier-report.err 2>&1 || true
    cat /tmp/carrier-report.out 2>&1 || true
    poweroff -f
fi

sync
poweroff -f
INITSCRIPT

    chmod +x "$RUN_DIR/init"

    echo "  Building initramfs..."
    ( cd "$RUN_DIR" && find . | "$CPIO" -o -H newc 2>/dev/null | "$GZIP" > "$WORK_DIR/initrd.img" )

    echo "  Booting QEMU guest..."
    set +e
    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      -kernel "$KERNEL_IMG" \
      -initrd "$WORK_DIR/initrd.img" \
      -append "console=ttyS0 quiet init=/init tidefs.qemu_carrier_validation=1" \
      -nographic \
      -m 768 \
      "''${QEMU_ACCEL[@]}" \
      > "$QEMU_LOG" 2> "$QEMU_ERR"
    QEMU_EXIT=$?
    set -e

    echo ""
    echo "  QEMU exit code: $QEMU_EXIT"
    echo "  QEMU log:       $QEMU_LOG"
    echo "  QEMU stderr:    $QEMU_ERR"

    echo ""
    echo "=== QEMU Guest Output (tail 120 lines) ==="
    tail -120 "$QEMU_LOG" 2>/dev/null || echo "(no stdout)"

    awk '
      /QEMU_TCP_CARRIER_REPORT_BEGIN/ { in_json = 1; next }
      /QEMU_TCP_CARRIER_REPORT_END/ { in_json = 0; next }
      in_json { print }
    ' "$QEMU_LOG" > "$REPORT_JSON"

    if [ "$QEMU_EXIT" -ne 0 ]; then
      echo "FAIL: QEMU exited with $QEMU_EXIT" >&2
      exit "$QEMU_EXIT"
    fi
    if [ ! -s "$REPORT_JSON" ]; then
      echo "FAIL: no carrier report was extracted from QEMU output" >&2
      exit 1
    fi
    if ! grep -q '"qemu_guest_detected":true' "$REPORT_JSON"; then
      echo "FAIL: carrier report did not confirm QEMU guest detection" >&2
      cat "$REPORT_JSON" >&2 || true
      exit 1
    fi
    if ! grep -q 'PASS: qemu_tcp_carrier_state_transfer' "$QEMU_LOG"; then
      echo "FAIL: QEMU output did not include carrier validation pass marker" >&2
      exit 1
    fi

    cat > "$SUMMARY_JSON" <<SUMMARY
{
  "test": "tidefs-two-node-qemu-carrier-validation",
  "version": 1,
  "validation_tier": "Tier 8 QEMU carrier validation",
  "qemu_exit_code": $QEMU_EXIT,
  "qemu_accel": "$QEMU_ACCEL_LABEL",
  "carrier_report": "$REPORT_JSON",
  "qemu_log": "$QEMU_LOG"
}
SUMMARY

    echo "SUMMARY: tidefs-two-node-qemu-carrier-validation PASS"
    echo "carrier_report=$REPORT_JSON"
    echo "validation_dir=$VALIDATION_DIR"
  '';
in
{
  twoNodeCarrierValidation = twoNodeCarrierValidationScript;
}
