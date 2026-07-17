# TideFS storage-intent acknowledgment fault matrix inside Linux 7.0 QEMU.
#
# The host runner boots three guests against one raw virtio-blk image.  It
# sends SIGKILL only to the exact QEMU PIDs launched by this script, after the
# guest has flushed either a pre-ack or earned-ack record.  The final boot
# verifies recovery and the remaining receipt/refusal fault rows.

{
  pkgs,
  linuxKernel_7_0,
  tidefsPackage,
}:

let
  storageIntentAckFaultMatrixScript = pkgs.writeShellScriptBin "tidefs-storage-intent-ack-fault-matrix" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    LDD_BIN="${pkgs.lib.getBin pkgs.glibc}/bin/ldd"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    GZIP="${pkgs.gzip}/bin/gzip"
    TRUNCATE="${pkgs.coreutils}/bin/truncate"
    DATE="${pkgs.coreutils}/bin/date"
    GIT="${pkgs.git}/bin/git"
    VALIDATION_BIN="${tidefsPackage}/bin/storage-intent-ack-fault-matrix-validation"

    TMPDIR="''${TIDEFS_ACK_FAULT_TMPDIR:-/tmp/tidefs-storage-intent-ack-fault-matrix}"
    VALIDATION_DIR="''${TIDEFS_ACK_FAULT_VALIDATION_DIR:-/tmp/tidefs-validation/storage-intent-ack-fault-matrix}"
    TIMEOUT_SEC="''${TIDEFS_ACK_FAULT_TIMEOUT:-600}"
    SOURCE_REF="''${TIDEFS_ACK_FAULT_SOURCE_REF:-}"
    RUN_ID="''${TIDEFS_ACK_FAULT_RUN_ID:-}"
    GENERATED_AT="''${TIDEFS_GENERATED_AT:-}"
    KEEP_TMP=0

    usage() {
      cat <<USAGE
Usage: tidefs-storage-intent-ack-fault-matrix [--timeout SECONDS] [--validation-dir DIR] [--keep-tmp]

Boot Linux 7.0 three times against one raw virtio-blk image, inject owned-QEMU
crashes before and after acknowledgment publication, verify the five issue
#2224 fault rows, and emit a v2 evidence manifest.

Options:
  --timeout SECONDS     Per-phase QEMU timeout (default: $TIMEOUT_SEC)
  --validation-dir DIR  Host output directory (default: $VALIDATION_DIR)
  --keep-tmp            Keep the temporary initramfs and raw fault image
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

    if ! [[ "$TIMEOUT_SEC" =~ ^[0-9]+$ ]]; then
      echo "ERROR: --timeout must be a positive integer" >&2
      exit 2
    fi
    if [ "$TIMEOUT_SEC" -le 0 ]; then
      echo "ERROR: --timeout must be greater than zero" >&2
      exit 2
    fi

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO" "$GZIP" "$TRUNCATE" "$DATE" "$VALIDATION_BIN"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ENVIRONMENT REFUSAL: dependency not found: $dep" >&2
        exit 2
      fi
    done
    if [ ! -x "$LDD_BIN" ]; then
      LDD_BIN="$(command -v ldd || true)"
    fi
    if [ -z "$LDD_BIN" ] || [ ! -x "$LDD_BIN" ]; then
      echo "ENVIRONMENT REFUSAL: ldd is unavailable for initramfs dependency discovery" >&2
      exit 2
    fi

    if [ -z "$SOURCE_REF" ]; then
      SOURCE_REF="$($GIT rev-parse HEAD 2>/dev/null || true)"
    fi
    if [ -z "$SOURCE_REF" ]; then
      echo "ENVIRONMENT REFUSAL: source ref is unavailable" >&2
      exit 2
    fi
    if [ -z "$RUN_ID" ]; then
      RUN_ID="manual-$($DATE -u +%Y%m%dT%H%M%SZ)-$$"
    fi
    if [ -z "$GENERATED_AT" ]; then
      GENERATED_AT="$($DATE -u +%Y-%m-%dT%H:%M:%SZ)"
    fi
    for value in "$SOURCE_REF" "$RUN_ID" "$GENERATED_AT"; do
      if [[ "$value" =~ [[:space:]] ]]; then
        echo "ENVIRONMENT REFUSAL: provenance values must not contain whitespace" >&2
        exit 2
      fi
    done

    QEMU_ACCEL=(-cpu qemu64)
    QEMU_ACCEL_LABEL="tcg"
    if [ -e /dev/kvm ]; then
      QEMU_ACCEL=(-enable-kvm -cpu host)
      QEMU_ACCEL_LABEL="kvm"
    fi

    WORK_DIR="$TMPDIR/validation-$$"
    RUN_DIR="$WORK_DIR/initrd"
    FAULT_MEDIA="$WORK_DIR/ack-fault-media.img"
    ARTIFACT_REL="validation/artifacts/storage-intent/ack-receipt-fault-matrix.json"
    ARTIFACT_JSON="$VALIDATION_DIR/$ARTIFACT_REL"
    MANIFEST_JSON="$VALIDATION_DIR/evidence-manifest.json"
    ACTIVE_QEMU_PID=""

    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,etc}
    mkdir -p "$VALIDATION_DIR" "$(dirname "$ARTIFACT_JSON")"
    "$TRUNCATE" -s 8M "$FAULT_MEDIA"

    cleanup() {
      if [ -n "$ACTIVE_QEMU_PID" ] && kill -0 "$ACTIVE_QEMU_PID" 2>/dev/null; then
        kill -KILL "$ACTIVE_QEMU_PID" 2>/dev/null || true
        wait "$ACTIVE_QEMU_PID" 2>/dev/null || true
      fi
      if [ "$KEEP_TMP" -eq 1 ]; then
        echo "Keeping task-owned QEMU workspace: $WORK_DIR"
      else
        rm -rf "$WORK_DIR"
      fi
    }
    trap cleanup EXIT INT TERM

    {
      echo "generated_at=$GENERATED_AT"
      echo "source_ref=$SOURCE_REF"
      echo "run_id=$RUN_ID"
      echo "kernel_package=linuxKernel_7_0"
      echo "qemu_accel=$QEMU_ACCEL_LABEL"
      echo "crash_injection=host-sigkill-owned-qemu-process"
      echo "fault_media=raw-virtio-blk-cache-none"
    } > "$VALIDATION_DIR/environment.txt"

    copy_binary_to_bin() {
      local src="$1"
      local dst="$2"
      cp "$src" "$RUN_DIR/bin/$dst"
      chmod +x "$RUN_DIR/bin/$dst"
    }

    copy_runtime_deps() {
      local deps
      deps=$("$LDD_BIN" "$BUSYBOX" "$VALIDATION_BIN" 2>/dev/null | grep -o '/nix/store/[^ ]*' | sort -u || true)
      for lib in $deps; do
        if [ -f "$lib" ]; then
          mkdir -p "$RUN_DIR$(dirname "$lib")"
          cp "$lib" "$RUN_DIR$lib" 2>/dev/null || true
        fi
      done
      for binary in "$BUSYBOX" "$VALIDATION_BIN"; do
        local ld_so
        ld_so=$("$LDD_BIN" "$binary" 2>/dev/null | grep -o '/nix/store/[^ ]*ld-linux[^ ]*' | head -1 || true)
        if [ -n "$ld_so" ] && [ -f "$ld_so" ]; then
          mkdir -p "$RUN_DIR$(dirname "$ld_so")"
          cp "$ld_so" "$RUN_DIR$ld_so" 2>/dev/null || true
          chmod +x "$RUN_DIR$ld_so" 2>/dev/null || true
        fi
      done
    }

    copy_binary_to_bin "$BUSYBOX" busybox
    for applet in sh cat echo mount dmesg sleep poweroff mkdir sync uname tr sed head; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done
    copy_binary_to_bin "$VALIDATION_BIN" storage-intent-ack-fault-matrix-validation
    copy_runtime_deps

    cat > "$RUN_DIR/init" <<'INITSCRIPT'
#!/bin/sh
export PATH=/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev || true

echo "=== TideFS storage-intent acknowledgment fault matrix ==="
echo "kernel=$(uname -r 2>/dev/null || echo unavailable)"

KVER=$(uname -r 2>/dev/null || echo unavailable)
case "$KVER" in
  7.*) ;;
  *) echo "ENVIRONMENT REFUSAL: expected Linux 7.0 guest kernel, found $KVER"; poweroff -f ;;
esac

attempt=0
while [ ! -b /dev/vda ] && [ "$attempt" -lt 30 ]; do
  attempt=$((attempt + 1))
  sleep 1
done
if [ ! -b /dev/vda ]; then
  echo "ENVIRONMENT REFUSAL: /dev/vda did not appear"
  poweroff -f
fi

PHASE=$(tr ' ' '\n' < /proc/cmdline | sed -n 's/^tidefs.ack_fault_phase=//p' | head -1)
if [ -z "$PHASE" ]; then
  echo "HARNESS FAIL: missing tidefs.ack_fault_phase"
  poweroff -f
fi

if storage-intent-ack-fault-matrix-validation guest --phase "$PHASE" --media /dev/vda; then
  echo "PASS: storage_intent_ack_fault_phase_$PHASE"
  sync
  poweroff -f
else
  echo "FAIL: storage_intent_ack_fault_phase_$PHASE"
  sync
  poweroff -f
fi
INITSCRIPT
    chmod +x "$RUN_DIR/init"

    echo "Building acknowledgment fault initramfs..."
    ( cd "$RUN_DIR" && find . | "$CPIO" -o -H newc 2>/dev/null | "$GZIP" > "$WORK_DIR/initrd.img" )

    QEMU_COMMON=(
      -kernel "$KERNEL_IMG"
      -initrd "$WORK_DIR/initrd.img"
      -nographic
      -no-reboot
      -m 768
      -drive "file=$FAULT_MEDIA,format=raw,if=virtio,cache=none"
      "''${QEMU_ACCEL[@]}"
    )

    run_crash_phase() {
      local phase="$1"
      local marker="$2"
      local log="$VALIDATION_DIR/$phase.log"
      local err="$VALIDATION_DIR/$phase.stderr.log"
      local deadline=$((SECONDS + TIMEOUT_SEC))

      echo "Booting crash phase: $phase"
      "$QEMU_BIN" "''${QEMU_COMMON[@]}" \
        -append "console=ttyS0 quiet init=/init tidefs.ack_fault_validation=1 tidefs.ack_fault_phase=$phase tidefs.source_ref=$SOURCE_REF tidefs.run_id=$RUN_ID tidefs.generated_at=$GENERATED_AT" \
        > "$log" 2> "$err" &
      ACTIVE_QEMU_PID=$!

      while ! grep -Fq "$marker" "$log" 2>/dev/null; do
        if ! kill -0 "$ACTIVE_QEMU_PID" 2>/dev/null; then
          set +e
          wait "$ACTIVE_QEMU_PID"
          local rc=$?
          set -e
          ACTIVE_QEMU_PID=""
          echo "HARNESS FAIL: QEMU phase $phase exited before marker (rc=$rc)" >&2
          tail -120 "$log" >&2 || true
          exit 1
        fi
        if [ "$SECONDS" -ge "$deadline" ]; then
          echo "HARNESS FAIL: QEMU phase $phase timed out before marker" >&2
          kill -KILL "$ACTIVE_QEMU_PID" 2>/dev/null || true
          wait "$ACTIVE_QEMU_PID" 2>/dev/null || true
          ACTIVE_QEMU_PID=""
          exit 1
        fi
        sleep 1
      done

      echo "Injecting crash into task-owned QEMU pid $ACTIVE_QEMU_PID after marker $marker"
      kill -KILL "$ACTIVE_QEMU_PID"
      set +e
      wait "$ACTIVE_QEMU_PID"
      local rc=$?
      set -e
      ACTIVE_QEMU_PID=""
      echo "phase=$phase qemu_wait_status=$rc marker=$marker" >> "$VALIDATION_DIR/crash-injection.txt"
    }

    run_verify_phase() {
      local log="$VALIDATION_DIR/verify.log"
      local err="$VALIDATION_DIR/verify.stderr.log"
      echo "Booting verification phase"
      set +e
      timeout "$TIMEOUT_SEC" "$QEMU_BIN" "''${QEMU_COMMON[@]}" \
        -append "console=ttyS0 quiet init=/init tidefs.ack_fault_validation=1 tidefs.ack_fault_phase=verify tidefs.source_ref=$SOURCE_REF tidefs.run_id=$RUN_ID tidefs.generated_at=$GENERATED_AT" \
        > "$log" 2> "$err"
      local rc=$?
      set -e
      if [ "$rc" -ne 0 ]; then
        echo "HARNESS FAIL: verification QEMU exited with $rc" >&2
        tail -160 "$log" >&2 || true
        exit "$rc"
      fi

      awk '
        /TIDEFS_ACK_FAULT_MATRIX_REPORT_BEGIN/ { in_json = 1; next }
        /TIDEFS_ACK_FAULT_MATRIX_REPORT_END/ { in_json = 0; next }
        in_json { print }
      ' "$log" > "$ARTIFACT_JSON"
      if [ ! -s "$ARTIFACT_JSON" ]; then
        echo "HARNESS FAIL: no acknowledgment fault report was extracted" >&2
        exit 1
      fi

      "$VALIDATION_BIN" manifest \
        --artifact-root "$VALIDATION_DIR" \
        --report "$ARTIFACT_JSON" \
        --manifest "$MANIFEST_JSON"
      if ! grep -Fq 'PASS: storage_intent_ack_fault_phase_verify' "$log"; then
        echo "PRODUCT FAIL: verification guest did not report a passing matrix" >&2
        exit 1
      fi
    }

    echo "=== TideFS storage-intent acknowledgment fault matrix ==="
    echo "source_ref=$SOURCE_REF"
    echo "run_id=$RUN_ID"
    echo "generated_at=$GENERATED_AT"
    echo "qemu_accel=$QEMU_ACCEL_LABEL"
    echo "validation_dir=$VALIDATION_DIR"

    run_crash_phase kill-before-ack TIDEFS_ACK_FAULT_KILL_BEFORE_ACK_READY
    run_crash_phase crash-after-ack TIDEFS_ACK_FAULT_CRASH_AFTER_ACK_READY
    run_verify_phase

    echo "SUMMARY: storage-intent acknowledgment fault matrix PASS"
    echo "artifact=$ARTIFACT_JSON"
    echo "manifest=$MANIFEST_JSON"
  '';
in
{
  storageIntentAckFaultMatrix = storageIntentAckFaultMatrixScript;
}
