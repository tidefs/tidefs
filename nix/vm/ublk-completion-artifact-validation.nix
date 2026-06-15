# TideFS: ublk qid/tag completion artifact runtime validation.
#
# Nix builds this runner, its initramfs inputs, and the Linux 7.0 kernel.  The
# script launches qemu-system-* as a normal host process so runtime validation
# does not execute inside the Nix build sandbox.

{
  pkgs,
  linuxKernel_7_0,
  tidefsPackage,
}:

let
  ublkCompletionArtifactValidationScript = pkgs.writeShellScriptBin "tidefs-ublk-completion-artifact-validation" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    LDD_BIN="${pkgs.lib.getBin pkgs.glibc}/bin/ldd"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    GZIP="${pkgs.gzip}/bin/gzip"
    FIO="${pkgs.fio}/bin/fio"
    TIDEFSCTL="${tidefsPackage}/bin/tidefsctl"
    UBLK_DAEMON="${tidefsPackage}/bin/tidefs-block-volume-adapter-daemon"
    XTASK="${tidefsPackage}/bin/tidefs-xtask"
    MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"

    TMPDIR="''${TIDEFS_UBLK_COMPLETION_TMPDIR:-/tmp/tidefs-ublk-completion-artifact}"
    VALIDATION_DIR="''${TIDEFS_UBLK_COMPLETION_VALIDATION_DIR:-/tmp/tidefs-validation/ublk}"
    TIMEOUT_SEC="''${TIDEFS_UBLK_COMPLETION_TIMEOUT:-600}"
    DISK_SIZE_MB="''${TIDEFS_UBLK_COMPLETION_DISK_MB:-256}"
    KEEP_TMP=0

    usage() {
      cat <<USAGE
Usage: tidefs-ublk-completion-artifact-validation [--timeout SECONDS] [--disk-size-mb MB] [--validation-dir DIR] [--keep-tmp]

Boot Linux 7.0 in QEMU, run the real tidefsctl ublk attach path, emit a qid/tag
completion artifact, and validate it with tidefs-xtask.

Options:
  --timeout SECONDS     QEMU boot timeout (default: $TIMEOUT_SEC)
  --disk-size-mb MB     Scratch disk size (default: $DISK_SIZE_MB)
  --validation-dir DIR  Host output directory (default: $VALIDATION_DIR)
  --keep-tmp            Do not remove temporary initramfs workspace
  --help, -h            Show this message
USAGE
    }

    while [ "$#" -gt 0 ]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --disk-size-mb) DISK_SIZE_MB="$2"; shift 2 ;;
        --validation-dir) VALIDATION_DIR="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO" "$GZIP" "$FIO" "$TIDEFSCTL" "$UBLK_DAEMON" "$XTASK"; do
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

    echo "=== TideFS VAL: ublk completion artifact QEMU ==="
    echo "  Kernel:         $KERNEL_IMG"
    echo "  tidefsctl:      $TIDEFSCTL"
    echo "  ublk daemon:    $UBLK_DAEMON"
    echo "  tidefs-xtask:   $XTASK"
    echo "  QEMU:           $QEMU_BIN"
    echo "  Accel:          $QEMU_ACCEL_LABEL"
    echo "  Timeout:        ''${TIMEOUT_SEC}s"
    echo "  Validation dir: $VALIDATION_DIR"
    echo ""

    WORK_DIR="$TMPDIR/validation-$$"
    RUN_DIR="$WORK_DIR/initrd"
    DISK_IMG="$WORK_DIR/scratch.img"
    QEMU_OUT="$VALIDATION_DIR/qemu-stdout.log"
    QEMU_ERR="$VALIDATION_DIR/qemu-stderr.log"
    HOST_ARTIFACT="$VALIDATION_DIR/qid-tag-completion-runtime.json"
    VERIFY_LOG="$VALIDATION_DIR/ublk-completion-verify.log"
    SUMMARY_JSON="$VALIDATION_DIR/qemu-ublk-completion.json"

    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib/modules,etc,run/tidefs/import}
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
      echo "tidefsctl=$TIDEFSCTL"
      echo "ublk_daemon=$UBLK_DAEMON"
      echo "xtask=$XTASK"
    } > "$VALIDATION_DIR/environment.txt"

    ${pkgs.coreutils}/bin/truncate -s "''${DISK_SIZE_MB}M" "$DISK_IMG"

    copy_binary_to_bin() {
      local src="$1"
      local dst="$2"
      cp "$src" "$RUN_DIR/bin/$dst"
      chmod +x "$RUN_DIR/bin/$dst"
    }

    copy_runtime_deps() {
      echo "  Copying exact Nix store runtime dependencies..."
      local deps
      deps=$("$LDD_BIN" "$BUSYBOX" "$FIO" "$TIDEFSCTL" "$UBLK_DAEMON" 2>/dev/null | grep -o '/nix/store/[^ ]*' | sort -u || true)
      for lib in $deps; do
        if [ -f "$lib" ]; then
          local lib_dir
          lib_dir=$(dirname "$lib")
          mkdir -p "$RUN_DIR$lib_dir"
          cp "$lib" "$RUN_DIR$lib" 2>/dev/null || true
        fi
      done

      for binary in "$BUSYBOX" "$FIO" "$TIDEFSCTL" "$UBLK_DAEMON"; do
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
    for applet in sh ls cat echo mount grep insmod dmesg sleep poweroff \
                    mknod mkdir rm touch find sync expr head tail cut kill ps \
                    test seq blockdev sed awk uname date true false; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done
    copy_binary_to_bin "$FIO" fio
    copy_binary_to_bin "$TIDEFSCTL" tidefsctl
    copy_binary_to_bin "$UBLK_DAEMON" tidefs-block-volume-adapter-daemon
    copy_runtime_deps

    UBLK_KO=""
    for c in \
      "$MODULE_DIR/kernel/drivers/block/ublk_drv.ko" \
      "$MODULE_DIR/kernel/drivers/block/ublk_drv.ko.xz" \
      "$MODULE_DIR/extra/ublk_drv.ko" \
      "$MODULE_DIR/ublk_drv.ko"; do
      [ -f "$c" ] && { UBLK_KO="$c"; break; }
    done
    UBLK_BUILTIN=0
    [ -z "$UBLK_KO" ] && { echo "  ublk_drv.ko not found; assuming built-in"; UBLK_BUILTIN=1; }

    if [ "$UBLK_BUILTIN" -eq 0 ]; then
      cp "$UBLK_KO" "$RUN_DIR/lib/modules/ublk_drv.ko"
    fi

    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin
export TIDEFS_ROOT_AUTHENTICATION_KEY_HEX=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /run/tidefs/import /tmp/validation/ublk

echo "=== TideFS ublk Completion Artifact Validation ==="
echo "kernel=$(uname -r 2>/dev/null || echo unknown)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"
echo ""

KVER=$(uname -r 2>/dev/null || echo unknown)
case "$KVER" in
  7.*) echo "PASS: linux_7_0_kernel $KVER" ;;
  *)   echo "FAIL: linux_7_0_kernel expected Linux 7.0 guest kernel, got $KVER"; poweroff -f ;;
esac

if [ -e /dev/ublk-control ]; then
    echo "PASS: ublk_control_device"
elif [ -f /lib/modules/ublk_drv.ko ]; then
    if insmod /lib/modules/ublk_drv.ko 2>/tmp/ublk-insmod.err; then
        if [ -e /dev/ublk-control ]; then
            echo "PASS: ublk_module_loaded"
        else
            mknod /dev/ublk-control c 246 0 2>/dev/null || true
        fi
    else
        echo "FAIL: ublk_module_loaded $(cat /tmp/ublk-insmod.err 2>/dev/null || echo load-failed)"
        poweroff -f
    fi
else
    mknod /dev/ublk-control c 246 0 2>/dev/null || true
fi

if [ ! -e /dev/ublk-control ]; then
    echo "FAIL: ublk_control_device missing"
    poweroff -f
fi

COMPLETION_ARTIFACT=/tmp/validation/ublk/qid-tag-completion-runtime.json
BACKING_FILE=/tmp/tidefs-ublk-completion.img
DAEMON_LOG=/tmp/tidefs-ublk-daemon.log

rm -f "$BACKING_FILE"

echo "--- Start ublk daemon ---"
TIDEFS_UBLK_COMPLETION_ARTIFACT="$COMPLETION_ARTIFACT" \
TIDEFS_UBLK_COMPLETION_ARTIFACT_MAX_COMPLETIONS=64 \
  tidefs-block-volume-adapter-daemon ublk-serve \
    --backing-file "$BACKING_FILE" \
    --create \
    --block-size 4096 \
    --block-count 128 \
    --nr-hw-queues 1 \
    --drain-deadline 10 \
  > "$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
echo "daemon_pid=$DAEMON_PID"

FOUND=0
for _ in $(seq 1 60); do
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "FAIL: ublk daemon exited before /dev/ublkb0 appeared"
        break
    fi
    if [ -b /dev/ublkb0 ]; then
        FOUND=1
        break
    fi
    sleep 1
done

if [ "$FOUND" -ne 1 ]; then
    echo "FAIL: ublkb0 did not appear"
    echo "--- daemon log ---"
    cat "$DAEMON_LOG" 2>&1 || true
    poweroff -f
fi

echo "PASS: ublkb0 appeared"
blockdev --getsize64 /dev/ublkb0 2>/dev/null || true

echo "--- Drive real ublk I/O ---"
fio --name=completion-randrw --rw=randrw --rwmixread=50 --size=64K \
    --offset=0 --direct=1 --bs=4k --iodepth=2 --filename=/dev/ublkb0 \
    --allow_file_create=0 --output=/tmp/fio-randrw.json --output-format=json \
    --end_fsync=1 2>/tmp/fio-randrw.err
if [ $? -ne 0 ]; then
    echo "FAIL: fio randrw"
    cat /tmp/fio-randrw.err 2>&1 || true
    cat "$DAEMON_LOG" 2>&1 || true
    poweroff -f
fi

fio --name=completion-read --rw=read --size=16K --offset=0 --direct=1 \
    --bs=4k --iodepth=1 --filename=/dev/ublkb0 --allow_file_create=0 \
    --output=/tmp/fio-read.json --output-format=json 2>/tmp/fio-read.err
if [ $? -ne 0 ]; then
    echo "FAIL: fio read"
    cat /tmp/fio-read.err 2>&1 || true
    cat "$DAEMON_LOG" 2>&1 || true
    poweroff -f
fi
echo "PASS: fio workloads"

echo "--- Stop ublk daemon ---"
kill -TERM "$DAEMON_PID" 2>/dev/null || true
DETACHED=0
for _ in $(seq 1 30); do
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        DETACHED=1
        break
    fi
    sleep 1
done

if kill -0 "$DAEMON_PID" 2>/dev/null; then
    echo "FAIL: ublk daemon still running after graceful shutdown"
    cat "$DAEMON_LOG" 2>&1 || true
    kill -KILL "$DAEMON_PID" 2>/dev/null || true
    poweroff -f
fi
echo "PASS: ublk daemon stopped"

if [ ! -s "$COMPLETION_ARTIFACT" ]; then
    echo "FAIL: completion artifact missing"
    echo "--- daemon log ---"
    cat "$DAEMON_LOG" 2>&1 || true
    poweroff -f
fi

echo "=== BEGIN UBLK COMPLETION ARTIFACT JSON ==="
cat "$COMPLETION_ARTIFACT"
echo "=== END UBLK COMPLETION ARTIFACT JSON ==="
echo "PASS: completion artifact emitted"
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
      -append "console=ttyS0 quiet init=/init" \
      -nographic \
      -m 2048 \
      "''${QEMU_ACCEL[@]}" \
      -drive file="$DISK_IMG",format=raw,if=virtio \
      > "$QEMU_OUT" 2> "$QEMU_ERR"
    QEMU_EXIT=$?
    set -e

    echo ""
    echo "  QEMU exit code: $QEMU_EXIT"
    echo "  QEMU stdout:    $QEMU_OUT"
    echo "  QEMU stderr:    $QEMU_ERR"

    echo ""
    echo "=== QEMU Guest Output (tail 120 lines) ==="
    tail -120 "$QEMU_OUT" 2>/dev/null || echo "(no stdout)"

    awk '
      /BEGIN UBLK COMPLETION ARTIFACT JSON/ { in_json = 1; next }
      /END UBLK COMPLETION ARTIFACT JSON/ { in_json = 0; next }
      in_json { print }
    ' "$QEMU_OUT" > "$HOST_ARTIFACT"

    if [ "$QEMU_EXIT" -ne 0 ]; then
      echo "FAIL: QEMU exited with $QEMU_EXIT" >&2
      exit "$QEMU_EXIT"
    fi
    if [ ! -s "$HOST_ARTIFACT" ]; then
      echo "FAIL: no completion artifact was extracted from QEMU output" >&2
      exit 1
    fi

    if "$XTASK" validate-ublk-completion-artifact "$HOST_ARTIFACT" > "$VERIFY_LOG" 2>&1; then
      cat "$VERIFY_LOG"
      cat > "$SUMMARY_JSON" <<SUMMARY
{
  "test": "qemu-ublk-completion-artifact",
  "version": 1,
  "validation_tier": "Tier 3 QEMU guest ublk/block-volume runtime",
  "qemu_exit_code": $QEMU_EXIT,
  "artifact": "$HOST_ARTIFACT",
  "verifier": "pass"
}
SUMMARY
      echo "SUMMARY: qemu-ublk-completion-artifact PASS"
      echo "artifact=$HOST_ARTIFACT"
      echo "validation_dir=$VALIDATION_DIR"
    else
      cat "$VERIFY_LOG" >&2 || true
      echo "FAIL: completion artifact verifier rejected $HOST_ARTIFACT" >&2
      exit 1
    fi
  '';
in
{
  ublkCompletionArtifactValidation = ublkCompletionArtifactValidationScript;
}
