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
    BLKDISCARD="${pkgs.util-linux}/bin/blkdiscard"
    TIDEFSCTL="${tidefsPackage}/bin/tidefsctl"
    XTASK="${tidefsPackage}/bin/tidefs-xtask"
    MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"

    TMPDIR="''${TIDEFS_UBLK_COMPLETION_TMPDIR:-/tmp/tidefs-ublk-completion-artifact}"
    VALIDATION_DIR="''${TIDEFS_UBLK_COMPLETION_VALIDATION_DIR:-/tmp/tidefs-validation/ublk}"
    TIMEOUT_SEC="''${TIDEFS_UBLK_COMPLETION_TIMEOUT:-600}"
    DISK_SIZE_MB="''${TIDEFS_UBLK_COMPLETION_DISK_MB:-256}"
    SCENARIO="''${TIDEFS_UBLK_COMPLETION_SCENARIO:-qemu-ublk-smoke}"
    KEEP_TMP=0

    usage() {
      cat <<USAGE
Usage: tidefs-ublk-completion-artifact-validation [--timeout SECONDS] [--disk-size-mb MB] [--validation-dir DIR] [--scenario NAME] [--keep-tmp]

Boot Linux 7.0 in QEMU, create a Pool-backed named volume, run the real
tidefsctl ublk attach path, emit a qid/tag completion artifact, and validate it
with tidefs-xtask.

Options:
  --timeout SECONDS     QEMU boot timeout (default: $TIMEOUT_SEC)
  --disk-size-mb MB     Scratch disk size (default: $DISK_SIZE_MB)
  --validation-dir DIR  Host output directory (default: $VALIDATION_DIR)
  --scenario NAME       qemu-ublk-smoke or qemu-ublk-qid-tag-runtime
  --keep-tmp            Do not remove temporary initramfs workspace
  --help, -h            Show this message
USAGE
    }

    while [ "$#" -gt 0 ]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --disk-size-mb) DISK_SIZE_MB="$2"; shift 2 ;;
        --validation-dir) VALIDATION_DIR="$2"; shift 2 ;;
        --scenario) SCENARIO="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done

    case "$SCENARIO" in
      qemu-ublk-smoke)
        NR_HW_QUEUES=1
        MAX_COMPLETIONS=64
        QEMU_SMP=1
        BLOCK_COUNT=128
        RUN_ERROR_INJECTION=0
        ;;
      qemu-ublk-qid-tag-runtime)
        NR_HW_QUEUES=2
        MAX_COMPLETIONS=1024
        QEMU_SMP=2
        BLOCK_COUNT=4096
        RUN_ERROR_INJECTION=1
        ;;
      *)
        echo "ERROR: unsupported scenario: $SCENARIO" >&2
        usage >&2
        exit 2
        ;;
    esac

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO" "$GZIP" "$FIO" "$BLKDISCARD" "$TIDEFSCTL" "$XTASK"; do
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
    echo "  tidefs-xtask:   $XTASK"
    echo "  QEMU:           $QEMU_BIN"
    echo "  Accel:          $QEMU_ACCEL_LABEL"
    echo "  Scenario:       $SCENARIO"
    echo "  Queues:         $NR_HW_QUEUES"
    echo "  Timeout:        ''${TIMEOUT_SEC}s"
    echo "  Validation dir: $VALIDATION_DIR"
    echo ""

    WORK_DIR="$TMPDIR/validation-$$"
    RUN_DIR="$WORK_DIR/initrd"
    DISK_IMG="$WORK_DIR/scratch.img"
    QEMU_OUT="$VALIDATION_DIR/qemu-stdout.log"
    QEMU_ERR="$VALIDATION_DIR/qemu-stderr.log"
    HOST_ARTIFACT="$VALIDATION_DIR/qid-tag-completion-runtime.json"
    HOST_STARTED_EXPORT_ARTIFACT="$VALIDATION_DIR/started-export-admission-runtime.json"
    HOST_ERROR_ARTIFACT="$VALIDATION_DIR/qid-tag-completion-error-injection-runtime.json"
    HOST_ERROR_STARTED_EXPORT_ARTIFACT="$VALIDATION_DIR/started-export-admission-error-injection-runtime.json"
    VERIFY_LOG="$VALIDATION_DIR/ublk-completion-verify.log"
    STARTED_EXPORT_VERIFY_LOG="$VALIDATION_DIR/ublk-started-export-admission-verify.log"
    ERROR_VERIFY_LOG="$VALIDATION_DIR/ublk-completion-error-injection-verify.log"
    ERROR_STARTED_EXPORT_VERIFY_LOG="$VALIDATION_DIR/ublk-started-export-admission-error-injection-verify.log"
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
      deps=$("$LDD_BIN" "$BUSYBOX" "$FIO" "$BLKDISCARD" "$TIDEFSCTL" 2>/dev/null | grep -o '/nix/store/[^ ]*' | sort -u || true)
      for lib in $deps; do
        if [ -f "$lib" ]; then
          local lib_dir
          lib_dir=$(dirname "$lib")
          mkdir -p "$RUN_DIR$lib_dir"
          cp "$lib" "$RUN_DIR$lib" 2>/dev/null || true
        fi
      done

      for binary in "$BUSYBOX" "$FIO" "$BLKDISCARD" "$TIDEFSCTL"; do
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
                    test seq blockdev sed awk uname date true false dd cmp tr; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done
    copy_binary_to_bin "$FIO" fio
    copy_binary_to_bin "$BLKDISCARD" blkdiscard
    copy_binary_to_bin "$TIDEFSCTL" tidefsctl
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

    cat > "$RUN_DIR/etc/ublk-validation-env" <<ENV
SCENARIO='$SCENARIO'
NR_HW_QUEUES='$NR_HW_QUEUES'
MAX_COMPLETIONS='$MAX_COMPLETIONS'
BLOCK_COUNT='$BLOCK_COUNT'
RUN_ERROR_INJECTION='$RUN_ERROR_INJECTION'
ENV

    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin
export TIDEFS_ROOT_AUTHENTICATION_KEY_HEX=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
. /etc/ublk-validation-env

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
STARTED_EXPORT_ARTIFACT=/tmp/validation/ublk/started-export-admission-runtime.json
ERROR_COMPLETION_ARTIFACT=/tmp/validation/ublk/qid-tag-completion-error-injection-runtime.json
ERROR_STARTED_EXPORT_ARTIFACT=/tmp/validation/ublk/started-export-admission-error-injection-runtime.json
POOL_DEVICE=/dev/vda
POOL_NAME=ublk_completion_pool
VOLUME_NAME=completion
ERROR_VOLUME_NAME=completion_error
VOLUME_SIZE_BYTES=$((BLOCK_COUNT * 4096))
SHRUNK_VOLUME_SIZE_BYTES=$((VOLUME_SIZE_BYTES / 2))
RETAINED_OFFSET=0
DISCARD_OFFSET=65536
WRITE_ZEROES_OFFSET=69632
REMOVED_TAIL_OFFSET=$((VOLUME_SIZE_BYTES - 4096))
ATTACH_LOG=/tmp/tidefs-ublk-attach.log
ERROR_ATTACH_LOG=/tmp/tidefs-ublk-attach-error.log
LIFECYCLE_ARTIFACT=/tmp/validation/ublk/lifecycle-completion.json
LIFECYCLE_STARTED_ARTIFACT=/tmp/validation/ublk/lifecycle-started-export.json

create_pool_volumes() {
    for _ in $(seq 1 30); do
        [ -b "$POOL_DEVICE" ] && break
        sleep 1
    done
    if [ ! -b "$POOL_DEVICE" ]; then
        echo "FAIL: Pool device $POOL_DEVICE missing"
        poweroff -f
    fi

    echo "--- Create Pool and named volumes ---"
    if ! tidefsctl pool create "$POOL_NAME" --devices "$POOL_DEVICE" >/tmp/tidefs-pool-create.log 2>&1; then
        echo "FAIL: Pool create"
        cat /tmp/tidefs-pool-create.log 2>&1 || true
        poweroff -f
    fi
    if ! tidefsctl dataset create "$POOL_NAME/$VOLUME_NAME" \
        --type volume --size "$VOLUME_SIZE_BYTES" --devices "$POOL_DEVICE" \
        >/tmp/tidefs-volume-create.log 2>&1; then
        echo "FAIL: named volume create"
        cat /tmp/tidefs-volume-create.log 2>&1 || true
        poweroff -f
    fi
    if [ "$RUN_ERROR_INJECTION" -eq 1 ] && \
       ! tidefsctl dataset create "$POOL_NAME/$ERROR_VOLUME_NAME" \
        --type volume --size "$VOLUME_SIZE_BYTES" --devices "$POOL_DEVICE" \
        >/tmp/tidefs-error-volume-create.log 2>&1; then
        echo "FAIL: error-injection named volume create"
        cat /tmp/tidefs-error-volume-create.log 2>&1 || true
        poweroff -f
    fi
    echo "PASS: Pool-backed named volumes created"
}

start_attach() {
    artifact="$1"
    started_artifact="$2"
    volume_name="$3"
    attach_log="$4"
    artifact_scenario="$5"
    inject_op="$6"
    expected_size="$7"

    rm -f "$artifact" "$started_artifact" "$attach_log"

    echo "--- Attach Pool volume through tidefsctl ($artifact_scenario) ---"
    if [ "$inject_op" = none ]; then
        TIDEFS_UBLK_COMPLETION_ARTIFACT="$artifact" \
        TIDEFS_UBLK_COMPLETION_ARTIFACT_SCENARIO="$artifact_scenario" \
        TIDEFS_UBLK_COMPLETION_ARTIFACT_MAX_COMPLETIONS="$MAX_COMPLETIONS" \
        TIDEFS_UBLK_STARTED_EXPORT_ARTIFACT="$started_artifact" \
          tidefsctl block attach "$POOL_NAME/$volume_name" \
            --nr-hw-queues "$NR_HW_QUEUES" \
            --queue-depth 64 \
            --drain-deadline-secs 10 \
            --devices "$POOL_DEVICE" \
          > "$attach_log" 2>&1 &
    else
        TIDEFS_UBLK_COMPLETION_ARTIFACT="$artifact" \
        TIDEFS_UBLK_COMPLETION_ARTIFACT_SCENARIO="$artifact_scenario" \
        TIDEFS_UBLK_COMPLETION_ARTIFACT_MAX_COMPLETIONS="$MAX_COMPLETIONS" \
        TIDEFS_UBLK_COMPLETION_ARTIFACT_INJECT_ERROR_OP="$inject_op" \
        TIDEFS_UBLK_COMPLETION_ARTIFACT_INJECT_ERROR_RESULT=-5 \
        TIDEFS_UBLK_STARTED_EXPORT_ARTIFACT="$started_artifact" \
          tidefsctl block attach "$POOL_NAME/$volume_name" \
            --nr-hw-queues "$NR_HW_QUEUES" \
            --queue-depth 64 \
            --drain-deadline-secs 10 \
            --devices "$POOL_DEVICE" \
          > "$attach_log" 2>&1 &
    fi
    ATTACH_PID=$!
    echo "attach_pid=$ATTACH_PID"

    FOUND=0
    for _ in $(seq 1 60); do
        if ! kill -0 "$ATTACH_PID" 2>/dev/null; then
            echo "FAIL: tidefsctl block attach exited before /dev/ublkb0 appeared"
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
        echo "--- attach log ---"
        cat "$attach_log" 2>&1 || true
        poweroff -f
    fi

    echo "PASS: ublkb0 appeared"
    observed_size=$(blockdev --getsize64 /dev/ublkb0 2>/dev/null || echo 0)
    if [ "$observed_size" -ne "$expected_size" ]; then
        echo "FAIL: ublkb0 size $observed_size does not match committed named-volume size $expected_size"
        cat "$attach_log" 2>&1 || true
        poweroff -f
    fi
    echo "PASS: ublkb0 committed geometry size=$observed_size"
}

wait_ublk_gone() {
    for _ in $(seq 1 30); do
        [ ! -b /dev/ublkb0 ] && return
        sleep 1
    done
    echo "FAIL: ublkb0 remained after block export teardown"
    poweroff -f
}

make_pattern_file() {
    path="$1"
    pattern="$2"
    head -c 4096 /dev/zero | tr '\000' "$pattern" > "$path"
}

make_zero_file() {
    head -c 4096 /dev/zero > "$1"
}

write_expected_block() {
    expected="$1"
    offset="$2"
    label="$3"
    if ! dd if="$expected" of=/dev/ublkb0 bs=4096 seek=$((offset / 4096)) count=1 conv=fsync >/tmp/dd-write.log 2>&1; then
        echo "FAIL: $label write"
        cat /tmp/dd-write.log 2>&1 || true
        poweroff -f
    fi
}

verify_expected_block() {
    expected="$1"
    offset="$2"
    label="$3"
    if ! dd if=/dev/ublkb0 of=/tmp/actual-block bs=4096 skip=$((offset / 4096)) count=1 >/tmp/dd-read.log 2>&1; then
        echo "FAIL: $label read"
        cat /tmp/dd-read.log 2>&1 || true
        poweroff -f
    fi
    if ! cmp "$expected" /tmp/actual-block >/tmp/cmp.log 2>&1; then
        echo "FAIL: $label contents"
        cat /tmp/cmp.log 2>&1 || true
        poweroff -f
    fi
    echo "PASS: $label"
}

    run_fio_or_fail() {
        label="$1"
        err_path="$2"
        daemon_log="$3"
        shift 3
        if "$@" 2>"$err_path"; then
            return
        fi
        echo "FAIL: $label"
        cat "$err_path" 2>&1 || true
        cat "$daemon_log" 2>&1 || true
        poweroff -f
}

echo "--- Drive real ublk I/O ---"
create_pool_volumes
start_attach "$COMPLETION_ARTIFACT" "$STARTED_EXPORT_ARTIFACT" "$VOLUME_NAME" "$ATTACH_LOG" "$SCENARIO" none "$VOLUME_SIZE_BYTES"
if [ "$SCENARIO" = "qemu-ublk-qid-tag-runtime" ]; then
    run_fio_or_fail "fio randrw multi-queue" /tmp/fio-randrw.err "$ATTACH_LOG" \
        fio --name=completion-randrw --rw=randrw --rwmixread=50 --size=1M \
        --offset=0 --direct=1 --bs=4k --iodepth=16 --numjobs=2 \
        --ioengine=io_uring --filename=/dev/ublkb0 --allow_file_create=0 \
        --group_reporting --output=/tmp/fio-randrw.json --output-format=json \
        --end_fsync=1
    run_fio_or_fail "fio FUA write" /tmp/fio-fua-write.err "$ATTACH_LOG" \
        fio --name=completion-fua-write --rw=write --size=128K --offset=2M \
        --direct=1 --bs=4k --iodepth=4 --ioengine=io_uring --writefua=1 \
        --filename=/dev/ublkb0 --allow_file_create=0 --output=/tmp/fio-fua-write.json \
        --output-format=json --end_fsync=1
    run_fio_or_fail "fio read" /tmp/fio-read.err "$ATTACH_LOG" \
        fio --name=completion-read --rw=read --size=128K --offset=0 --direct=1 \
        --bs=4k --iodepth=8 --numjobs=2 --ioengine=io_uring --filename=/dev/ublkb0 \
        --allow_file_create=0 --group_reporting --output=/tmp/fio-read.json \
        --output-format=json
    if ! blockdev --flushbufs /dev/ublkb0 2>/tmp/blockdev-flushbufs.err; then
        echo "FAIL: blockdev flushbufs"
        cat /tmp/blockdev-flushbufs.err 2>&1 || true
        cat "$ATTACH_LOG" 2>&1 || true
        poweroff -f
    fi
    if ! blkdiscard -f --offset 4194304 --length 65536 /dev/ublkb0 2>/tmp/blkdiscard.err; then
        echo "FAIL: blkdiscard discard"
        cat /tmp/blkdiscard.err 2>&1 || true
        cat "$ATTACH_LOG" 2>&1 || true
        poweroff -f
    fi
    if ! blkdiscard -z -f --offset 4259840 --length 65536 /dev/ublkb0 2>/tmp/blkdiscard-zero.err; then
        echo "FAIL: blkdiscard zeroout"
        cat /tmp/blkdiscard-zero.err 2>&1 || true
        cat "$ATTACH_LOG" 2>&1 || true
        poweroff -f
    fi
else
    run_fio_or_fail "fio randrw" /tmp/fio-randrw.err "$ATTACH_LOG" \
        fio --name=completion-randrw --rw=randrw --rwmixread=50 --size=64K \
        --offset=0 --direct=1 --bs=4k --iodepth=2 --filename=/dev/ublkb0 \
        --allow_file_create=0 --output=/tmp/fio-randrw.json --output-format=json \
        --end_fsync=1
    run_fio_or_fail "fio read" /tmp/fio-read.err "$ATTACH_LOG" \
        fio --name=completion-read --rw=read --size=16K --offset=0 --direct=1 \
        --bs=4k --iodepth=1 --filename=/dev/ublkb0 --allow_file_create=0 \
        --output=/tmp/fio-read.json --output-format=json
fi
echo "PASS: fio workloads"

make_pattern_file /tmp/retained-pattern R
make_pattern_file /tmp/discard-pattern D
make_pattern_file /tmp/write-zeroes-pattern Z
make_pattern_file /tmp/removed-tail-pattern T
make_zero_file /tmp/zero-pattern

write_expected_block /tmp/retained-pattern "$RETAINED_OFFSET" "retained-prefix pattern"
write_expected_block /tmp/discard-pattern "$DISCARD_OFFSET" "discard-range pattern"
write_expected_block /tmp/write-zeroes-pattern "$WRITE_ZEROES_OFFSET" "write-zeroes-range pattern"
write_expected_block /tmp/removed-tail-pattern "$REMOVED_TAIL_OFFSET" "removed-tail pattern"
if ! blockdev --flushbufs /dev/ublkb0 2>/tmp/lifecycle-pattern-flush.err; then
    echo "FAIL: flush lifecycle patterns"
    cat /tmp/lifecycle-pattern-flush.err 2>&1 || true
    poweroff -f
fi
if ! blkdiscard -f --offset "$DISCARD_OFFSET" --length 4096 /dev/ublkb0 2>/tmp/lifecycle-discard.err; then
    echo "FAIL: discard lifecycle range"
    cat /tmp/lifecycle-discard.err 2>&1 || true
    poweroff -f
fi
if ! blkdiscard -z -f --offset "$WRITE_ZEROES_OFFSET" --length 4096 /dev/ublkb0 2>/tmp/lifecycle-write-zeroes.err; then
    echo "FAIL: write zeroes lifecycle range"
    cat /tmp/lifecycle-write-zeroes.err 2>&1 || true
    poweroff -f
fi
if ! blockdev --flushbufs /dev/ublkb0 2>/tmp/lifecycle-zero-flush.err; then
    echo "FAIL: flush discard and write zeroes"
    cat /tmp/lifecycle-zero-flush.err 2>&1 || true
    poweroff -f
fi
verify_expected_block /tmp/retained-pattern "$RETAINED_OFFSET" "retained prefix before reopen"
verify_expected_block /tmp/zero-pattern "$DISCARD_OFFSET" "discard is zero before reopen"
verify_expected_block /tmp/zero-pattern "$WRITE_ZEROES_OFFSET" "write zeroes is zero before reopen"
verify_expected_block /tmp/removed-tail-pattern "$REMOVED_TAIL_OFFSET" "tail pattern before shrink"

set +e
tidefsctl dataset resize "$POOL_NAME/$VOLUME_NAME" --size "$SHRUNK_VOLUME_SIZE_BYTES" \
    --devices "$POOL_DEVICE" >/tmp/active-resize.log 2>&1
ACTIVE_RESIZE_RC=$?
set -e
if [ "$ACTIVE_RESIZE_RC" -eq 0 ]; then
    echo "FAIL: resize succeeded while the volume export was active"
    cat /tmp/active-resize.log 2>&1 || true
    poweroff -f
fi
echo "PASS: active volume export refused concurrent resize"

stop_attach() {
    attach_log="$1"
    echo "--- Stop tidefsctl block attach ---"
    kill -TERM "$ATTACH_PID" 2>/dev/null || true
    for _ in $(seq 1 30); do
        if ! kill -0 "$ATTACH_PID" 2>/dev/null; then
            break
        fi
        sleep 1
    done

    if kill -0 "$ATTACH_PID" 2>/dev/null; then
        echo "FAIL: tidefsctl block attach still running after graceful shutdown"
        cat "$attach_log" 2>&1 || true
        kill -KILL "$ATTACH_PID" 2>/dev/null || true
        poweroff -f
    fi
    echo "PASS: tidefsctl block attach stopped and Pool exported"
}

stop_attach "$ATTACH_LOG"
wait_ublk_gone

echo "--- Reopen committed volume data ---"
start_attach "$LIFECYCLE_ARTIFACT" "$LIFECYCLE_STARTED_ARTIFACT" "$VOLUME_NAME" \
    "$ATTACH_LOG" "$SCENARIO" none "$VOLUME_SIZE_BYTES"
verify_expected_block /tmp/retained-pattern "$RETAINED_OFFSET" "retained prefix after reopen"
verify_expected_block /tmp/zero-pattern "$DISCARD_OFFSET" "discard stays zero after reopen"
verify_expected_block /tmp/zero-pattern "$WRITE_ZEROES_OFFSET" "write zeroes stays zero after reopen"
verify_expected_block /tmp/removed-tail-pattern "$REMOVED_TAIL_OFFSET" "tail persists before shrink"
stop_attach "$ATTACH_LOG"
wait_ublk_gone

echo "--- Shrink committed volume geometry ---"
if ! tidefsctl dataset resize "$POOL_NAME/$VOLUME_NAME" --size "$SHRUNK_VOLUME_SIZE_BYTES" \
    --devices "$POOL_DEVICE" >/tmp/shrink-volume.log 2>&1; then
    echo "FAIL: shrink named volume"
    cat /tmp/shrink-volume.log 2>&1 || true
    poweroff -f
fi
start_attach "$LIFECYCLE_ARTIFACT" "$LIFECYCLE_STARTED_ARTIFACT" "$VOLUME_NAME" \
    "$ATTACH_LOG" "$SCENARIO" none "$SHRUNK_VOLUME_SIZE_BYTES"
verify_expected_block /tmp/retained-pattern "$RETAINED_OFFSET" "retained prefix after shrink"
verify_expected_block /tmp/zero-pattern "$DISCARD_OFFSET" "discard stays zero after shrink"
verify_expected_block /tmp/zero-pattern "$WRITE_ZEROES_OFFSET" "write zeroes stays zero after shrink"
stop_attach "$ATTACH_LOG"
wait_ublk_gone

echo "--- Regrow committed volume geometry ---"
if ! tidefsctl dataset resize "$POOL_NAME/$VOLUME_NAME" --size "$VOLUME_SIZE_BYTES" \
    --devices "$POOL_DEVICE" >/tmp/regrow-volume.log 2>&1; then
    echo "FAIL: regrow named volume"
    cat /tmp/regrow-volume.log 2>&1 || true
    poweroff -f
fi
start_attach "$LIFECYCLE_ARTIFACT" "$LIFECYCLE_STARTED_ARTIFACT" "$VOLUME_NAME" \
    "$ATTACH_LOG" "$SCENARIO" none "$VOLUME_SIZE_BYTES"
verify_expected_block /tmp/retained-pattern "$RETAINED_OFFSET" "retained prefix after regrow"
verify_expected_block /tmp/zero-pattern "$DISCARD_OFFSET" "discard stays zero after regrow"
verify_expected_block /tmp/zero-pattern "$WRITE_ZEROES_OFFSET" "write zeroes stays zero after regrow"
verify_expected_block /tmp/zero-pattern "$REMOVED_TAIL_OFFSET" "removed tail stays zero after regrow"

set +e
tidefsctl dataset destroy "$POOL_NAME/$VOLUME_NAME" --devices "$POOL_DEVICE" \
    >/tmp/active-destroy.log 2>&1
ACTIVE_DESTROY_RC=$?
set -e
if [ "$ACTIVE_DESTROY_RC" -eq 0 ]; then
    echo "FAIL: destroy succeeded while the volume export was active"
    cat /tmp/active-destroy.log 2>&1 || true
    poweroff -f
fi
echo "PASS: active volume export refused concurrent destroy"
stop_attach "$ATTACH_LOG"
wait_ublk_gone

echo "--- Destroy committed volume and refuse later attach ---"
if ! tidefsctl dataset destroy "$POOL_NAME/$VOLUME_NAME" --devices "$POOL_DEVICE" \
    >/tmp/destroy-volume.log 2>&1; then
    echo "FAIL: destroy named volume"
    cat /tmp/destroy-volume.log 2>&1 || true
    poweroff -f
fi
set +e
tidefsctl block attach "$POOL_NAME/$VOLUME_NAME" --devices "$POOL_DEVICE" \
    >/tmp/destroyed-attach.log 2>&1
DESTROYED_ATTACH_RC=$?
set -e
if [ "$DESTROYED_ATTACH_RC" -eq 0 ]; then
    echo "FAIL: destroyed volume attached successfully"
    cat /tmp/destroyed-attach.log 2>&1 || true
    poweroff -f
fi
if [ -b /dev/ublkb0 ]; then
    echo "FAIL: destroyed volume created /dev/ublkb0"
    cat /tmp/destroyed-attach.log 2>&1 || true
    poweroff -f
fi
echo "PASS: destroyed volume refuses later attach"

if [ "$RUN_ERROR_INJECTION" -eq 1 ]; then
    start_attach "$ERROR_COMPLETION_ARTIFACT" "$ERROR_STARTED_EXPORT_ARTIFACT" "$ERROR_VOLUME_NAME" "$ERROR_ATTACH_LOG" "qemu-ublk-qid-tag-runtime-error-injection" write "$VOLUME_SIZE_BYTES"
    run_fio_or_fail "fio error-injection pre-read" /tmp/fio-error-read.err "$ERROR_ATTACH_LOG" \
        fio --name=completion-error-preread --rw=read --size=4k --offset=0 \
        --direct=1 --bs=4k --iodepth=1 --filename=/dev/ublkb0 \
        --allow_file_create=0 --output=/tmp/fio-error-read.json \
        --output-format=json
    set +e
    fio --name=completion-error-write --rw=write --size=4k --offset=0 \
        --direct=1 --bs=4k --iodepth=1 --filename=/dev/ublkb0 \
        --allow_file_create=0 --output=/tmp/fio-error-write.json \
        --output-format=json 2>/tmp/fio-error-write.err
    ERROR_WRITE_RC=$?
    set -e
    if [ "$ERROR_WRITE_RC" -eq 0 ]; then
        echo "FAIL: error injection write unexpectedly succeeded"
        cat /tmp/fio-error-write.json 2>&1 || true
        cat "$ERROR_ATTACH_LOG" 2>&1 || true
        poweroff -f
    fi
    echo "PASS: error injection write refused rc=$ERROR_WRITE_RC"
    stop_attach "$ERROR_ATTACH_LOG"
fi

if [ ! -s "$COMPLETION_ARTIFACT" ]; then
    echo "FAIL: completion artifact missing"
    echo "--- attach log ---"
    cat "$ATTACH_LOG" 2>&1 || true
    poweroff -f
fi
if [ ! -s "$STARTED_EXPORT_ARTIFACT" ]; then
    echo "FAIL: started-export admission artifact missing"
    echo "--- attach log ---"
    cat "$ATTACH_LOG" 2>&1 || true
    poweroff -f
fi
if [ "$RUN_ERROR_INJECTION" -eq 1 ]; then
    if [ ! -s "$ERROR_COMPLETION_ARTIFACT" ]; then
        echo "FAIL: error injection completion artifact missing"
        echo "--- attach log ---"
        cat "$ERROR_ATTACH_LOG" 2>&1 || true
        poweroff -f
    fi
    if [ ! -s "$ERROR_STARTED_EXPORT_ARTIFACT" ]; then
        echo "FAIL: error injection started-export admission artifact missing"
        echo "--- attach log ---"
        cat "$ERROR_ATTACH_LOG" 2>&1 || true
        poweroff -f
    fi
fi

echo "=== BEGIN UBLK COMPLETION ARTIFACT JSON ==="
cat "$COMPLETION_ARTIFACT"
echo "=== END UBLK COMPLETION ARTIFACT JSON ==="
echo "PASS: completion artifact emitted"
echo "=== BEGIN UBLK STARTED EXPORT ADMISSION ARTIFACT JSON ==="
cat "$STARTED_EXPORT_ARTIFACT"
echo "=== END UBLK STARTED EXPORT ADMISSION ARTIFACT JSON ==="
echo "PASS: started-export admission artifact emitted"
if [ "$RUN_ERROR_INJECTION" -eq 1 ]; then
    echo "=== BEGIN UBLK ERROR INJECTION COMPLETION ARTIFACT JSON ==="
    cat "$ERROR_COMPLETION_ARTIFACT"
    echo "=== END UBLK ERROR INJECTION COMPLETION ARTIFACT JSON ==="
    echo "PASS: error injection completion artifact emitted"
    echo "=== BEGIN UBLK ERROR INJECTION STARTED EXPORT ADMISSION ARTIFACT JSON ==="
    cat "$ERROR_STARTED_EXPORT_ARTIFACT"
    echo "=== END UBLK ERROR INJECTION STARTED EXPORT ADMISSION ARTIFACT JSON ==="
    echo "PASS: error injection started-export admission artifact emitted"
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
      -append "console=ttyS0 quiet init=/init" \
      -nographic \
      -m 2048 \
      -smp "$QEMU_SMP" \
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
    awk '
      /BEGIN UBLK STARTED EXPORT ADMISSION ARTIFACT JSON/ { in_json = 1; next }
      /END UBLK STARTED EXPORT ADMISSION ARTIFACT JSON/ { in_json = 0; next }
      in_json { print }
    ' "$QEMU_OUT" > "$HOST_STARTED_EXPORT_ARTIFACT"
    awk '
      /BEGIN UBLK ERROR INJECTION COMPLETION ARTIFACT JSON/ { in_json = 1; next }
      /END UBLK ERROR INJECTION COMPLETION ARTIFACT JSON/ { in_json = 0; next }
      in_json { print }
    ' "$QEMU_OUT" > "$HOST_ERROR_ARTIFACT"
    awk '
      /BEGIN UBLK ERROR INJECTION STARTED EXPORT ADMISSION ARTIFACT JSON/ { in_json = 1; next }
      /END UBLK ERROR INJECTION STARTED EXPORT ADMISSION ARTIFACT JSON/ { in_json = 0; next }
      in_json { print }
    ' "$QEMU_OUT" > "$HOST_ERROR_STARTED_EXPORT_ARTIFACT"

    if [ "$QEMU_EXIT" -ne 0 ]; then
      echo "FAIL: QEMU exited with $QEMU_EXIT" >&2
      exit "$QEMU_EXIT"
    fi
    if [ ! -s "$HOST_ARTIFACT" ]; then
      echo "FAIL: no completion artifact was extracted from QEMU output" >&2
      exit 1
    fi
    if [ ! -s "$HOST_STARTED_EXPORT_ARTIFACT" ]; then
      echo "FAIL: no started-export admission artifact was extracted from QEMU output" >&2
      exit 1
    fi
    if [ "$RUN_ERROR_INJECTION" -eq 1 ] && [ ! -s "$HOST_ERROR_ARTIFACT" ]; then
      echo "FAIL: no error injection completion artifact was extracted from QEMU output" >&2
      exit 1
    fi
    if [ "$RUN_ERROR_INJECTION" -eq 1 ] && [ ! -s "$HOST_ERROR_STARTED_EXPORT_ARTIFACT" ]; then
      echo "FAIL: no error injection started-export admission artifact was extracted from QEMU output" >&2
      exit 1
    fi

    if "$XTASK" validate-ublk-completion-artifact "$HOST_ARTIFACT" > "$VERIFY_LOG" 2>&1; then
      cat "$VERIFY_LOG"
    else
      cat "$VERIFY_LOG" >&2 || true
      echo "FAIL: completion artifact verifier rejected $HOST_ARTIFACT" >&2
      exit 1
    fi

    if "$XTASK" validate-ublk-started-export-admission-artifact "$HOST_STARTED_EXPORT_ARTIFACT" > "$STARTED_EXPORT_VERIFY_LOG" 2>&1; then
      cat "$STARTED_EXPORT_VERIFY_LOG"
    else
      cat "$STARTED_EXPORT_VERIFY_LOG" >&2 || true
      echo "FAIL: started-export admission artifact verifier rejected $HOST_STARTED_EXPORT_ARTIFACT" >&2
      exit 1
    fi

    ERROR_COMPLETION_VERIFIER="not-run"
    ERROR_STARTED_EXPORT_VERIFIER="not-run"
    if [ "$RUN_ERROR_INJECTION" -eq 1 ]; then
      if "$XTASK" validate-ublk-completion-artifact "$HOST_ERROR_ARTIFACT" > "$ERROR_VERIFY_LOG" 2>&1; then
        cat "$ERROR_VERIFY_LOG"
        ERROR_COMPLETION_VERIFIER="pass"
      else
        cat "$ERROR_VERIFY_LOG" >&2 || true
        echo "FAIL: error injection completion artifact verifier rejected $HOST_ERROR_ARTIFACT" >&2
        exit 1
      fi
      if "$XTASK" validate-ublk-started-export-admission-artifact "$HOST_ERROR_STARTED_EXPORT_ARTIFACT" > "$ERROR_STARTED_EXPORT_VERIFY_LOG" 2>&1; then
        cat "$ERROR_STARTED_EXPORT_VERIFY_LOG"
        ERROR_STARTED_EXPORT_VERIFIER="pass"
      else
        cat "$ERROR_STARTED_EXPORT_VERIFY_LOG" >&2 || true
        echo "FAIL: error injection started-export admission artifact verifier rejected $HOST_ERROR_STARTED_EXPORT_ARTIFACT" >&2
        exit 1
      fi
    fi

    cat > "$SUMMARY_JSON" <<SUMMARY
{
  "test": "qemu-ublk-completion-artifact",
  "version": 3,
  "scenario": "$SCENARIO",
  "validation_tier": "Tier 3 QEMU guest ublk/block-volume runtime",
  "evidence_scope": "bounded qid/tag completion runtime row; not block-device product readiness, release readiness, or successor/comparator evidence",
  "qemu_exit_code": $QEMU_EXIT,
  "nr_hw_queues": $NR_HW_QUEUES,
  "queue_depth": 64,
  "completion_artifact": "$HOST_ARTIFACT",
  "started_export_admission_artifact": "$HOST_STARTED_EXPORT_ARTIFACT",
  "error_injection_completion_artifact": "$HOST_ERROR_ARTIFACT",
  "error_injection_started_export_admission_artifact": "$HOST_ERROR_STARTED_EXPORT_ARTIFACT",
  "completion_verifier": "pass",
  "started_export_admission_verifier": "pass",
  "error_injection_completion_verifier": "$ERROR_COMPLETION_VERIFIER",
  "error_injection_started_export_admission_verifier": "$ERROR_STARTED_EXPORT_VERIFIER"
}
SUMMARY
    echo "SUMMARY: qemu-ublk-completion-artifact PASS"
    echo "scenario=$SCENARIO"
    echo "completion_artifact=$HOST_ARTIFACT"
    echo "started_export_admission_artifact=$HOST_STARTED_EXPORT_ARTIFACT"
    if [ "$RUN_ERROR_INJECTION" -eq 1 ]; then
      echo "error_injection_completion_artifact=$HOST_ERROR_ARTIFACT"
      echo "error_injection_started_export_admission_artifact=$HOST_ERROR_STARTED_EXPORT_ARTIFACT"
    fi
    echo "validation_dir=$VALIDATION_DIR"
  '';
in
{
  ublkCompletionArtifactValidation = ublkCompletionArtifactValidationScript;
}
