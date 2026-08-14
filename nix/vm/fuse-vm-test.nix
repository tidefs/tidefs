# TideFS FUSE VM smoke validation.
#
# Nix builds the Linux 7.0 kernel, TideFS workspace binaries, and this runner
# script. The runner constructs a tiny initrd and launches QEMU from the caller,
# outside the Nix build sandbox.
{
  pkgs,
  linuxKernel_7_0,
  tidefsPackage,
  ackValidationPackage,
  dataShapeValidationPackage,
}:

let
  syncWriteCrashHelper = pkgs.pkgsStatic.stdenv.mkDerivation {
    pname = "tidefs-sync-write-crash-helper";
    version = "1";
    dontUnpack = true;
    buildPhase = ''
      $CC -O2 -Wall -Wextra -Werror ${./tidefs-sync-write-crash-helper.c} \
        -o tidefs-sync-write-crash-helper
    '';
    installPhase = ''
      mkdir -p $out/bin
      install -m 0755 tidefs-sync-write-crash-helper $out/bin/
    '';
  };
in
pkgs.writeShellScriptBin "tidefs-fuse-vm-test-runner" ''
  set -euo pipefail

  export PATH="${pkgs.coreutils}/bin:${pkgs.gnugrep}/bin:${pkgs.gnused}/bin:${pkgs.gawk}/bin:${pkgs.findutils}/bin:${pkgs.glibc.bin}/bin:${pkgs.cpio}/bin:${pkgs.xz}/bin:${pkgs.qemu}/bin:$PATH"

  QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
  BUSYBOX="${pkgs.busybox}/bin/busybox"
  CPIO="${pkgs.cpio}/bin/cpio"
  XZ_BIN="${pkgs.xz}/bin/xz"
  KERNEL_IMG="${linuxKernel_7_0}/bzImage"
  MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"
  TIDEFSCTL="${tidefsPackage}/bin/tidefsctl"
  ACK_VALIDATION="${ackValidationPackage}/bin/storage-intent-ack-runtime-validation"
  DATA_SHAPE_VALIDATION="${dataShapeValidationPackage}/bin/storage-intent-data-shape-runtime-validation"
  SYNC_WRITE_CRASH_HELPER="${syncWriteCrashHelper}/bin/tidefs-sync-write-crash-helper"
  BASE64="${pkgs.coreutils}/bin/base64"
  B3SUM="${pkgs.b3sum}/bin/b3sum"
  JQ="${pkgs.jq}/bin/jq"

  TMPDIR="''${TIDEFS_FUSE_VM_TEST_TMPDIR:-/tmp/tidefs-fuse-vm-test}"
  TIMEOUT_SEC="''${TIDEFS_FUSE_VM_TEST_TIMEOUT:-900}"
  VALIDATION_DIR="''${TIDEFS_FUSE_VM_TEST_VALIDATION_DIR:-/tmp/tidefs-validation/fuse-vm-test}"
  ACK_RECEIPT_RUNTIME=0
  DATA_SHAPE_RUNTIME=0
  SYNC_WRITE_CRASH=0
  KEEP_TMP=0

  usage() {
    cat <<'EOF'
Usage: tidefs-fuse-vm-test-runner [OPTIONS]

Build a tiny Linux 7.0 initrd from Nix-built artifacts and launch QEMU outside
the Nix sandbox. The guest runs the tidefsFuseVmTest validation sequence:
kernel check, /dev/fuse check, and the canonical pool create, mount, mounted
I/O, clean remount, and persistence lifecycle. Focused runtime options replace
that default sequence and finish after returning their typed output.

Options:
  --timeout SECONDS              QEMU runtime timeout (default: 900)
  --validation-dir DIR           Host directory for qemu-boot.log and summary
  --ack-receipt-runtime          Run the mounted acknowledgment receipt rows
  --data-shape-runtime           Run the data-shape helper evidence rows
  --sync-write-crash             Crash-test O_SYNC/O_DSYNC with both cache modes
  --keep-tmp                     Keep generated initrd/run directory
  --help, -h                     Show this help
EOF
  }

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --timeout)
        TIMEOUT_SEC="$2"
        shift 2
        ;;
      --validation-dir)
        VALIDATION_DIR="$2"
        shift 2
        ;;
      --ack-receipt-runtime)
        ACK_RECEIPT_RUNTIME=1
        shift
        ;;
      --data-shape-runtime)
        DATA_SHAPE_RUNTIME=1
        shift
        ;;
      --sync-write-crash)
        SYNC_WRITE_CRASH=1
        shift
        ;;
      --keep-tmp)
        KEEP_TMP=1
        shift
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        echo "ERROR: unknown option: $1" >&2
        usage >&2
        exit 2
        ;;
    esac
  done

  FOCUSED_MODE_COUNT=$((ACK_RECEIPT_RUNTIME + DATA_SHAPE_RUNTIME + SYNC_WRITE_CRASH))
  if [ "$FOCUSED_MODE_COUNT" -gt 1 ]; then
    echo "ERROR: focused runtime options are mutually exclusive" >&2
    exit 2
  fi

  if [ ! -e /dev/kvm ]; then
    echo "ENVIRONMENT REFUSAL: /dev/kvm not available" >&2
    exit 2
  fi

  for dep in "$QEMU_BIN" "$BUSYBOX" "$CPIO" "$XZ_BIN" "$KERNEL_IMG" "$TIDEFSCTL"; do
    if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
      echo "ERROR: dependency not found: $dep" >&2
      exit 2
    fi
  done
  if [ "$ACK_RECEIPT_RUNTIME" -eq 1 ]; then
    for dep in "$ACK_VALIDATION" "$BASE64" "$B3SUM" "$JQ"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ERROR: dependency not found: $dep" >&2
        exit 2
      fi
    done
  fi
  if [ "$DATA_SHAPE_RUNTIME" -eq 1 ]; then
    for dep in "$DATA_SHAPE_VALIDATION" "$BASE64" "$B3SUM" "$JQ"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ERROR: dependency not found: $dep" >&2
        exit 2
      fi
    done
  fi
  if [ "$SYNC_WRITE_CRASH" -eq 1 ] && [ ! -x "$SYNC_WRITE_CRASH_HELPER" ]; then
    echo "ERROR: dependency not found: $SYNC_WRITE_CRASH_HELPER" >&2
    exit 2
  fi

  echo "=== TideFS FUSE VM Test ==="
  echo "  Kernel:          $KERNEL_IMG"
  echo "  Module dir:      $MODULE_DIR"
  echo "  QEMU:            $QEMU_BIN"
  echo "  TideFS control:  $TIDEFSCTL"
  if [ "$ACK_RECEIPT_RUNTIME" -eq 1 ]; then
    echo "  Ack validator:   $ACK_VALIDATION"
  fi
  if [ "$DATA_SHAPE_RUNTIME" -eq 1 ]; then
    echo "  Data-shape validator: $DATA_SHAPE_VALIDATION"
  fi
  echo "  Validation dir:  $VALIDATION_DIR"
  echo "  Timeout:         ''${TIMEOUT_SEC}s"

  RUN_DIR="$TMPDIR/run-$$"
  mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib,lib64,lib/modules,usr/lib,nix/store}
  cleanup() {
    if [ "$KEEP_TMP" -eq 1 ]; then
      echo "  Keeping temp directory: $RUN_DIR"
    else
      rm -rf "$RUN_DIR"
    fi
  }
  trap cleanup EXIT

  copy_binary() {
    local src="$1"
    local dst="$2"
    cp -L "$src" "$dst"
    chmod +x "$dst"
  }

  copy_runtime_deps() {
    local bin lib lib_base dst
    for bin in "$@"; do
      ldd "$bin" 2>/dev/null \
        | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^\//) { sub(/\(.*/, "", $i); print $i } }' \
        | sort -u \
        | while IFS= read -r lib; do
          [ -f "$lib" ] || continue
          lib_base="$(basename "$lib")"
          dst="$RUN_DIR$lib"
          mkdir -p "$(dirname "$dst")" "$RUN_DIR/usr/lib" "$RUN_DIR/lib" "$RUN_DIR/lib64"
          cp -L "$lib" "$dst" 2>/dev/null || true
          cp -L "$lib" "$RUN_DIR/usr/lib/$lib_base" 2>/dev/null || true
          cp -L "$lib" "$RUN_DIR/lib/$lib_base" 2>/dev/null || true
          cp -L "$lib" "$RUN_DIR/lib64/$lib_base" 2>/dev/null || true
          chmod +x "$dst" "$RUN_DIR/usr/lib/$lib_base" "$RUN_DIR/lib/$lib_base" "$RUN_DIR/lib64/$lib_base" 2>/dev/null || true
          case "$lib_base" in
            ld-linux-*.so.*)
              mkdir -p "$RUN_DIR/lib64"
              cp -L "$lib" "$RUN_DIR/lib64/ld-linux-x86-64.so.2" 2>/dev/null || true
              chmod +x "$RUN_DIR/lib64/ld-linux-x86-64.so.2" 2>/dev/null || true
              ;;
          esac
        done
    done
  }

  copy_binary "$BUSYBOX" "$RUN_DIR/bin/busybox"
  for applet in sh ls cat echo mount umount grep dmesg sleep timeout poweroff reboot mknod mkdir rmdir dd stat cp mv rm touch find wc cmp sync expr head tail cut kill ps test seq date uname tr sed tee true false env printf basename dirname readlink chmod insmod truncate; do
    ln -sf busybox "$RUN_DIR/bin/$applet"
  done

  cat > "$RUN_DIR/bin/mountpoint" <<'EOF'
#!/bin/sh
quiet=0
if [ "''${1:-}" = "-q" ]; then
    quiet=1
    shift
fi
target="''${1:-}"
if [ -n "$target" ] && grep -qs " $target " /proc/mounts; then
    exit 0
fi
[ "$quiet" -eq 1 ] || echo "$target is not a mountpoint"
exit 1
EOF
  chmod +x "$RUN_DIR/bin/mountpoint"

  cat > "$RUN_DIR/bin/fusermount" <<'EOF'
#!/bin/sh
if [ "''${1:-}" = "-u" ]; then
    shift
fi
exec umount "$@"
EOF
  chmod +x "$RUN_DIR/bin/fusermount"

  copy_binary "$TIDEFSCTL" "$RUN_DIR/bin/tidefsctl"
  copy_runtime_deps "$BUSYBOX" "$TIDEFSCTL"
  if [ "$SYNC_WRITE_CRASH" -eq 1 ]; then
    copy_binary "$SYNC_WRITE_CRASH_HELPER" "$RUN_DIR/bin/tidefs-sync-write-crash-helper"
  fi
  if [ "$ACK_RECEIPT_RUNTIME" -eq 1 ]; then
    copy_binary "$ACK_VALIDATION" "$RUN_DIR/bin/storage-intent-ack-runtime-validation"
    copy_runtime_deps "$ACK_VALIDATION"
  fi
  if [ "$DATA_SHAPE_RUNTIME" -eq 1 ]; then
    copy_binary "$DATA_SHAPE_VALIDATION" "$RUN_DIR/bin/storage-intent-data-shape-runtime-validation"
    copy_runtime_deps "$DATA_SHAPE_VALIDATION"
  fi

  FUSE_KO=""
  for candidate in \
    "$MODULE_DIR/kernel/fs/fuse/fuse.ko" \
    "$MODULE_DIR/kernel/fs/fuse/fuse.ko.xz" \
    "$MODULE_DIR/extra/fuse.ko" \
    "$MODULE_DIR/fuse.ko"; do
    if [ -f "$candidate" ]; then
      FUSE_KO="$candidate"
      break
    fi
  done
  if [ -n "$FUSE_KO" ]; then
    case "$FUSE_KO" in
      *.xz)
        "$XZ_BIN" -dc "$FUSE_KO" > "$RUN_DIR/lib/modules/fuse.ko"
        ;;
      *)
        cp -L "$FUSE_KO" "$RUN_DIR/lib/modules/fuse.ko"
        ;;
    esac
  fi

  cat > "$RUN_DIR/init" <<'INITSCRIPT'
#!/bin/sh
export PATH=/bin
export LD_LIBRARY_PATH=/usr/lib:/lib:/lib64
ACK_RECEIPT_RUNTIME=__ACK_RECEIPT_RUNTIME__
DATA_SHAPE_RUNTIME=__DATA_SHAPE_RUNTIME__
SYNC_WRITE_CRASH=__SYNC_WRITE_CRASH__
GITHUB_RUN_ID="__GITHUB_RUN_ID__"
GITHUB_RUN_ATTEMPT="__GITHUB_RUN_ATTEMPT__"
GITHUB_SHA="__GITHUB_SHA__"
TIDEFS_GENERATED_AT="__TIDEFS_GENERATED_AT__"
export GITHUB_RUN_ID GITHUB_RUN_ATTEMPT GITHUB_SHA TIDEFS_GENERATED_AT

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /tmp/tidefs-validation/performance

echo "=== TideFS FUSE VM Test Guest ==="
echo "kernel_version=$(uname -r)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

PASSED=0
FAILED=0
REFUSED=0
pass() { echo "PASS: $1"; PASSED=$((PASSED + 1)); }
fail() { echo "FAIL: $1 -- $2"; FAILED=$((FAILED + 1)); }
refuse() { echo "REFUSAL: $1 -- $2"; REFUSED=$((REFUSED + 1)); }

finish() {
    echo "validation_summary: passed=$PASSED failed=$FAILED refused=$REFUSED"
    echo "TIDEFS_FUSE_VM_TEST_DONE"
    sync
    poweroff -f
}

kernel_ver=$(uname -r)
case "$kernel_ver" in
    7.*) pass "linux_7_0_kernel" ;;
    *)
        refuse "linux_7_0_kernel" "expected Linux 7.0 guest kernel, got $kernel_ver"
        finish
        ;;
esac

if [ -f /lib/modules/fuse.ko ]; then
    insmod /lib/modules/fuse.ko 2>/tmp/fuse-insmod.err || true
fi
if [ ! -e /dev/fuse ]; then
    mknod /dev/fuse c 10 229 2>/dev/null || true
fi
if [ -e /dev/fuse ]; then
    chmod 666 /dev/fuse 2>/dev/null || true
    pass "fuse_device"
else
    refuse "fuse_device" "/dev/fuse is not available"
    finish
fi

if [ "$ACK_RECEIPT_RUNTIME" -eq 1 ]; then
    ACK_RUNTIME_DIR=/tmp/tidefs-validation/storage-intent-ack-runtime
    mkdir -p "$ACK_RUNTIME_DIR"
    TIDEFS_ACK_RECEIPT_RUNTIME_OUTPUT_DIR="$ACK_RUNTIME_DIR" \
      TIDEFS_ACK_RECEIPT_RUNTIME_RUN_ID="$GITHUB_RUN_ID/$GITHUB_RUN_ATTEMPT" \
      TIDEFS_ACK_RECEIPT_RUNTIME_SOURCE_REF="$GITHUB_SHA" \
      TIDEFS_ACK_RECEIPT_RUNTIME_GENERATED_AT="$TIDEFS_GENERATED_AT" \
      TIDEFS_ACK_RECEIPT_RUNTIME_CARRIER="linux-7.0-qemu-guest" \
      timeout 180 storage-intent-ack-runtime-validation \
      >/tmp/ack-receipt-runtime-output.txt 2>&1
    ACK_RUNTIME_RC=$?
    cat /tmp/ack-receipt-runtime-output.txt

    if [ "$ACK_RUNTIME_RC" -eq 0 ]; then
        pass "ack_receipt_runtime_process"
    else
        fail "ack_receipt_runtime_process" "exit status $ACK_RUNTIME_RC"
    fi
    if [ -s "$ACK_RUNTIME_DIR/ack-receipt-runtime.json" ]; then
        echo "TIDEFS_ACK_RUNTIME_ARTIFACT_BEGIN"
        /bin/busybox base64 "$ACK_RUNTIME_DIR/ack-receipt-runtime.json"
        echo "TIDEFS_ACK_RUNTIME_ARTIFACT_END"
    fi
    if [ -s "$ACK_RUNTIME_DIR/ack-receipt-runtime.manifest.json" ]; then
        echo "TIDEFS_ACK_RUNTIME_MANIFEST_BEGIN"
        /bin/busybox base64 "$ACK_RUNTIME_DIR/ack-receipt-runtime.manifest.json"
        echo "TIDEFS_ACK_RUNTIME_MANIFEST_END"
    fi
    echo "ack_receipt_runtime_exit_status=$ACK_RUNTIME_RC"
    finish
fi

if [ "$DATA_SHAPE_RUNTIME" -eq 1 ]; then
    DATA_SHAPE_RUNTIME_DIR=/tmp/tidefs-validation/storage-intent-data-shape-runtime
    mkdir -p "$DATA_SHAPE_RUNTIME_DIR"
    TIDEFS_DATA_SHAPE_RUNTIME_OUTPUT_DIR="$DATA_SHAPE_RUNTIME_DIR" \
      TIDEFS_DATA_SHAPE_RUNTIME_RUN_ID="$GITHUB_RUN_ID/$GITHUB_RUN_ATTEMPT" \
      TIDEFS_DATA_SHAPE_RUNTIME_SOURCE_REF="$GITHUB_SHA" \
      TIDEFS_DATA_SHAPE_RUNTIME_GENERATED_AT="$TIDEFS_GENERATED_AT" \
      TIDEFS_DATA_SHAPE_RUNTIME_CARRIER="linux-7.0-qemu-guest/fuse-vm-test" \
      timeout 180 storage-intent-data-shape-runtime-validation \
      >/tmp/data-shape-runtime-output.txt 2>&1
    DATA_SHAPE_RUNTIME_RC=$?
    cat /tmp/data-shape-runtime-output.txt

    if [ "$DATA_SHAPE_RUNTIME_RC" -eq 0 ]; then
        pass "data_shape_runtime_process"
    else
        fail "data_shape_runtime_process" "exit status $DATA_SHAPE_RUNTIME_RC"
    fi
    if [ -s "$DATA_SHAPE_RUNTIME_DIR/data-shape-transform-execution.json" ]; then
        echo "TIDEFS_DATA_SHAPE_TRANSFORM_ARTIFACT_BEGIN"
        /bin/busybox base64 "$DATA_SHAPE_RUNTIME_DIR/data-shape-transform-execution.json"
        echo "TIDEFS_DATA_SHAPE_TRANSFORM_ARTIFACT_END"
    fi
    if [ -s "$DATA_SHAPE_RUNTIME_DIR/data-shape-transform-execution.manifest.json" ]; then
        echo "TIDEFS_DATA_SHAPE_TRANSFORM_MANIFEST_BEGIN"
        /bin/busybox base64 "$DATA_SHAPE_RUNTIME_DIR/data-shape-transform-execution.manifest.json"
        echo "TIDEFS_DATA_SHAPE_TRANSFORM_MANIFEST_END"
    fi
    if [ -s "$DATA_SHAPE_RUNTIME_DIR/data-shape-performance-fault-rows.json" ]; then
        echo "TIDEFS_DATA_SHAPE_PERFORMANCE_ARTIFACT_BEGIN"
        /bin/busybox base64 "$DATA_SHAPE_RUNTIME_DIR/data-shape-performance-fault-rows.json"
        echo "TIDEFS_DATA_SHAPE_PERFORMANCE_ARTIFACT_END"
    fi
    if [ -s "$DATA_SHAPE_RUNTIME_DIR/data-shape-performance-fault-rows.manifest.json" ]; then
        echo "TIDEFS_DATA_SHAPE_PERFORMANCE_MANIFEST_BEGIN"
        /bin/busybox base64 "$DATA_SHAPE_RUNTIME_DIR/data-shape-performance-fault-rows.manifest.json"
        echo "TIDEFS_DATA_SHAPE_PERFORMANCE_MANIFEST_END"
    fi
    echo "data_shape_runtime_exit_status=$DATA_SHAPE_RUNTIME_RC"
    finish
fi

if [ "$SYNC_WRITE_CRASH" -eq 1 ]; then
    export TIDEFS_ROOT_AUTHENTICATION_KEY_HEX=4141414141414141414141414141414141414141414141414141414141414141
    SYNC_WRITE_PASSED=0
    SYNC_WRITE_PRODUCT_FAILED=0
    SYNC_WRITE_HARNESS_FAILED=0

    sync_write_product_fail() {
        echo "PRODUCT FAIL: $1 -- $2"
        SYNC_WRITE_PRODUCT_FAILED=$((SYNC_WRITE_PRODUCT_FAILED + 1))
    }

    sync_write_harness_fail() {
        echo "HARNESS FAIL: $1 -- $2"
        SYNC_WRITE_HARNESS_FAILED=$((SYNC_WRITE_HARNESS_FAILED + 1))
    }

    wait_for_mount() {
        WAIT_MOUNTPOINT="$1"
        WAIT_PID="$2"
        for WAIT_I in $(seq 30); do
            if mountpoint -q "$WAIT_MOUNTPOINT" 2>/dev/null; then
                return 0
            fi
            if ! kill -0 "$WAIT_PID" 2>/dev/null; then
                return 1
            fi
            sleep 1
        done
        return 1
    }

    cleanup_sync_write_row() {
        CLEANUP_MNT="$1"
        CLEANUP_HELPER_PID="$2"
        CLEANUP_MOUNT_PID="$3"
        CLEANUP_RELEASE="$4"
        touch "$CLEANUP_RELEASE" 2>/dev/null || true
        if [ -n "$CLEANUP_HELPER_PID" ] && kill -0 "$CLEANUP_HELPER_PID" 2>/dev/null; then
            kill -KILL "$CLEANUP_HELPER_PID" 2>/dev/null || true
            wait "$CLEANUP_HELPER_PID" 2>/dev/null || true
        fi
        umount -l "$CLEANUP_MNT" 2>/dev/null || true
        if [ -n "$CLEANUP_MOUNT_PID" ] && kill -0 "$CLEANUP_MOUNT_PID" 2>/dev/null; then
            kill -KILL "$CLEANUP_MOUNT_PID" 2>/dev/null || true
            wait "$CLEANUP_MOUNT_PID" 2>/dev/null || true
        fi
    }

    run_sync_write_crash_row() {
        SYNC_MODE="$1"
        CACHE_MODE="$2"
        ROW="''${SYNC_MODE}_writeback_''${CACHE_MODE}"
        ROOT="/tmp/tidefs-sync-write-crash-$ROW"
        DEVICE="$ROOT/device.tidefs"
        MNT="$ROOT/mnt"
        POOL="sync_write_''${SYNC_MODE}_''${CACHE_MODE}"
        TEST_FILE="$MNT/payload.bin"
        EXPECTED_FILE="$ROOT/expected.bin"
        RELEASE="$ROOT/release-helper"
        HELPER_LOG="$ROOT/helper.log"
        MOUNT_LOG="$ROOT/mount.log"
        REMOUNT_LOG="$ROOT/remount.log"
        PAYLOAD="TIDEFS_''${SYNC_MODE}_WRITEBACK_''${CACHE_MODE}_CRASH_V1"
        EXPECTED_LENGTH=$(printf '%s' "$PAYLOAD" | wc -c)
        HELPER_PID=""
        MOUNT_PID=""

        rm -rf "$ROOT"
        mkdir -p "$MNT"
        printf '%s' "$PAYLOAD" > "$EXPECTED_FILE"
        truncate -s 268435456 "$DEVICE"
        if ! tidefsctl pool create "$POOL" --file-devices --devices "$DEVICE" >"$ROOT/create.log" 2>&1; then
            cat "$ROOT/create.log"
            sync_write_product_fail "$ROW" "fresh pool creation failed"
            rm -rf "$ROOT"
            return
        fi

        if [ "$CACHE_MODE" = "enabled" ]; then
            tidefsctl pool mount "$POOL" "$MNT" --devices "$DEVICE" --writeback-cache >"$MOUNT_LOG" 2>&1 &
        else
            tidefsctl pool mount "$POOL" "$MNT" --devices "$DEVICE" >"$MOUNT_LOG" 2>&1 &
        fi
        MOUNT_PID=$!
        if ! wait_for_mount "$MNT" "$MOUNT_PID"; then
            cat "$MOUNT_LOG"
            sync_write_product_fail "$ROW" "fresh mount did not become ready"
            cleanup_sync_write_row "$MNT" "$HELPER_PID" "$MOUNT_PID" "$RELEASE"
            rm -rf "$ROOT"
            return
        fi

        tidefs-sync-write-crash-helper "$SYNC_MODE" "$TEST_FILE" "$RELEASE" "$PAYLOAD" >"$HELPER_LOG" 2>&1 &
        HELPER_PID=$!
        WRITE_RETURNED=0
        for MARKER_I in $(seq 30); do
            if grep -q "^WRITE_SUCCEEDED mode=$SYNC_MODE bytes=$EXPECTED_LENGTH$" "$HELPER_LOG" 2>/dev/null; then
                WRITE_RETURNED=1
                break
            fi
            if ! kill -0 "$HELPER_PID" 2>/dev/null; then
                break
            fi
            sleep 1
        done
        if [ "$WRITE_RETURNED" -ne 1 ]; then
            cat "$HELPER_LOG" 2>/dev/null || true
            if kill -0 "$HELPER_PID" 2>/dev/null; then
                sync_write_harness_fail "$ROW" "helper did not publish its successful-write marker"
            else
                wait "$HELPER_PID" 2>/dev/null || true
                HELPER_PID=""
                sync_write_product_fail "$ROW" "synchronous mounted write did not succeed"
            fi
            cleanup_sync_write_row "$MNT" "$HELPER_PID" "$MOUNT_PID" "$RELEASE"
            rm -rf "$ROOT"
            return
        fi

        if ! kill -0 "$MOUNT_PID" 2>/dev/null; then
            sync_write_product_fail "$ROW" "mount owner exited before crash injection"
            cleanup_sync_write_row "$MNT" "$HELPER_PID" "$MOUNT_PID" "$RELEASE"
            rm -rf "$ROOT"
            return
        fi
        if ! kill -KILL "$MOUNT_PID" 2>/dev/null; then
            sync_write_harness_fail "$ROW" "could not SIGKILL captured mount-owner PID $MOUNT_PID"
            cleanup_sync_write_row "$MNT" "$HELPER_PID" "$MOUNT_PID" "$RELEASE"
            rm -rf "$ROOT"
            return
        fi
        wait "$MOUNT_PID" 2>/dev/null || true
        if kill -0 "$MOUNT_PID" 2>/dev/null; then
            sync_write_harness_fail "$ROW" "captured mount-owner PID remained alive after SIGKILL"
            cleanup_sync_write_row "$MNT" "$HELPER_PID" "$MOUNT_PID" "$RELEASE"
            rm -rf "$ROOT"
            return
        fi
        MOUNT_PID=""

        touch "$RELEASE"
        if ! wait "$HELPER_PID"; then
            cat "$HELPER_LOG" 2>/dev/null || true
            HELPER_PID=""
            sync_write_harness_fail "$ROW" "writer helper failed after daemon death was confirmed"
            cleanup_sync_write_row "$MNT" "$HELPER_PID" "$MOUNT_PID" "$RELEASE"
            rm -rf "$ROOT"
            return
        fi
        HELPER_PID=""

        if ! umount -l "$MNT" 2>"$ROOT/detach.err"; then
            cat "$ROOT/detach.err" 2>/dev/null || true
            sync_write_product_fail "$ROW" "dead FUSE connection could not be detached"
            rm -rf "$ROOT"
            return
        fi

        if [ "$CACHE_MODE" = "enabled" ]; then
            tidefsctl pool mount "$POOL" "$MNT" --devices "$DEVICE" --writeback-cache >"$REMOUNT_LOG" 2>&1 &
        else
            tidefsctl pool mount "$POOL" "$MNT" --devices "$DEVICE" >"$REMOUNT_LOG" 2>&1 &
        fi
        MOUNT_PID=$!
        if ! wait_for_mount "$MNT" "$MOUNT_PID"; then
            cat "$REMOUNT_LOG"
            sync_write_product_fail "$ROW" "fresh recovery remount did not become ready"
            cleanup_sync_write_row "$MNT" "$HELPER_PID" "$MOUNT_PID" "$RELEASE"
            rm -rf "$ROOT"
            return
        fi

        ACTUAL_LENGTH=$(wc -c < "$TEST_FILE" 2>/dev/null || echo missing)
        if [ "$ACTUAL_LENGTH" != "$EXPECTED_LENGTH" ] || ! cmp -s "$EXPECTED_FILE" "$TEST_FILE"; then
            sync_write_product_fail "$ROW" "expected $EXPECTED_LENGTH exact bytes after crash, got $ACTUAL_LENGTH"
            cleanup_sync_write_row "$MNT" "$HELPER_PID" "$MOUNT_PID" "$RELEASE"
            rm -rf "$ROOT"
            return
        fi

        if ! umount "$MNT" || ! wait "$MOUNT_PID"; then
            sync_write_harness_fail "$ROW" "recovery mount did not shut down cleanly"
            cleanup_sync_write_row "$MNT" "$HELPER_PID" "$MOUNT_PID" "$RELEASE"
            rm -rf "$ROOT"
            return
        fi
        MOUNT_PID=""
        echo "PASS: sync_write_crash_$ROW"
        SYNC_WRITE_PASSED=$((SYNC_WRITE_PASSED + 1))
        rm -rf "$ROOT"
    }

    run_sync_write_crash_row sync disabled
    run_sync_write_crash_row dsync disabled
    run_sync_write_crash_row sync enabled
    run_sync_write_crash_row dsync enabled
    echo "sync_write_crash_summary: passed=$SYNC_WRITE_PASSED product_failed=$SYNC_WRITE_PRODUCT_FAILED harness_failed=$SYNC_WRITE_HARNESS_FAILED environment_refused=$REFUSED"
    if [ "$SYNC_WRITE_PASSED" -ne 4 ] || [ "$SYNC_WRITE_PRODUCT_FAILED" -ne 0 ] || [ "$SYNC_WRITE_HARNESS_FAILED" -ne 0 ] || [ "$REFUSED" -ne 0 ]; then
        FAILED=$((FAILED + SYNC_WRITE_PRODUCT_FAILED + SYNC_WRITE_HARNESS_FAILED + 1))
    fi
    finish
fi

export TIDEFS_ROOT_AUTHENTICATION_KEY_HEX=4141414141414141414141414141414141414141414141414141414141414141
LIFECYCLE_ROOT=/tmp/tidefs-canonical-lifecycle
DEVICE="$LIFECYCLE_ROOT/device0.tidefs"
MNT="$LIFECYCLE_ROOT/mnt"
POOL=fuse_vm_test_pool
PAYLOAD=tidefs-canonical-mounted-lifecycle
OVERWRITE_PAYLOAD=tidefs-post-snapshot-overwrite
SNAPSHOT=before-overwrite
mkdir -p "$LIFECYCLE_ROOT" "$MNT"
truncate -s 268435456 "$DEVICE"

if tidefsctl pool create "$POOL" --file-devices --devices "$DEVICE" >/tmp/pool-create.log 2>&1; then
    pass "pool_create"
else
    cat /tmp/pool-create.log
    fail "pool_create" "tidefsctl pool create failed"
    finish
fi

tidefsctl pool mount "$POOL" "$MNT" --devices "$DEVICE" >/tmp/pool-mount.log 2>&1 &
MOUNT_PID=$!
MOUNTED=0
for i in $(seq 30); do
    if mountpoint -q "$MNT" 2>/dev/null; then
        MOUNTED=1
        break
    fi
    if ! kill -0 "$MOUNT_PID" 2>/dev/null; then
        break
    fi
    sleep 1
done
if [ "$MOUNTED" -ne 1 ]; then
    cat /tmp/pool-mount.log
    fail "pool_mount" "canonical mount did not become ready"
    finish
fi
pass "pool_mount"

printf '%s\n' "$PAYLOAD" > "$MNT/original.txt"
sync "$MNT/original.txt"
mv "$MNT/original.txt" "$MNT/renamed.txt"
sync
if [ "$(cat "$MNT/renamed.txt")" = "$PAYLOAD" ]; then
    pass "mounted_create_write_fsync_rename_read"
else
    fail "mounted_create_write_fsync_rename_read" "mounted payload mismatch"
fi

if tidefsctl snapshot create "$POOL" "$SNAPSHOT" >/tmp/snapshot-create.log 2>&1 \
  && tidefsctl snapshot list "$POOL" >/tmp/snapshot-list.log 2>&1 \
  && grep -Fq "snapshot '$SNAPSHOT' (source tx=" /tmp/snapshot-list.log; then
    pass "mounted_snapshot_create_list"
else
    cat /tmp/snapshot-create.log 2>/dev/null || true
    cat /tmp/snapshot-list.log 2>/dev/null || true
    fail "mounted_snapshot_create_list" "canonical snapshot was not created and listed"
fi

printf '%s\n' "$OVERWRITE_PAYLOAD" > "$MNT/renamed.txt"
sync "$MNT/renamed.txt"
if [ "$(cat "$MNT/renamed.txt")" = "$OVERWRITE_PAYLOAD" ]; then
    pass "mounted_post_snapshot_overwrite_fsync"
else
    fail "mounted_post_snapshot_overwrite_fsync" "post-snapshot overwrite mismatch"
fi

if tidefsctl snapshot rollback "$POOL" "$SNAPSHOT" >/tmp/snapshot-rollback.log 2>&1 \
  && [ "$(cat "$MNT/renamed.txt")" = "$PAYLOAD" ] \
  && tidefsctl snapshot list "$POOL" >/tmp/snapshot-list-after-rollback.log 2>&1 \
  && grep -Fq "snapshot '$SNAPSHOT' (source tx=" /tmp/snapshot-list-after-rollback.log; then
    pass "mounted_snapshot_rollback_exact_bytes_retained"
else
    cat /tmp/snapshot-rollback.log 2>/dev/null || true
    cat /tmp/snapshot-list-after-rollback.log 2>/dev/null || true
    fail "mounted_snapshot_rollback_exact_bytes_retained" "rollback did not restore exact bytes while retaining the snapshot"
fi

if umount "$MNT" && wait "$MOUNT_PID"; then
    pass "clean_unmount_export"
else
    fail "clean_unmount_export" "mount owner did not exit cleanly"
fi

tidefsctl pool mount "$POOL" "$MNT" --devices "$DEVICE" >/tmp/pool-remount.log 2>&1 &
REMOUNT_PID=$!
REMOUNTED=0
for i in $(seq 30); do
    if mountpoint -q "$MNT" 2>/dev/null; then
        REMOUNTED=1
        break
    fi
    if ! kill -0 "$REMOUNT_PID" 2>/dev/null; then
        break
    fi
    sleep 1
done
if [ "$REMOUNTED" -eq 1 ] \
  && [ "$(cat "$MNT/renamed.txt" 2>/dev/null)" = "$PAYLOAD" ] \
  && tidefsctl snapshot list "$POOL" >/tmp/snapshot-list-after-remount.log 2>&1 \
  && grep -Fq "snapshot '$SNAPSHOT' (source tx=" /tmp/snapshot-list-after-remount.log; then
    pass "remount_snapshot_rollback_persistence"
else
    cat /tmp/pool-remount.log
    cat /tmp/snapshot-list-after-remount.log 2>/dev/null || true
    fail "remount_snapshot_rollback_persistence" "restored bytes and snapshot did not survive remount"
fi

if tidefsctl snapshot destroy "$POOL" "$SNAPSHOT" >/tmp/snapshot-destroy.log 2>&1; then
    pass "mounted_snapshot_logical_destroy"
else
    cat /tmp/snapshot-destroy.log
    fail "mounted_snapshot_logical_destroy" "snapshot destroy failed"
fi

if ! umount "$MNT" || ! wait "$REMOUNT_PID"; then
    fail "post_destroy_unmount" "mount owner did not exit cleanly after snapshot destroy"
fi

tidefsctl pool mount "$POOL" "$MNT" --devices "$DEVICE" >/tmp/pool-final-remount.log 2>&1 &
FINAL_MOUNT_PID=$!
FINAL_REMOUNTED=0
for i in $(seq 30); do
    if mountpoint -q "$MNT" 2>/dev/null; then
        FINAL_REMOUNTED=1
        break
    fi
    if ! kill -0 "$FINAL_MOUNT_PID" 2>/dev/null; then
        break
    fi
    sleep 1
done
if [ "$FINAL_REMOUNTED" -eq 1 ] \
  && ! tidefsctl snapshot rollback "$POOL" "$SNAPSHOT" >/tmp/snapshot-rollback-after-destroy.log 2>&1; then
    pass "destroyed_snapshot_rollback_refused_after_reopen"
else
    cat /tmp/pool-final-remount.log 2>/dev/null || true
    cat /tmp/snapshot-rollback-after-destroy.log 2>/dev/null || true
    fail "destroyed_snapshot_rollback_refused_after_reopen" "destroyed snapshot remained rollback-reachable after reopen"
fi
umount "$MNT" 2>/dev/null || true
wait "$FINAL_MOUNT_PID" 2>/dev/null || true

echo "--- dmesg tail ---"
dmesg | tail -80 2>/dev/null || true
echo "--- end dmesg tail ---"

finish
INITSCRIPT

  for provenance in \
    "GITHUB_RUN_ID=''${GITHUB_RUN_ID:-local}" \
    "GITHUB_RUN_ATTEMPT=''${GITHUB_RUN_ATTEMPT:-1}" \
    "GITHUB_SHA=''${GITHUB_SHA:-unknown}" \
    "TIDEFS_GENERATED_AT=''${TIDEFS_GENERATED_AT:-1970-01-01T00:00:00Z}"; do
    value="''${provenance#*=}"
    case "$value" in
      *[!A-Za-z0-9._:/+-]*)
        echo "ERROR: unsafe runtime provenance value for ''${provenance%%=*}" >&2
        exit 2
        ;;
    esac
  done

  sed -i "s|__ACK_RECEIPT_RUNTIME__|$ACK_RECEIPT_RUNTIME|g" "$RUN_DIR/init"
  sed -i "s|__DATA_SHAPE_RUNTIME__|$DATA_SHAPE_RUNTIME|g" "$RUN_DIR/init"
  sed -i "s|__SYNC_WRITE_CRASH__|$SYNC_WRITE_CRASH|g" "$RUN_DIR/init"
  sed -i "s|__GITHUB_RUN_ID__|''${GITHUB_RUN_ID:-local}|g" "$RUN_DIR/init"
  sed -i "s|__GITHUB_RUN_ATTEMPT__|''${GITHUB_RUN_ATTEMPT:-1}|g" "$RUN_DIR/init"
  sed -i "s|__GITHUB_SHA__|''${GITHUB_SHA:-unknown}|g" "$RUN_DIR/init"
  sed -i "s|__TIDEFS_GENERATED_AT__|''${TIDEFS_GENERATED_AT:-1970-01-01T00:00:00Z}|g" "$RUN_DIR/init"
  chmod +x "$RUN_DIR/init"

  (cd "$RUN_DIR" && find . -path ./initrd.img -prune -o -print | "$CPIO" -o -H newc 2>/dev/null) > "$RUN_DIR/initrd.img"
  echo "  Initrd prepared: $(du -h "$RUN_DIR/initrd.img" | cut -f1)"

  mkdir -p "$VALIDATION_DIR"
  VAL_LOG="$RUN_DIR/qemu-boot.log"
  echo "  Booting QEMU VM..."
  set +e
  timeout --foreground "$TIMEOUT_SEC" "$QEMU_BIN" \
    -machine pc,accel=kvm \
    -kernel "$KERNEL_IMG" \
    -initrd "$RUN_DIR/initrd.img" \
    -append "console=ttyS0 quiet panic=10 panic_on_oops=1" \
    -m 1024M \
    -smp 2 \
    -nographic \
    -no-reboot \
    > "$VAL_LOG" 2>&1
  QEMU_STATUS=$?
  set -e

  cp "$VAL_LOG" "$VALIDATION_DIR/qemu-boot.log"
  if [ "$SYNC_WRITE_CRASH" -ne 1 ]; then
    cp "$RUN_DIR/init" "$VALIDATION_DIR/init-script"
  fi

  extract_between() {
    local start="$1"
    local end="$2"
    awk -v start="$start" -v end="$end" '
      { sub(/\r$/, "") }
      $0 == start { capture = 1; next }
      $0 == end { capture = 0; next }
      capture { print }
    ' "$VAL_LOG"
  }

  count_serial_lines() {
    local pattern="$1"
    awk -v pattern="$pattern" '
      { sub(/\r$/, "") }
      $0 ~ pattern { count++ }
      END { print count + 0 }
    ' "$VAL_LOG"
  }


  ack_artifact="$VALIDATION_DIR/ack-receipt-runtime.json"
  ack_manifest="$VALIDATION_DIR/ack-receipt-runtime.manifest.json"
  if [ "$ACK_RECEIPT_RUNTIME" -eq 1 ]; then
    extract_between \
      "TIDEFS_ACK_RUNTIME_ARTIFACT_BEGIN" \
      "TIDEFS_ACK_RUNTIME_ARTIFACT_END" \
      | "$BASE64" --decode > "$ack_artifact" || true
    extract_between \
      "TIDEFS_ACK_RUNTIME_MANIFEST_BEGIN" \
      "TIDEFS_ACK_RUNTIME_MANIFEST_END" \
      | "$BASE64" --decode > "$ack_manifest" || true
  fi

  data_shape_transform_artifact="$VALIDATION_DIR/data-shape-transform-execution.json"
  data_shape_transform_manifest="$VALIDATION_DIR/data-shape-transform-execution.manifest.json"
  data_shape_performance_artifact="$VALIDATION_DIR/data-shape-performance-fault-rows.json"
  data_shape_performance_manifest="$VALIDATION_DIR/data-shape-performance-fault-rows.manifest.json"
  if [ "$DATA_SHAPE_RUNTIME" -eq 1 ]; then
    extract_between \
      "TIDEFS_DATA_SHAPE_TRANSFORM_ARTIFACT_BEGIN" \
      "TIDEFS_DATA_SHAPE_TRANSFORM_ARTIFACT_END" \
      | "$BASE64" --decode > "$data_shape_transform_artifact" || true
    extract_between \
      "TIDEFS_DATA_SHAPE_TRANSFORM_MANIFEST_BEGIN" \
      "TIDEFS_DATA_SHAPE_TRANSFORM_MANIFEST_END" \
      | "$BASE64" --decode > "$data_shape_transform_manifest" || true
    extract_between \
      "TIDEFS_DATA_SHAPE_PERFORMANCE_ARTIFACT_BEGIN" \
      "TIDEFS_DATA_SHAPE_PERFORMANCE_ARTIFACT_END" \
      | "$BASE64" --decode > "$data_shape_performance_artifact" || true
    extract_between \
      "TIDEFS_DATA_SHAPE_PERFORMANCE_MANIFEST_BEGIN" \
      "TIDEFS_DATA_SHAPE_PERFORMANCE_MANIFEST_END" \
      | "$BASE64" --decode > "$data_shape_performance_manifest" || true
  fi

  PASSC=$(count_serial_lines '^PASS:')
  FAILC=$(count_serial_lines '^FAIL:')
  REFUSALC=$(count_serial_lines '^REFUSAL:')
  DONEC=$(count_serial_lines '^TIDEFS_FUSE_VM_TEST_DONE$')
  if [ "$SYNC_WRITE_CRASH" -eq 1 ]; then
    SYNC_PASSC=$(count_serial_lines '^PASS: sync_write_crash_')
    SYNC_PRODUCT_FAILC=$(count_serial_lines '^PRODUCT FAIL:')
    SYNC_HARNESS_FAILC=$(count_serial_lines '^HARNESS FAIL:')
    echo "=== TideFS synchronous-write crash results ==="
    grep -E '^(PASS: sync_write_crash_|PRODUCT FAIL:|HARNESS FAIL:|REFUSAL:|sync_write_crash_summary:)' "$VAL_LOG" 2>/dev/null || true
    echo "Validation: $SYNC_PASSC passed, $SYNC_PRODUCT_FAILC product-failed, $SYNC_HARNESS_FAILC harness-failed, $REFUSALC environment-refused"
    echo "Validation log: $VALIDATION_DIR/qemu-boot.log"
    if [ "$QEMU_STATUS" -eq 124 ]; then
      echo "VALIDATION: HARNESS FAIL -- QEMU timed out after ''${TIMEOUT_SEC}s" >&2
      exit 1
    fi
    if [ "$DONEC" -eq 0 ]; then
      echo "VALIDATION: HARNESS FAIL -- guest did not emit completion marker" >&2
      exit 1
    fi
    if [ "$REFUSALC" -gt 0 ]; then
      echo "VALIDATION: ENVIRONMENT REFUSAL -- $REFUSALC refusal(s)" >&2
      exit 2
    fi
    if [ "$SYNC_PRODUCT_FAILC" -gt 0 ] || [ "$SYNC_HARNESS_FAILC" -gt 0 ] || [ "$SYNC_PASSC" -ne 4 ]; then
      echo "VALIDATION: NON-PASS -- expected four passing synchronous-write crash rows" >&2
      exit 1
    fi
    echo "VALIDATION: PASS"
    exit 0
  fi
  if [ "$ACK_RECEIPT_RUNTIME" -eq 1 ]; then
    if [ ! -s "$ack_artifact" ] || [ ! -s "$ack_manifest" ]; then
      echo "FAIL: ack_runtime_artifact_capture -- evidence payload or manifest is missing" >&2
      FAILC=$((FAILC + 1))
    elif ! "$JQ" -e 'type == "object"' "$ack_artifact" >/dev/null \
      || ! "$JQ" -e 'type == "object"' "$ack_manifest" >/dev/null; then
      echo "FAIL: ack_runtime_artifact_capture -- evidence payload or manifest is not a JSON object" >&2
      FAILC=$((FAILC + 1))
    else
      declared_digest=$("$JQ" -r '.content_digest // empty' "$ack_manifest")
      actual_digest="blake3:$("$B3SUM" "$ack_artifact" | awk '{print $1}')"
      artifact_outcome=$("$JQ" -r '.summary.status // empty' "$ack_artifact")
      manifest_outcome=$("$JQ" -r '.outcome // empty' "$ack_manifest")
      artifact_source_ref=$("$JQ" -r '.source_ref // empty' "$ack_artifact")
      manifest_source_ref=$("$JQ" -r '.source_ref // empty' "$ack_manifest")
      artifact_run_id=$("$JQ" -r '.run_id // empty' "$ack_artifact")
      manifest_run_id=$("$JQ" -r '.run_id // empty' "$ack_manifest")
      expected_source_ref="''${GITHUB_SHA:-unknown}"
      expected_run_id="''${GITHUB_RUN_ID:-local}/''${GITHUB_RUN_ATTEMPT:-1}"
      if [ -z "$declared_digest" ] || [ "$declared_digest" != "$actual_digest" ]; then
        echo "FAIL: ack_runtime_artifact_digest -- declared=$declared_digest actual=$actual_digest" >&2
        FAILC=$((FAILC + 1))
      elif [ -z "$artifact_source_ref" ] \
        || [ "$artifact_source_ref" != "$manifest_source_ref" ] \
        || [ "$artifact_source_ref" != "$expected_source_ref" ]; then
        echo "FAIL: ack_runtime_source_ref -- artifact=$artifact_source_ref manifest=$manifest_source_ref expected=$expected_source_ref" >&2
        FAILC=$((FAILC + 1))
      elif [ -z "$artifact_run_id" ] \
        || [ "$artifact_run_id" != "$manifest_run_id" ] \
        || [ "$artifact_run_id" != "$expected_run_id" ]; then
        echo "FAIL: ack_runtime_run_id -- artifact=$artifact_run_id manifest=$manifest_run_id expected=$expected_run_id" >&2
        FAILC=$((FAILC + 1))
      elif [ -z "$artifact_outcome" ] || [ "$artifact_outcome" != "$manifest_outcome" ]; then
        echo "FAIL: ack_runtime_outcome -- artifact=$artifact_outcome manifest=$manifest_outcome" >&2
        FAILC=$((FAILC + 1))
      else
        echo "ACK RUNTIME: captured digest-matched mounted evidence with outcome=$artifact_outcome"
        PASSC=$((PASSC + 1))
      fi
    fi
  fi
  validate_data_shape_pair() {
    local label="$1"
    local artifact="$2"
    local manifest="$3"
    local expected_artifact_path="$4"
    local declared_digest actual_digest artifact_outcome manifest_outcome
    local artifact_source_ref manifest_source_ref artifact_run_id manifest_run_id
    local artifact_tier manifest_tier expected_source_ref expected_run_id

    if [ ! -s "$artifact" ] || [ ! -s "$manifest" ]; then
      echo "FAIL: data_shape_$label artifact capture -- evidence payload or manifest is missing" >&2
      FAILC=$((FAILC + 1))
      return
    fi
    if ! "$JQ" -e 'type == "object"' "$artifact" >/dev/null \
      || ! "$JQ" -e 'type == "object"' "$manifest" >/dev/null; then
      echo "FAIL: data_shape_$label artifact capture -- evidence payload or manifest is not a JSON object" >&2
      FAILC=$((FAILC + 1))
      return
    fi

    declared_digest=$("$JQ" -r '.content_digest // empty' "$manifest")
    actual_digest="blake3:$("$B3SUM" "$artifact" | awk '{print $1}')"
    artifact_outcome=$("$JQ" -r '.outcome // empty' "$artifact")
    manifest_outcome=$("$JQ" -r '.outcome // empty' "$manifest")
    artifact_source_ref=$("$JQ" -r '.source_ref // empty' "$artifact")
    manifest_source_ref=$("$JQ" -r '.source_ref // empty' "$manifest")
    artifact_run_id=$("$JQ" -r '.run_id // empty' "$artifact")
    manifest_run_id=$("$JQ" -r '.run_id // empty' "$manifest")
    artifact_tier=$("$JQ" -r '.validation_tier // empty' "$artifact")
    manifest_tier=$("$JQ" -r '.validation_tier // empty' "$manifest")
    expected_source_ref="''${GITHUB_SHA:-unknown}"
    expected_run_id="''${GITHUB_RUN_ID:-local}/''${GITHUB_RUN_ATTEMPT:-1}"

    if [ -z "$declared_digest" ] || [ "$declared_digest" != "$actual_digest" ]; then
      echo "FAIL: data_shape_$label artifact digest -- declared=$declared_digest actual=$actual_digest" >&2
      FAILC=$((FAILC + 1))
    elif [ -z "$artifact_source_ref" ] \
      || [ "$artifact_source_ref" != "$manifest_source_ref" ] \
      || [ "$artifact_source_ref" != "$expected_source_ref" ]; then
      echo "FAIL: data_shape_$label source ref -- artifact=$artifact_source_ref manifest=$manifest_source_ref expected=$expected_source_ref" >&2
      FAILC=$((FAILC + 1))
    elif [ -z "$artifact_run_id" ] \
      || [ "$artifact_run_id" != "$manifest_run_id" ] \
      || [ "$artifact_run_id" != "$expected_run_id" ]; then
      echo "FAIL: data_shape_$label run id -- artifact=$artifact_run_id manifest=$manifest_run_id expected=$expected_run_id" >&2
      FAILC=$((FAILC + 1))
    elif [ "$artifact_tier" != "qemu-guest" ] || [ "$manifest_tier" != "qemu-guest" ]; then
      echo "FAIL: data_shape_$label tier -- artifact=$artifact_tier manifest=$manifest_tier expected=qemu-guest" >&2
      FAILC=$((FAILC + 1))
    elif [ "$artifact_outcome" != "skip" ] || [ "$manifest_outcome" != "skip" ]; then
      echo "FAIL: data_shape_$label outcome -- artifact=$artifact_outcome manifest=$manifest_outcome expected=skip" >&2
      FAILC=$((FAILC + 1))
    elif ! "$JQ" -e \
      '.claim_id == "storage.intent.data_shape_honesty.v1"
       and .runtime_execution_produced == true
       and .summary.status == "skip"
       and .summary.passed > 0
       and .summary.product_failed == 0
       and .summary.skipped > 0' \
      "$artifact" >/dev/null; then
      echo "FAIL: data_shape_$label runtime boundary -- expected passing execution plus explicit skipped rows without product failure" >&2
      FAILC=$((FAILC + 1))
    elif ! "$JQ" -e \
      --arg artifact_path "$expected_artifact_path" \
      '.manifest_version == 2
       and .claim_id == "storage.intent.data_shape_honesty.v1"
       and .artifact_path == $artifact_path
       and (.blocking_issues | any(.repo == "tidefs/tidefs" and .number == 1981))' \
      "$manifest" >/dev/null; then
      echo "FAIL: data_shape_$label manifest boundary -- expected registered path and blocker #1981" >&2
      FAILC=$((FAILC + 1))
    else
      echo "DATA SHAPE RUNTIME: captured digest-matched $label evidence with partial outcome=skip"
      PASSC=$((PASSC + 1))
    fi
  }

  if [ "$DATA_SHAPE_RUNTIME" -eq 1 ]; then
    validate_data_shape_pair \
      transform \
      "$data_shape_transform_artifact" \
      "$data_shape_transform_manifest" \
      "validation/artifacts/storage-intent/data-shape-transform-execution.json"
    validate_data_shape_pair \
      performance_fault \
      "$data_shape_performance_artifact" \
      "$data_shape_performance_manifest" \
      "validation/artifacts/storage-intent/data-shape-performance-fault-rows.json"
  fi
  KERNEL_VERSION=$(awk '
    { sub(/\r$/, "") }
    /^kernel_version=/ { sub(/^kernel_version=/, ""); print; exit }
  ' "$VAL_LOG")
  [ -n "$KERNEL_VERSION" ] || KERNEL_VERSION="unknown"
  DATA_SHAPE_TRANSFORM_PRESENT=false
  DATA_SHAPE_PERFORMANCE_PRESENT=false
  if [ "$DATA_SHAPE_RUNTIME" -eq 1 ]; then
    [ -s "$data_shape_transform_artifact" ] && [ -s "$data_shape_transform_manifest" ] \
      && DATA_SHAPE_TRANSFORM_PRESENT=true
    [ -s "$data_shape_performance_artifact" ] && [ -s "$data_shape_performance_manifest" ] \
      && DATA_SHAPE_PERFORMANCE_PRESENT=true
  fi

  cat > "$VALIDATION_DIR/fuse-vm-test.json" <<JSON
{
  "test": "tidefs-fuse-vm-test",
  "version": 4,
  "tier": "outside-sandbox-qemu-guest",
  "kernel_version": "$KERNEL_VERSION",
  "kernel_package": "linuxKernel_7_0",
  "qemu_status": $QEMU_STATUS,
  "done_marker_seen": $DONEC,
  "passed": $PASSC,
  "product_failures": $FAILC,
  "environment_refusals": $REFUSALC,
  "data_shape_transform_artifact": "$data_shape_transform_artifact",
  "data_shape_transform_artifact_present": $DATA_SHAPE_TRANSFORM_PRESENT,
  "data_shape_performance_fault_artifact": "$data_shape_performance_artifact",
  "data_shape_performance_fault_artifact_present": $DATA_SHAPE_PERFORMANCE_PRESENT
}
JSON

  echo "=== TideFS FUSE VM Test Results ==="
  grep -E '^(PASS|FAIL|REFUSAL):' "$VAL_LOG" 2>/dev/null || true
  echo "Validation: $PASSC passed, $FAILC failed, $REFUSALC refused"
  echo "Validation log: $VALIDATION_DIR/qemu-boot.log"
  echo "Validation JSON: $VALIDATION_DIR/fuse-vm-test.json"
  if [ "$DATA_SHAPE_TRANSFORM_PRESENT" = true ]; then
    echo "Data-shape transform artifact: $data_shape_transform_artifact"
  fi
  if [ "$DATA_SHAPE_PERFORMANCE_PRESENT" = true ]; then
    echo "Data-shape performance/fault artifact: $data_shape_performance_artifact"
  fi

  if [ "$QEMU_STATUS" -eq 124 ]; then
    echo "VALIDATION: FAIL -- QEMU timed out after ''${TIMEOUT_SEC}s" >&2
    exit 1
  fi
  if [ "$DONEC" -eq 0 ]; then
    echo "VALIDATION: FAIL -- guest did not emit completion marker" >&2
    exit 1
  fi
  if [ "$REFUSALC" -gt 0 ]; then
    echo "VALIDATION: REFUSAL -- $REFUSALC environment refusal(s)" >&2
    exit 2
  fi
  if [ "$FAILC" -gt 0 ]; then
    echo "VALIDATION: FAIL -- $FAILC validation row(s) failed" >&2
    exit 1
  fi

  echo "VALIDATION: PASS"
''
