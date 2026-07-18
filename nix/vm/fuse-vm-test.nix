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
  scrubValidationPackage,
}:

pkgs.writeShellScriptBin "tidefs-fuse-vm-test-runner" ''
  set -euo pipefail

  export PATH="${pkgs.coreutils}/bin:${pkgs.gnugrep}/bin:${pkgs.gnused}/bin:${pkgs.gawk}/bin:${pkgs.findutils}/bin:${pkgs.glibc.bin}/bin:${pkgs.cpio}/bin:${pkgs.xz}/bin:${pkgs.qemu}/bin:$PATH"

  QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
  BUSYBOX="${pkgs.busybox}/bin/busybox"
  CPIO="${pkgs.cpio}/bin/cpio"
  XZ_BIN="${pkgs.xz}/bin/xz"
  KERNEL_IMG="${linuxKernel_7_0}/bzImage"
  MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"
  TIDEFS_XTASK="${tidefsPackage}/bin/tidefs-xtask"
  TIDEFS_STORE_DEMO="${tidefsPackage}/bin/tidefs-store-demo"
  FUSE_DAEMON="${tidefsPackage}/bin/tidefs-posix-filesystem-adapter-daemon"
  ACK_VALIDATION="${ackValidationPackage}/bin/storage-intent-ack-runtime-validation"
  DATA_SHAPE_VALIDATION="${dataShapeValidationPackage}/bin/storage-intent-data-shape-runtime-validation"
  SCRUB_VALIDATION="${scrubValidationPackage}/bin/scrub_foreground_read_validation"
  BASE64="${pkgs.coreutils}/bin/base64"
  B3SUM="${pkgs.b3sum}/bin/b3sum"
  JQ="${pkgs.jq}/bin/jq"

  TMPDIR="''${TIDEFS_FUSE_VM_TEST_TMPDIR:-/tmp/tidefs-fuse-vm-test}"
  TIMEOUT_SEC="''${TIDEFS_FUSE_VM_TEST_TIMEOUT:-900}"
  VALIDATION_DIR="''${TIDEFS_FUSE_VM_TEST_VALIDATION_DIR:-/tmp/tidefs-validation/fuse-vm-test}"
  QUEUE_DEPTH_ARTIFACT="''${TIDEFS_FUSE_VM_TEST_QUEUE_DEPTH_ARTIFACT:-}"
  ACK_RECEIPT_RUNTIME=0
  SCRUB_FOREGROUND_READ=0
  KEEP_TMP=0

  usage() {
    cat <<'EOF'
Usage: tidefs-fuse-vm-test-runner [OPTIONS]

Build a tiny Linux 7.0 initrd from Nix-built artifacts and launch QEMU outside
the Nix sandbox. The guest runs the tidefsFuseVmTest validation sequence:
kernel check, /dev/fuse check, focused data-shape helper execution,
tidefs-xtask summary, tidefs-store-demo, and smoke-mount with queue-depth
artifact capture. The scrub option instead runs
the mounted scrub/read isolation binary and returns its typed evidence files.
The acknowledgment option runs the focused receipt producer on the same live
FUSE guest without adding crash or fault coverage.

Options:
  --timeout SECONDS              QEMU runtime timeout (default: 900)
  --validation-dir DIR           Host directory for qemu-boot.log and summary
  --queue-depth-artifact PATH    Host artifact path for queue-depth JSON
  --ack-receipt-runtime          Run the mounted acknowledgment receipt rows
  --scrub-foreground-read        Run the mounted scrub/read isolation row
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
      --queue-depth-artifact)
        QUEUE_DEPTH_ARTIFACT="$2"
        shift 2
        ;;
      --queue-depth-artifact=*)
        QUEUE_DEPTH_ARTIFACT="''${1#--queue-depth-artifact=}"
        shift
        ;;
      --ack-receipt-runtime)
        ACK_RECEIPT_RUNTIME=1
        shift
        ;;
      --scrub-foreground-read)
        SCRUB_FOREGROUND_READ=1
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

  if [ "$ACK_RECEIPT_RUNTIME" -eq 1 ] && [ "$SCRUB_FOREGROUND_READ" -eq 1 ]; then
    echo "ERROR: --ack-receipt-runtime and --scrub-foreground-read are mutually exclusive" >&2
    exit 2
  fi

  if [ -z "$QUEUE_DEPTH_ARTIFACT" ]; then
    QUEUE_DEPTH_ARTIFACT="$VALIDATION_DIR/performance/queue-depth-runtime.json"
  fi

  if [ ! -e /dev/kvm ]; then
    echo "ENVIRONMENT REFUSAL: /dev/kvm not available" >&2
    exit 2
  fi

  for dep in "$QEMU_BIN" "$BUSYBOX" "$CPIO" "$XZ_BIN" "$KERNEL_IMG" "$TIDEFS_XTASK" "$TIDEFS_STORE_DEMO" "$FUSE_DAEMON"; do
    if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
      echo "ERROR: dependency not found: $dep" >&2
      exit 2
    fi
  done
  if [ "$SCRUB_FOREGROUND_READ" -eq 1 ]; then
    for dep in "$SCRUB_VALIDATION" "$BASE64" "$B3SUM" "$JQ"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ERROR: dependency not found: $dep" >&2
        exit 2
      fi
    done
  fi
  if [ "$ACK_RECEIPT_RUNTIME" -eq 1 ]; then
    for dep in "$ACK_VALIDATION" "$BASE64" "$B3SUM" "$JQ"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ERROR: dependency not found: $dep" >&2
        exit 2
      fi
    done
  fi
  if [ "$ACK_RECEIPT_RUNTIME" -eq 0 ] && [ "$SCRUB_FOREGROUND_READ" -eq 0 ]; then
    for dep in "$DATA_SHAPE_VALIDATION" "$BASE64" "$B3SUM" "$JQ"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ERROR: dependency not found: $dep" >&2
        exit 2
      fi
    done
  fi

  echo "=== TideFS FUSE VM Test ==="
  echo "  Kernel:          $KERNEL_IMG"
  echo "  Module dir:      $MODULE_DIR"
  echo "  QEMU:            $QEMU_BIN"
  echo "  TideFS xtask:    $TIDEFS_XTASK"
  echo "  TideFS demo:     $TIDEFS_STORE_DEMO"
  echo "  TideFS daemon:   $FUSE_DAEMON"
  if [ "$ACK_RECEIPT_RUNTIME" -eq 1 ]; then
    echo "  Ack validator:   $ACK_VALIDATION"
  fi
  if [ "$SCRUB_FOREGROUND_READ" -eq 1 ]; then
    echo "  Scrub validator: $SCRUB_VALIDATION"
  fi
  if [ "$ACK_RECEIPT_RUNTIME" -eq 0 ] && [ "$SCRUB_FOREGROUND_READ" -eq 0 ]; then
    echo "  Data-shape validator: $DATA_SHAPE_VALIDATION"
  fi
  echo "  Validation dir:  $VALIDATION_DIR"
  echo "  Queue artifact:  $QUEUE_DEPTH_ARTIFACT"
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
  for applet in sh ls cat echo mount umount grep dmesg sleep timeout poweroff reboot mknod mkdir rmdir dd stat cp mv rm touch find wc sync expr head tail cut kill ps test seq date uname tr sed tee true false env printf basename dirname readlink chmod insmod; do
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

  copy_binary "$TIDEFS_XTASK" "$RUN_DIR/bin/tidefs-xtask"
  copy_binary "$TIDEFS_STORE_DEMO" "$RUN_DIR/bin/tidefs-store-demo"
  copy_binary "$FUSE_DAEMON" "$RUN_DIR/bin/tidefs-posix-filesystem-adapter-daemon"
  copy_runtime_deps "$BUSYBOX" "$TIDEFS_XTASK" "$TIDEFS_STORE_DEMO" "$FUSE_DAEMON"
  if [ "$ACK_RECEIPT_RUNTIME" -eq 1 ]; then
    copy_binary "$ACK_VALIDATION" "$RUN_DIR/bin/storage-intent-ack-runtime-validation"
    copy_runtime_deps "$ACK_VALIDATION"
  fi
  if [ "$SCRUB_FOREGROUND_READ" -eq 1 ]; then
    copy_binary "$SCRUB_VALIDATION" "$RUN_DIR/bin/scrub_foreground_read_validation"
    copy_runtime_deps "$SCRUB_VALIDATION"
  fi
  if [ "$ACK_RECEIPT_RUNTIME" -eq 0 ] && [ "$SCRUB_FOREGROUND_READ" -eq 0 ]; then
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
SCRUB_FOREGROUND_READ=__SCRUB_FOREGROUND_READ__
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

if [ "$SCRUB_FOREGROUND_READ" -eq 1 ]; then
    SCRUB_RUNTIME_DIR=/tmp/tidefs-validation/scrub-foreground-read-runtime
    mkdir -p "$SCRUB_RUNTIME_DIR"
    TIDEFS_DAEMON_BIN=/bin/tidefs-posix-filesystem-adapter-daemon \
      timeout 180 scrub_foreground_read_validation \
      --row scrub-foreground-read-runtime \
      --output-dir "$SCRUB_RUNTIME_DIR" \
      >/tmp/scrub-foreground-read-output.txt 2>&1
    SCRUB_RUNTIME_RC=$?
    cat /tmp/scrub-foreground-read-output.txt

    if [ -s "$SCRUB_RUNTIME_DIR/scrub-read-runtime.json" ]; then
        echo "TIDEFS_SCRUB_RUNTIME_ARTIFACT_BEGIN"
        /bin/busybox base64 "$SCRUB_RUNTIME_DIR/scrub-read-runtime.json"
        echo "TIDEFS_SCRUB_RUNTIME_ARTIFACT_END"
    fi
    if [ -s "$SCRUB_RUNTIME_DIR/evidence-manifest.json" ]; then
        echo "TIDEFS_SCRUB_EVIDENCE_MANIFEST_BEGIN"
        /bin/busybox base64 "$SCRUB_RUNTIME_DIR/evidence-manifest.json"
        echo "TIDEFS_SCRUB_EVIDENCE_MANIFEST_END"
    fi
    echo "scrub_runtime_exit_status=$SCRUB_RUNTIME_RC"
    finish
fi

if [ "$ACK_RECEIPT_RUNTIME" -eq 0 ] && [ "$SCRUB_FOREGROUND_READ" -eq 0 ]; then
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
fi

if tidefs-xtask summary >/tmp/xtask-summary.out 2>&1; then
    cat /tmp/xtask-summary.out
    pass "xtask_summary"
else
    cat /tmp/xtask-summary.out
    fail "xtask_summary" "tidefs-xtask summary exited nonzero"
fi

if tidefs-store-demo >/tmp/store-demo.out 2>&1; then
    cat /tmp/store-demo.out
    pass "store_demo"
else
    cat /tmp/store-demo.out
    fail "store_demo" "tidefs-store-demo exited nonzero"
fi

QUEUE_DEPTH_ARTIFACT="__QUEUE_DEPTH_ARTIFACT__"
mkdir -p "$(dirname "$QUEUE_DEPTH_ARTIFACT")"
TIDEFS_ROOT_AUTHENTICATION_KEY_HEX=4141414141414141414141414141414141414141414141414141414141414141 \
  tidefs-posix-filesystem-adapter-daemon smoke-mount \
  --profile quick \
  --queue-depth-artifact "$QUEUE_DEPTH_ARTIFACT" \
  >/tmp/smoke-mount-output.txt 2>&1
SMOKE_RC=$?
cat /tmp/smoke-mount-output.txt

SMOKE_SUMMARY=$(sed -n 's/.*smoke-mount:[[:space:]]*\([0-9][0-9]*\)[[:space:]]*passed,[[:space:]]*\([0-9][0-9]*\)[[:space:]]*failed.*/\1 \2/p' /tmp/smoke-mount-output.txt | tail -1)
SMOKE_FAILED=1
if [ -n "$SMOKE_SUMMARY" ]; then
    SMOKE_FAILED=$(echo "$SMOKE_SUMMARY" | cut -d' ' -f2)
fi

if [ "$SMOKE_RC" -eq 0 ] && [ "$SMOKE_FAILED" -eq 0 ]; then
    pass "smoke_mount"
else
    fail "smoke_mount" "rc=$SMOKE_RC failed=$SMOKE_FAILED"
fi

echo "--- dmesg tail ---"
dmesg | tail -80 2>/dev/null || true
echo "--- end dmesg tail ---"

if [ -s "$QUEUE_DEPTH_ARTIFACT" ]; then
    pass "queue_depth_runtime_artifact"
    echo "TIDEFS_QUEUE_DEPTH_ARTIFACT_BEGIN"
    cat "$QUEUE_DEPTH_ARTIFACT"
    echo
    echo "TIDEFS_QUEUE_DEPTH_ARTIFACT_END"
else
    fail "queue_depth_runtime_artifact" "missing $QUEUE_DEPTH_ARTIFACT"
fi

umount -l /tmp/tidefs-smoke-mount-point 2>/dev/null || true
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
        echo "ERROR: unsafe scrub provenance value for ''${provenance%%=*}" >&2
        exit 2
        ;;
    esac
  done

  escaped_queue_path="$(printf '%s' "$QUEUE_DEPTH_ARTIFACT" | sed 's/[&|\\]/\\&/g')"
  sed -i "s|__QUEUE_DEPTH_ARTIFACT__|$escaped_queue_path|g" "$RUN_DIR/init"
  sed -i "s|__ACK_RECEIPT_RUNTIME__|$ACK_RECEIPT_RUNTIME|g" "$RUN_DIR/init"
  sed -i "s|__SCRUB_FOREGROUND_READ__|$SCRUB_FOREGROUND_READ|g" "$RUN_DIR/init"
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
  cp "$RUN_DIR/init" "$VALIDATION_DIR/init-script"

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

  queue_tmp="$RUN_DIR/queue-depth-runtime.json"
  extract_between "TIDEFS_QUEUE_DEPTH_ARTIFACT_BEGIN" "TIDEFS_QUEUE_DEPTH_ARTIFACT_END" > "$queue_tmp" || true
  if [ -s "$queue_tmp" ]; then
    mkdir -p "$(dirname "$QUEUE_DEPTH_ARTIFACT")"
    cp "$queue_tmp" "$QUEUE_DEPTH_ARTIFACT"
  fi

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

  scrub_artifact="$VALIDATION_DIR/scrub-read-runtime.json"
  scrub_manifest="$VALIDATION_DIR/evidence-manifest.json"
  if [ "$SCRUB_FOREGROUND_READ" -eq 1 ]; then
    extract_between \
      "TIDEFS_SCRUB_RUNTIME_ARTIFACT_BEGIN" \
      "TIDEFS_SCRUB_RUNTIME_ARTIFACT_END" \
      | "$BASE64" --decode > "$scrub_artifact" || true
    extract_between \
      "TIDEFS_SCRUB_EVIDENCE_MANIFEST_BEGIN" \
      "TIDEFS_SCRUB_EVIDENCE_MANIFEST_END" \
      | "$BASE64" --decode > "$scrub_manifest" || true
  fi

  data_shape_transform_artifact="$VALIDATION_DIR/data-shape-transform-execution.json"
  data_shape_transform_manifest="$VALIDATION_DIR/data-shape-transform-execution.manifest.json"
  data_shape_performance_artifact="$VALIDATION_DIR/data-shape-performance-fault-rows.json"
  data_shape_performance_manifest="$VALIDATION_DIR/data-shape-performance-fault-rows.manifest.json"
  if [ "$ACK_RECEIPT_RUNTIME" -eq 0 ] && [ "$SCRUB_FOREGROUND_READ" -eq 0 ]; then
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
  if [ "$SCRUB_FOREGROUND_READ" -eq 1 ]; then
    if [ ! -s "$scrub_artifact" ] || [ ! -s "$scrub_manifest" ]; then
      if [ "$REFUSALC" -eq 0 ]; then
        FAILC=$((FAILC + 1))
      fi
    elif ! "$JQ" -e 'type == "object"' "$scrub_artifact" >/dev/null \
      || ! "$JQ" -e 'type == "object"' "$scrub_manifest" >/dev/null; then
      FAILC=$((FAILC + 1))
    else
      declared_digest=$("$JQ" -r '.content_digest // empty' "$scrub_manifest")
      actual_digest="blake3:$("$B3SUM" "$scrub_artifact" | awk '{print $1}')"
      scrub_outcome=$("$JQ" -r '.outcome // empty' "$scrub_artifact")
      manifest_outcome=$("$JQ" -r '.outcome // empty' "$scrub_manifest")
      scrub_source_ref=$("$JQ" -r '.source_ref // empty' "$scrub_artifact")
      manifest_source_ref=$("$JQ" -r '.source_ref // empty' "$scrub_manifest")
      expected_source_ref="''${GITHUB_SHA:-unknown}"
      if [ -z "$declared_digest" ] || [ "$declared_digest" != "$actual_digest" ]; then
        echo "FAIL: scrub_runtime_artifact_digest -- declared=$declared_digest actual=$actual_digest" >&2
        FAILC=$((FAILC + 1))
      elif [ -z "$scrub_source_ref" ] \
        || [ "$scrub_source_ref" != "$manifest_source_ref" ] \
        || [ "$scrub_source_ref" != "$expected_source_ref" ]; then
        echo "FAIL: scrub_runtime_source_ref -- artifact=$scrub_source_ref manifest=$manifest_source_ref expected=$expected_source_ref" >&2
        FAILC=$((FAILC + 1))
      elif [ "$scrub_outcome" != "$manifest_outcome" ]; then
        FAILC=$((FAILC + 1))
      else
        case "$scrub_outcome" in
          pass)
            if "$JQ" -e \
              '.passed == true and .runtime_source.workload_ran == true and .mount != null and .scrub_activity.daemon_runtime != null' \
              "$scrub_artifact" >/dev/null; then
              PASSC=$((PASSC + 1))
            else
              FAILC=$((FAILC + 1))
            fi
            ;;
          environment-refusal)
            REFUSALC=$((REFUSALC + 1))
            ;;
          product-fail|harness-fail)
            FAILC=$((FAILC + 1))
            ;;
          *)
            FAILC=$((FAILC + 1))
            ;;
        esac
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

  if [ "$ACK_RECEIPT_RUNTIME" -eq 0 ] && [ "$SCRUB_FOREGROUND_READ" -eq 0 ]; then
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
  QUEUE_PRESENT=false
  [ -s "$queue_tmp" ] && QUEUE_PRESENT=true
  DATA_SHAPE_TRANSFORM_PRESENT=false
  DATA_SHAPE_PERFORMANCE_PRESENT=false
  if [ "$ACK_RECEIPT_RUNTIME" -eq 0 ] && [ "$SCRUB_FOREGROUND_READ" -eq 0 ]; then
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
  "queue_depth_artifact": "$QUEUE_DEPTH_ARTIFACT",
  "queue_depth_artifact_present": $QUEUE_PRESENT,
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
  if [ "$QUEUE_PRESENT" = true ]; then
    echo "Queue-depth artifact: $QUEUE_DEPTH_ARTIFACT"
  fi
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
