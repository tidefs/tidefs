# TideFS FUSE VM smoke validation.
#
# Nix builds the Linux 7.0 kernel, TideFS workspace binaries, and this runner
# script. The runner constructs a tiny initrd and launches QEMU from the caller,
# outside the Nix build sandbox.
{
  pkgs,
  linuxKernel_7_0,
  tidefsPackage,
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
  SCRUB_VALIDATION="${scrubValidationPackage}/bin/scrub_foreground_read_validation"
  JQ="${pkgs.jq}/bin/jq"

  TMPDIR="''${TIDEFS_FUSE_VM_TEST_TMPDIR:-/tmp/tidefs-fuse-vm-test}"
  TIMEOUT_SEC="''${TIDEFS_FUSE_VM_TEST_TIMEOUT:-900}"
  VALIDATION_DIR="''${TIDEFS_FUSE_VM_TEST_VALIDATION_DIR:-/tmp/tidefs-validation/fuse-vm-test}"
  QUEUE_DEPTH_ARTIFACT="''${TIDEFS_FUSE_VM_TEST_QUEUE_DEPTH_ARTIFACT:-}"
  SCRUB_FOREGROUND_READ=0
  KEEP_TMP=0

  usage() {
    cat <<'EOF'
Usage: tidefs-fuse-vm-test-runner [OPTIONS]

Build a tiny Linux 7.0 initrd from Nix-built artifacts and launch QEMU outside
the Nix sandbox. The guest runs the legacy tidefsFuseVmTest validation sequence:
kernel check, /dev/fuse check, tidefs-xtask summary, tidefs-store-demo, and
smoke-mount with queue-depth artifact capture. The scrub option instead runs
the mounted scrub/read isolation binary and returns its typed evidence files.

Options:
  --timeout SECONDS              QEMU runtime timeout (default: 900)
  --validation-dir DIR           Host directory for qemu-boot.log and summary
  --queue-depth-artifact PATH    Host artifact path for queue-depth JSON
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
    for dep in "$SCRUB_VALIDATION" "$JQ"; do
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
  if [ "$SCRUB_FOREGROUND_READ" -eq 1 ]; then
    echo "  Scrub validator: $SCRUB_VALIDATION"
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
  if [ "$SCRUB_FOREGROUND_READ" -eq 1 ]; then
    copy_binary "$SCRUB_VALIDATION" "$RUN_DIR/bin/scrub_foreground_read_validation"
    copy_runtime_deps "$SCRUB_VALIDATION"
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
        cat "$SCRUB_RUNTIME_DIR/scrub-read-runtime.json"
        echo
        echo "TIDEFS_SCRUB_RUNTIME_ARTIFACT_END"
    fi
    if [ -s "$SCRUB_RUNTIME_DIR/evidence-manifest.json" ]; then
        echo "TIDEFS_SCRUB_EVIDENCE_MANIFEST_BEGIN"
        cat "$SCRUB_RUNTIME_DIR/evidence-manifest.json"
        echo
        echo "TIDEFS_SCRUB_EVIDENCE_MANIFEST_END"
    fi
    echo "scrub_runtime_exit_status=$SCRUB_RUNTIME_RC"
    finish
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

  scrub_artifact="$VALIDATION_DIR/scrub-read-runtime.json"
  scrub_manifest="$VALIDATION_DIR/evidence-manifest.json"
  if [ "$SCRUB_FOREGROUND_READ" -eq 1 ]; then
    extract_between \
      "TIDEFS_SCRUB_RUNTIME_ARTIFACT_BEGIN" \
      "TIDEFS_SCRUB_RUNTIME_ARTIFACT_END" \
      > "$scrub_artifact" || true
    extract_between \
      "TIDEFS_SCRUB_EVIDENCE_MANIFEST_BEGIN" \
      "TIDEFS_SCRUB_EVIDENCE_MANIFEST_END" \
      > "$scrub_manifest" || true
  fi

  PASSC=$(count_serial_lines '^PASS:')
  FAILC=$(count_serial_lines '^FAIL:')
  REFUSALC=$(count_serial_lines '^REFUSAL:')
  DONEC=$(count_serial_lines '^TIDEFS_FUSE_VM_TEST_DONE$')
  if [ "$SCRUB_FOREGROUND_READ" -eq 1 ]; then
    if [ ! -s "$scrub_artifact" ] || [ ! -s "$scrub_manifest" ]; then
      if [ "$REFUSALC" -eq 0 ]; then
        FAILC=$((FAILC + 1))
      fi
    elif ! "$JQ" -e 'type == "object"' "$scrub_artifact" >/dev/null \
      || ! "$JQ" -e 'type == "object"' "$scrub_manifest" >/dev/null; then
      FAILC=$((FAILC + 1))
    else
      scrub_outcome=$("$JQ" -r '.outcome // empty' "$scrub_artifact")
      manifest_outcome=$("$JQ" -r '.outcome // empty' "$scrub_manifest")
      if [ "$scrub_outcome" != "$manifest_outcome" ]; then
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
  KERNEL_VERSION=$(awk '
    { sub(/\r$/, "") }
    /^kernel_version=/ { sub(/^kernel_version=/, ""); print; exit }
  ' "$VAL_LOG")
  [ -n "$KERNEL_VERSION" ] || KERNEL_VERSION="unknown"
  QUEUE_PRESENT=false
  [ -s "$queue_tmp" ] && QUEUE_PRESENT=true

  cat > "$VALIDATION_DIR/fuse-vm-test.json" <<JSON
{
  "test": "tidefs-fuse-vm-test",
  "version": 3,
  "tier": "outside-sandbox-qemu-guest",
  "kernel_version": "$KERNEL_VERSION",
  "kernel_package": "linuxKernel_7_0",
  "qemu_status": $QEMU_STATUS,
  "done_marker_seen": $DONEC,
  "passed": $PASSC,
  "product_failures": $FAILC,
  "environment_refusals": $REFUSALC,
  "queue_depth_artifact": "$QUEUE_DEPTH_ARTIFACT",
  "queue_depth_artifact_present": $QUEUE_PRESENT
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
