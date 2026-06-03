# TideFS: FUSE fio performance baseline in a direct Linux 7.0 QEMU guest.
#
# This is intentionally not a NixOS VM test.  It builds a small initramfs with
# busybox, fio, and the FUSE daemon so release-loop perf validation does not drag
# a full NixOS test-system closure into every iteration.

{
  pkgs,
  linuxKernel_7_0,
  tidefsPackage,
}:

let
  fuseFioBaselineScript = pkgs.writeShellScriptBin "tidefs-fuse-fio-baseline" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    LDD_BIN="${pkgs.lib.getBin pkgs.glibc}/bin/ldd"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    GZIP="${pkgs.gzip}/bin/gzip"
    FIO="${pkgs.fio}/bin/fio"
    PYTHON="${pkgs.python3}/bin/python3"
    FUSE_DAEMON="${tidefsPackage}/bin/tidefs-posix-filesystem-adapter-daemon"

    TMPDIR="''${TIDEFS_FUSE_FIO_TMPDIR:-/tmp/tidefs-fuse-fio-baseline}"
    TIMEOUT_SEC="''${TIDEFS_FUSE_FIO_TIMEOUT:-900}"
    FIO_RUNTIME="''${TIDEFS_FUSE_FIO_RUNTIME:-3}"

    usage() {
      cat <<USAGE
Usage: tidefs-fuse-fio-baseline [--timeout SECONDS] [--keep-tmp]

Run the TideFS FUSE fio performance baseline in a direct Linux 7.0 QEMU guest.
The guest emits a JSON validation document between marker lines on stdout.

Options:
  --timeout SECONDS  QEMU timeout (default: $TIMEOUT_SEC)
  --keep-tmp         Do not remove temp directory on exit
  --help, -h         Show this message
USAGE
    }

    KEEP_TMP=0
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO" "$GZIP" "$FIO" "$PYTHON" "$FUSE_DAEMON"; do
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

    echo "=== TideFS VAL: fuse-fio-baseline direct QEMU ==="
    echo "  Kernel:      $KERNEL_IMG"
    echo "  FUSE daemon: $FUSE_DAEMON"
    echo "  fio:         $FIO"
    echo "  QEMU:        $QEMU_BIN"
    echo "  Accel:       $QEMU_ACCEL_LABEL"
    echo "  Timeout:     $TIMEOUT_SEC"
    echo "  fio runtime: $FIO_RUNTIME seconds per workload"
    echo ""

    WORK_DIR="$TMPDIR/validation-$$"
    RUN_DIR="$WORK_DIR/initrd"
    QEMU_OUT="$WORK_DIR/qemu-stdout.log"
    QEMU_ERR="$WORK_DIR/qemu-stderr.log"
    VALIDATION_JSON="$WORK_DIR/validation.json"

    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,mnt/tidefs,store,etc}

    cleanup() {
      if [ "$KEEP_TMP" -eq 1 ]; then
        echo "  Keeping: $WORK_DIR"
      else
        rm -rf "$WORK_DIR"
      fi
    }
    trap cleanup EXIT

    copy_binary_to_bin() {
      local src="$1"
      local dst="$2"
      cp "$src" "$RUN_DIR/bin/$dst"
      chmod +x "$RUN_DIR/bin/$dst"
    }

    copy_runtime_deps() {
      echo "  Copying exact Nix store runtime dependencies..."
      local deps
      deps=$("$LDD_BIN" "$BUSYBOX" "$FIO" "$FUSE_DAEMON" 2>/dev/null | grep -o '/nix/store/[^ ]*' | sort -u || true)
      for lib in $deps; do
        if [ -f "$lib" ]; then
          local lib_dir
          lib_dir=$(dirname "$lib")
          mkdir -p "$RUN_DIR$lib_dir"
          cp "$lib" "$RUN_DIR$lib" 2>/dev/null || true
        fi
      done

      for binary in "$BUSYBOX" "$FIO" "$FUSE_DAEMON"; do
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
    for applet in sh ls cat echo mount grep dmesg sleep poweroff reboot mknod \
                    mkdir rmdir dd stat cp mv rm touch find wc sync expr head \
                    tail cut kill ps test seq mountpoint uname date umount sed tr \
                    awk hostname truncate; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    copy_binary_to_bin "$FIO" fio
    copy_binary_to_bin "$FUSE_DAEMON" tidefs-posix-filesystem-adapter-daemon
    copy_runtime_deps

    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin
export TIDEFS_ROOT_AUTHENTICATION_KEY_HEX=4141414141414141414141414141414141414141414141414141414141414141

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

echo "=== TideFS FUSE fio Baseline ==="
KVER=$(uname -r 2>/dev/null || echo unknown)
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)
echo "kernel=$KVER"
echo "timestamp=$TS"

PASSED=0
PRODUCT_FAILED=0
HARNESS_FAILED=0
ENV_REFUSALS=0
SKIPPED=0
RESULTS=/tmp/results.ndjson
BENCHMARKS=/tmp/benchmarks.ndjson
: > "$RESULTS"
: > "$BENCHMARKS"

json_array() {
    local file="$1"
    local first=1
    printf '['
    while IFS= read -r row; do
        if [ -n "$row" ]; then
            if [ "$first" -eq 1 ]; then
                first=0
            else
                printf ','
            fi
            printf '%s' "$row"
        fi
    done < "$file"
    printf ']'
}

result_row() {
    echo "{\"name\":\"$1\",\"status\":\"$2\"}" >> "$RESULTS"
}

pass() {
    echo "PASS: $1"
    PASSED=$((PASSED + 1))
    result_row "$1" "pass"
}

product_fail() {
    echo "PRODUCT-FAIL: $1 -- $2"
    PRODUCT_FAILED=$((PRODUCT_FAILED + 1))
    result_row "$1" "product-fail"
}

harness_fail() {
    echo "HARNESS-FAIL: $1 -- $2"
    HARNESS_FAILED=$((HARNESS_FAILED + 1))
    result_row "$1" "harness-fail"
}

environment_refusal() {
    echo "ENVIRONMENT-REFUSAL: $1 -- $2"
    ENV_REFUSALS=$((ENV_REFUSALS + 1))
    result_row "$1" "environment-refusal"
}

append_benchmark() {
    echo "$1" >> "$BENCHMARKS"
}

metric_sum() {
    local key="$1"
    local file="$2"
    grep -o "\"$key\"[[:space:]]*:[[:space:]]*[0-9.]*" "$file" 2>/dev/null | \
      awk -F: '{gsub(/[ ,]/, "", $2); s += $2} END { if (s == "") s = 0; print s + 0 }'
}

metric_percentile() {
    local pct="$1"
    local file="$2"
    local value
    value=$(grep -o "\"$pct\"[[:space:]]*:[[:space:]]*[0-9.]*" "$file" 2>/dev/null | \
      head -1 | awk -F: '{gsub(/[ ,]/, "", $2); print $2 + 0}')
    if [ -z "$value" ]; then
        value=0
    fi
    printf '%s' "$value"
}

case "$KVER" in
  7.*) pass "linux_7_0_kernel" ;;
  *) environment_refusal "linux_7_0_kernel" "expected Linux 7.0 guest kernel";;
esac

if grep -q fuse /proc/filesystems 2>/dev/null; then
    pass "fuse_builtin"
else
    environment_refusal "fuse_builtin" "FUSE filesystem not built into kernel"
fi

if [ ! -e /dev/fuse ]; then
    mknod /dev/fuse c 10 229 2>/dev/null || true
fi

if [ -e /dev/fuse ]; then
    pass "fuse_device"
else
    environment_refusal "fuse_device" "/dev/fuse not available"
fi

STORE=/store/tidefs-fio
MNT=/mnt/tidefs
DAEMON_PID=""
MOUNTED=0

mkdir -p "$STORE" "$MNT"
if [ -e /dev/fuse ] && grep -q fuse /proc/filesystems 2>/dev/null; then
    /bin/tidefs-posix-filesystem-adapter-daemon mount-vfs \
      --store "$STORE" \
      --mount "$MNT" \
      --root-auth-key-hex 4141414141414141414141414141414141414141414141414141414141414141 \
      --no-writeback-cache \
      > /tmp/tidefs-fuse-daemon.log 2>&1 &
    DAEMON_PID=$!
    echo "daemon_pid=$DAEMON_PID"

    for i in $(seq 1 45); do
        if mountpoint -q "$MNT" 2>/dev/null; then
            MOUNTED=1
            break
        fi
        if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
            break
        fi
        sleep 1
    done

    if [ "$MOUNTED" -eq 1 ]; then
        pass "fuse_mount"
    else
        tail -40 /tmp/tidefs-fuse-daemon.log 2>/dev/null || true
        harness_fail "fuse_mount" "mountpoint did not appear"
    fi
else
    environment_refusal "fuse_mount" "FUSE kernel support unavailable"
fi

FIO_FILE="$MNT/tidefs-fio-benchmark-file"
FIO_RUNTIME=__FIO_RUNTIME__
if [ "$MOUNTED" -eq 1 ]; then
    for spec in "4k 256K" "64k 512K" "128k 1M" "1m 2M"; do
        set -- $spec
        BS="$1"
        SIZE="$2"
        for workload in sequential-write sequential-read random-write random-read sync-write; do
            EXTRA=""
            RW="write"
            case "$workload" in
              sequential-write) RW="write" ;;
              sequential-read) RW="read" ;;
              random-write) RW="randwrite" ;;
              random-read) RW="randread" ;;
              sync-write) RW="write"; EXTRA="--fsync=1" ;;
            esac
            NAME="$workload-$BS"
            OUT="/tmp/fio-$NAME.json"
            ERR="/tmp/fio-$NAME.err"
            echo "fio: $NAME size=$SIZE"
            truncate -s "$SIZE" "$FIO_FILE" 2>/dev/null || true
            if fio --name="$NAME" --filename="$FIO_FILE" --bs="$BS" --rw="$RW" \
                  --size="$SIZE" --iodepth=1 --output="$OUT" --output-format=json \
                  --group_reporting --norandommap --randrepeat=0 --refill_buffers \
                  --direct=0 --runtime="$FIO_RUNTIME" --time_based --eta=never \
                  $EXTRA 2>"$ERR"; then
                pass "fio_$NAME"
                BW=$(metric_sum bw_bytes "$OUT")
                IOPS=$(metric_sum iops "$OUT")
                P50=$(metric_percentile "50\\.000000" "$OUT")
                P95=$(metric_percentile "95\\.000000" "$OUT")
                P99=$(metric_percentile "99\\.000000" "$OUT")
                append_benchmark "{\"name\":\"$NAME\",\"workload\":\"$workload\",\"block_size\":\"$BS\",\"size\":\"$SIZE\",\"runtime_s\":$FIO_RUNTIME,\"bw_bytes_per_sec\":$BW,\"iops\":$IOPS,\"lat_ns_p50\":$P50,\"lat_ns_p95\":$P95,\"lat_ns_p99\":$P99}"
            else
                product_fail "fio_$NAME" "$(head -5 "$ERR" 2>/dev/null || echo fio-failed)"
                append_benchmark "{\"name\":\"$NAME\",\"workload\":\"$workload\",\"block_size\":\"$BS\",\"size\":\"$SIZE\",\"status\":\"fail\"}"
            fi
        done
        rm -f "$FIO_FILE" 2>/dev/null || true
    done
else
    for workload in sequential-write sequential-read random-write random-read sync-write; do
        environment_refusal "fio_$workload" "filesystem not mounted"
    done
fi

META_COUNT=20
META_DIR="$MNT/tidefs-meta-bench"
META_CREATE_S=0
META_STAT_S=0
META_UNLINK_S=0
if [ "$MOUNTED" -eq 1 ]; then
    echo "metadata: create/stat/unlink $META_COUNT files"
    mkdir -p "$META_DIR"
    START=$(date +%s)
    for i in $(seq 1 "$META_COUNT"); do
        touch "$META_DIR/f$i" 2>/tmp/meta-create.err || break
    done
    END=$(date +%s)
    META_CREATE_S=$((END - START))
    [ "$META_CREATE_S" -le 0 ] && META_CREATE_S=1
    if [ -s /tmp/meta-create.err ]; then
        product_fail "meta_create" "$(cat /tmp/meta-create.err)"
    else
        pass "meta_create"
    fi

    START=$(date +%s)
    for i in $(seq 1 "$META_COUNT"); do
        stat "$META_DIR/f$i" >/dev/null 2>/tmp/meta-stat.err || break
    done
    END=$(date +%s)
    META_STAT_S=$((END - START))
    [ "$META_STAT_S" -le 0 ] && META_STAT_S=1
    if [ -s /tmp/meta-stat.err ]; then
        product_fail "meta_stat" "$(cat /tmp/meta-stat.err)"
    else
        pass "meta_stat"
    fi

    START=$(date +%s)
    for i in $(seq 1 "$META_COUNT"); do
        rm -f "$META_DIR/f$i" 2>/tmp/meta-unlink.err || break
    done
    END=$(date +%s)
    META_UNLINK_S=$((END - START))
    [ "$META_UNLINK_S" -le 0 ] && META_UNLINK_S=1
    if [ -s /tmp/meta-unlink.err ]; then
        product_fail "meta_unlink" "$(cat /tmp/meta-unlink.err)"
    else
        pass "meta_unlink"
    fi
    rmdir "$META_DIR" 2>/dev/null || true
else
    environment_refusal "metadata_bench" "filesystem not mounted"
fi

if [ "$MOUNTED" -eq 1 ]; then
    sync || true
    umount "$MNT" 2>/tmp/fuse-umount.err || true
fi
if [ -n "$DAEMON_PID" ]; then
    kill "$DAEMON_PID" 2>/dev/null || true
    sleep 1
    kill -9 "$DAEMON_PID" 2>/dev/null || true
fi

DMESG_TAIL=$(dmesg | tail -30 2>/dev/null | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\n' ' ' | cut -c1-2000)
RESULT_ROWS=$(json_array "$RESULTS")
BENCHMARK_ROWS=$(json_array "$BENCHMARKS")

echo "=== BEGIN FUSE FIO BENCHMARK JSON ==="
cat << JSON
{
  "test": "tidefs-fuse-fio-baseline",
  "version": 1,
  "validation_id": "fuse-fio-baseline",
  "timestamp": "$TS",
  "kernel_version": "$KVER",
  "linux_7_0": true,
  "kernel_package": "linuxKernel_7_0",
  "mode": "fuse",
  "backend": "local-object-store",
  "validation_tier": "Tier 3 QEMU guest mounted-userspace FUSE runtime",
  "fio_runtime_s": $FIO_RUNTIME,
  "passed": $PASSED,
  "product_failures": $PRODUCT_FAILED,
  "harness_failures": $HARNESS_FAILED,
  "environment_refusals": $ENV_REFUSALS,
  "skipped": $SKIPPED,
  "results": $RESULT_ROWS,
  "benchmarks": $BENCHMARK_ROWS,
  "metadata_bench": {
    "num_files": $META_COUNT,
    "create_s": $META_CREATE_S,
    "stat_s": $META_STAT_S,
    "unlink_s": $META_UNLINK_S
  },
  "dmesg_tail": "$DMESG_TAIL"
}
JSON
echo "=== END FUSE FIO BENCHMARK JSON ==="
echo "SUMMARY: PASSED=$PASSED PRODUCT_FAILED=$PRODUCT_FAILED HARNESS_FAILED=$HARNESS_FAILED ENV_REFUSALS=$ENV_REFUSALS SKIPPED=$SKIPPED"

sync
sleep 1
poweroff -f
INITSCRIPT

    sed -i "s/__FIO_RUNTIME__/$FIO_RUNTIME/g" "$RUN_DIR/init"
    chmod +x "$RUN_DIR/init"

    echo "  Building initramfs..."
    ( cd "$RUN_DIR" && find . | "$CPIO" -o -H newc 2>/dev/null | "$GZIP" > "$WORK_DIR/initrd.img" )

    echo "  Booting QEMU guest..."
    set +e
    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      -kernel "$KERNEL_IMG" \
      -initrd "$WORK_DIR/initrd.img" \
      -append "console=ttyS0 quiet init=/init panic=10 panic_on_oops=1" \
      -nographic \
      -no-reboot \
      -m 1536 \
      -smp 2 \
      "''${QEMU_ACCEL[@]}" \
      > "$QEMU_OUT" 2> "$QEMU_ERR"
    QEMU_EXIT=$?
    set -e

    echo ""
    echo "  QEMU exit code: $QEMU_EXIT"
    echo ""
    echo "=== QEMU Guest Output (tail 160 lines) ==="
    tail -160 "$QEMU_OUT" 2>/dev/null || echo "(no stdout)"
    echo ""
    echo "=== QEMU stderr (tail 80 lines) ==="
    tail -80 "$QEMU_ERR" 2>/dev/null || echo "(no stderr)"

    awk '
      { sub(/\r$/, "", $0) }
      /BEGIN FUSE FIO BENCHMARK JSON/ { in_json = 1; next }
      /END FUSE FIO BENCHMARK JSON/ { in_json = 0; next }
      in_json { print }
    ' "$QEMU_OUT" > "$VALIDATION_JSON"

    if [ ! -s "$VALIDATION_JSON" ]; then
      echo "ERROR: FUSE fio benchmark JSON markers missing" >&2
      exit 1
    fi

    "$PYTHON" - "$VALIDATION_JSON" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    validation = json.load(f)
print("=== Extracted FUSE fio benchmark JSON ===")
print(json.dumps(validation, indent=2, sort_keys=True))
product = int(validation.get("product_failures", 0))
harness = int(validation.get("harness_failures", 0))
env = int(validation.get("environment_refusals", 0))
if product or harness:
    sys.exit(1)
if env:
    sys.exit(2)
sys.exit(0)
PY
    JSON_EXIT=$?

    if [ "$QEMU_EXIT" -eq 124 ]; then
      echo "ERROR: QEMU timed out after $TIMEOUT_SEC seconds" >&2
      exit 1
    fi
    if [ "$QEMU_EXIT" -ne 0 ] && [ "$QEMU_EXIT" -ne 1 ]; then
      echo "ERROR: QEMU exited with unexpected status $QEMU_EXIT" >&2
      exit 1
    fi
    exit "$JSON_EXIT"
  '';
in
{
  fuseFioBaseline = fuseFioBaselineScript;
}
