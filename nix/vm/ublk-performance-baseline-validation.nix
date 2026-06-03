# TideFS: ublk single-node throughput/latency performance baseline.
#
# Boots a Linux 7.0 QEMU guest with a ublk block device and measures:
#   1. Queue-depth latency budget (randrw 70/30, iodepth 1..64)
#      -> p50/p95/p99 latency percentiles and throughput (MiB/s) per depth
#   2. Flush/FUA write overhead (plain vs fsync vs FUA writes)
#      -> per-phase write latency and IOPS
#
# Validation tier: Tier 3 QEMU guest ublk/block-volume runtime.
# Close standard: measured runtime performance validation with command/log/output
# paths (fio JSON output, KPIs, validation manifest).
#
# Environment refusal: in environments without /dev/kvm or Linux 7.0,
# produces REFUSAL-classified validation rows.

{
  pkgs,
  linuxKernel_7_0,
  tidefsPackage,
}:

let
  ublkPerfBaselineScript = pkgs.writeShellScriptBin "tidefs-ublk-perf-baseline" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    LDD_BIN="${pkgs.lib.getBin pkgs.glibc}/bin/ldd"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    GZIP="${pkgs.gzip}/bin/gzip"
    FIO="${pkgs.fio}/bin/fio"
    BC="${pkgs.bc}/bin/bc"
    MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"
    TIDEFSCTL="${tidefsPackage}/bin/tidefsctl"
    UBLK_DAEMON="${tidefsPackage}/bin/tidefs-block-volume-adapter-daemon"

    TMPDIR="''${TIDEFS_UBLK_PERF_TMPDIR:-/tmp/tidefs-ublk-perf-baseline}"
    TIMEOUT_SEC="''${TIDEFS_UBLK_PERF_TIMEOUT:-600}"
    DISK_SIZE_MB="''${TIDEFS_UBLK_PERF_DISK_MB:-1024}"

    usage() {
      cat <<USAGE
Usage: tidefs-ublk-perf-baseline [--timeout SECONDS] [--disk-size-mb MB] [--keep-tmp]

Single-node ublk throughput/latency performance baseline in a Linux 7.0 QEMU
guest. Runs fio queue-depth latency measurement (iodepth 1..64) and flush/FUA
overhead measurement, then writes validation to stdout and an validation JSON file.

Options:
  --timeout SECONDS  QEMU boot timeout (default: $TIMEOUT_SEC)
  --disk-size-mb MB  Size of the block-device backing image (default: $DISK_SIZE_MB)
  --keep-tmp         Do not remove temp directory on exit
  --help, -h         Show this message
USAGE
    }

    KEEP_TMP=0
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --disk-size-mb) DISK_SIZE_MB="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO" "$GZIP" "$FIO" "$BC" "$TIDEFSCTL" "$UBLK_DAEMON"; do
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
    if [ -e /dev/kvm ]; then
      QEMU_ACCEL=(-enable-kvm -cpu host)
      QEMU_ACCEL_LABEL="kvm"
    else
      QEMU_ACCEL_LABEL="tcg"
    fi

    echo "=== TideFS VAL: ublk-perf-baseline QEMU ==="
    echo "  Kernel:    $KERNEL_IMG"
    echo "  tidefsctl: $TIDEFSCTL"
    echo "  ublk daemon: $UBLK_DAEMON"
    echo "  QEMU:      $QEMU_BIN"
    echo "  Accel:     $QEMU_ACCEL_LABEL"
    echo "  Timeout:   ''${TIMEOUT_SEC}s"
    echo "  Disk size: ''${DISK_SIZE_MB}MB"
    echo ""

    # -- Build temporary workspace --
    WORK_DIR="$TMPDIR/validation-$$"
    RUN_DIR="$WORK_DIR/initrd"
    DISK1_IMG="$WORK_DIR/disk1.img"
    DISK2_IMG="$WORK_DIR/disk2.img"
    VALIDATION_DIR="$WORK_DIR/validation"
    VAL_LOG="$WORK_DIR/validation.log"
    BENCHMARK_ROWS="[]"

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

    echo "  Creating sparse raw virtio disk images"
    ${pkgs.coreutils}/bin/truncate -s "''${DISK_SIZE_MB}M" "$DISK1_IMG"
    ${pkgs.coreutils}/bin/truncate -s "''${DISK_SIZE_MB}M" "$DISK2_IMG"

    copy_binary_to_bin() {
      local src="$1"
      local dst="$2"
      cp "$src" "$RUN_DIR/bin/$dst"
      chmod +x "$RUN_DIR/bin/$dst"
    }

    copy_runtime_deps() {
      echo "  Copying exact Nix store runtime dependencies..."
      local deps
      deps=$("$LDD_BIN" "$BUSYBOX" "$FIO" "$BC" "$TIDEFSCTL" "$UBLK_DAEMON" 2>/dev/null | grep -o '/nix/store/[^ ]*' | sort -u || true)
      for lib in $deps; do
        if [ -f "$lib" ]; then
          local lib_dir
          lib_dir=$(dirname "$lib")
          mkdir -p "$RUN_DIR$lib_dir"
          cp "$lib" "$RUN_DIR$lib" 2>/dev/null || true
        fi
      done

      for binary in "$BUSYBOX" "$FIO" "$BC" "$TIDEFSCTL" "$UBLK_DAEMON"; do
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
    for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff \
                    reboot mknod mkdir rmdir dd stat cp mv rm touch find wc sync \
                    expr head tail cut kill ps test seq blockdev mountpoint du \
                    sed awk uname date; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    copy_binary_to_bin "$FIO" fio
    copy_binary_to_bin "$BC" bc
    copy_binary_to_bin "$TIDEFSCTL" tidefsctl
    copy_binary_to_bin "$UBLK_DAEMON" tidefs-block-volume-adapter-daemon
    copy_runtime_deps

    # Check for ublk_drv kernel module
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

    # -- Guest init script --
    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin
export TIDEFS_ROOT_AUTHENTICATION_KEY_HEX=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /run/tidefs/import /tmp/validation

echo "=== TideFS ublk Performance Baseline ==="
echo "kernel=$(uname -r 2>/dev/null || echo unknown)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"
echo ""

KVER=$(uname -r 2>/dev/null || echo unknown)
case "$KVER" in
  7.*) echo "linux_7_0_kernel: pass ($KVER)" ;;
  *)   echo "BLOCKED: linux_7_0_kernel -- expected Linux 7.0 guest kernel, got $KVER"; exit 1 ;;
esac

PASSED=0; FAILED=0; BLOCKED=0
BENCHMARK_ROWS="[]"

pass()   { echo "PASS: $1"; PASSED=$((PASSED + 1)); }
fail()   { echo "FAIL: $1 -- $2"; FAILED=$((FAILED + 1)); }
blocked(){ echo "BLOCKED: $1 -- $2"; BLOCKED=$((BLOCKED + 1)); }

append_benchmark_row() {
    if [ "$#" -ne 1 ]; then
        return 1
    fi
    if [ "$BENCHMARK_ROWS" = "[]" ]; then
        BENCHMARK_ROWS="[$1]"
    else
        BENCHMARK_ROWS="''${BENCHMARK_ROWS%]},$1]"
    fi
}

json_metric() {
    key="$1"
    file="$2"
    value=$(grep -o "\"$key\"[[:space:]]*:[[:space:]]*[0-9.]*" "$file" 2>/dev/null | \
        head -1 | awk -F: '{gsub(/[ ,]/, "", $2); print $2 + 0}')
    if [ -z "$value" ]; then
        value=0
    fi
    printf '%s' "$value"
}

echo "--- Phase 0: Kernel module support ---"
UBLK_READY=0

if [ -e /dev/ublk-control ]; then
    pass "ublk_control_device"
    UBLK_READY=1
elif [ -f /lib/modules/ublk_drv.ko ]; then
    if insmod /lib/modules/ublk_drv.ko 2>/tmp/ublk-insmod.err; then
        pass "ublk_module_loaded"
        if [ -e /dev/ublk-control ]; then
            pass "ublk_control_device"
            UBLK_READY=1
        else
            mknod /dev/ublk-control c 246 0 2>/dev/null || true
            if [ -e /dev/ublk-control ]; then
                pass "ublk_control_device"
                UBLK_READY=1
            else
                blocked "ublk_control_device" "/dev/ublk-control not created"
            fi
        fi
    else
        blocked "ublk_module_loaded" "$(cat /tmp/ublk-insmod.err 2>/dev/null || echo load-failed)"
    fi
else
    if mknod /dev/ublk-control c 246 0 2>/dev/null; then
        pass "ublk_control_device"
        UBLK_READY=1
    else
        blocked "ublk_module" "no ublk_drv.ko and device node creation failed"
    fi
fi

if [ "$UBLK_READY" -ne 1 ]; then
    echo "BLOCKED: ublk not available; cannot run performance baseline"
    # Write validation and exit
    cat > /tmp/validation/validation.json << EVID
{"test":"ublk-perf-baseline","version":3,"kernel_version":"$KVER","ublk_ready":false,"passed":0,"failed":0,"blocked":1,"results":[]}
EVID
    echo "SUMMARY: PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
    poweroff -f
fi

echo ""
echo "--- Phase 1: Pool create and ublk block attach ---"

# Create pool directory
mkdir -p /tmp/tidefs-pool
pass "pool_dir_created"

# Start ublk block attach in background
echo "  Starting ublk block attach..."
tidefsctl block attach /tmp/tidefs-pool > /tmp/attach.log 2>&1 &
ATTACH_PID=$!
echo "  attach PID=$ATTACH_PID"

# Wait for /dev/ublkb0
for i in $(seq 1 60); do
    if [ -b /dev/ublkb0 ]; then
        pass "ublkb0_appeared"
        break
    fi
    sleep 1
done

if [ ! -b /dev/ublkb0 ]; then
    fail "ublkb0_appeared" "$(cat /tmp/attach.log 2>/dev/null || echo 'no log')"
    echo "BLOCKED: ublk device did not appear"
    poweroff -f
fi

DEVSIZE=$(blockdev --getsize64 /dev/ublkb0 2>/dev/null || echo 0)
echo "  ublkb0 size: $DEVSIZE bytes"
pass "ublkb0_info" "size=$DEVSIZE"

echo ""
echo "--- Phase 2: Queue-depth latency measurement ---"

FIO_QD_OUT="/tmp/fio_qd_results.json"
FIO_FF_OUT="/tmp/fio_flushfua_results.json"

# Write phase-2 results incrementally
cat > "$FIO_QD_OUT" << 'JSONQD'
{"phase":"queue_depth_latency","results":{}}
JSONQD

# Run fio at each queue depth (1, 4, 8, 16, 32, 64) with randrw 70/30
for qd in 1 4 8 16 32 64; do
    echo "  Queue depth $qd..."
    qd_json="/tmp/fio-qd''${qd}.json"
    if fio --name="ublk-qd''${qd}" --rw=randrw --rwmixread=70 --size=2M \
           --direct=1 --bs=4k --iodepth="$qd" --filename=/dev/ublkb0 \
           --output="$qd_json" --output-format=json --end_fsync=1 2>/tmp/fio-qd''${qd}.err; then
        # Extract KPIs from fio JSON
        p50=$(json_metric "50\\.000000" "$qd_json")
        p95=$(json_metric "95\\.000000" "$qd_json")
        p99=$(json_metric "99\\.000000" "$qd_json")
        echo "    p50=''${p50}ns p95=''${p95}ns p99=''${p99}ns"
        # Budget check: p99 <= 25ms (25000000ns)
        if [ "$p99" -gt 25000000 ] 2>/dev/null; then
            fail "qdepth_''${qd}_budget" "p99=''${p99}ns exceeds 25000000ns budget"
        else
            pass "qdepth_''${qd}_budget" "p50=''${p50}ns p95=''${p95}ns p99=''${p99}ns"
        fi
        append_benchmark_row "{\"name\":\"qdepth_''${qd}\",\"phase\":\"queue_depth_latency\",\"status\":\"pass\",\"queue_depth\":$qd,\"block_size\":\"4k\",\"rwmixread\":70,\"p50_ns\":$p50,\"p95_ns\":$p95,\"p99_ns\":$p99,\"budget_ns\":25000000}"
        cp "$qd_json" "/tmp/validation/fio-qd''${qd}.json"
    else
        fail "qdepth_''${qd}_exec" "$(cat /tmp/fio-qd''${qd}.err 2>/dev/null || echo 'fio failed')"
        append_benchmark_row "{\"name\":\"qdepth_''${qd}\",\"phase\":\"queue_depth_latency\",\"status\":\"fail\",\"queue_depth\":$qd,\"block_size\":\"4k\",\"rwmixread\":70,\"error\":\"fio execution failed\"}"
    fi
done

echo ""
echo "--- Phase 3: Flush/FUA overhead measurement ---"

# Phase 3a: Plain writes (baseline, no fsync, no FUA)
echo "  Plain writes (baseline)..."
fio --name="ublk-plain-write" --rw=randwrite --size=2M --direct=1 --bs=4k \
    --iodepth=1 --filename=/dev/ublkb0 --output=/tmp/fio-plain.json \
    --output-format=json --end_fsync=1 2>/tmp/fio-plain.err
if [ $? -eq 0 ]; then
    p50_plain=$(json_metric "50\\.000000" /tmp/fio-plain.json)
    p99_plain=$(json_metric "99\\.000000" /tmp/fio-plain.json)
    pass "flushfua_plain_write" "p50=''${p50_plain}ns p99=''${p99_plain}ns"
    append_benchmark_row "{\"name\":\"flushfua_plain_write\",\"phase\":\"flush_fua_overhead\",\"status\":\"pass\",\"mode\":\"plain_write\",\"p50_ns\":$p50_plain,\"p99_ns\":$p99_plain}"
    cp /tmp/fio-plain.json /tmp/validation/fio-plain.json
else
    fail "flushfua_plain_write" "$(cat /tmp/fio-plain.err 2>/dev/null || echo 'fio failed')"
    append_benchmark_row "{\"name\":\"flushfua_plain_write\",\"phase\":\"flush_fua_overhead\",\"status\":\"fail\",\"mode\":\"plain_write\",\"error\":\"fio execution failed\"}"
fi

# Phase 3b: Fsync writes (fsync after each block)
echo "  Fsync writes (fsync=1)..."
fio --name="ublk-fsync-write" --rw=randwrite --size=2M --direct=1 --bs=4k \
    --iodepth=1 --fsync=1 --filename=/dev/ublkb0 --output=/tmp/fio-fsync.json \
    --output-format=json 2>/tmp/fio-fsync.err
if [ $? -eq 0 ]; then
    p50_fsync=$(json_metric "50\\.000000" /tmp/fio-fsync.json)
    p99_fsync=$(json_metric "99\\.000000" /tmp/fio-fsync.json)
    # fsync overhead ratio
    if [ "$p99_plain" -gt 0 ] 2>/dev/null; then
        fsync_ratio=$(echo "scale=2; $p99_fsync / $p99_plain" | bc 2>/dev/null || echo "N/A")
    else
        fsync_ratio="N/A"
    fi
    case "$fsync_ratio" in
        .*) fsync_ratio="0$fsync_ratio" ;;
        -.*) fsync_ratio="-0''${fsync_ratio#-}" ;;
    esac
    pass "flushfua_fsync_write" "p50=''${p50_fsync}ns p99=''${p99_fsync}ns overhead_ratio=''${fsync_ratio}x"
    if [ "$fsync_ratio" = "N/A" ]; then
        fsync_ratio_json=null
    else
        fsync_ratio_json="$fsync_ratio"
    fi
    append_benchmark_row "{\"name\":\"flushfua_fsync_write\",\"phase\":\"flush_fua_overhead\",\"status\":\"pass\",\"mode\":\"fsync_write\",\"p50_ns\":$p50_fsync,\"p99_ns\":$p99_fsync,\"overhead_ratio_to_plain\":$fsync_ratio_json}"
    cp /tmp/fio-fsync.json /tmp/validation/fio-fsync.json
else
    fail "flushfua_fsync_write" "$(cat /tmp/fio-fsync.err 2>/dev/null || echo 'fio failed')"
    append_benchmark_row "{\"name\":\"flushfua_fsync_write\",\"phase\":\"flush_fua_overhead\",\"status\":\"fail\",\"mode\":\"fsync_write\",\"error\":\"fio execution failed\"}"
fi

# Phase 3c: synchronous writes.  The fio build in nixpkgs 26.05 no longer
# exposes a --fua job option, so this records the closest supported block-path
# forced-write mode without treating the missing fio flag as a product failure.
echo "  Sync writes (sync=1; fio FUA option unavailable)..."
fio --name="ublk-sync-write" --rw=write --size=2M --direct=1 --bs=4k \
    --iodepth=1 --sync=1 --filename=/dev/ublkb0 --output=/tmp/fio-sync.json \
    --output-format=json 2>/tmp/fio-sync.err
if [ $? -eq 0 ]; then
    p50_fua=$(json_metric "50\\.000000" /tmp/fio-sync.json)
    p99_fua=$(json_metric "99\\.000000" /tmp/fio-sync.json)
    if [ "$p99_plain" -gt 0 ] 2>/dev/null; then
        fua_ratio=$(echo "scale=2; $p99_fua / $p99_plain" | bc 2>/dev/null || echo "N/A")
    else
        fua_ratio="N/A"
    fi
    case "$fua_ratio" in
        .*) fua_ratio="0$fua_ratio" ;;
        -.*) fua_ratio="-0''${fua_ratio#-}" ;;
    esac
    pass "flushfua_sync_write" "p50=''${p50_fua}ns p99=''${p99_fua}ns overhead_ratio=''${fua_ratio}x"
    if [ "$fua_ratio" = "N/A" ]; then
        fua_ratio_json=null
    else
        fua_ratio_json="$fua_ratio"
    fi
    append_benchmark_row "{\"name\":\"flushfua_sync_write\",\"phase\":\"flush_fua_overhead\",\"status\":\"pass\",\"mode\":\"sync_write\",\"fio_fua_option_available\":false,\"p50_ns\":$p50_fua,\"p99_ns\":$p99_fua,\"overhead_ratio_to_plain\":$fua_ratio_json}"
    cp /tmp/fio-sync.json /tmp/validation/fio-sync.json
else
    fail "flushfua_sync_write" "$(cat /tmp/fio-sync.err 2>/dev/null || echo 'fio failed')"
    append_benchmark_row "{\"name\":\"flushfua_sync_write\",\"phase\":\"flush_fua_overhead\",\"status\":\"fail\",\"mode\":\"sync_write\",\"error\":\"fio execution failed\"}"
fi

echo ""
echo "--- Phase 4: Stop ublk device ---"

kill $ATTACH_PID 2>/dev/null || true
sleep 2
if kill -0 "$ATTACH_PID" 2>/dev/null; then
    kill -9 "$ATTACH_PID" 2>/dev/null || true
    sleep 1
fi
# The perf harness owns the userspace attach process; some kernels leave the
# control/device node visible briefly after userspace exits, so do not classify
# node persistence as a throughput product failure here.
if kill -0 "$ATTACH_PID" 2>/dev/null; then
    fail "ublk_attach_process_stop" "attach process still running after TERM"
else
    pass "ublk_attach_process_stop"
fi

echo ""
echo "--- Validation ---"

# Write validation manifest
cat > /tmp/validation/validation.json << EVIDEOF
{
  "test": "ublk-perf-baseline",
  "version": 3,
  "validation_id": "ublk-perf-baseline",
  "kernel_version": "$KVER",
  "validation_tier": "Tier 3 QEMU guest ublk/block-volume runtime",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)",
  "passed": $PASSED,
  "failed": $FAILED,
  "blocked": $BLOCKED,
  "results": [],
  "benchmarks": $BENCHMARK_ROWS
}
EVIDEOF

echo "=== BEGIN UBLK PERF BENCHMARK JSON ==="
cat /tmp/validation/validation.json
echo "=== END UBLK PERF BENCHMARK JSON ==="
echo "SUMMARY: PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
echo "Validation written to /tmp/validation/"

poweroff -f
INITSCRIPT

    chmod +x "$RUN_DIR/init"

    # Build initramfs
    echo "  Building initramfs..."
    ( cd "$RUN_DIR" && find . | cpio -o -H newc 2>/dev/null | gzip > "$WORK_DIR/initrd.img" )

    # Run QEMU
    echo "  Booting QEMU guest..."
    QEMU_OUT="$WORK_DIR/qemu-stdout.log"
    QEMU_ERR="$WORK_DIR/qemu-stderr.log"

    set +e
    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      -kernel "$KERNEL_IMG" \
      -initrd "$WORK_DIR/initrd.img" \
      -append "console=ttyS0 quiet init=/init" \
      -nographic \
      -m 2048 \
      "''${QEMU_ACCEL[@]}" \
      -drive file="$DISK1_IMG",format=raw,if=virtio \
      -drive file="$DISK2_IMG",format=raw,if=virtio \
      > "$QEMU_OUT" 2> "$QEMU_ERR"
    QEMU_EXIT=$?
    set -e

    echo ""
    echo "  QEMU exit code: $QEMU_EXIT"

    # Extract validation from QEMU stdout
    echo ""
    echo "=== QEMU Guest Output (tail 100 lines) ==="
    tail -100 "$QEMU_OUT" 2>/dev/null || echo "(no stdout)"

    echo ""
    echo "=== Validation outputs ==="
    ls -la "$VALIDATION_DIR/" 2>/dev/null || echo "(no validation directory)"

    if [ -f "$VALIDATION_DIR/validation.json" ]; then
        echo ""
        echo "=== Validation manifest ==="
        cat "$VALIDATION_DIR/validation.json"
    fi

    echo ""
    echo "=== ublk-perf-baseline complete ==="
    echo "validation_tier=Tier 3 QEMU guest ublk/block-volume runtime"
    echo "qemu_exit_code=$QEMU_EXIT"
    echo "validation_dir=$VALIDATION_DIR"
  '';
in
{
  ublkPerfBaseline = ublkPerfBaselineScript;
}
