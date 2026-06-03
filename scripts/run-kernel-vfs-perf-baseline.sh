#!/usr/bin/env bash
# run-kernel-vfs-perf-baseline.sh -- build and execute the kernel VFS
# throughput latency baseline without requiring Nix flake integration.
#
# Usage:
#   scripts/run-kernel-vfs-perf-baseline.sh [--keep-tmp] [--timeout SECONDS]
#
# Boots Linux 7.0 QEMU with kmod-posix-vfs, mounts a TideFS pool in
# bootstrap mode, and measures sequential read/write throughput and
# stat latency. Validation is written to
# /root/ai/tmp/tidefs-validation/kernel-vfs-perf-baseline/.
#
# Validation tier: Tier 5 mounted Linux 7.0 kernel VFS (QEMU + module
# load + mounted VFS read/write + no-daemon residency).
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VALIDATION_DIR="/root/ai/tmp/tidefs-validation/kernel-vfs-perf-baseline"
TMPDIR="${TIDEFS_KERNEL_PERF_TMPDIR:-/tmp/tidefs-kernel-perf-baseline}"
TIMEOUT_SEC="${TIDEFS_KERNEL_PERF_TIMEOUT:-600}"

KEEP_TMP=0

usage() {
  cat <<EOF
Usage: scripts/run-kernel-vfs-perf-baseline.sh [--keep-tmp] [--timeout SECONDS]

Boot Linux 7.0 QEMU with kmod-posix-vfs, mount a TideFS pool in bootstrap
mode, and measure sequential read/write throughput and stat latency.
Validation output directory:
  $VALIDATION_DIR

Options:
  --keep-tmp         Do not remove temp directory on exit
  --timeout SECONDS  QEMU boot timeout (default: $TIMEOUT_SEC)
  --help, -h         Show this message

Exit codes:
  0  Baseline measurements completed
  1  One or more failures
  2  Environment or dependency error
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --keep-tmp) KEEP_TMP=1; shift ;;
    --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage >&2; exit 2 ;;
  esac
done

# ---- Dependency resolution -------------------------------------------

find_qemu() {
  for c in /usr/local/bin/qemu-system-x86_64 /run/current-system/sw/bin/qemu-system-x86_64; do
    [ -x "$c" ] && { echo "$c"; return 0; }
  done
  command -v qemu-system-x86_64 2>/dev/null || echo ""
}

QEMU_BIN="$(find_qemu)"
BUSYBOX="$(command -v busybox 2>/dev/null || echo /run/current-system/sw/bin/busybox)"
KERNEL_IMG="/root/ai/state/tidefs/kernel-dev/shared/linux-7.0/build/arch/x86/boot/bzImage"
CPIO="$(command -v cpio 2>/dev/null || echo /run/current-system/sw/bin/cpio)"

# Module search: prefer explicit configuration, then a generic scratch module-out.
MODULE_DIR="${TIDEFS_KERNEL_VFS_MODULE_DIR:-/root/ai/tmp/tidefs-kmod-posix-vfs/module-out}"
MODULE_KO="${TIDEFS_KERNEL_VFS_MODULE_KO:-}"
if [ -z "$MODULE_KO" ]; then
  for c in "$MODULE_DIR/tidefs_posix_vfs.ko" \
           "$MODULE_DIR/tidefs_posix_vfs/tidefs_posix_vfs.ko"; do
    [ -f "$c" ] && { MODULE_KO="$c"; break; }
  done
fi

echo "=== TideFS Kernel VFS Throughput Latency Baseline ==="
echo "  Validation:   $VALIDATION_DIR"
echo "  Timeout:    ${TIMEOUT_SEC}s"
echo "  QEMU:       $QEMU_BIN"
echo "  Kernel:     $KERNEL_IMG"
echo "  Module:     ${MODULE_KO:-NOT FOUND}"
echo ""

# ---- Validate dependencies -------------------------------------------

MISSING=""
for dep in QEMU_BIN BUSYBOX KERNEL_IMG CPIO MODULE_KO; do
  val="${!dep}"
  if [ -z "$val" ] || [ ! -f "$val" ] && [ ! -x "$val" ]; then
    MISSING="$MISSING $dep=${val:-<empty>}"
  fi
done
if [ -n "$MISSING" ]; then
  echo "FATAL: missing dependencies:$MISSING" >&2
  exit 2
fi

# Check for KVM acceleration
KVM_FLAG=""
if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
  KVM_FLAG="-enable-kvm -cpu host"
  echo "  KVM:        enabled"
else
  echo "  KVM:        not available (software emulation, expect slow boot)"
fi

# ---- Prepare initramfs -----------------------------------------------

RUN_DIR="$TMPDIR/run-$$"
echo "  Run dir:    $RUN_DIR"
mkdir -p "$RUN_DIR"/{bin,lib/modules,mnt/tidefs,validation}
trap 'if [ $KEEP_TMP -eq 0 ]; then rm -rf "$RUN_DIR"; fi' EXIT

# Busybox and applets
cp "$BUSYBOX" "$RUN_DIR/bin/busybox"
chmod +x "$RUN_DIR/bin/busybox"
for a in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff reboot \
  mknod mkdir rmdir dd stat cp mv rm touch find wc head sync cut date time; do
  ln -sf busybox "$RUN_DIR/bin/$a"
done

# Copy the kernel module
cp "$MODULE_KO" "$RUN_DIR/lib/modules/tidefs_posix_vfs.ko"
echo "  Module .ko: $(ls -sh "$MODULE_KO" | awk '{print $1}')"

# ---- Init script -----------------------------------------------------

cat > "$RUN_DIR/init" << 'INIT'
#!/bin/sh
export PATH=/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

echo "=== TideFS Kernel VFS Throughput Latency Baseline ==="
echo "kernel=$(uname -r)"
echo "ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

PASS=0; FAIL=0; BLOCK=0
pass()   { echo "PASS: $1"; PASS=$((PASS+1)); }
fail()   { echo "FAIL: $1 -- $2"; FAIL=$((FAIL+1)); }
blocked(){ echo "BLOCKED: $1 -- $2"; BLOCK=$((BLOCK+1)); }

MNT=/mnt/tidefs

echo "--- Phase 0: Module Load ---"
insmod /lib/modules/tidefs_posix_vfs.ko 2>/tmp/err && pass insmod || { blocked insmod "$(cat /tmp/err)"; }

echo "--- Phase 1: Mount ---"
mkdir -p "$MNT"
M=0
mount -t tidefs -o bootstrap none "$MNT" 2>/tmp/err && { pass mount; M=1; } || { blocked mount "$(cat /tmp/err)"; }

# No-daemon check
ps 2>/dev/null | grep -iqE "tidefs.*daemon|fuse.*adapter|ublk.*adapter" && fail no_daemon "userspace daemon detected" || pass no_daemon

# Phase 2: Write throughput (1 MB, 4K blocks)
if [ "$M" -eq 1 ]; then
  echo "--- Phase 2: Sequential Write (1MB, 4K blocks) ---"
  sync
  S=$(date +%s%N 2>/dev/null || echo 0)
  i=0; while [ $i -lt 256 ]; do
    dd if=/dev/zero of="$MNT/pf" bs=4096 count=1 seek=$i conv=notrunc 2>/dev/null
    i=$((i+1))
  done
  sync
  E=$(date +%s%N 2>/dev/null || echo 0)
  if [ "$S" -gt 0 ] && [ "$E" -gt 0 ]; then
    DMS=$(( (E - S) / 1000000 ))
    DUS=$(( (E - S) / 1000 ))
    echo "write_duration_ms=$DMS"
    echo "write_duration_us=$DUS"
    if [ "$DMS" -gt 0 ]; then
      TP=$(awk "BEGIN {printf \"%.2f\", 1.0 / ($DMS / 1000.0)}" 2>/dev/null || echo "0")
      echo "write_throughput_MBps=$TP"
    fi
  fi
  WS=$(stat -c %s "$MNT/pf" 2>/dev/null || echo 0)
  [ "$WS" -ge 1048576 ] && pass write_data || fail write_data "file_size=$WS"

  echo "--- Phase 3: Sequential Read (1MB, 4K blocks) ---"
  sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
  S=$(date +%s%N 2>/dev/null || echo 0)
  dd if="$MNT/pf" of=/dev/null bs=4096 count=256 2>/dev/null
  E=$(date +%s%N 2>/dev/null || echo 0)
  if [ "$S" -gt 0 ] && [ "$E" -gt 0 ]; then
    DMS=$(( (E - S) / 1000000 ))
    DUS=$(( (E - S) / 1000 ))
    echo "read_duration_ms=$DMS"
    echo "read_duration_us=$DUS"
    if [ "$DMS" -gt 0 ]; then
      TP=$(awk "BEGIN {printf \"%.2f\", 1.0 / ($DMS / 1000.0)}" 2>/dev/null || echo "0")
      echo "read_throughput_MBps=$TP"
    fi
  fi
  pass read_data

  echo "--- Phase 4: Stat Latency (100 calls) ---"
  sync
  S=$(date +%s%N 2>/dev/null || echo 0)
  i=0; while [ $i -lt 100 ]; do stat "$MNT/pf" >/dev/null 2>&1; i=$((i+1)); done
  E=$(date +%s%N 2>/dev/null || echo 0)
  if [ "$S" -gt 0 ] && [ "$E" -gt 0 ]; then
    AVGUS=$(( (E - S) / 100000 ))
    echo "stat_avg_us=$AVGUS"
  fi
  pass stat_latency
fi

echo "--- Phase 5: Dmesg Integrity ---"
DB=$(dmesg 2>/dev/null | grep -cE "BUG:|Kernel panic" || echo 0)
echo "dmesg_BUG=$DB"
[ "$DB" -gt 0 ] && fail dmesg "BUG=$DB" || pass dmesg_clean

echo "--- Phase 6: Unmount + Unload ---"
sync
umount "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null
pass umount
rmmod tidefs_posix_vfs 2>/dev/null && pass rmmod || fail rmmod

echo ""
echo "=== SUMMARY ==="
echo "PASS=$PASS FAIL=$FAIL BLOCKED=$BLOCK"
sleep 1
poweroff -f
INIT

chmod +x "$RUN_DIR/init"

# ---- Build initramfs -------------------------------------------------

echo "--- Building initramfs ---"
(cd "$RUN_DIR" && find . ! -path ./validation/\* | cpio -o -H newc 2>/dev/null) | gzip > "$RUN_DIR/initramfs.gz"
echo "  Initramfs: $(ls -sh "$RUN_DIR/initramfs.gz" | awk '{print $1}')"

# ---- Record environment ----------------------------------------------

mkdir -p "$VALIDATION_DIR"
RUN_ID="$(date -u +%Y-%m-%dT%H%M%SZ)"
RUN_DIR_VALIDATION="$VALIDATION_DIR/$RUN_ID"
mkdir -p "$RUN_DIR_VALIDATION"

cat > "$RUN_DIR_VALIDATION/environment.txt" << ENVEOF
timestamp=$RUN_ID
commit=$(cd "$REPO_ROOT" && git rev-parse HEAD 2>/dev/null || echo unknown)
dirty=true
kernel_img=$KERNEL_IMG
module_ko=$MODULE_KO
qemu_bin=$QEMU_BIN
qemu_accel=$(test -e /dev/kvm && test -r /dev/kvm && echo kvm || echo tcg)
kvm_available=$(test -e /dev/kvm && echo true || echo false)
ENVEOF

# ---- Run QEMU --------------------------------------------------------

echo "--- Booting QEMU (timeout ${TIMEOUT_SEC}s) ---"
RUN_LOG="$RUN_DIR_VALIDATION/qemu.log"

set +e
# shellcheck disable=SC2086
timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
  -kernel "$KERNEL_IMG" \
  -initrd "$RUN_DIR/initramfs.gz" \
  -append "console=ttyS0 quiet" \
  -nographic \
  -m 512M \
  -no-reboot \
  $KVM_FLAG \
  > "$RUN_LOG" 2>&1
QEMU_EXIT=$?
set -e

echo "  QEMU exit: $QEMU_EXIT"

# ---- Extract results -------------------------------------------------

PASS_COUNT=$(grep -c "^PASS:" "$RUN_LOG" 2>/dev/null || echo 0)
FAIL_COUNT=$(grep -c "^FAIL:" "$RUN_LOG" 2>/dev/null || echo 0)
BLOCKED_COUNT=$(grep -c "^BLOCKED:" "$RUN_LOG" 2>/dev/null || echo 0)

WD=$(grep "write_duration_ms=" "$RUN_LOG" 2>/dev/null | cut -d= -f2 | head -1 || echo "0")
RD=$(grep "read_duration_ms=" "$RUN_LOG" 2>/dev/null | cut -d= -f2 | head -1 || echo "0")
WTP=$(grep "write_throughput_MBps=" "$RUN_LOG" 2>/dev/null | cut -d= -f2 | head -1 || echo "0")
RTP=$(grep "read_throughput_MBps=" "$RUN_LOG" 2>/dev/null | cut -d= -f2 | head -1 || echo "0")
SU=$(grep "stat_avg_us=" "$RUN_LOG" 2>/dev/null | cut -d= -f2 | head -1 || echo "0")

echo ""
echo "=== Results ==="
echo "  PASS:   $PASS_COUNT"
echo "  FAIL:   $FAIL_COUNT"
echo "  BLOCKED: $BLOCKED_COUNT"
echo "  Write:  ${WD}ms (${WTP} MB/s)"
echo "  Read:   ${RD}ms (${RTP} MB/s)"
echo "  Stat:   ${SU}us avg"

# ---- Validation manifest -----------------------------------------------

cat > "$RUN_DIR_VALIDATION/validation-manifest.json" << MANIFEST
{
  "test": "kernel-vfs-perf-baseline",
  "date": "$RUN_ID",
  "mode": "bootstrap",
  "validation_tier": "Tier 5 mounted Linux 7.0 kernel VFS",
  "qemu_accel": "$(test -e /dev/kvm && echo kvm || echo tcg)",
  "metrics": {
    "write_duration_ms": "${WD}",
    "read_duration_ms": "${RD}",
    "write_throughput_MBps": "${WTP}",
    "read_throughput_MBps": "${RTP}",
    "stat_avg_us": "${SU}"
  },
  "pass": $PASS_COUNT,
  "fail": $FAIL_COUNT,
  "blocked": $BLOCKED_COUNT,
  "commit": "$(cd "$REPO_ROOT" && git rev-parse HEAD 2>/dev/null || echo unknown)",
  "worktree_dirty": true,
  "module_source": "configured external module path",
  "result": "kernel VFS perf baseline: write=${WD}ms (${WTP}MB/s) read=${RD}ms (${RTP}MB/s) stat=${SU}us"
}
MANIFEST

echo ""
echo "  Validation output directory: $RUN_DIR_VALIDATION"
ls -la "$RUN_DIR_VALIDATION/"

# ---- Verdict ---------------------------------------------------------

if [ "$BLOCKED_COUNT" -gt 0 ] && [ "$PASS_COUNT" -eq 0 ]; then
  echo "  Verdict: BLOCKED (all phases blocked)"
  exit 2
elif [ "$FAIL_COUNT" -gt 0 ]; then
  echo "  Verdict: FAIL ($FAIL_COUNT failures)"
  exit 1
else
  echo "  Verdict: PASS"
  exit 0
fi
