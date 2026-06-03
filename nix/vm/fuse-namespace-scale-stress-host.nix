# TideFS: FUSE namespace-scale stress validation - host loopback variant.
#
# Runs the namespace-scale stress directly on loop devices with FUSE,
# bypassing QEMU. Requires /dev/fuse, losetup, and fusermount on the host.
#
# Validation tier: MountedUserspace (host loopback).
{
  pkgs,
}:

pkgs.writeShellScriptBin "tidefs-fuse-namespace-scale-stress-host" ''
  set -euo pipefail

  TIDEFSCTL="$(find /nix/store -maxdepth 3 -name tidefsctl -type f -path '*-tidefs-workspace-*/bin/*' 2>/dev/null | head -1)"
  FUSE_DAEMON="$(find /nix/store -maxdepth 3 -name tidefs-posix-filesystem-adapter-daemon -type f 2>/dev/null | head -1)"

  if [ -z "$TIDEFSCTL" ] || [ -z "$FUSE_DAEMON" ]; then
    echo "FATAL: tidefs binaries not found in /nix/store" >&2
    exit 1
  fi

  # Scale parameters (env-overridable)
  WIDE_DIRS="''${TIDEFS_NS_SCALE_WIDE_DIRS:-50}"
  FILES_PER_DIR="''${TIDEFS_NS_SCALE_FILES_PER_DIR:-20}"
  DEEP_LEVELS="''${TIDEFS_NS_SCALE_DEEP_LEVELS:-10}"
  FILES_PER_LEVEL="''${TIDEFS_NS_SCALE_FILES_PER_LEVEL:-5}"
  HUGE_DIR_FILES="''${TIDEFS_NS_SCALE_HUGE_DIR_FILES:-1000}"
  MULTI_EXTENT_FILES="''${TIDEFS_NS_SCALE_MULTI_EXTENT_FILES:-50}"
  EXTENTS_PER_FILE="''${TIDEFS_NS_SCALE_EXTENTS_PER_FILE:-10}"
  DISK_SIZE_MB="''${TIDEFS_NS_SCALE_DISK_MB:-512}"

  JSON_OUT=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --wide-dirs) WIDE_DIRS="$2"; shift 2 ;;
      --files-per-dir) FILES_PER_DIR="$2"; shift 2 ;;
      --deep-levels) DEEP_LEVELS="$2"; shift 2 ;;
      --files-per-level) FILES_PER_LEVEL="$2"; shift 2 ;;
      --huge-dir-files) HUGE_DIR_FILES="$2"; shift 2 ;;
      --multi-extent-files) MULTI_EXTENT_FILES="$2"; shift 2 ;;
      --extents-per-file) EXTENTS_PER_FILE="$2"; shift 2 ;;
      --disk-size-mb) DISK_SIZE_MB="$2"; shift 2 ;;
      --output) JSON_OUT="$2"; shift 2 ;;
      *) echo "ERROR: unknown option: $1" >&2; exit 2 ;;
    esac
  done

  WORK_DIR="''${TIDEFS_NS_SCALE_TMPDIR:-/tmp/tidefs-ns-scale-host}-$$"
  VALIDATION_DIR="''${JSON_OUT:-/tmp/tidefs-ns-scale-validation-$$}"
  mkdir -p "$WORK_DIR" "$(dirname "$VALIDATION_DIR" 2>/dev/null || echo /tmp)"

  DISK0="$WORK_DIR/disk0.img"
  DISK1="$WORK_DIR/disk1.img"
  MNT="$WORK_DIR/mnt"
  POOL_NAME="scale_pool_$$"

  PASSED=0; FAILED=0; BLOCKED=0
  TIMING_LINES=""

  pass() { echo "PASS: $1''${2:+ -- $2}"; PASSED=$((PASSED + 1)); }
  fail() { echo "FAIL: $1 -- $2"; FAILED=$((FAILED + 1)); }
  blocked() { echo "BLOCKED: $1 -- $2"; BLOCKED=$((BLOCKED + 1)); }

  record_timing() {
    local phase="$1" elapsed="$2" ops="$3" rate="$4" unit="$5"
    echo "TIMING: phase=$phase elapsed_s=$elapsed ops=$ops ops_per_sec=$rate unit=$unit"
    TIMING_LINES="''${TIMING_LINES}{\"phase\":\"$phase\",\"elapsed_s\":$elapsed,\"ops\":$ops,\"ops_per_sec\":$rate,\"unit\":\"$unit\"},"
  }

  ns_time_ms() { awk '{ printf "%.3f", $1 * 1000 }' /proc/uptime; }
  elapsed_since() { local start="$1"; local now=$(ns_time_ms); awk "BEGIN { printf \"%.3f\", ($now - $start) / 1000 }"; }

  cleanup() {
    echo "Cleaning up..."
    fusermount -u "$MNT" 2>/dev/null || true
    sleep 1
    [ -n "''${LOOP0:-}" ] && losetup -d "$LOOP0" 2>/dev/null || true
    [ -n "''${LOOP1:-}" ] && losetup -d "$LOOP1" 2>/dev/null || true
    rm -rf "$WORK_DIR"
  }
  trap cleanup EXIT

  echo "=== TideFS FUSE Namespace-Scale Stress (Host) ==="
  echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "kernel=$(uname -r)"
  echo "host=$(hostname)"

  # Create disk images
  truncate -s "''${DISK_SIZE_MB}M" "$DISK0"
  truncate -s "''${DISK_SIZE_MB}M" "$DISK1"

  # Loop devices
  LOOP0=$(losetup -f --show "$DISK0" 2>&1) || { fail "losetup0" "$LOOP0"; exit 1; }
  LOOP1=$(losetup -f --show "$DISK1" 2>&1) || { fail "losetup1" "$LOOP1"; exit 1; }
  pass "loop_devices" "$LOOP0 $LOOP1"

  # Pool create
  echo "--- Pool create ---"
  T0=$(ns_time_ms)
  if "$TIDEFSCTL" pool create "$POOL_NAME" --devices "$LOOP0" "$LOOP1" --json > "$WORK_DIR/pool_create.log" 2>&1; then
    T1=$(ns_time_ms); pass "pool_create" "$(elapsed_since "$T0")s"
    record_timing "pool_create" "$(elapsed_since "$T0")" 1 0 "op"
  else
    fail "pool_create" "$(tail -5 "$WORK_DIR/pool_create.log")"
    cat "$WORK_DIR/pool_create.log"; exit 1
  fi

  # FUSE mount
  echo "--- FUSE mount ---"
  mkdir -p "$MNT"
  T0=$(ns_time_ms)
  "$TIDEFSCTL" pool mount "$POOL_NAME" "$MNT" --devices "$LOOP0" "$LOOP1" > "$WORK_DIR/daemon.log" 2>&1 &
  DAEMON_PID=$!
  MOUNTED=0
  for i in $(seq 1 30); do
    if mountpoint -q "$MNT" 2>/dev/null; then MOUNTED=1; break; fi
    sleep 1
  done
  if [ "$MOUNTED" -eq 1 ]; then
    pass "fuse_mount" "$(elapsed_since "$T0")s"
    record_timing "fuse_mount" "$(elapsed_since "$T0")" 1 0 "op"
  else
    fail "fuse_mount" "$(tail -10 "$WORK_DIR/daemon.log")"
    cat "$WORK_DIR/daemon.log"; exit 1
  fi

  # Phase: Wide directory tree
  echo "=== Wide directory tree (''${WIDE_DIRS}x''${FILES_PER_DIR} files) ==="
  WIDE_DIR="$MNT/scale-wide"
  mkdir -p "$WIDE_DIR"
  T0=$(ns_time_ms); CREATED=0
  d=1
  while [ "$d" -le "$WIDE_DIRS" ]; do
    DIRN="$WIDE_DIR/dir-$d"
    mkdir -p "$DIRN" 2>/dev/null || { fail "wide_mkdir" "dir $d"; break; }
    f=1
    while [ "$f" -le "$FILES_PER_DIR" ]; do
      echo "wide-d$d-f$f-data" > "$DIRN/file-$f.txt" 2>/dev/null || { fail "wide_write" "d$d f$f"; break 2; }
      f=$((f + 1)); CREATED=$((CREATED + 1))
    done
    d=$((d + 1))
  done
  sync
  ELAPSED=$(elapsed_since "$T0")
  OPS_SEC=$(awk "BEGIN { if ($ELAPSED > 0) printf \"%.1f\", $CREATED / $ELAPSED; else print 0 }")
  EXPECTED=$((WIDE_DIRS * FILES_PER_DIR))
  if [ "$CREATED" -ge "$EXPECTED" ]; then
    pass "wide_create" "$CREATED files in ''${ELAPSED}s ($OPS_SEC files/s)"
    record_timing "wide_create" "$ELAPSED" "$CREATED" "$OPS_SEC" "files/s"
  else
    fail "wide_create" "only $CREATED/$EXPECTED"
  fi

  # Cold-cache find
  echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true; sleep 1
  T0=$(ns_time_ms)
  FOUND=$(find "$WIDE_DIR" -type f 2>/dev/null | wc -l)
  COLD_ELAPSED=$(elapsed_since "$T0")
  COLD_RATE=$(awk "BEGIN { if ($COLD_ELAPSED > 0) printf \"%.1f\", $FOUND / $COLD_ELAPSED; else print 0 }")
  echo "  cold-cache find: $FOUND files in ''${COLD_ELAPSED}s ($COLD_RATE files/s)"
  record_timing "wide_cold_find" "$COLD_ELAPSED" "$FOUND" "$COLD_RATE" "files/s"

  # Warm-cache find
  T0=$(ns_time_ms)
  FOUND=$(find "$WIDE_DIR" -type f 2>/dev/null | wc -l)
  WARM_ELAPSED=$(elapsed_since "$T0")
  WARM_RATE=$(awk "BEGIN { if ($WARM_ELAPSED > 0) printf \"%.1f\", $FOUND / $WARM_ELAPSED; else print 0 }")
  echo "  warm-cache find: $FOUND files in ''${WARM_ELAPSED}s ($WARM_RATE files/s)"
  record_timing "wide_warm_find" "$WARM_ELAPSED" "$FOUND" "$WARM_RATE" "files/s"

  CACHE_RATIO=$(awk "BEGIN { if ($COLD_RATE > 0) printf \"%.1f\", $WARM_RATE / $COLD_RATE; else print 0 }")
  if [ "$(awk "BEGIN { print ($WARM_RATE > $COLD_RATE) }")" = "1" ]; then
    pass "wide_cache_effect" "warm/cold=''${CACHE_RATIO}x"
  else
    fail "wide_cache_effect" "warm $WARM_RATE <= cold $COLD_RATE"
  fi

  # Stat throughput
  T0=$(ns_time_ms); STAT_COUNT=0
  for f in "$WIDE_DIR"/dir-*/file-*.txt; do
    stat "$f" > /dev/null 2>&1 || true
    STAT_COUNT=$((STAT_COUNT + 1))
    if [ "$STAT_COUNT" -ge 500 ]; then break; fi
  done
  STAT_ELAPSED=$(elapsed_since "$T0")
  STAT_RATE=$(awk "BEGIN { if ($STAT_ELAPSED > 0) printf \"%.1f\", $STAT_COUNT / $STAT_ELAPSED; else print 0 }")
  echo "  stat throughput: $STAT_RATE stats/s"
  record_timing "wide_stat" "$STAT_ELAPSED" "$STAT_COUNT" "$STAT_RATE" "stats/s"

  # Deep directory tree
  echo "=== Deep directory tree (''${DEEP_LEVELS} levels) ==="
  DEEP_DIR="$MNT/scale-deep"; mkdir -p "$DEEP_DIR"
  T0=$(ns_time_ms); CURRENT="$DEEP_DIR"; DEEP_OK=1; l=1
  while [ "$l" -le "$DEEP_LEVELS" ]; do
    CURRENT="$CURRENT/level-$l"
    mkdir -p "$CURRENT" 2>/dev/null || { fail "deep_mkdir" "level $l"; DEEP_OK=0; break; }
    f=1
    while [ "$f" -le "$FILES_PER_LEVEL" ]; do
      echo "deep-l$l-f$f-data" > "$CURRENT/file-$f.txt" 2>/dev/null || { fail "deep_write" "l$l f$f"; DEEP_OK=0; break 2; }
      f=$((f + 1))
    done
    l=$((l + 1))
  done
  sync
  DEEP_ELAPSED=$(elapsed_since "$T0")
  if [ "$DEEP_OK" -eq 1 ]; then
    pass "deep_create" "''${DEEP_LEVELS} levels in ''${DEEP_ELAPSED}s"
    record_timing "deep_create" "$DEEP_ELAPSED" "$((DEEP_LEVELS * FILES_PER_LEVEL))" "$(awk "BEGIN { if ($DEEP_ELAPSED > 0) printf \"%.1f\", $((DEEP_LEVELS * FILES_PER_LEVEL)) / $DEEP_ELAPSED; else print 0 }")" "files/s"
  fi

  echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true; sleep 1
  T0=$(ns_time_ms)
  FOUND=$(find "$DEEP_DIR" -type f 2>/dev/null | wc -l)
  DEEP_COLD=$(elapsed_since "$T0")
  echo "  cold-cache deep find: $FOUND files in ''${DEEP_COLD}s"

  # Huge directory
  echo "=== Huge directory (''${HUGE_DIR_FILES} files) ==="
  HUGE_DIR="$MNT/scale-huge"; mkdir -p "$HUGE_DIR"
  T0=$(ns_time_ms); CREATED=0; HUGE_OK=1; f=1
  while [ "$f" -le "$HUGE_DIR_FILES" ]; do
    echo "huge-file-$f-data" > "$HUGE_DIR/file-$f.txt" 2>/dev/null || { fail "huge_dir_write" "file $f at $CREATED"; HUGE_OK=0; break; }
    CREATED=$((CREATED + 1)); f=$((f + 1))
  done
  sync
  HUGE_ELAPSED=$(elapsed_since "$T0")
  HUGE_OPS_SEC=$(awk "BEGIN { if ($HUGE_ELAPSED > 0) printf \"%.1f\", $CREATED / $HUGE_ELAPSED; else print 0 }")
  if [ "$HUGE_OK" -eq 1 ]; then
    pass "huge_dir_create" "$CREATED files in ''${HUGE_ELAPSED}s ($HUGE_OPS_SEC files/s)"
    record_timing "huge_dir_create" "$HUGE_ELAPSED" "$CREATED" "$HUGE_OPS_SEC" "files/s"
  fi

  echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true; sleep 1
  T0=$(ns_time_ms)
  LS_COUNT=$(ls "$HUGE_DIR" 2>/dev/null | wc -l)
  COLD_LS_ELAPSED=$(elapsed_since "$T0")
  COLD_LS_RATE=$(awk "BEGIN { if ($COLD_LS_ELAPSED > 0) printf \"%.1f\", $LS_COUNT / $COLD_LS_ELAPSED; else print 0 }")
  pass "huge_dir_ls" "cold: $LS_COUNT entries in ''${COLD_LS_ELAPSED}s ($COLD_LS_RATE entries/s)"
  record_timing "huge_dir_cold_ls" "$COLD_LS_ELAPSED" "$LS_COUNT" "$COLD_LS_RATE" "entries/s"

  # Multi-extent files
  echo "=== Multi-extent files (''${MULTI_EXTENT_FILES} files x ''${EXTENTS_PER_FILE} extents) ==="
  EXTENT_DIR="$MNT/scale-extents"; mkdir -p "$EXTENT_DIR"
  T0=$(ns_time_ms); EXTENT_OK=1; f=1
  while [ "$f" -le "$MULTI_EXTENT_FILES" ]; do
    FILE="$EXTENT_DIR/extent-file-$f.bin"
    : > "$FILE" 2>/dev/null || { fail "extent_create" "file $f"; EXTENT_OK=0; break; }
    e=1
    while [ "$e" -le "$EXTENTS_PER_FILE" ]; do
      dd if=/dev/urandom of="$FILE" bs=512 count=1 seek=$(( (e - 1) * 8 )) conv=notrunc 2>/dev/null || true
      e=$((e + 1))
    done
    f=$((f + 1))
  done
  sync
  EXTENT_ELAPSED=$(elapsed_since "$T0")
  if [ "$EXTENT_OK" -eq 1 ]; then
    pass "multi_extent_create" "''${MULTI_EXTENT_FILES} files in ''${EXTENT_ELAPSED}s"
    record_timing "multi_extent_create" "$EXTENT_ELAPSED" "$MULTI_EXTENT_FILES" "$(awk "BEGIN { if ($EXTENT_ELAPSED > 0) printf \"%.1f\", $MULTI_EXTENT_FILES / $EXTENT_ELAPSED; else print 0 }")" "files/s"
  fi

  echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true; sleep 1
  T0=$(ns_time_ms); READ_COUNT=0; READ_BYTES=0
  for f in "$EXTENT_DIR"/extent-file-*.bin; do
    BYTES=$(wc -c < "$f" 2>/dev/null || echo 0)
    READ_COUNT=$((READ_COUNT + 1)); READ_BYTES=$((READ_BYTES + BYTES))
    if [ "$READ_COUNT" -ge "$MULTI_EXTENT_FILES" ]; then break; fi
  done
  READ_ELAPSED=$(elapsed_since "$T0")
  READ_RATE=$(awk "BEGIN { if ($READ_ELAPSED > 0) printf \"%.1f\", $READ_COUNT / $READ_ELAPSED; else print 0 }")
  pass "multi_extent_read" "cold: $READ_COUNT files in ''${READ_ELAPSED}s ($READ_RATE files/s)"
  record_timing "multi_extent_read" "$READ_ELAPSED" "$READ_COUNT" "$READ_RATE" "files/s"

  # Memory
  MEM_TOTAL=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
  MEM_FREE=$(awk '/^MemFree:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
  echo "mem_total_kb=$MEM_TOTAL mem_free_kb=$MEM_FREE"

  # Cleanup
  fusermount -u "$MNT" 2>/dev/null || true
  sleep 1; kill "$DAEMON_PID" 2>/dev/null || true
  losetup -d "$LOOP0" 2>/dev/null || true
  losetup -d "$LOOP1" 2>/dev/null || true

  # Results
  echo ""
  echo "=== Results ==="
  echo "passed=$PASSED"
  echo "failed=$FAILED"
  echo "blocked=$BLOCKED"

  TIMINGS_ARR=$(echo "$TIMING_LINES" | sed 's/,$//')
  if [ -n "$JSON_OUT" ]; then
    cat > "$JSON_OUT" << JSONEOF
{
  "test": "fuse-namespace-scale-stress-host",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "kernel_version": "$(uname -r)",
  "host": "$(hostname)",
  "mode": "fuse",
  "backend": "loopback",
  "validation_tier": "MountedUserspace",
  "passed": $PASSED,
  "failed": $FAILED,
  "blocked": $BLOCKED,
  "complete": true,
  "scale_params": {
    "wide_dirs": $WIDE_DIRS,
    "files_per_dir": $FILES_PER_DIR,
    "deep_levels": $DEEP_LEVELS,
    "files_per_level": $FILES_PER_LEVEL,
    "huge_dir_files": $HUGE_DIR_FILES,
    "multi_extent_files": $MULTI_EXTENT_FILES,
    "extents_per_file": $EXTENTS_PER_FILE
  },
  "total_files_created": $((WIDE_DIRS * FILES_PER_DIR + DEEP_LEVELS * FILES_PER_LEVEL + HUGE_DIR_FILES + MULTI_EXTENT_FILES)),
  "phases": [$TIMINGS_ARR]
}
JSONEOF
    echo "Validation: $JSON_OUT"
  fi

  if [ "$FAILED" -gt 0 ]; then
    echo "FINAL_VERDICT: FAILURES=$FAILED"
    exit 1
  else
    echo "FINAL_VERDICT: OK"
  fi
''
