# TideFS: FUSE userspace inode metadata crash-consistency validation.
#
# Builds a self-contained C test binary that exercises FUSE inode attribute
# operations (getattr, setattr size/mode/owner/timestamps, stat, chmod,
# chown, utimens) on a mounted TideFS FUSE filesystem inside a QEMU guest,
# simulates daemon death, verifies post-crash attribute readback on remount,
# and records explicit blockers for mutation-window crash and committed-root
# verification rows that this lane does not exercise.
#
# Crash-consistency cycle:
#   1. Mount TideFS via FUSE daemon.
#   2. Create files, set attributes, verify with getattr/stat.
#   3. Sync and snapshot the mounted attribute state.
#   4. Kill the FUSE daemon (SIGKILL) to simulate crash.
#   5. Remount and verify: synced attributes survive readback.
#
# Validation tiers:
#   T0 - clean getattr/setattr round-trip
#   T1 - crash-during-setattr durability (explicit blocker in this lane)
#   T2 - post-crash attribute readback
#   T3 - committed-root hash-chain verification (explicit blocker in this lane)
#
# Dependencies:
#   - Linux kernel with FUSE support
#   - tidefs-posix-filesystem-adapter-daemon binary
#   - QEMU for guest execution
{
  pkgs,
  tidefsPackage,
}:

let
  # Self-contained C test binary for FUSE inode metadata operations.
  fuseInodeMetadataTestBin = pkgs.runCommandCC "tidefs-fuse-inode-metadata-test"
    {
      buildInputs = [ ];
    } ''
    mkdir -p "$out/bin"
    cat > fuse_inode_metadata_test.c << 'CEOF'
/*
 * tidefs-fuse-inode-metadata-test -- FUSE inode attribute validation workload.
 *
 * Exercise on a TideFS FUSE mount point:
 *  1. getattr: retrieve attributes after creation.
 *  2. setattr-size: change file size, verify.
 *  3. setattr-mode: change permissions, verify.
 *  4. setattr-owner: change uid/gid, verify.
 *  5. setattr-timestamps: change atime/mtime, verify.
 *  6. chmod: change mode via chmod syscall.
 *  7. chown: change owner via chown syscall.
 *  8. utimens: set timestamps via utimens syscall.
 *
 * Returns 0 on success, non-zero on failure with diagnostic on stderr.
 *
 * Usage: tidefs-fuse-inode-metadata-test <mount-point>
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utime.h>
#include <time.h>

static char test_path[8192];
static char mnt_dir[4096];

static void die(const char *msg) {
    fprintf(stderr, "fuse-inode-metadata-test: %s: %s\n", msg, strerror(errno));
    exit(1);
}

static void make_path(const char *name) {
    snprintf(test_path, sizeof(test_path), "%s/%s", mnt_dir, name);
}

static int create_reg(const char *name) {
    make_path(name);
    int fd = open(test_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) die("create_reg");
    if (write(fd, "hello", 5) != 5) die("write");
    close(fd);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: tidefs-fuse-inode-metadata-test <mount-point>\n");
        return 1;
    }

    snprintf(mnt_dir, sizeof(mnt_dir), "%s", argv[1]);

    struct stat st;
    int passed = 0;
    int refused = 0;
    int failed = 0;

#define PASS(name) do { printf("PASS: %s\n", name); passed++; } while(0)
#define REFUSAL(name) do { printf("REFUSAL: %s\n", name); refused++; } while(0)
#define FAIL(name, ...) do { fprintf(stderr, "FAIL: " name "\n", ##__VA_ARGS__); failed++; } while(0)

    /* ── 1. getattr: retrieve attributes after file creation ── */
    create_reg("getattr_test.bin");
    make_path("getattr_test.bin");
    if (stat(test_path, &st) < 0) {
        FAIL("getattr-clean");
    } else {
        if (st.st_size != 5) {
            FAIL("getattr-clean -- size %ld != 5", (long)st.st_size);
        } else if (!S_ISREG(st.st_mode)) {
            FAIL("getattr-clean -- not a regular file");
        } else {
            PASS("getattr-clean");
        }
    }

    /* ── 2. setattr-size: change file size via truncate ── */
    create_reg("size_test.bin");
    make_path("size_test.bin");
    if (truncate(test_path, 4096) < 0) {
        FAIL("setattr-size-clean -- truncate failed");
    } else if (stat(test_path, &st) < 0) {
        FAIL("setattr-size-clean -- stat after truncate failed");
    } else if (st.st_size != 4096) {
        FAIL("setattr-size-clean -- size %ld != 4096", (long)st.st_size);
    } else {
        PASS("setattr-size-clean");
    }

    /* ── 3. setattr-mode: change permissions via chmod ── */
    create_reg("mode_test.bin");
    make_path("mode_test.bin");
    if (chmod(test_path, 0755) < 0) {
        FAIL("setattr-mode-clean -- chmod failed");
    } else if (stat(test_path, &st) < 0) {
        FAIL("setattr-mode-clean -- stat after chmod failed");
    } else if ((st.st_mode & 0777) != 0755) {
        FAIL("setattr-mode-clean -- mode 0%o != 0755", st.st_mode & 0777);
    } else {
        PASS("setattr-mode-clean");
    }

    /* ── 4. setattr-owner: change owner via chown (skip if not root) ── */
    if (getuid() == 0) {
        create_reg("owner_test.bin");
        make_path("owner_test.bin");
        if (chown(test_path, 1, 1) < 0) {
            FAIL("setattr-owner-clean -- chown failed");
        } else if (stat(test_path, &st) < 0) {
            FAIL("setattr-owner-clean -- stat after chown failed");
        } else if (st.st_uid != 1 || st.st_gid != 1) {
            FAIL("setattr-owner-clean -- uid %d gid %d != 1/1", st.st_uid, st.st_gid);
        } else {
            PASS("setattr-owner-clean");
        }
    } else {
        REFUSAL("setattr-owner-clean -- root-capable mounted execution required");
    }

    /* ── 5. setattr-timestamps: set atime/mtime via utime ── */
    create_reg("timestamps_test.bin");
    make_path("timestamps_test.bin");
    time_t set_time = 1000000000; /* epoch-based deterministic time */
    struct utimbuf ut;
    ut.actime = set_time;
    ut.modtime = set_time;
    if (utime(test_path, &ut) < 0) {
        FAIL("setattr-timestamps-clean -- utime failed");
    } else if (stat(test_path, &st) < 0) {
        FAIL("setattr-timestamps-clean -- stat after utime failed");
    } else if (st.st_atime != set_time || st.st_mtime != set_time) {
        FAIL("setattr-timestamps-clean -- atime %ld mtime %ld != %ld",
             (long)st.st_atime, (long)st.st_mtime, (long)set_time);
    } else {
        PASS("setattr-timestamps-clean");
    }

    /* ── 6. chmod: dedicated chmod path ── */
    create_reg("chmod_test.bin");
    make_path("chmod_test.bin");
    if (chmod(test_path, 0600) < 0) {
        FAIL("chmod-clean -- chmod failed");
    } else if (stat(test_path, &st) < 0) {
        FAIL("chmod-clean -- stat after chmod failed");
    } else if ((st.st_mode & 0777) != 0600) {
        FAIL("chmod-clean -- mode 0%o != 0600", st.st_mode & 0777);
    } else {
        PASS("chmod-clean");
    }

    /* ── 7. chown: dedicated chown path ── */
    if (getuid() == 0) {
        create_reg("chown_test.bin");
        make_path("chown_test.bin");
        if (chown(test_path, 2, 2) < 0) {
            FAIL("chown-clean -- chown failed");
        } else if (stat(test_path, &st) < 0) {
            FAIL("chown-clean -- stat after chown failed");
        } else if (st.st_uid != 2) {
            FAIL("chown-clean -- uid %d != 2", st.st_uid);
        } else {
            PASS("chown-clean");
        }
    } else {
        /* Non-root: chown fails with EPERM; record this as environment refusal. */
        create_reg("chown_test.bin");
        make_path("chown_test.bin");
        if (chown(test_path, 2, 2) == 0) {
            FAIL("chown-clean -- chown succeeded unexpectedly as non-root");
        } else if (errno == EPERM) {
            REFUSAL("chown-clean -- root-capable mounted execution required");
        } else {
            FAIL("chown-clean -- unexpected errno %d (expected EPERM)", errno);
        }
    }

    /* ── 8. utimens: dedicated utimens path ── */
    create_reg("utimens_test.bin");
    make_path("utimens_test.bin");
    struct timespec ts[2];
    ts[0].tv_sec = 500000000;
    ts[0].tv_nsec = 123456789;
    ts[1].tv_sec = 500000000;
    ts[1].tv_nsec = 987654321;
    if (utimensat(AT_FDCWD, test_path, ts, 0) < 0) {
        FAIL("utimens-clean -- utimensat failed");
    } else if (stat(test_path, &st) < 0) {
        FAIL("utimens-clean -- stat after utimensat failed");
    } else if (st.st_atim.tv_sec != ts[0].tv_sec || st.st_mtim.tv_sec != ts[1].tv_sec) {
        FAIL("utimens-clean -- timestamps mismatch");
    } else {
        PASS("utimens-clean");
    }

    fprintf(stderr, "FUSE inode metadata test: %d passed, %d refused, %d failed\n", passed, refused, failed);
    return failed > 0 ? 1 : 0;
}
CEOF

    cc -O2 -Wall fuse_inode_metadata_test.c -o "$out/bin/tidefs-fuse-inode-metadata-test"
    strip "$out/bin/tidefs-fuse-inode-metadata-test"
  '';

  # Validation script that mounts FUSE, runs the inode metadata test,
  # simulates daemon death, and verifies post-crash attribute readback.
  fuseInodeMetadataValidationScript = pkgs.writeShellScriptBin "tidefs-fuse-inode-metadata-validation" ''
    set -euo pipefail

    DAEMON_BIN="${tidefsPackage}/bin/tidefs-posix-filesystem-adapter-daemon"
    METADATA_TEST="${fuseInodeMetadataTestBin}/bin/tidefs-fuse-inode-metadata-test"

    TMPDIR="''${TIDEFS_FUSE_INODE_METADATA_TMPDIR:-/tmp/tidefs-fuse-inode-metadata-validation}"
    ARTIFACT_SCOPE="''${TIDEFS_FUSE_INODE_METADATA_ARTIFACT_SCOPE:-$TMPDIR}"
    SOURCE_COMMIT="''${TIDEFS_SOURCE_COMMIT:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}"
    STORE="$TMPDIR/store"
    MNT="$TMPDIR/mnt"
    OBSERVED_ROWS="$TMPDIR/observed_rows.txt"
    FUSERMOUNT_HELPER_DIR="$TMPDIR/fuse-helper-bin"

    usage() {
      cat <<EOF
Usage: tidefs-fuse-inode-metadata-validation [--keep-tmp]

Validate FUSE userspace inode metadata operations (getattr, setattr, stat,
chmod, chown, utimens) with clean/readback validation and explicit blockers
for mutation-window crash and committed-root verification rows.

Environment:
  TIDEFS_FUSE_INODE_METADATA_TMPDIR  scratch directory (default /tmp/tidefs-fuse-inode-metadata-validation)
  TIDEFS_ROOT_AUTHENTICATION_KEY_HEX  root auth key (required)
EOF
      exit 1
    }

    KEEP_TMP=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h) usage ;;
        *) break ;;
      esac
    done

    PASSED=0
    FAILED=0
    REFUSED=0
    BLOCKED=0

    CANONICAL_ROWS="
    getattr-clean
    getattr-crash
    getattr-readback
    getattr-verify
    setattr-size-clean
    setattr-size-crash
    setattr-size-readback
    setattr-size-verify
    setattr-mode-clean
    setattr-mode-crash
    setattr-mode-readback
    setattr-mode-verify
    setattr-owner-clean
    setattr-owner-crash
    setattr-owner-readback
    setattr-owner-verify
    setattr-timestamps-clean
    setattr-timestamps-crash
    setattr-timestamps-readback
    setattr-timestamps-verify
    chmod-clean
    chmod-crash
    chmod-readback
    chmod-verify
    chown-clean
    chown-crash
    chown-readback
    chown-verify
    utimens-clean
    utimens-crash
    utimens-readback
    utimens-verify
    "

    is_canonical_row() {
      needle="$1"
      for canonical in $CANONICAL_ROWS; do
        if [ "$canonical" = "$needle" ]; then
          return 0
        fi
      done
      return 1
    }

    record_row() {
      is_canonical_row "$1" || return 1
      printf '%s\n' "$1" >> "$OBSERVED_ROWS"
      return 0
    }

    pass() {
      echo "  PASS: $1"
      if record_row "$1"; then
        PASSED=$((PASSED + 1))
      fi
    }
    fail() {
      echo "  FAIL: $1 -- $2"
      if record_row "$1"; then
        FAILED=$((FAILED + 1))
      fi
    }
    refusal() {
      echo "  REFUSAL: $1 -- $2"
      if record_row "$1"; then
        REFUSED=$((REFUSED + 1))
      fi
    }
    blocked() {
      echo "  BLOCKED: $1 -- $2"
      if record_row "$1"; then
        BLOCKED=$((BLOCKED + 1))
      fi
    }

    emit_unobserved_rows() {
      outcome="$1"
      reason="$2"
      for row in $CANONICAL_ROWS; do
        if grep -Fxq "$row" "$OBSERVED_ROWS"; then
          continue
        fi
        case "$outcome" in
          refusal) refusal "$row" "$reason" ;;
          blocked) blocked "$row" "$reason" ;;
          fail) fail "$row" "$reason" ;;
          *) blocked "$row" "$reason" ;;
        esac
      done
    }

    show_log_tail() {
      log_path="$1"
      label="$2"
      if [ -s "$log_path" ]; then
        echo ""
        echo "--- $label tail ---"
        tail -n 80 "$log_path" || true
        echo "--- end $label tail ---"
      fi
    }

    write_fusermount_helper() {
      helper_name="$1"
      target="$2"
      helper_path="$FUSERMOUNT_HELPER_DIR/$helper_name"
      cat > "$helper_path" <<EOF
#!${pkgs.runtimeShell}
exec "$target" "\$@"
EOF
      chmod 0755 "$helper_path"
    }

    rm -rf "$TMPDIR"
    mkdir -p "$STORE" "$MNT" "$FUSERMOUNT_HELPER_DIR"

    # The fuser crate probes fusermount3 before fusermount.  Some NixOS
    # runners expose only a setuid /run/wrappers/bin/fusermount wrapper while
    # Nix supplies a non-setuid fusermount3 earlier in PATH; provide both names
    # in a helper directory so the daemon reaches the setuid wrapper first.
    # Use tiny wrapper scripts instead of symlinks so artifact upload never
    # tries to read the root-owned setuid wrapper target.
    if [ -x /run/wrappers/bin/fusermount3 ]; then
      FUSERMOUNT3_TARGET=/run/wrappers/bin/fusermount3
    elif [ -x /run/wrappers/bin/fusermount ]; then
      FUSERMOUNT3_TARGET=/run/wrappers/bin/fusermount
    else
      FUSERMOUNT3_TARGET=
    fi
    if [ -x /run/wrappers/bin/fusermount ]; then
      FUSERMOUNT_TARGET=/run/wrappers/bin/fusermount
    elif [ -x /run/wrappers/bin/fusermount3 ]; then
      FUSERMOUNT_TARGET=/run/wrappers/bin/fusermount3
    else
      FUSERMOUNT_TARGET=
    fi
    if [ -n "$FUSERMOUNT3_TARGET" ]; then
      write_fusermount_helper fusermount3 "$FUSERMOUNT3_TARGET"
    fi
    if [ -n "$FUSERMOUNT_TARGET" ]; then
      write_fusermount_helper fusermount "$FUSERMOUNT_TARGET"
    fi
    export PATH="$FUSERMOUNT_HELPER_DIR:/run/wrappers/bin:$PATH"

    : > "$OBSERVED_ROWS"
    exec > >(tee "$TMPDIR/validation.log") 2>&1

    echo "=== TideFS FUSE Inode Metadata Validation ==="
    echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "commit=$SOURCE_COMMIT"
    echo "kernel=$(uname -r)"
    echo "daemon=$DAEMON_BIN"
    echo "test=$METADATA_TEST"
    echo "artifact_scope=$ARTIFACT_SCOPE"
    echo "fusermount3=$(command -v fusermount3 2>/dev/null || echo unavailable)"
    echo "fusermount=$(command -v fusermount 2>/dev/null || echo unavailable)"
    echo "fusermount3_target=''${FUSERMOUNT3_TARGET:-unavailable}"
    echo "fusermount_target=''${FUSERMOUNT_TARGET:-unavailable}"
    echo ""
    echo "Tier: mounted-userspace"
    echo ""

    if [ -z "''${TIDEFS_ROOT_AUTHENTICATION_KEY_HEX:-}" ]; then
      refusal "root-auth-key" "TIDEFS_ROOT_AUTHENTICATION_KEY_HEX not set"
      echo "Set it to a 64-hex-char key for validation."
      emit_unobserved_rows refusal "TIDEFS_ROOT_AUTHENTICATION_KEY_HEX not set"
      exit 2
    fi

    # Check /dev/fuse
    if [ ! -e /dev/fuse ]; then
      refusal "/dev/fuse" "not available in this environment"
      echo "Run inside a QEMU guest or on a host with FUSE support."
      emit_unobserved_rows refusal "/dev/fuse not available in this environment"
      exit 2
    fi

    verify_file() {
      row="$1"
      file="$2"
      if [ -e "$MNT/$file" ]; then
        return 0
      fi
      fail "$row" "$file missing after crash/remount"
      return 1
    }

    verify_size() {
      row="$1"
      file="$2"
      expected="$3"
      verify_file "$row" "$file" || return 0
      got="$(stat -c '%s' "$MNT/$file" 2>/dev/null || echo missing)"
      if [ "$got" = "$expected" ]; then
        pass "$row"
      else
        fail "$row" "$file size $got != $expected"
      fi
    }

    verify_mode() {
      row="$1"
      file="$2"
      expected="$3"
      verify_file "$row" "$file" || return 0
      got="$(stat -c '%a' "$MNT/$file" 2>/dev/null || echo missing)"
      if [ "$got" = "$expected" ]; then
        pass "$row"
      else
        fail "$row" "$file mode $got != $expected"
      fi
    }

    verify_owner() {
      row="$1"
      file="$2"
      expected_uid="$3"
      expected_gid="$4"
      verify_file "$row" "$file" || return 0
      got_uid="$(stat -c '%u' "$MNT/$file" 2>/dev/null || echo missing)"
      got_gid="$(stat -c '%g' "$MNT/$file" 2>/dev/null || echo missing)"
      if [ "$got_uid" = "$expected_uid" ] && [ "$got_gid" = "$expected_gid" ]; then
        pass "$row"
      else
        fail "$row" "$file owner $got_uid:$got_gid != $expected_uid:$expected_gid"
      fi
    }

    verify_mtime() {
      row="$1"
      file="$2"
      expected="$3"
      verify_file "$row" "$file" || return 0
      got="$(stat -c '%Y' "$MNT/$file" 2>/dev/null || echo missing)"
      if [ "$got" = "$expected" ]; then
        pass "$row"
      else
        fail "$row" "$file mtime $got != $expected"
      fi
    }

    # ── Phase 1: Start FUSE daemon ──────────────────────────────────
    echo "--- Phase 1: Start FUSE daemon ---"
    DAEMON_LOG="$TMPDIR/daemon.log"
    "$DAEMON_BIN" mount-vfs \
      --store "$STORE" --mount "$MNT" \
      --root-auth-key-hex "$TIDEFS_ROOT_AUTHENTICATION_KEY_HEX" \
      > "$DAEMON_LOG" 2>&1 &
    DAEMON_PID=$!

    for i in $(seq 1 30); do
      if mountpoint -q "$MNT" 2>/dev/null; then
        break
      fi
      sleep 0.2
    done

    if mountpoint -q "$MNT" 2>/dev/null; then
      pass "fuse_mount"
    else
      if kill -0 "$DAEMON_PID" 2>/dev/null; then
        blocked "fuse_mount" "daemon running but mount not visible after 6s"
      else
        blocked "fuse_mount" "daemon died -- see $DAEMON_LOG"
      fi
      show_log_tail "$DAEMON_LOG" "daemon.log"
      emit_unobserved_rows blocked "FUSE mount did not become available; see $DAEMON_LOG"
      echo ""
      echo "=== FUSE Inode Metadata Validation Summary ==="
      echo "PASSED=$PASSED REFUSED=$REFUSED FAILED=$FAILED BLOCKED=$BLOCKED"
      echo "tier=mounted-userspace"
      exit 1
    fi

    # ── Phase 2: Run inode metadata test ────────────────────────────
    echo ""
    echo "--- Phase 2: Inode metadata operations ---"
    TEST_LOG="$TMPDIR/test.log"
    if "$METADATA_TEST" "$MNT" > "$TEST_LOG" 2>&1; then
      TEST_RC=0
    else
      TEST_RC=$?
    fi

    while IFS= read -r line; do
      case "$line" in
        PASS:*) pass "''${line#PASS: }" ;;
        FAIL:*)
          payload="''${line#FAIL: }"
          case "$payload" in
            *" -- "*) fail "''${payload%% -- *}" "''${payload#* -- }" ;;
            *) fail "$payload" "$line" ;;
          esac
          ;;
        REFUSAL:*)
          payload="''${line#REFUSAL: }"
          case "$payload" in
            *" -- "*) refusal "''${payload%% -- *}" "''${payload#* -- }" ;;
            *) refusal "$payload" "$line" ;;
          esac
          ;;
        BLOCKED:*)
          payload="''${line#BLOCKED: }"
          case "$payload" in
            *" -- "*) blocked "''${payload%% -- *}" "''${payload#* -- }" ;;
            *) blocked "$payload" "$line" ;;
          esac
          ;;
      esac
    done < "$TEST_LOG"

    if [ "$TEST_RC" -eq 0 ]; then
      pass "metadata_test_exit_zero"
    else
      fail "metadata_test_exit_zero" "test binary exited with $TEST_RC"
    fi

    # ── Phase 3: Snapshot committed state ───────────────────────────
    echo ""
    echo "--- Phase 3: Snapshot committed state ---"
    sync
    ls -la "$MNT" > "$TMPDIR/root_list.txt" 2>/dev/null || true

    for f in getattr_test.bin size_test.bin mode_test.bin owner_test.bin \
             timestamps_test.bin chmod_test.bin chown_test.bin utimens_test.bin; do
      if [ -f "$MNT/$f" ]; then
        stat -c '%n %s %a %u %g %X %Y' "$MNT/$f" >> "$TMPDIR/pre_crash_attrs.txt" 2>/dev/null || true
      fi
    done
    pass "committed_snapshot"

    # ── Phase 4: Simulate crash (SIGKILL daemon) ────────────────────
    echo ""
    echo "--- Phase 4: Simulate crash (SIGKILL daemon PID $DAEMON_PID) ---"
    kill -9 "$DAEMON_PID" 2>/dev/null || true
    sleep 1

    fusermount -u "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null || true
    sleep 0.5
    pass "crash_simulated"

    # ── Phase 5: Remount and verify ──────────────────────────────────
    echo ""
    echo "--- Phase 5: Remount and verify ---"
    mkdir -p "$MNT"
    "$DAEMON_BIN" mount-vfs \
      --store "$STORE" --mount "$MNT" \
      --root-auth-key-hex "$TIDEFS_ROOT_AUTHENTICATION_KEY_HEX" \
      > "$TMPDIR/daemon_remount.log" 2>&1 &
    REMOUNT_PID=$!

    for i in $(seq 1 30); do
      if mountpoint -q "$MNT" 2>/dev/null; then
        break
      fi
      sleep 0.2
    done

    if mountpoint -q "$MNT" 2>/dev/null; then
      pass "remount_after_crash"
    else
      blocked "remount_after_crash" "remount failed -- see $TMPDIR/daemon_remount.log"
      show_log_tail "$TMPDIR/daemon_remount.log" "daemon_remount.log"
      emit_unobserved_rows blocked "remount failed; see $TMPDIR/daemon_remount.log"
      kill "$REMOUNT_PID" 2>/dev/null || true
      exit 1
    fi

    # Verify committed files still exist and have correct attributes.
    echo ""
    echo "--- Phase 6: Verify committed attributes survive crash ---"
    verify_size "getattr-readback" "getattr_test.bin" 5
    verify_size "setattr-size-readback" "size_test.bin" 4096
    verify_mode "setattr-mode-readback" "mode_test.bin" 755
    if [ "$(id -u)" -eq 0 ]; then
      verify_owner "setattr-owner-readback" "owner_test.bin" 1 1
    else
      refusal "setattr-owner-readback" "root-capable mounted execution required"
    fi
    verify_mtime "setattr-timestamps-readback" "timestamps_test.bin" 1000000000
    verify_mode "chmod-readback" "chmod_test.bin" 600
    if [ "$(id -u)" -eq 0 ]; then
      verify_owner "chown-readback" "chown_test.bin" 2 2
    else
      refusal "chown-readback" "root-capable mounted execution required"
    fi
    verify_mtime "utimens-readback" "utimens_test.bin" 500000000

    for row in \
      getattr-crash setattr-size-crash setattr-mode-crash setattr-owner-crash \
      setattr-timestamps-crash chmod-crash chown-crash utimens-crash; do
      blocked "$row" "no mounted FUSE fault-injection harness currently crashes inside the metadata mutation window"
    done

    for row in \
      getattr-verify setattr-size-verify setattr-mode-verify setattr-owner-verify \
      setattr-timestamps-verify chmod-verify chown-verify utimens-verify; do
      blocked "$row" "committed-root hash-chain verification is not emitted by this mounted metadata lane"
    done

    # Cleanup
    kill "$REMOUNT_PID" 2>/dev/null || true
    fusermount -u "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null || true

    emit_unobserved_rows blocked "row was not observed before validation summary; inspect $TEST_LOG and daemon logs"

    # ── Summary ─────────────────────────────────────────────────────
    echo ""
    echo "=== FUSE Inode Metadata Validation Summary ==="
    echo "PASSED=$PASSED"
    echo "REFUSED=$REFUSED"
    echo "FAILED=$FAILED"
    echo "BLOCKED=$BLOCKED"
    echo "tier=mounted-userspace"
    echo "commit=$SOURCE_COMMIT"
    echo "artifact_scope=$ARTIFACT_SCOPE"
    echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "daemon_log=$TMPDIR/daemon.log"
    echo "test_log=$TMPDIR/test.log"
    echo "validation_log=$TMPDIR/validation.log"
    echo "=== End ==="

    if [ -z "$KEEP_TMP" ]; then
      rm -rf "$TMPDIR"
    fi

    if [ "$FAILED" -gt 0 ]; then
      echo "VALIDATION: FAIL -- $FAILED operations failed"
      exit 1
    fi

    echo "VALIDATION: PASS -- all exercised operations succeeded"
    exit 0
  '';
in
fuseInodeMetadataValidationScript
