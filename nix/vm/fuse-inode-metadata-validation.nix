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
  linuxKernel_7_0,
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
    fflush(stderr);
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

    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);

#define BEGIN(name) do { printf("BEGIN: %s\n", name); fflush(stdout); } while(0)
#define PASS(name) do { printf("PASS: %s\n", name); fflush(stdout); passed++; } while(0)
#define REFUSAL(name) do { printf("REFUSAL: %s\n", name); fflush(stdout); refused++; } while(0)
#define FAIL(name, ...) do { fprintf(stderr, "FAIL: " name "\n", ##__VA_ARGS__); fflush(stderr); failed++; } while(0)

    /* ── 1. getattr: retrieve attributes after file creation ── */
    BEGIN("getattr-clean");
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
    BEGIN("setattr-size-clean");
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
    BEGIN("setattr-mode-clean");
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
    BEGIN("setattr-owner-clean");
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
    BEGIN("setattr-timestamps-clean");
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
    BEGIN("chmod-clean");
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
    BEGIN("chown-clean");
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
    BEGIN("utimens-clean");
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

  # QEMU runner that mounts FUSE, runs the inode metadata test, simulates
  # daemon death, and verifies post-crash attribute readback inside the guest.
  fuseInodeMetadataValidationScript = pkgs.writeShellScriptBin "tidefs-fuse-inode-metadata-validation" ''
    set -euo pipefail

    export PATH="${pkgs.coreutils}/bin:${pkgs.gnugrep}/bin:${pkgs.gnused}/bin:${pkgs.gawk}/bin:${pkgs.findutils}/bin:${pkgs.glibc.bin}/bin:${pkgs.cpio}/bin:${pkgs.xz}/bin:${pkgs.qemu}/bin:$PATH"

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    CPIO="${pkgs.cpio}/bin/cpio"
    XZ_BIN="${pkgs.xz}/bin/xz"
    TIMEOUT_BIN="${pkgs.coreutils}/bin/timeout"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"
    DAEMON_BIN="${tidefsPackage}/bin/tidefs-posix-filesystem-adapter-daemon"
    METADATA_TEST="${fuseInodeMetadataTestBin}/bin/tidefs-fuse-inode-metadata-test"

    TMPDIR="''${TIDEFS_FUSE_INODE_METADATA_TMPDIR:-/tmp/tidefs-fuse-inode-metadata-validation}"
    VALIDATION_DIR="''${TIDEFS_FUSE_INODE_METADATA_VALIDATION_DIR:-}"
    if [ -z "$VALIDATION_DIR" ]; then
      VALIDATION_DIR="''${TIDEFS_FUSE_INODE_METADATA_ARTIFACT_SCOPE:-/tmp/tidefs-validation/fuse-inode-metadata-validation}"
    fi
    ARTIFACT_SCOPE="''${TIDEFS_FUSE_INODE_METADATA_ARTIFACT_SCOPE:-$VALIDATION_DIR}"
    SOURCE_COMMIT="''${TIDEFS_SOURCE_COMMIT:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}"
    ROOT_KEY="''${TIDEFS_ROOT_AUTHENTICATION_KEY_HEX:-0000000000000000000000000000000000000000000000000000000000000001}"
    TIMEOUT_SEC="''${TIDEFS_FUSE_INODE_METADATA_TIMEOUT:-900}"

    usage() {
      cat <<'EOF'
Usage: tidefs-fuse-inode-metadata-validation [--timeout SECONDS] [--validation-dir DIR] [--keep-tmp]

Validate FUSE userspace inode metadata operations (getattr, setattr, stat,
chmod, chown, utimens) inside a Linux 7.0 QEMU guest, with clean/readback
validation and explicit blockers for mutation-window crash and committed-root
verification rows.

Environment:
  TIDEFS_FUSE_INODE_METADATA_TMPDIR         host scratch directory
  TIDEFS_FUSE_INODE_METADATA_VALIDATION_DIR host artifact directory
  TIDEFS_ROOT_AUTHENTICATION_KEY_HEX        root auth key (non-secret test key by default)
EOF
      exit 1
    }

    KEEP_TMP=0
    while [ $# -gt 0 ]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --timeout=*) TIMEOUT_SEC="''${1#--timeout=}"; shift ;;
        --validation-dir) VALIDATION_DIR="$2"; ARTIFACT_SCOPE="$2"; shift 2 ;;
        --validation-dir=*) VALIDATION_DIR="''${1#--validation-dir=}"; ARTIFACT_SCOPE="$VALIDATION_DIR"; shift ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h) usage ;;
        *) echo "ERROR: unknown option: $1" >&2; usage ;;
      esac
    done

    if [ ! -e /dev/kvm ]; then
      echo "ENVIRONMENT REFUSAL: /dev/kvm not available" >&2
      exit 2
    fi

    for dep in "$QEMU_BIN" "$BUSYBOX" "$CPIO" "$XZ_BIN" "$TIMEOUT_BIN" "$KERNEL_IMG" "$DAEMON_BIN" "$METADATA_TEST"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ERROR: dependency not found: $dep" >&2
        exit 2
      fi
    done

    echo "=== TideFS FUSE Inode Metadata Validation Runner ==="
    echo "  Kernel:         $KERNEL_IMG"
    echo "  Module dir:     $MODULE_DIR"
    echo "  QEMU:           $QEMU_BIN"
    echo "  Daemon:         $DAEMON_BIN"
    echo "  Metadata test:  $METADATA_TEST"
    echo "  Validation dir: $VALIDATION_DIR"
    echo "  Timeout:        ''${TIMEOUT_SEC}s"

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
    for applet in sh ls cat echo mount umount grep dmesg sleep poweroff reboot mknod mkdir rmdir dd stat cp mv rm touch find wc sync expr head tail cut kill ps test seq date uname tr sed tee true false env printf basename dirname readlink chmod id insmod; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    cat > "$RUN_DIR/bin/mountpoint" <<'EOF'
#!/bin/sh
quiet=0
if [ "$#" -gt 0 ] && [ "$1" = "-q" ]; then
    quiet=1
    shift
fi
target="$1"
if [ -n "$target" ] && grep -qs " $target " /proc/mounts; then
    exit 0
fi
[ "$quiet" -eq 1 ] || echo "$target is not a mountpoint"
exit 1
EOF
    chmod +x "$RUN_DIR/bin/mountpoint"

    cat > "$RUN_DIR/bin/fusermount" <<'EOF'
#!/bin/sh
if [ "$#" -gt 0 ] && [ "$1" = "-u" ]; then
    shift
fi
exec umount "$@"
EOF
    chmod +x "$RUN_DIR/bin/fusermount"
    ln -sf fusermount "$RUN_DIR/bin/fusermount3"

    copy_binary "$DAEMON_BIN" "$RUN_DIR/bin/tidefs-posix-filesystem-adapter-daemon"
    copy_binary "$METADATA_TEST" "$RUN_DIR/bin/tidefs-fuse-inode-metadata-test"
    copy_binary "$TIMEOUT_BIN" "$RUN_DIR/bin/timeout"
    copy_runtime_deps "$BUSYBOX" "$DAEMON_BIN" "$METADATA_TEST" "$TIMEOUT_BIN"

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
        *.xz) "$XZ_BIN" -dc "$FUSE_KO" > "$RUN_DIR/lib/modules/fuse.ko" ;;
        *) cp -L "$FUSE_KO" "$RUN_DIR/lib/modules/fuse.ko" ;;
      esac
    fi

    cat > "$RUN_DIR/init" <<'INITSCRIPT'
#!/bin/sh
export PATH=/bin
export LD_LIBRARY_PATH=/usr/lib:/lib:/lib64

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /tmp/tidefs-validation

PASSED=0
FAILED=0
REFUSED=0
BLOCKED=0
SOURCE_COMMIT="__SOURCE_COMMIT__"
ARTIFACT_SCOPE="__ARTIFACT_SCOPE__"
ROOT_KEY="__ROOT_KEY__"
STORE=/tmp/tidefs-validation/store
MNT=/tmp/tidefs-validation/mnt
OBSERVED_ROWS=/tmp/tidefs-validation/observed_rows.txt
DAEMON_LOG=/tmp/tidefs-validation/daemon.log
REMOUNT_LOG=/tmp/tidefs-validation/daemon_remount.log
TEST_LOG=/tmp/tidefs-validation/test.log
TEST_TIMEOUT=120
ROOT_LIST=/tmp/tidefs-validation/root_list.txt
PRE_CRASH_ATTRS=/tmp/tidefs-validation/pre_crash_attrs.txt

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
    echo "$1" >> "$OBSERVED_ROWS"
    return 0
}

pass() {
    echo "PASS: $1"
    if record_row "$1"; then PASSED=$((PASSED + 1)); fi
}

fail() {
    echo "FAIL: $1 -- $2"
    if record_row "$1"; then FAILED=$((FAILED + 1)); fi
}

refusal() {
    echo "REFUSAL: $1 -- $2"
    if record_row "$1"; then REFUSED=$((REFUSED + 1)); fi
}

blocked() {
    echo "BLOCKED: $1 -- $2"
    if record_row "$1"; then BLOCKED=$((BLOCKED + 1)); fi
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

last_unfinished_test_row() {
    candidate=""
    for row in $(grep '^BEGIN: ' "$TEST_LOG" 2>/dev/null | sed 's/^BEGIN: //'); do
        if grep -Eq "^(PASS|FAIL|REFUSAL|BLOCKED): $row($| --)" "$TEST_LOG" 2>/dev/null; then
            continue
        fi
        candidate="$row"
    done
    echo "$candidate"
}

finish() {
    echo ""
    echo "=== FUSE Inode Metadata Validation Summary ==="
    echo "PASSED=$PASSED"
    echo "REFUSED=$REFUSED"
    echo "FAILED=$FAILED"
    echo "BLOCKED=$BLOCKED"
    echo "tier=mounted-userspace-qemu-guest"
    echo "commit=$SOURCE_COMMIT"
    echo "artifact_scope=$ARTIFACT_SCOPE"
    echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "daemon_log=$DAEMON_LOG"
    echo "test_log=$TEST_LOG"
    echo "validation_log=qemu-boot.log"
    echo "=== End ==="
    echo "TIDEFS_OBSERVED_ROWS_BEGIN"
    cat "$OBSERVED_ROWS" 2>/dev/null || true
    echo "TIDEFS_OBSERVED_ROWS_END"
    echo "TIDEFS_DAEMON_LOG_BEGIN"
    cat "$DAEMON_LOG" 2>/dev/null || true
    echo "TIDEFS_DAEMON_LOG_END"
    echo "TIDEFS_DAEMON_REMOUNT_LOG_BEGIN"
    cat "$REMOUNT_LOG" 2>/dev/null || true
    echo "TIDEFS_DAEMON_REMOUNT_LOG_END"
    echo "TIDEFS_TEST_LOG_BEGIN"
    cat "$TEST_LOG" 2>/dev/null || true
    echo "TIDEFS_TEST_LOG_END"
    echo "TIDEFS_ROOT_LIST_BEGIN"
    cat "$ROOT_LIST" 2>/dev/null || true
    echo "TIDEFS_ROOT_LIST_END"
    echo "TIDEFS_PRE_CRASH_ATTRS_BEGIN"
    cat "$PRE_CRASH_ATTRS" 2>/dev/null || true
    echo "TIDEFS_PRE_CRASH_ATTRS_END"
    echo "TIDEFS_FUSE_INODE_METADATA_VALIDATION_DONE"
    sync
    sleep 1
    poweroff -f
    exit 0
}

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

: > "$OBSERVED_ROWS"
mkdir -p "$STORE" "$MNT"

echo "=== TideFS FUSE Inode Metadata Validation ==="
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "commit=$SOURCE_COMMIT"
echo "kernel=$(uname -r)"
echo "daemon=/bin/tidefs-posix-filesystem-adapter-daemon"
echo "test=/bin/tidefs-fuse-inode-metadata-test"
echo "artifact_scope=$ARTIFACT_SCOPE"
echo "Tier: mounted-userspace-qemu-guest"
echo ""

if [ -f /lib/modules/fuse.ko ]; then
    insmod /lib/modules/fuse.ko 2>/tmp/fuse-insmod.err || true
fi
if [ ! -e /dev/fuse ]; then
    mknod /dev/fuse c 10 229 2>/dev/null || true
fi
if [ -e /dev/fuse ]; then
    chmod 666 /dev/fuse 2>/dev/null || true
else
    refusal "/dev/fuse" "not available in QEMU guest"
    emit_unobserved_rows refusal "/dev/fuse not available in QEMU guest"
    finish
fi

echo "--- Phase 1: Start FUSE daemon ---"
/bin/tidefs-posix-filesystem-adapter-daemon mount-vfs \
    --store "$STORE" --mount "$MNT" \
    --root-auth-key-hex "$ROOT_KEY" \
    --options noatime \
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
    finish
fi

echo ""
echo "--- Phase 2: Inode metadata operations ---"
TEST_TIMED_OUT=0
TEST_RC=0
TEST_DONE=/tmp/tidefs-validation/test.done
TEST_RC_FILE=/tmp/tidefs-validation/test.rc
rm -f "$TEST_DONE" "$TEST_RC_FILE"

(
    /bin/tidefs-fuse-inode-metadata-test "$MNT" > "$TEST_LOG" 2>&1
    echo "$?" > "$TEST_RC_FILE"
    : > "$TEST_DONE"
) &
TEST_PID=$!
elapsed=0

while [ ! -e "$TEST_DONE" ]; do
    if [ "$elapsed" -ge "$TEST_TIMEOUT" ]; then
        TEST_TIMED_OUT=1
        TEST_RC=124
        echo "WATCHDOG: metadata helper exceeded ''${TEST_TIMEOUT}s" >> "$TEST_LOG"
        kill "$TEST_PID" 2>/dev/null || true
        sleep 5
        kill -9 "$TEST_PID" 2>/dev/null || true
        for cmdline in /proc/[0-9]*/cmdline; do
            pid="''${cmdline%/cmdline}"
            pid="''${pid##*/}"
            if tr '\0' ' ' < "$cmdline" 2>/dev/null | grep -q 'tidefs-fuse-inode-metadata-test'; then
                kill -9 "$pid" 2>/dev/null || true
            fi
        done
        break
    fi
    sleep 1
    elapsed=$((elapsed + 1))
done

if [ "$TEST_TIMED_OUT" -eq 0 ]; then
    TEST_RC="$(cat "$TEST_RC_FILE" 2>/dev/null || echo 1)"
    wait "$TEST_PID" 2>/dev/null || true
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

if [ "$TEST_TIMED_OUT" -eq 1 ]; then
    HUNG_ROW="$(last_unfinished_test_row)"
    [ -n "$HUNG_ROW" ] || HUNG_ROW="getattr-clean"
    fail "$HUNG_ROW" "metadata helper timed out after ''${TEST_TIMEOUT}s while exercising this row"
    show_log_tail "$TEST_LOG" "test.log"
    show_log_tail "$DAEMON_LOG" "daemon.log"
    emit_unobserved_rows blocked "metadata helper timed out before row execution completed; inspect test and daemon logs"
    kill "$DAEMON_PID" 2>/dev/null || true
    umount -l "$MNT" 2>/dev/null || true
    finish
fi

if [ "$TEST_RC" -eq 0 ]; then
    pass "metadata_test_exit_zero"
else
    fail "metadata_test_exit_zero" "test binary exited with $TEST_RC"
fi

echo ""
echo "--- Phase 3: Snapshot committed state ---"
sync
ls -la "$MNT" > "$ROOT_LIST" 2>/dev/null || true
for f in getattr_test.bin size_test.bin mode_test.bin owner_test.bin \
         timestamps_test.bin chmod_test.bin chown_test.bin utimens_test.bin; do
    if [ -f "$MNT/$f" ]; then
        stat -c '%n %s %a %u %g %X %Y' "$MNT/$f" >> "$PRE_CRASH_ATTRS" 2>/dev/null || true
    fi
done
pass "committed_snapshot"

echo ""
echo "--- Phase 4: Simulate crash (SIGKILL daemon PID $DAEMON_PID) ---"
kill -9 "$DAEMON_PID" 2>/dev/null || true
sleep 1
umount -l "$MNT" 2>/dev/null || true
sleep 0.5
pass "crash_simulated"

echo ""
echo "--- Phase 5: Remount and verify ---"
mkdir -p "$MNT"
/bin/tidefs-posix-filesystem-adapter-daemon mount-vfs \
    --store "$STORE" --mount "$MNT" \
    --root-auth-key-hex "$ROOT_KEY" \
    --options noatime \
    > "$REMOUNT_LOG" 2>&1 &
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
    blocked "remount_after_crash" "remount failed -- see $REMOUNT_LOG"
    show_log_tail "$REMOUNT_LOG" "daemon_remount.log"
    emit_unobserved_rows blocked "remount failed; see $REMOUNT_LOG"
    kill "$REMOUNT_PID" 2>/dev/null || true
    finish
fi

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

kill "$REMOUNT_PID" 2>/dev/null || true
umount -l "$MNT" 2>/dev/null || true
emit_unobserved_rows blocked "row was not observed before validation summary; inspect test and daemon logs"
finish
INITSCRIPT

    escape_sed() {
      printf '%s' "$1" | sed 's/[&|\\]/\\&/g'
    }
    sed -i \
      -e "s|__SOURCE_COMMIT__|$(escape_sed "$SOURCE_COMMIT")|g" \
      -e "s|__ARTIFACT_SCOPE__|$(escape_sed "$ARTIFACT_SCOPE")|g" \
      -e "s|__ROOT_KEY__|$(escape_sed "$ROOT_KEY")|g" \
      "$RUN_DIR/init"
    chmod +x "$RUN_DIR/init"

    (cd "$RUN_DIR" && find . -path ./initrd.img -prune -o -print | "$CPIO" -o -H newc 2>/dev/null) > "$RUN_DIR/initrd.img"
    echo "  Initrd prepared: $(du -h "$RUN_DIR/initrd.img" | cut -f1)"

    rm -rf "$VALIDATION_DIR"
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

    extract_value() {
      local key="$1"
      grep "^$key=" "$VAL_LOG" 2>/dev/null | tail -1 | cut -d= -f2 | awk '{print $1}'
    }

    extract_between "TIDEFS_OBSERVED_ROWS_BEGIN" "TIDEFS_OBSERVED_ROWS_END" > "$VALIDATION_DIR/observed_rows.txt" || true
    extract_between "TIDEFS_DAEMON_LOG_BEGIN" "TIDEFS_DAEMON_LOG_END" > "$VALIDATION_DIR/daemon.log" || true
    extract_between "TIDEFS_DAEMON_REMOUNT_LOG_BEGIN" "TIDEFS_DAEMON_REMOUNT_LOG_END" > "$VALIDATION_DIR/daemon_remount.log" || true
    extract_between "TIDEFS_TEST_LOG_BEGIN" "TIDEFS_TEST_LOG_END" > "$VALIDATION_DIR/test.log" || true
    extract_between "TIDEFS_ROOT_LIST_BEGIN" "TIDEFS_ROOT_LIST_END" > "$VALIDATION_DIR/root_list.txt" || true
    extract_between "TIDEFS_PRE_CRASH_ATTRS_BEGIN" "TIDEFS_PRE_CRASH_ATTRS_END" > "$VALIDATION_DIR/pre_crash_attrs.txt" || true
    awk '
      { sub(/\r$/, "") }
      /^=== TideFS FUSE Inode Metadata Validation ===$/ { capture = 1 }
      capture { print }
      /^TIDEFS_FUSE_INODE_METADATA_VALIDATION_DONE$/ { capture = 0 }
    ' "$VAL_LOG" > "$VALIDATION_DIR/validation.log" || true

    PASSED="$(extract_value PASSED)"; PASSED="''${PASSED:-0}"
    REFUSED="$(extract_value REFUSED)"; REFUSED="''${REFUSED:-0}"
    FAILED="$(extract_value FAILED)"; FAILED="''${FAILED:-0}"
    BLOCKED="$(extract_value BLOCKED)"; BLOCKED="''${BLOCKED:-0}"
    DONEC="$(grep -c '^TIDEFS_FUSE_INODE_METADATA_VALIDATION_DONE$' "$VAL_LOG" 2>/dev/null || true)"
    KERNEL_VERSION="$(grep '^kernel=' "$VAL_LOG" 2>/dev/null | tail -1 | cut -d= -f2- || echo unknown)"
    [ -n "$KERNEL_VERSION" ] || KERNEL_VERSION=unknown

    cat > "$VALIDATION_DIR/fuse-inode-metadata-validation.json" <<JSON
{
  "test": "tidefs-fuse-inode-metadata-validation",
  "version": 2,
  "tier": "mounted-userspace-qemu-guest",
  "commit": "$SOURCE_COMMIT",
  "artifact_scope": "$ARTIFACT_SCOPE",
  "kernel_version": "$KERNEL_VERSION",
  "kernel_package": "linuxKernel_7_0",
  "qemu_status": $QEMU_STATUS,
  "done_marker_seen": $DONEC,
  "passed": $PASSED,
  "environment_refusals": $REFUSED,
  "product_failures": $FAILED,
  "blocked": $BLOCKED
}
JSON

    echo "=== FUSE Inode Metadata Validation Results ==="
    grep -E '^(PASS|FAIL|REFUSAL|BLOCKED):' "$VAL_LOG" 2>/dev/null || true
    echo "Validation: $PASSED passed, $FAILED failed, $REFUSED refused, $BLOCKED blocked"
    echo "Validation log: $VALIDATION_DIR/qemu-boot.log"
    echo "Validation JSON: $VALIDATION_DIR/fuse-inode-metadata-validation.json"

    if [ "$QEMU_STATUS" -eq 124 ]; then
      echo "VALIDATION: FAIL -- QEMU timed out after ''${TIMEOUT_SEC}s" >&2
      exit 1
    fi
    if [ "$DONEC" -eq 0 ]; then
      echo "VALIDATION: FAIL -- guest did not emit completion marker" >&2
      exit 1
    fi
    if [ "$FAILED" -gt 0 ]; then
      echo "VALIDATION: FAIL -- $FAILED validation row(s) failed" >&2
      exit 1
    fi
    if [ "$PASSED" -eq 0 ] && [ "$REFUSED" -gt 0 ]; then
      echo "VALIDATION: REFUSAL -- no canonical row passed and $REFUSED row(s) refused" >&2
      exit 2
    fi
    if [ "$PASSED" -eq 0 ] && [ "$BLOCKED" -gt 0 ]; then
      echo "VALIDATION: FAIL -- no canonical row passed and $BLOCKED row(s) blocked" >&2
      exit 1
    fi

    echo "VALIDATION: PASS -- all exercised operations succeeded"
    exit 0
  '';
in
fuseInodeMetadataValidationScript
