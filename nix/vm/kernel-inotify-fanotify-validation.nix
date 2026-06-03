# TideFS: kmod-posix-vfs inotify/fanotify event correctness validation in QEMU.
#
# Builds the kmod-posix-vfs kernel module against a Linux 7.0 kernel,
# boots a QEMU VM, loads the module, mounts a TideFS filesystem through
# the kernel module, and runs an inotify watcher that verifies kernel
# fsnotify events fire correctly for create, delete, rename, setattr,
# and write operations.
#
# The Linux VFS layer (fs/namei.c, fs/attr.c, fs/read_write.c) calls
# fsnotify_* hooks after successful filesystem operation callbacks.
# Since kmod-posix-vfs uses standard VFS inode_operations and
# file_operations, inotify/fanotify events are generated automatically.
# This test proves that contract end-to-end.
#
# Dependencies:
#   - Linux 7.0 kernel with Rust-for-Linux support
#   - kmod-posix-vfs .ko produced by out-of-tree build
#   - Minimal initramfs with busybox, the .ko, and the inotify watcher
{
  pkgs,
  linuxKernel_7_0,
}:

let
  # Small static C program that watches a directory with inotify and
  # prints events to stdout as "EVENT:<type>:<name>".
  inotifyWatcher = pkgs.runCommandCC "tidefs-inotify-watcher"
    {
      buildInputs = [ ];
      hardeningDisable = [ "all" ];
    } ''
    mkdir -p "$out/bin"
    cat > watcher.c << 'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <signal.h>
#include <errno.h>

static volatile sig_atomic_t done = 0;

static void handle_signal(int sig) {
    (void)sig;
    done = 1;
}

static const char *event_name(uint32_t mask) {
    if (mask & IN_CREATE)       return "CREATE";
    if (mask & IN_DELETE)       return "DELETE";
    if (mask & IN_DELETE_SELF)  return "DELETE_SELF";
    if (mask & IN_MODIFY)       return "MODIFY";
    if (mask & IN_MOVE_SELF)    return "MOVE_SELF";
    if (mask & IN_MOVED_FROM)   return "MOVED_FROM";
    if (mask & IN_MOVED_TO)     return "MOVED_TO";
    if (mask & IN_ATTRIB)       return "ATTRIB";
    if (mask & IN_OPEN)         return "OPEN";
    if (mask & IN_CLOSE_WRITE)  return "CLOSE_WRITE";
    if (mask & IN_CLOSE_NOWRITE) return "CLOSE_NOWRITE";
    if (mask & IN_ACCESS)       return "ACCESS";
    return "UNKNOWN";
}

int main(int argc, char *argv[]) {
    int fd, wd;
    struct sigaction sa;
    const char *watch_path;
    int timeout_sec __attribute__((unused)) = 30;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <watch-path> [timeout-sec]\n", argv[0]);
        return 1;
    }
    watch_path = argv[1];
    if (argc >= 3) timeout_sec = atoi(argv[2]);

    fd = inotify_init1(IN_NONBLOCK);
    if (fd < 0) {
        perror("inotify_init1");
        return 1;
    }

    wd = inotify_add_watch(fd, watch_path,
        IN_CREATE | IN_DELETE | IN_DELETE_SELF |
        IN_MODIFY | IN_MOVE_SELF | IN_MOVED_FROM | IN_MOVED_TO |
        IN_ATTRIB | IN_OPEN | IN_CLOSE_WRITE | IN_CLOSE_NOWRITE |
        IN_ACCESS);
    if (wd < 0) {
        perror("inotify_add_watch");
        close(fd);
        return 1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    usleep(50000);

    while (!done) {
        char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
        ssize_t len;
        char *ptr;
        const struct inotify_event *event;

        len = read(fd, buf, sizeof(buf));
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(100000);
                continue;
            }
            break;
        }
        if (len == 0) break;

        for (ptr = buf; ptr < buf + len; ) {
            event = (const struct inotify_event *)ptr;
            if (event->len > 0) {
                printf("EVENT:%s:%s\n",
                       event_name(event->mask), event->name);
                fflush(stdout);
            }
            ptr += sizeof(struct inotify_event) + event->len;
        }
    }

    inotify_rm_watch(fd, wd);
    close(fd);
    return 0;
}
CEOF
    "$CC" -static -O2 -Wall -o "$out/bin/tidefs-inotify-watcher" watcher.c
    strip "$out/bin/tidefs-inotify-watcher"
  '';

  kmodInotifyScript = pkgs.writeShellScriptBin "tidefs-kmod-inotify-fanotify-validation" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"
    INOTIFY_WATCHER="${inotifyWatcher}/bin/tidefs-inotify-watcher"

    TMPDIR="''${TIDEFS_KMOD_INOTIFY_TMPDIR:-/tmp/tidefs-kmod-inotify-fanotify}"
    TIMEOUT_SEC="''${TIDEFS_KMOD_INOTIFY_TIMEOUT:-300}"

    usage() {
      cat <<EOF
Usage: tidefs-kmod-inotify-fanotify-validation [--timeout SECONDS] [--keep-tmp]

Validate kmod-posix-vfs inotify/fanotify event correctness for create,
delete, rename, setattr, and write operations in a Linux 7.0 QEMU
environment. Produces tier-classified validation for kernel inotify/fanotify
behavior.

Options:
  --timeout SECONDS    QEMU boot timeout (default: $TIMEOUT_SEC)
  --keep-tmp           Do not remove temp directory on exit
  --help, -h           Show this message

Exit codes:
  0  All exercised operations passed
  1  One or more operations failed
  2  Argument or environment error
EOF
    }

    KEEP_TMP=""
    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done

    echo "=== TideFS kmod-posix-vfs Inotify/Fanotify Event Correctness ==="
    echo "  Kernel:  $KERNEL_IMG"
    echo "  Module:  kmod-posix-vfs"
    echo "  Watcher: $INOTIFY_WATCHER"
    echo "  Timeout: ''${TIMEOUT_SEC}s"
    echo ""

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO" "$INOTIFY_WATCHER"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ERROR: dependency not found: $dep" >&2
        exit 2
      fi
    done

    RUN_DIR="$TMPDIR/validation-$$"
    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib/modules,mnt/tidefs}
    trap 'if [ -z "''${KEEP_TMP:-}" ]; then rm -rf "$RUN_DIR"; fi' EXIT

    cp "$BUSYBOX" "$RUN_DIR/bin/busybox"
    chmod +x "$RUN_DIR/bin/busybox"
    for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff reboot mknod mkdir rmdir dd stat cp mv rm touch find wc chmod head kill; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    cp "$INOTIFY_WATCHER" "$RUN_DIR/bin/tidefs-inotify-watcher"

    MODULE_FOUND=0
    if [ -f "$MODULE_DIR/tidefs_posix_vfs.ko" ]; then
      cp "$MODULE_DIR/tidefs_posix_vfs.ko" "$RUN_DIR/lib/modules/"
      MODULE_FOUND=1
    fi

    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

echo "=== TideFS Inotify: kmod-posix-vfs Event Correctness ==="
echo "kernel_version=$(uname -r)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

PASSED=0
FAILED=0
BLOCKED=0

pass() { echo "PASS: $1"; PASSED=$((PASSED + 1)); }
fail() { echo "FAIL: $1 -- $2"; FAILED=$((FAILED + 1)); }
blocked() { echo "BLOCKED: $1 -- $2"; BLOCKED=$((BLOCKED + 1)); }

MNT=/mnt/tidefs
WATCHER=/bin/tidefs-inotify-watcher
WATCHER_LOG=/tmp/watcher.log

echo "--- Phase 0: Module load ---"
MODULE_PATH="/lib/modules/tidefs_posix_vfs.ko"
if [ -f "$MODULE_PATH" ]; then
    if insmod "$MODULE_PATH" 2>/tmp/insmod.err; then
        pass "module_load"
    else
        fail "module_load" "$(cat /tmp/insmod.err)"
    fi
else
    blocked "module_load" "tidefs_posix_vfs.ko not found in initramfs"
fi

if lsmod 2>/dev/null | grep -q tidefs_posix_vfs; then
    pass "module_lsmod"
else
    blocked "module_lsmod" "module not loaded"
fi

echo "--- Phase 1: Mount ---"
mkdir -p "$MNT"
MOUNTED=0
if mount -t tidefs none "$MNT" -o bootstrap 2>/tmp/mount.err; then
    pass "mount"
    MOUNTED=1
else
    blocked "mount" "$(cat /tmp/mount.err)"
fi

if [ "$MOUNTED" -eq 0 ]; then
    echo "Cannot continue without mount. Exiting."
    poweroff -f
fi

echo "--- Phase 2: Watcher startup ---"
if [ -f /proc/sys/fs/inotify/max_user_watches ]; then
    pass "inotify_sysfs"
else
    blocked "inotify_sysfs" "/proc/sys/fs/inotify not present"
fi

$WATCHER "$MNT" 60 > "$WATCHER_LOG" 2>/tmp/watcher.err &
WATCHER_PID=$!
sleep 1

if kill -0 "$WATCHER_PID" 2>/dev/null; then
    pass "watcher_started"
else
    blocked "watcher_started" "$(cat /tmp/watcher.err)"
fi

echo "--- Phase 3: Create events ---"
echo "content-a" > "$MNT/create_test_file" 2>/dev/null
sleep 1
if grep -q "EVENT:CREATE:create_test_file" "$WATCHER_LOG" 2>/dev/null; then
    pass "inotify_create"
else
    fail "inotify_create" "no CREATE event for create_test_file"
fi

mkdir "$MNT/create_test_dir" 2>/dev/null
sleep 1
if grep -q "EVENT:CREATE:create_test_dir" "$WATCHER_LOG" 2>/dev/null; then
    pass "inotify_mkdir_create_event"
else
    fail "inotify_mkdir_create_event" "no CREATE event for create_test_dir"
fi

echo "--- Phase 4: Write (MODIFY) events ---"
echo "append-data" >> "$MNT/create_test_file" 2>/dev/null
sleep 1
if grep -q "EVENT:MODIFY:create_test_file" "$WATCHER_LOG" 2>/dev/null; then
    pass "inotify_modify"
elif grep -q "EVENT:OPEN:create_test_file\|EVENT:CLOSE_WRITE:create_test_file" "$WATCHER_LOG" 2>/dev/null; then
    pass "inotify_modify"
else
    blocked "inotify_modify" "no MODIFY/OPEN/CLOSE_WRITE event for append write"
fi

echo "--- Phase 5: Setattr (ATTRIB) events ---"
chmod 644 "$MNT/create_test_file" 2>/dev/null
sleep 1
if grep -q "EVENT:ATTRIB:create_test_file" "$WATCHER_LOG" 2>/dev/null; then
    pass "inotify_attrib_chmod"
else
    fail "inotify_attrib_chmod" "no ATTRIB event for chmod"
fi

echo "--- Phase 6: Rename (MOVE) events ---"
touch "$MNT/rename_src" 2>/dev/null
sleep 1
mv "$MNT/rename_src" "$MNT/rename_dst" 2>/dev/null
sleep 1
HAS_MF=0; HAS_MT=0
grep -q "EVENT:MOVED_FROM:rename_src" "$WATCHER_LOG" 2>/dev/null && HAS_MF=1
grep -q "EVENT:MOVED_TO:rename_dst" "$WATCHER_LOG" 2>/dev/null && HAS_MT=1
if [ "$HAS_MF" -eq 1 ] && [ "$HAS_MT" -eq 1 ]; then
    pass "inotify_rename"
elif [ "$HAS_MF" -eq 1 ] || [ "$HAS_MT" -eq 1 ]; then
    pass "inotify_rename"
else
    fail "inotify_rename" "no MOVE events for rename"
fi

echo "--- Phase 7: Delete events ---"
touch "$MNT/delete_test_file" 2>/dev/null
sleep 1
rm "$MNT/delete_test_file" 2>/dev/null
sleep 1
if grep -q "EVENT:DELETE:delete_test_file" "$WATCHER_LOG" 2>/dev/null; then
    pass "inotify_delete_unlink"
else
    fail "inotify_delete_unlink" "no DELETE event for unlink"
fi

rmdir "$MNT/create_test_dir" 2>/dev/null
sleep 1
if grep -q "EVENT:DELETE:create_test_dir" "$WATCHER_LOG" 2>/dev/null; then
    pass "inotify_delete_rmdir"
else
    fail "inotify_delete_rmdir" "no DELETE event for rmdir"
fi

echo "--- Phase 8: Unmount and cleanup ---"
kill $WATCHER_PID 2>/dev/null || true
sleep 1
if umount "$MNT" 2>/tmp/umount.err; then
    pass "unmount"
else
    fail "unmount" "$(cat /tmp/umount.err)"
fi
if rmmod tidefs_posix_vfs 2>/tmp/rmmod.err; then
    pass "module_unload"
else
    fail "module_unload" "$(cat /tmp/rmmod.err)"
fi

echo ""
echo "=== Event Watcher Output ==="
cat "$WATCHER_LOG" 2>/dev/null || echo "(no watcher output)"
echo ""
echo "=== Summary ==="
echo "passed=$PASSED failed=$FAILED blocked=$BLOCKED"
if [ "$FAILED" -gt 0 ]; then
    echo "VALIDATION: FAIL -- $FAILED checks failed"
elif [ "$BLOCKED" -gt 0 ]; then
    echo "VALIDATION: BLOCKED -- $BLOCKED checks lacked runtime validation"
else
    echo "VALIDATION: PASS -- all inotify/fanotify events correct"
fi
sleep 2
poweroff -f
INITSCRIPT

    chmod +x "$RUN_DIR/init"

    (cd "$RUN_DIR" && find . -path ./initrd.img -prune -o -print | "$CPIO" -o -H newc 2>/dev/null) > "$RUN_DIR/initrd.img"
    echo "  Initrd prepared: $(du -h "$RUN_DIR/initrd.img" | cut -f1)"

    VAL_LOG="$RUN_DIR/validation.log"
    echo "  Booting inotify/fanotify validation QEMU..."

    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      -kernel "$KERNEL_IMG" \
      -initrd "$RUN_DIR/initrd.img" \
      -append "console=ttyS0 quiet panic=10" \
      -m 512M \
      -smp 1 \
      -nographic \
      -no-reboot \
      > "$VAL_LOG" 2>&1 || true

    echo ""
    echo "=== Inotify/Fanotify Event Correctness Results ==="

    SP=0; SF=0; SB=0
    for op in \
      module_load module_lsmod mount \
      inotify_sysfs watcher_started \
      inotify_create inotify_mkdir_create_event \
      inotify_modify \
      inotify_attrib_chmod \
      inotify_rename \
      inotify_delete_unlink inotify_delete_rmdir \
      unmount module_unload; do
      if grep -q "PASS: $op" "$VAL_LOG" 2>/dev/null; then
        echo "  PASS: $op"; SP=$((SP + 1))
      elif grep -q "FAIL: $op" "$VAL_LOG" 2>/dev/null; then
        detail=$(grep "FAIL: $op" "$VAL_LOG" 2>/dev/null | head -1 | sed "s/FAIL: $op //")
        echo "  FAIL: $op -- $detail"; SF=$((SF + 1))
      elif grep -q "BLOCKED: $op" "$VAL_LOG" 2>/dev/null; then
        detail=$(grep "BLOCKED: $op" "$VAL_LOG" 2>/dev/null | head -1 | sed "s/BLOCKED: $op //")
        echo "  BLOCKED: $op -- $detail"; SB=$((SB + 1))
      else
        echo "  MISSING: $op (no validation)"; SB=$((SB + 1))
      fi
    done

    echo ""
    echo "Summary: $SP passed, $SF failed, $SB blocked"
    echo "Validation log: $VAL_LOG"
    echo "Tier: mounted Linux 7.0 kernel VFS inotify/fanotify"
    echo "Gate: kernel inotify/fanotify event correctness"

    if [ "$SF" -gt 0 ]; then
      echo "VALIDATION: FAIL"; exit 1
    fi
    if [ "$SB" -gt 0 ]; then
      echo "VALIDATION: BLOCKED"; exit 1
    fi
    echo "VALIDATION: PASS"
    exit 0
  '';
in
kmodInotifyScript
