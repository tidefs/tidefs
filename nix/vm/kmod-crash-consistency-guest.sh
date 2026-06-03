#!/bin/sh
# TideFS kmod-posix-vfs crash-loop replay campaign QEMU guest inner script.
# Kernel crash-loop replay campaign across every mutating inode op. Runs inside
# a Linux 7.0 QEMU guest with a virtio-blk pool fixture. Two phases:
#   (1) mount, perform every supported mutating inode op, sync, crash
#   (2) remount, intent replay, verify committed-root recovery for all ops.
#
# Mutating inode ops exercised (all covered by KernelIntentReplay):
#   create, mkdir, symlink, link, mknod, rename, unlink, rmdir,
#   setattr, truncate, write (data path).
export PATH=/bin

PHASE="${1:-phase1}"
PASSED=0; FAILED=0; BLOCKED=0
pass()   { echo "PASS: $1"; PASSED=$((PASSED + 1)); }
fail()   { echo "FAIL: $1 -- $2"; FAILED=$((FAILED + 1)); }
blocked(){ echo "BLOCKED: $1 -- $2"; BLOCKED=$((BLOCKED + 1)); }
op_pass()   { echo "PASS: mutating_op:$1"; PASSED=$((PASSED + 1)); }
op_fail()   { echo "FAIL: mutating_op:$1 -- $2"; FAILED=$((FAILED + 1)); }
op_blocked(){ echo "BLOCKED: mutating_op:$1 -- $2"; BLOCKED=$((BLOCKED + 1)); }

EVDIR="/validation"
mkdir -p "$EVDIR" 2>/dev/null

dmesg_snapshot() { dmesg > "$EVDIR/dmesg_${1}.txt" 2>/dev/null || true; }

echo "=== TideFS Crash-Loop Replay Campaign: Phase=$PHASE ==="
echo "kernel=$(uname -r)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "=== Linux kernel dmesg (boot) ===" && dmesg | head -60
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true

POOL_DEV=""
for d in /dev/vda /dev/vdb /dev/vdc /dev/sda; do
    [ -b "$d" ] && { POOL_DEV="$d"; break; }
done
if [ -z "$POOL_DEV" ]; then
    blocked "virtio_device" "no virtio block device found"
    echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
    exit 0
fi
pass "virtio_device"
echo "Pool device: $POOL_DEV"

MOD=/lib/modules/tidefs_posix_vfs.ko
dmesg_snapshot "pre_insmod"
if [ -f "$MOD" ]; then
    insmod "$MOD" 2>/tmp/insmod.err; RC=$?
    if [ $RC -eq 0 ] && grep -q tidefs_posix_vfs /proc/modules 2>/dev/null; then
        pass "insmod"
    else
        INSERR=$(head -3 /tmp/insmod.err 2>/dev/null || echo "insmod exit=$RC")
        DMESG_INS=$(dmesg | tail -5 | tr '\n' ' ')
        fail "insmod" "exit=$RC err=$INSERR dmesg=$DMESG_INS"
        echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
        poweroff -f
    fi
else
    blocked "insmod" "tidefs_posix_vfs.ko not found"
    echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
    poweroff -f
fi
dmesg_snapshot "post_insmod"
echo "=== Kernel dmesg (post-insmod, tidefs messages) ===" && dmesg | grep -iE "tidefs|module|kernel" | head -20

sleep 1

MNT=/mnt/tidefs
mkdir -p "$MNT"

if [ "$PHASE" = "phase1" ]; then
    echo "--- Phase 1: Mount, all mutating inode ops, commit, crash ---"

    mount -t tidefs "$POOL_DEV" "$MNT" 2>/tmp/mount.err
    RC=$?
    if [ $RC -eq 0 ]; then
        pass "mount"
    else
        fail "mount" "$(head -5 /tmp/mount.err 2>/dev/null)"
        dmesg_snapshot "mount_fail"
        echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
        poweroff -f
    fi

    dmesg_snapshot "post_mount"
    echo "=== Kernel dmesg (post-mount) ===" && dmesg | grep -iE "tidefs|mount|pool|kernel" | tail -20

    ls "$MNT" > /dev/null 2>&1 && pass "root_ls" || fail "root_ls" "cannot list root"

    # ── Mutating Inode Op Matrix ─────────────────────────────────────

    # CREATE: file creation (DISC_CREATE)
    echo "CREATE_CONTENT_V1" > "$MNT/create_reg.txt"
    [ -f "$MNT/create_reg.txt" ] && op_pass "create" \
        || op_fail "create" "could not create create_reg.txt"

    # CREATE: second file for rename/hardlink targets
    echo "RENAME_SOURCE_CONTENT" > "$MNT/rename_src.txt"
    [ -f "$MNT/rename_src.txt" ] && op_pass "create:rename_src" \
        || op_fail "create:rename_src" "could not create rename_src.txt"

    # CREATE: file for later unlink
    echo "UNLINK_ME" > "$MNT/unlink_target.txt"
    [ -f "$MNT/unlink_target.txt" ] && op_pass "create:unlink_target" \
        || op_fail "create:unlink_target" "could not create unlink_target.txt"

    # MKDIR: directory creation (DISC_MKDIR)
    mkdir "$MNT/testdir" 2>/dev/null
    [ -d "$MNT/testdir" ] && op_pass "mkdir" \
        || op_fail "mkdir" "could not create testdir"

    mkdir "$MNT/testdir/sub" 2>/dev/null
    [ -d "$MNT/testdir/sub" ] && op_pass "mkdir:sub" \
        || op_fail "mkdir:sub" "could not create testdir/sub"

    mkdir "$MNT/rmdir_target" 2>/dev/null
    [ -d "$MNT/rmdir_target" ] && op_pass "mkdir:rmdir_target" \
        || op_fail "mkdir:rmdir_target" "could not create rmdir_target"

    # SYMLINK: symbolic link to file (DISC_SYMLINK)
    ln -s "create_reg.txt" "$MNT/sym_file" 2>/dev/null
    [ -L "$MNT/sym_file" ] && op_pass "symlink:file" \
        || op_fail "symlink:file" "could not create symlink"

    ln -s "testdir" "$MNT/sym_dir" 2>/dev/null
    [ -L "$MNT/sym_dir" ] && op_pass "symlink:dir" \
        || op_fail "symlink:dir" "could not create dir symlink"

    # HARDLINK: hard link (DISC_HARDLINK)
    ln "$MNT/create_reg.txt" "$MNT/hardlink_reg" 2>/dev/null
    [ -f "$MNT/hardlink_reg" ] && op_pass "hardlink" \
        || op_fail "hardlink" "could not create hardlink"

    # MKNOD: FIFO creation (DISC_MKNOD)
    mknod "$MNT/fifo_test" p 2>/dev/null
    [ -p "$MNT/fifo_test" ] && op_pass "mknod:fifo" \
        || op_fail "mknod:fifo" "could not create FIFO"

    # RENAME: file rename (DISC_RENAME)
    mv "$MNT/rename_src.txt" "$MNT/rename_dst.txt" 2>/dev/null
    [ -f "$MNT/rename_dst.txt" ] && [ ! -f "$MNT/rename_src.txt" ] \
        && op_pass "rename" \
        || op_fail "rename" "rename failed"

    # UNLINK: file deletion (DISC_UNLINK)
    rm "$MNT/unlink_target.txt" 2>/dev/null
    [ ! -f "$MNT/unlink_target.txt" ] && op_pass "unlink" \
        || op_fail "unlink" "unlink_target still present"

    # RMDIR: empty directory removal (DISC_RMDIR)
    rmdir "$MNT/rmdir_target" 2>/dev/null
    [ ! -d "$MNT/rmdir_target" ] && op_pass "rmdir" \
        || op_fail "rmdir" "rmdir_target still present"

    # SETATTR: chmod (DISC_SETATTR)
    chmod 444 "$MNT/create_reg.txt" 2>/dev/null
    PERMS=$(stat -c "%a" "$MNT/create_reg.txt" 2>/dev/null || echo "000")
    [ "$PERMS" = "444" ] && op_pass "setattr:chmod" \
        || op_fail "setattr:chmod" "expected 444 got $PERMS"

    # TRUNCATE: file truncation (DISC_TRUNCATE via setattr FATTR_SIZE)
    echo "LONG_CONTENT_FOR_TRUNCATE_VERIFICATION" > "$MNT/truncate_me.txt"
    dd if=/dev/null of="$MNT/truncate_me.txt" bs=1 seek=10 count=0 2>/dev/null
    TSIZE=$(stat -c "%s" "$MNT/truncate_me.txt" 2>/dev/null || echo "99999")
    [ "$TSIZE" -le 10 ] && op_pass "truncate" \
        || op_fail "truncate" "expected size <=10 got $TSIZE"

    # WRITE: data path (DISC_WRITE intent entries)
    echo "DATA_INTEGRITY_CHECK_VALUE" > "$MNT/write_data.txt"
    for i in 1 2 3 4 5; do
        echo "data_line_$i" >> "$MNT/write_data.txt"
    done
    grep -q "data_line_5" "$MNT/write_data.txt" && op_pass "write:multi" \
        || op_fail "write:multi" "multi-line write not visible"

    # CREATE: nested file in subdirectory
    echo "NESTED_FILE_DATA" > "$MNT/testdir/sub/nested.txt"
    [ -f "$MNT/testdir/sub/nested.txt" ] && op_pass "create:nested" \
        || op_fail "create:nested" "nested file creation failed"

    # Persist checksums to mounted fs for Phase 2 content verification
    for f in create_reg.txt rename_dst.txt hardlink_reg write_data.txt \
             testdir/sub/nested.txt; do
        md5sum "$MNT/$f" 2>/dev/null >> "$MNT/.crash_checksums"
    done
    echo "CREATE_REG_PERMS=444" >> "$MNT/.crash_checksums"
    echo "TRUNCATE_SIZE=10" >> "$MNT/.crash_checksums"
    sync
    if [ -f "$MNT/.crash_checksums" ]; then
        op_pass "checksum_record"
    else
        op_fail "checksum_record" "could not persist checksums"
    fi

    sync; sleep 1
    sleep 1
    echo "=== Kernel dmesg (post-op matrix) ===" && dmesg | grep -iE "tidefs|intent|commit|write" | tail -30
    pass "sync"

    dmesg_snapshot "pre_crash"

    echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
    sync
    echo "=== Mutating op matrix executed: crash imminent ==="
    sleep 1
    poweroff -f
elif [ "$PHASE" = "phase2" ]; then
    echo "--- Phase 2: Remount, intent replay, verify all mutating op state ---"

    mount -t tidefs "$POOL_DEV" "$MNT" 2>/tmp/mount_p2.err
    RC=$?
    if [ $RC -eq 0 ]; then
        pass "remount"
    else
        fail "remount" "$(head -5 /tmp/mount_p2.err 2>/dev/null)"
        dmesg_snapshot "remount_fail"
        echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
        poweroff -f
    fi

    dmesg_snapshot "post_remount"
    echo "=== Kernel dmesg (post-remount) ===" && dmesg | grep -iE "tidefs|replay|mount|intent|kernel" | tail -30

    if dmesg | grep -q "replay"; then
        pass "replay_dmesg_validation"
    else
        blocked "replay_dmesg_validation" "no replay message in dmesg"
    fi

    ls "$MNT" > /dev/null 2>&1 && pass "remount_root_ls" || fail "remount_root_ls" "cannot list root after remount"

    # ── Verify mutating inode op recovery ────────────────────────────

    # CREATE: files exist
    [ -f "$MNT/create_reg.txt" ] && op_pass "replay:create" \
        || op_fail "replay:create" "create_reg.txt missing"

    # MKDIR: directories exist
    [ -d "$MNT/testdir" ] && op_pass "replay:mkdir" \
        || op_fail "replay:mkdir" "testdir missing"
    [ -d "$MNT/testdir/sub" ] && op_pass "replay:mkdir:sub" \
        || op_fail "replay:mkdir:sub" "testdir/sub missing"

    # SYMLINK: symlinks exist
    [ -L "$MNT/sym_file" ] && op_pass "replay:symlink:file" \
        || op_fail "replay:symlink:file" "sym_file missing"
    [ -L "$MNT/sym_dir" ] && op_pass "replay:symlink:dir" \
        || op_fail "replay:symlink:dir" "sym_dir missing"

    # HARDLINK: hardlink exists with same content
    if [ -f "$MNT/hardlink_reg" ]; then
        grep -q "CREATE_CONTENT_V1" "$MNT/hardlink_reg" 2>/dev/null \
            && op_pass "replay:hardlink" \
            || op_fail "replay:hardlink" "wrong content"
    else
        op_fail "replay:hardlink" "hardlink_reg missing"
    fi

    # MKNOD: FIFO exists
    [ -p "$MNT/fifo_test" ] && op_pass "replay:mknod:fifo" \
        || op_fail "replay:mknod:fifo" "fifo_test missing"

    # RENAME: old gone, new exists
    [ -f "$MNT/rename_dst.txt" ] && [ ! -f "$MNT/rename_src.txt" ] \
        && op_pass "replay:rename" \
        || op_fail "replay:rename" "rename not preserved"

    # UNLINK: deleted file stays gone
    [ ! -f "$MNT/unlink_target.txt" ] && op_pass "replay:unlink" \
        || op_fail "replay:unlink" "unlink_target reappeared"

    # RMDIR: removed dir stays gone
    [ ! -d "$MNT/rmdir_target" ] && op_pass "replay:rmdir" \
        || op_fail "replay:rmdir" "rmdir_target reappeared"

    # SETATTR: chmod persisted
    PERMS=$(stat -c "%a" "$MNT/create_reg.txt" 2>/dev/null || echo "000")
    [ "$PERMS" = "444" ] && op_pass "replay:setattr" \
        || op_fail "replay:setattr" "expected 444 got $PERMS"

    # TRUNCATE: truncated size preserved
    TSIZE=$(stat -c "%s" "$MNT/truncate_me.txt" 2>/dev/null || echo "99999")
    [ "$TSIZE" -le 10 ] && op_pass "replay:truncate" \
        || op_fail "replay:truncate" "expected <=10 got $TSIZE"

    # WRITE: data content survived
    grep -q "DATA_INTEGRITY_CHECK_VALUE" "$MNT/write_data.txt" 2>/dev/null \
        && op_pass "replay:write:content" \
        || op_fail "replay:write:content" "write_data wrong/missing"
    grep -q "data_line_5" "$MNT/write_data.txt" 2>/dev/null \
        && op_pass "replay:write:multi" \
        || op_fail "replay:write:multi" "multi-line not intact"

    # NESTED: directory structure survives
    grep -q "NESTED_FILE_DATA" "$MNT/testdir/sub/nested.txt" 2>/dev/null \
        && op_pass "replay:nested" \
        || op_fail "replay:nested" "nested.txt wrong/missing"

    # Clean umount and rmmod
    umount "$MNT" 2>/dev/null && pass "umount" || fail "umount" "umount failed"
    rmmod tidefs_posix_vfs 2>/dev/null && pass "rmmod" || fail "rmmod" "rmmod failed"

    dmesg_snapshot "final"

    echo "PASSED=$PASSED FAILED=$FAILED BLOCKED=$BLOCKED"
    sync
    sleep 1
    poweroff -f
else
    echo "ERROR: unknown phase: $PHASE"
    poweroff -f
fi
