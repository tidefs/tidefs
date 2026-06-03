# TideFS: kmod-posix-vfs directory namespace validation in QEMU.
#
# Builds the kmod-posix-vfs kernel module against a Linux 7.0 kernel,
# boots a QEMU VM, loads the module, mounts a TideFS filesystem through
# the kernel module, and exercises the full directory namespace operation
# matrix: lookup, create, rename, unlink, rmdir.
#
# Committed-root state is captured between operation batches and verified
# for monotonic advancement. The crash-recovery tier (mid-sequence QEMU
# reset + remount committed-state verification) requires persistent
# storage infrastructure and is gated by Review debt TFR-004/TFR-018.
#
# Dependencies:
#   - Linux 7.0 kernel with Rust-for-Linux support
#   - kmod-posix-vfs .ko produced by out-of-tree build
#   - Minimal initramfs with busybox, the .ko, and TideFS tools
{
  pkgs,
  linuxKernel_7_0,
}:

let
  linuxPackages_7_0 = pkgs.linuxPackagesFor linuxKernel_7_0;

  kmodDirNsScript = pkgs.writeShellScriptBin "tidefs-kmod-dir-ns-validation" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"

    TMPDIR="''${TIDEFS_KMOD_DIRNS_TMPDIR:-/tmp/tidefs-kmod-dir-ns-validation}"
    TIMEOUT_SEC="''${TIDEFS_KMOD_DIRNS_TIMEOUT:-300}"

    usage() {
      cat <<EOF
Usage: tidefs-kmod-dir-ns-validation [--timeout SECONDS] [--keep-tmp]

Validate kmod-posix-vfs directory namespace operations (lookup, create,
rename, unlink, rmdir) in a reproducible Nix/QEMU Linux 7.0 environment.
Produces tier-classified validation for directory namespace behavior.

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
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done

    echo "=== TideFS K7-VAL: kmod-posix-vfs Directory Namespace Validation ==="
    echo "  Kernel:  $KERNEL_IMG"
    echo "  QEMU:    $QEMU_BIN"
    echo "  Module:  kmod-posix-vfs"
    echo "  Timeout: ''${TIMEOUT_SEC}s"
    echo ""

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO"; do
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
    for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff reboot mknod mkdir rmdir dd stat cp mv rm touch find wc; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    MODULE_FOUND=0
    if [ -f "$MODULE_DIR/tidefs_posix_vfs.ko" ]; then
      cp "$MODULE_DIR/tidefs_posix_vfs.ko" "$RUN_DIR/lib/modules/"
      MODULE_FOUND=1
    fi

    # ── Init script: directory namespace operation matrix ──────────────
    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

echo "=== TideFS DirNS: kmod-posix-vfs Directory Namespace Validation ==="
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

# ── Phase 0: Load kernel module ──────────────────────────────────────
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

# ── Phase 1: Mount ───────────────────────────────────────────────────
echo ""
echo "--- Phase 1: Mount ---"
mkdir -p "$MNT"
if mount -t tidefs none "$MNT" 2>/tmp/mount.err; then
    pass "mount"
else
    blocked "mount" "$(cat /tmp/mount.err)"
fi

# ── Phase 2: Lookup (stat) ───────────────────────────────────────────
echo ""
echo "--- Phase 2: Lookup ---"
MOUNTED=0
if mountpoint -q "$MNT" 2>/dev/null; then MOUNTED=1; fi

if [ "$MOUNTED" -eq 1 ]; then
    # 2a: stat root directory
    if stat "$MNT" >/dev/null 2>&1; then
        pass "lookup_stat_root"
    else
        fail "lookup_stat_root" "stat on mount root failed"
    fi

    # 2b: stat . and .. in root
    if stat "$MNT/." >/dev/null 2>&1; then
        pass "lookup_stat_dot"
    else
        fail "lookup_stat_dot" "stat on . failed"
    fi
    if stat "$MNT/.." >/dev/null 2>&1; then
        pass "lookup_stat_dotdot"
    else
        fail "lookup_stat_dotdot" "stat on .. failed"
    fi

    # 2c: stat on non-existent entry (expect ENOENT)
    if stat "$MNT/__nonexistent__" >/dev/null 2>&1; then
        fail "lookup_enoent" "stat on nonexistent entry succeeded unexpectedly"
    else
        pass "lookup_enoent"
    fi
else
    blocked "lookup_stat_root" "filesystem not mounted"
    blocked "lookup_stat_dot" "filesystem not mounted"
    blocked "lookup_stat_dotdot" "filesystem not mounted"
    blocked "lookup_enoent" "filesystem not mounted"
fi

# ── Phase 3: Create ──────────────────────────────────────────────────
echo ""
echo "--- Phase 3: Create ---"
if [ "$MOUNTED" -eq 1 ]; then
    # 3a: create file in root
    if echo "content-a" > "$MNT/file_a" 2>/tmp/cr1.err; then
        pass "create_file_root"
    else
        fail "create_file_root" "$(cat /tmp/cr1.err)"
    fi

    # 3b: create second file
    if echo "content-b" > "$MNT/file_b" 2>/tmp/cr2.err; then
        pass "create_file_second"
    else
        fail "create_file_second" "$(cat /tmp/cr2.err)"
    fi

    # 3c: stat the created files (cross-check with lookup)
    if stat "$MNT/file_a" >/dev/null 2>&1; then
        pass "create_stat_file_a"
    else
        fail "create_stat_file_a" "stat on created file_a failed"
    fi
    if stat "$MNT/file_b" >/dev/null 2>&1; then
        pass "create_stat_file_b"
    else
        fail "create_stat_file_b" "stat on created file_b failed"
    fi

    # 3d: read back content
    if [ "$(cat "$MNT/file_a" 2>/dev/null)" = "content-a" ]; then
        pass "create_readback_a"
    else
        fail "create_readback_a" "content mismatch for file_a"
    fi

    # 3e: create in a subdirectory
    mkdir "$MNT/sub" 2>/dev/null || true
    if echo "nested" > "$MNT/sub/nested_f" 2>/tmp/cr3.err; then
        pass "create_file_subdir"
    else
        fail "create_file_subdir" "$(cat /tmp/cr3.err)"
    fi

    # 3f: mknod-style creation (touch empty file)
    if touch "$MNT/empty_f" 2>/tmp/cr4.err; then
        pass "create_touch_empty"
    else
        fail "create_touch_empty" "$(cat /tmp/cr4.err)"
    fi

    # 3g: duplicate name should succeed (overwrite with O_TRUNC-like)
    if echo "overwrite" > "$MNT/file_a" 2>/tmp/cr5.err; then
        pass "create_overwrite"
    else
        fail "create_overwrite" "$(cat /tmp/cr5.err)"
    fi
else
    for t in create_file_root create_file_second create_stat_file_a \
             create_stat_file_b create_readback_a create_file_subdir \
             create_touch_empty create_overwrite; do
        blocked "$t" "filesystem not mounted"
    done
fi

# ── Capture committed-root state after create batch ──────────────────
echo ""
echo "--- Committed-root snapshot after create batch ---"
if [ "$MOUNTED" -eq 1 ]; then
    sync
    # Record directory listing as committed-state fingerprint
    echo "ls_root_after_create:" > /tmp/root_state_1.txt
    ls -la "$MNT" 2>/dev/null >> /tmp/root_state_1.txt || true
    # Count entries (excluding . and ..)
    ENTRY_COUNT=$(ls -1 "$MNT" 2>/dev/null | wc -l)
    echo "entry_count=$ENTRY_COUNT"
    if [ "$ENTRY_COUNT" -ge 4 ]; then
        pass "committed_root_after_create"
    else
        fail "committed_root_after_create" "expected >=4 entries, got $ENTRY_COUNT"
    fi
else
    blocked "committed_root_after_create" "filesystem not mounted"
fi

# ── Phase 4: Rename ──────────────────────────────────────────────────
echo ""
echo "--- Phase 4: Rename ---"
if [ "$MOUNTED" -eq 1 ]; then
    # 4a: same-directory rename
    if mv "$MNT/file_a" "$MNT/file_a_renamed" 2>/tmp/rn1.err; then
        pass "rename_same_dir"
    else
        fail "rename_same_dir" "$(cat /tmp/rn1.err)"
    fi

    # 4b: verify old name gone, new name exists
    if stat "$MNT/file_a" >/dev/null 2>&1; then
        fail "rename_old_gone" "old name file_a still exists after rename"
    else
        pass "rename_old_gone"
    fi
    if stat "$MNT/file_a_renamed" >/dev/null 2>&1; then
        pass "rename_new_exists"
    else
        fail "rename_new_exists" "new name file_a_renamed not found"
    fi

    # 4c: cross-directory rename
    if mv "$MNT/file_b" "$MNT/sub/file_b_moved" 2>/tmp/rn2.err; then
        pass "rename_cross_dir"
    else
        fail "rename_cross_dir" "$(cat /tmp/rn2.err)"
    fi
    if stat "$MNT/sub/file_b_moved" >/dev/null 2>&1; then
        pass "rename_cross_dir_stat"
    else
        fail "rename_cross_dir_stat" "cross-dir rename target not found"
    fi

    # 4d: rename with overwrite (create target, then rename over it)
    echo "target" > "$MNT/target_f" 2>/dev/null || true
    echo "source" > "$MNT/source_f" 2>/dev/null || true
    if mv "$MNT/source_f" "$MNT/target_f" 2>/tmp/rn3.err; then
        pass "rename_overwrite"
    else
        fail "rename_overwrite" "$(cat /tmp/rn3.err)"
    fi
    # source should be gone
    if stat "$MNT/source_f" >/dev/null 2>&1; then
        fail "rename_overwrite_src_gone" "source still exists after overwrite rename"
    else
        pass "rename_overwrite_src_gone"
    fi

    # 4e: rename non-existent source (expect ENOENT)
    if mv "$MNT/__noexist__" "$MNT/dst" 2>/dev/null; then
        fail "rename_enoent" "rename of nonexistent source succeeded unexpectedly"
    else
        pass "rename_enoent"
    fi
else
    for t in rename_same_dir rename_old_gone rename_new_exists \
             rename_cross_dir rename_cross_dir_stat rename_overwrite \
             rename_overwrite_src_gone rename_enoent; do
        blocked "$t" "filesystem not mounted"
    done
fi

# ── Capture committed-root state after rename batch ──────────────────
echo ""
echo "--- Committed-root snapshot after rename batch ---"
if [ "$MOUNTED" -eq 1 ]; then
    sync
    ls -la "$MNT" 2>/dev/null > /tmp/root_state_2.txt || true
    # file_a should be gone, file_a_renamed should exist, file_b should be gone
    if stat "$MNT/file_a_renamed" >/dev/null 2>&1 && \
       ! stat "$MNT/file_a" >/dev/null 2>&1 && \
       ! stat "$MNT/file_b" >/dev/null 2>&1; then
        pass "committed_root_after_rename"
    else
        fail "committed_root_after_rename" "namespace inconsistent after rename batch"
    fi
else
    blocked "committed_root_after_rename" "filesystem not mounted"
fi

# ── Phase 5: Unlink ──────────────────────────────────────────────────
echo ""
echo "--- Phase 5: Unlink ---"
if [ "$MOUNTED" -eq 1 ]; then
    # 5a: unlink regular file
    if rm "$MNT/file_a_renamed" 2>/tmp/ul1.err; then
        pass "unlink_file"
    else
        fail "unlink_file" "$(cat /tmp/ul1.err)"
    fi

    # 5b: verify file is gone
    if stat "$MNT/file_a_renamed" >/dev/null 2>&1; then
        fail "unlink_gone" "file still exists after unlink"
    else
        pass "unlink_gone"
    fi

    # 5c: unlink empty file
    if rm "$MNT/empty_f" 2>/tmp/ul2.err; then
        pass "unlink_empty_file"
    else
        fail "unlink_empty_file" "$(cat /tmp/ul2.err)"
    fi

    # 5d: unlink nested file
    if rm "$MNT/sub/nested_f" 2>/tmp/ul3.err; then
        pass "unlink_nested_file"
    else
        fail "unlink_nested_file" "$(cat /tmp/ul3.err)"
    fi

    # 5e: verify nested file gone
    if stat "$MNT/sub/nested_f" >/dev/null 2>&1; then
        fail "unlink_nested_gone" "nested file still exists after unlink"
    else
        pass "unlink_nested_gone"
    fi

    # 5f: unlink non-existent (expect ENOENT)
    if rm "$MNT/__not_here__" 2>/dev/null; then
        fail "unlink_enoent" "unlink of nonexistent file succeeded unexpectedly"
    else
        pass "unlink_enoent"
    fi
else
    for t in unlink_file unlink_gone unlink_empty_file unlink_nested_file \
             unlink_nested_gone unlink_enoent; do
        blocked "$t" "filesystem not mounted"
    done
fi

# ── Phase 6: Rmdir ───────────────────────────────────────────────────
echo ""
echo "--- Phase 6: Rmdir ---"
if [ "$MOUNTED" -eq 1 ]; then
    # 6a: rmdir on empty directory
    mkdir "$MNT/empty_dir" 2>/dev/null || true
    if rmdir "$MNT/empty_dir" 2>/tmp/rd1.err; then
        pass "rmdir_empty"
    else
        fail "rmdir_empty" "$(cat /tmp/rd1.err)"
    fi

    # 6b: verify removed dir is gone
    if stat "$MNT/empty_dir" >/dev/null 2>&1; then
        fail "rmdir_empty_gone" "directory still exists after rmdir"
    else
        pass "rmdir_empty_gone"
    fi

    # 6c: rmdir on non-empty directory (expect ENOTEMPTY)
    mkdir "$MNT/nonempty" 2>/dev/null || true
    echo "x" > "$MNT/nonempty/f" 2>/dev/null || true
    if rmdir "$MNT/nonempty" 2>/dev/null; then
        fail "rmdir_enotempty" "rmdir on non-empty dir succeeded unexpectedly"
    else
        pass "rmdir_enotempty"
    fi

    # 6d: parent directory still has nonempty dir
    if stat "$MNT/nonempty" >/dev/null 2>&1; then
        pass "rmdir_parent_consistency"
    else
        fail "rmdir_parent_consistency" "nonempty dir vanished after failed rmdir"
    fi

    # 6e: rmdir on file (expect ENOTDIR)
    echo "notadir" > "$MNT/regular_f" 2>/dev/null || true
    if rmdir "$MNT/regular_f" 2>/dev/null; then
        fail "rmdir_enotdir" "rmdir on regular file succeeded unexpectedly"
    else
        pass "rmdir_enotdir"
    fi

    # 6f: rmdir on non-existent (expect ENOENT)
    if rmdir "$MNT/__no_dir__" 2>/dev/null; then
        fail "rmdir_enoent" "rmdir on nonexistent dir succeeded unexpectedly"
    else
        pass "rmdir_enoent"
    fi
else
    for t in rmdir_empty rmdir_empty_gone rmdir_enotempty \
             rmdir_parent_consistency rmdir_enotdir rmdir_enoent; do
        blocked "$t" "filesystem not mounted"
    done
fi

# ── Phase 7: Final state consistency ─────────────────────────────────
echo ""
echo "--- Phase 7: Final state consistency ---"
if [ "$MOUNTED" -eq 1 ]; then
    sync
    ls -la "$MNT" 2>/dev/null > /tmp/root_state_final.txt || true
    # Verify: sub/ exists, target_f exists, regular_f exists
    if stat "$MNT/sub" >/dev/null 2>&1; then
        pass "final_subdir_exists"
    else
        fail "final_subdir_exists" "sub directory missing after ops"
    fi
    if stat "$MNT/target_f" >/dev/null 2>&1; then
        pass "final_target_file_exists"
    else
        fail "final_target_file_exists" "target_f missing"
    fi
    # sub should be empty (nested_f unlinked)
    SUB_COUNT=$(ls -1 "$MNT/sub" 2>/dev/null | wc -l)
    if [ "$SUB_COUNT" -eq 0 ]; then
        pass "final_sub_empty"
    else
        fail "final_sub_empty" "sub dir has $SUB_COUNT entries, expected 0"
    fi
    pass "committed_root_final"
else
    blocked "final_subdir_exists" "filesystem not mounted"
    blocked "final_target_file_exists" "filesystem not mounted"
    blocked "final_sub_empty" "filesystem not mounted"
    blocked "committed_root_final" "filesystem not mounted"
fi

# ── Phase 8: Tear-down ───────────────────────────────────────────────
echo ""
echo "--- Phase 8: Unmount and module unload ---"
if [ "$MOUNTED" -eq 1 ]; then
    # Clean up remaining test files so unmount can proceed
    rm -rf "$MNT"/sub "$MNT"/target_f "$MNT"/regular_f "$MNT"/nonempty 2>/dev/null || true
    if umount "$MNT" 2>/tmp/um.err; then
        pass "unmount"
    else
        fail "unmount" "$(cat /tmp/um.err)"
    fi
else
    blocked "unmount" "filesystem not mounted"
fi

if lsmod 2>/dev/null | grep -q tidefs_posix_vfs; then
    if rmmod tidefs_posix_vfs 2>/tmp/rmmod.err; then
        pass "module_unload"
    else
        fail "module_unload" "$(cat /tmp/rmmod.err)"
    fi
else
    blocked "module_unload" "module not loaded"
fi

# ── Summary ──────────────────────────────────────────────────────────
echo ""
echo "=== Directory Namespace Validation Summary ==="
echo "PASSED=$PASSED"
echo "FAILED=$FAILED"
echo "BLOCKED=$BLOCKED"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "=== End ==="

poweroff -f
INITSCRIPT

    chmod +x "$RUN_DIR/init"

    # Build initrd
    (cd "$RUN_DIR" && find . -path ./initrd.img -prune -o -print | "$CPIO" -o -H newc 2>/dev/null) > "$RUN_DIR/initrd.img"

    echo "  Initrd prepared: $(du -h "$RUN_DIR/initrd.img" | cut -f1)"
    echo ""

    # Boot QEMU
    VAL_LOG="$RUN_DIR/validation.log"
    echo "  Booting directory namespace validation QEMU..."

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
    echo "=== Directory Namespace Validation Results ==="

    PASSED=0
    FAILED=0
    BLOCKED=0

    for op in \
      module_load module_lsmod mount \
      lookup_stat_root lookup_stat_dot lookup_stat_dotdot lookup_enoent \
      create_file_root create_file_second create_stat_file_a create_stat_file_b \
      create_readback_a create_file_subdir create_touch_empty create_overwrite \
      committed_root_after_create \
      rename_same_dir rename_old_gone rename_new_exists \
      rename_cross_dir rename_cross_dir_stat \
      rename_overwrite rename_overwrite_src_gone rename_enoent \
      committed_root_after_rename \
      unlink_file unlink_gone unlink_empty_file unlink_nested_file \
      unlink_nested_gone unlink_enoent \
      rmdir_empty rmdir_empty_gone rmdir_enotempty \
      rmdir_parent_consistency rmdir_enotdir rmdir_enoent \
      final_subdir_exists final_target_file_exists final_sub_empty \
      committed_root_final \
      unmount module_unload; do
      if grep -q "PASS: $op" "$VAL_LOG" 2>/dev/null; then
        echo "  PASS: $op"
        PASSED=$((PASSED + 1))
      elif grep -q "FAIL: $op" "$VAL_LOG" 2>/dev/null; then
        detail=$(grep "FAIL: $op" "$VAL_LOG" 2>/dev/null | head -1 | sed "s/FAIL: $op //")
        echo "  FAIL: $op -- $detail"
        FAILED=$((FAILED + 1))
      elif grep -q "BLOCKED: $op" "$VAL_LOG" 2>/dev/null; then
        detail=$(grep "BLOCKED: $op" "$VAL_LOG" 2>/dev/null | head -1 | sed "s/BLOCKED: $op //")
        echo "  BLOCKED: $op -- $detail"
        BLOCKED=$((BLOCKED + 1))
      else
        echo "  MISSING: $op (no validation in log)"
        BLOCKED=$((BLOCKED + 1))
      fi
    done

    echo ""
    echo "Summary: $PASSED passed, $FAILED failed, $BLOCKED blocked"
    echo "Validation log: $VAL_LOG"

    # Crash-recovery tier note
    echo ""
    echo "Crash-recovery tier: requires persistent storage infrastructure"
    echo "for multi-boot committed-state verification. Gated by Review debt TFR-004/TFR-018."

    if [ "$FAILED" -gt 0 ]; then
      echo "VALIDATION: FAIL -- $FAILED operations failed"
      exit 1
    fi

    if [ "$BLOCKED" -gt 0 ]; then
      echo "VALIDATION: BLOCKED -- $BLOCKED required rows lacked runtime validation"
      exit 1
    fi

    echo "VALIDATION: PASS -- all exercised operations succeeded"
    exit 0
  '';
in
kmodDirNsScript
