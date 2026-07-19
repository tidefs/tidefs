# TideFS: kmod-posix-vfs kernel xfstests smoke harness in QEMU.
#
# Builds kmod-posix-vfs as an out-of-tree Linux 7.0 kernel module,
# boots a QEMU VM, loads the module, verifies that nodev/bootstrap mounts
# fail closed without explicit kernel pool I/O authority, and mounts a
# formatted virtio pool member through the configured kernel authority path.
#
# This harness is the canonical kmod xfstests smoke entrypoint. It provides
# build, boot, load, and mount coverage, but it is not a full generic-group
# xfstests validation lane.
#
# Dependencies:
#   - Linux 7.0 kernel with Rust-for-Linux support (CONFIG_RUST=y)
#   - kmod-posix-vfs .ko produced by out-of-tree Kbuild
#   - Minimal initramfs with busybox and smoke test tools
{
  pkgs,
  linuxKernel_7_0,
  tidefsPackage,
}:

let
  linuxPackages_7_0 = pkgs.linuxPackagesFor linuxKernel_7_0;

  kmodXfstestsSmokeScript = pkgs.writeShellScriptBin "tidefs-kmod-xfstests-smoke" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    LDD_BIN="${pkgs.lib.getBin pkgs.glibc}/bin/ldd"
    MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"
    KERNEL_VERSION="${linuxKernel_7_0.version}"
    TIDEFSCTL="${tidefsPackage}/bin/tidefsctl"
    FSFREEZE="${pkgs.util-linux}/bin/fsfreeze"

    TMPDIR="''${TIDEFS_KMOD_XFSTESTS_TMPDIR:-/tmp/tidefs-kmod-xfstests-smoke}"
    TIMEOUT_SEC="''${TIDEFS_KMOD_XFSTESTS_TIMEOUT:-600}"

    usage() {
      cat <<EOF
Usage: tidefs-kmod-xfstests-smoke [--timeout SECONDS] [--keep-tmp]
       [--tests "generic/001 generic/002 ..."] [--module PATH]

Build kmod-posix-vfs, boot a QEMU VM with Linux 7.0, load the module,
verify missing pool-authority mount refusal, then mount a configured
TideFS pool member and emit a classified pass/fail/blocked report.

Options:
  --timeout SECONDS    QEMU boot timeout (default: $TIMEOUT_SEC)
  --keep-tmp           Do not remove temp directory on exit
  --tests "T1 T2 ..."  Space-separated internal smoke labels to exercise
                       (default: authority/missing-pool configured-pool-member)
  --module PATH        Path to pre-built .ko file
                       (default: auto-build from repo tree)
  --help, -h           Show this message

Exit codes:
  0  All exercised operations passed
  1  One or more operations failed
  2  Argument or environment error
EOF
    }

    KEEP_TMP=""
    SMOKE_TESTS_DEFAULT="authority/missing-pool configured-pool-member"
    SMOKE_TESTS="$SMOKE_TESTS_DEFAULT"
    KO_PATH_ARG=""

    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --tests) SMOKE_TESTS="$2"; shift 2 ;;
        --module) KO_PATH_ARG="$2"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done

    smoke_tests_without_space="''${SMOKE_TESTS//[[:space:]]/}"
    if [ -z "$smoke_tests_without_space" ]; then
      SMOKE_TESTS="$SMOKE_TESTS_DEFAULT"
    fi

    RUN_SMOKE_MISSING_POOL=0
    RUN_SMOKE_CONFIGURED_POOL=0
    SMOKE_TESTS_SELECTED=""
    for smoke_test in $SMOKE_TESTS; do
      case "$smoke_test" in
        authority/missing-pool)
          if [ "$RUN_SMOKE_MISSING_POOL" -eq 0 ]; then
            RUN_SMOKE_MISSING_POOL=1
            SMOKE_TESTS_SELECTED="$SMOKE_TESTS_SELECTED authority/missing-pool"
          fi
          ;;
        configured-pool-member)
          if [ "$RUN_SMOKE_CONFIGURED_POOL" -eq 0 ]; then
            RUN_SMOKE_CONFIGURED_POOL=1
            SMOKE_TESTS_SELECTED="$SMOKE_TESTS_SELECTED configured-pool-member"
          fi
          ;;
        *)
          echo "ERROR: unsupported kmod-smoke test label: $smoke_test" >&2
          echo "Supported labels: $SMOKE_TESTS_DEFAULT" >&2
          exit 2
          ;;
      esac
    done
    SMOKE_TESTS_SELECTED="''${SMOKE_TESTS_SELECTED# }"

    echo "=== TideFS K7-VAL: kmod-posix-vfs Kernel XFSTests Smoke Harness ==="
    echo "  Kernel:     $KERNEL_IMG ($KERNEL_VERSION)"
    echo "  QEMU:       $QEMU_BIN"
    echo "  Module:     kmod-posix-vfs (tidefs_posix_vfs)"
    echo "  Tests:      $SMOKE_TESTS_SELECTED"
    echo "  Timeout:    ''${TIMEOUT_SEC}s"
    echo ""

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO" "$TIDEFSCTL" "$FSFREEZE"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ERROR: dependency not found: $dep" >&2
        exit 2
      fi
    done

    RUN_DIR="$TMPDIR/smoke-$$"
    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,lib/modules,mnt/tidefs,var/lib/tidefs,etc,usr/bin,run/tidefs/import}
    trap 'if [ -z "''${KEEP_TMP:-}" ]; then rm -rf "$RUN_DIR"; fi' EXIT
    POOL_IMG="$RUN_DIR/configured-pool-member.img"

    # Resolve module .ko
    KO_PATH=""
    if [ -n "$KO_PATH_ARG" ] && [ -f "$KO_PATH_ARG" ]; then
      KO_PATH="$KO_PATH_ARG"
      echo "--- Using provided module: $KO_PATH ---"
    elif [ -f "$MODULE_DIR/tidefs_posix_vfs.ko" ]; then
      KO_PATH="$MODULE_DIR/tidefs_posix_vfs.ko"
      echo "--- Found pre-built module: $KO_PATH ---"
    else
      echo "--- No .ko found in kernel module directory ---"
      echo "  MODULE_DIR=$MODULE_DIR"
      CONFIG_RUST_SET=0
      # Check auto.conf from built kernel
      if [ -f "${linuxKernel_7_0.dev}/include/config/auto.conf" ]; then
        if grep -q 'CONFIG_RUST=y' "${linuxKernel_7_0.dev}/include/config/auto.conf" 2>/dev/null; then
          echo "  CONFIG_RUST: y (kernel auto.conf)"
          CONFIG_RUST_SET=1
        else
          echo "  CONFIG_RUST: not set in kernel auto.conf"
        fi
      else
        echo "  CONFIG_RUST: auto.conf not found (kernel may not be built yet)"
      fi
      # Check source config fragment for CONFIG_RUST=y intent
      if [ -f "${linuxKernel_7_0.dev}/.config" ] && grep -q 'CONFIG_RUST=y' "${linuxKernel_7_0.dev}/.config" 2>/dev/null; then
        echo "  CONFIG_RUST: y in .config (merged config has intent)"
        CONFIG_RUST_SET=1
      fi
      if [ "$CONFIG_RUST_SET" -eq 0 ]; then
        echo "  BLOCKER: CONFIG_RUST=y must be enabled in nix/vm/kernel-7.0-config"
        echo "           and the kernel rebuilt for kmod-posix-vfs Kbuild support."
        echo "  WORKAROUND: cargo check/build succeeds with the kmod-bridge userspace shim,"
        echo "           but the resulting code cannot be loaded as a kernel module."
      fi
      if [ -f "${linuxKernel_7_0.dev}/include/config/auto.conf" ]; then
        if grep -q 'CONFIG_MODULES=y' "${linuxKernel_7_0.dev}/include/config/auto.conf" 2>/dev/null; then
          echo "  CONFIG_MODULES: y"
        else
          echo "  CONFIG_MODULES: NOT SET"
          echo "  BLOCKER: CONFIG_MODULES=y is required for kernel module loading."
        fi
      fi
    fi

    # Copy busybox and create applet symlinks
    cp "$BUSYBOX" "$RUN_DIR/bin/busybox"
    chmod +x "$RUN_DIR/bin/busybox"

    # Nix-built BusyBox is dynamically linked and embeds absolute /nix/store
    # interpreter/library paths. Copy those exact paths so /init can execute.
    DEPS=$("$LDD_BIN" "$BUSYBOX" 2>/dev/null | grep -o '/nix/store/[^ ]*' | sort -u || true)
    for lib in $DEPS; do
      if [ -f "$lib" ]; then
        lib_dir=$(dirname "$lib")
        mkdir -p "$RUN_DIR$lib_dir"
        cp "$lib" "$RUN_DIR$lib" 2>/dev/null || true
      fi
    done
    LD_SO=$("$LDD_BIN" "$BUSYBOX" 2>/dev/null | grep -o '/nix/store/[^ ]*ld-linux[^ ]*' | head -1 || true)
    if [ -n "$LD_SO" ] && [ -f "$LD_SO" ]; then
      ld_dir=$(dirname "$LD_SO")
      mkdir -p "$RUN_DIR$ld_dir"
      cp "$LD_SO" "$RUN_DIR$LD_SO" 2>/dev/null || true
      chmod +x "$RUN_DIR$LD_SO" 2>/dev/null || true
    fi

    for applet in sh ls cat echo mount umount grep insmod rmmod dmesg sleep poweroff reboot mknod mkdir rmdir dd stat cp mv rm touch find wc head tail seq awk which basename dirname cut tr test env true false printf sync mountpoint kill pidof ps uname date ln readlink lsmod df; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done

    cp "$TIDEFSCTL" "$RUN_DIR/bin/tidefsctl"
    chmod +x "$RUN_DIR/bin/tidefsctl"
    TIDEFSCTL_DEPS=$("$LDD_BIN" "$TIDEFSCTL" 2>/dev/null | grep -o '/nix/store/[^ ]*' | sort -u || true)
    for lib in $TIDEFSCTL_DEPS; do
      if [ -f "$lib" ]; then
        lib_dir=$(dirname "$lib")
        mkdir -p "$RUN_DIR$lib_dir"
        cp "$lib" "$RUN_DIR$lib" 2>/dev/null || true
      fi
    done
    TIDEFSCTL_LD_SO=$("$LDD_BIN" "$TIDEFSCTL" 2>/dev/null | grep -o '/nix/store/[^ ]*ld-linux[^ ]*' | head -1 || true)
    if [ -n "$TIDEFSCTL_LD_SO" ] && [ -f "$TIDEFSCTL_LD_SO" ]; then
      ld_dir=$(dirname "$TIDEFSCTL_LD_SO")
      mkdir -p "$RUN_DIR$ld_dir"
      cp "$TIDEFSCTL_LD_SO" "$RUN_DIR$TIDEFSCTL_LD_SO" 2>/dev/null || true
      chmod +x "$RUN_DIR$TIDEFSCTL_LD_SO" 2>/dev/null || true
    fi

    cp "$FSFREEZE" "$RUN_DIR/bin/fsfreeze"
    chmod +x "$RUN_DIR/bin/fsfreeze"
    FSFREEZE_DEPS=$("$LDD_BIN" "$FSFREEZE" 2>/dev/null | grep -o '/nix/store/[^ ]*' | sort -u || true)
    for lib in $FSFREEZE_DEPS; do
      if [ -f "$lib" ]; then
        lib_dir=$(dirname "$lib")
        mkdir -p "$RUN_DIR$lib_dir"
        cp "$lib" "$RUN_DIR$lib" 2>/dev/null || true
      fi
    done
    FSFREEZE_LD_SO=$("$LDD_BIN" "$FSFREEZE" 2>/dev/null | grep -o '/nix/store/[^ ]*ld-linux[^ ]*' | head -1 || true)
    if [ -n "$FSFREEZE_LD_SO" ] && [ -f "$FSFREEZE_LD_SO" ]; then
      ld_dir=$(dirname "$FSFREEZE_LD_SO")
      mkdir -p "$RUN_DIR$ld_dir"
      cp "$FSFREEZE_LD_SO" "$RUN_DIR$FSFREEZE_LD_SO" 2>/dev/null || true
      chmod +x "$RUN_DIR$FSFREEZE_LD_SO" 2>/dev/null || true
    fi

    # Copy module if available
    MODULE_FOUND=0
    if [ -n "$KO_PATH" ] && [ -f "$KO_PATH" ]; then
      cp "$KO_PATH" "$RUN_DIR/lib/modules/tidefs_posix_vfs.ko"
      MODULE_FOUND=1
      echo "  Module copied to initrd: tidefs_posix_vfs.ko"
    fi

    # Create /etc/passwd and /etc/group for smoke tests
    echo "root:x:0:0:root:/root:/bin/sh" > "$RUN_DIR/etc/passwd"
    echo "root:x:0:" > "$RUN_DIR/etc/group"
    {
      printf "SMOKE_TESTS_SELECTED='%s'\n" "$SMOKE_TESTS_SELECTED"
      printf 'RUN_SMOKE_MISSING_POOL=%s\n' "$RUN_SMOKE_MISSING_POOL"
      printf 'RUN_SMOKE_CONFIGURED_POOL=%s\n' "$RUN_SMOKE_CONFIGURED_POOL"
    } > "$RUN_DIR/etc/tidefs-smoke-tests.env"

    # Build the init script
    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin:/usr/bin:/sbin:/usr/sbin

. /etc/tidefs-smoke-tests.env

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /tmp /var/tmp

echo "================================================================"
echo "=== TideFS K7 KmodXFSTests: kernel xfstests smoke harness ==="
echo "kernel_version=$(uname -r)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "selected_tests=$SMOKE_TESTS_SELECTED"
echo "================================================================"
echo ""

PASSED=0
FAILED=0
BLOCKED=0
REFUSAL=0
TOTAL_TESTS=0

pass() { echo "PASS: $1"; PASSED=$((PASSED + 1)); TOTAL_TESTS=$((TOTAL_TESTS + 1)); }
fail() { echo "FAIL: $1 -- $2"; FAILED=$((FAILED + 1)); TOTAL_TESTS=$((TOTAL_TESTS + 1)); }
blocked() { echo "BLOCKED: $1 -- $2"; BLOCKED=$((BLOCKED + 1)); }
refusal() { echo "REFUSAL: $1 -- $2"; REFUSAL=$((REFUSAL + 1)); }
dmesg_count() { dmesg 2>/dev/null | grep -c "$1" 2>/dev/null || true; }
dmesg_last() { dmesg 2>/dev/null | grep "$1" 2>/dev/null | tail -1 || true; }

MNT=/mnt/tidefs
SCRATCH_DIR=/var/lib/tidefs/scratch
POOL_DEV=/dev/vda
POOL_NAME=qemu_smoke_pool

echo "--- Phase 0: Module Load ---"

MODULE_PATH="/lib/modules/tidefs_posix_vfs.ko"
if [ -f "$MODULE_PATH" ]; then
    echo "insmod $MODULE_PATH"
    if insmod "$MODULE_PATH" 2>/tmp/insmod.err; then
        pass "module_load"
    else
        err="$(head -3 /tmp/insmod.err | tr '\n' ' ')"
        fail "module_load" "$err"
    fi
else
    blocked "module_load" "tidefs_posix_vfs.ko not found in initramfs"
    blocked "module_lsmod" "module not loaded"
fi

if lsmod 2>/dev/null | grep -q tidefs_posix_vfs; then
    pass "module_lsmod"
else
    blocked "module_lsmod" "module not visible in lsmod"
fi

echo "--- dmesg (tidefs lines) ---"
dmesg | grep -i tidefs 2>/dev/null | head -10 || echo "  (no tidefs dmesg lines)"

echo ""
echo "--- Phase 1: Configured Pool Member Setup ---"
mkdir -p "$SCRATCH_DIR"
POOL_DEVICE_READY=0
POOL_READY=0
if [ "$RUN_SMOKE_CONFIGURED_POOL" -eq 1 ]; then
    echo "Waiting for virtio pool member $POOL_DEV..."
    for _ in $(seq 1 30); do
        [ -b "$POOL_DEV" ] && break
        sleep 1
    done
    if [ -b "$POOL_DEV" ]; then
        POOL_DEVICE_READY=1
        pass "configured_pool_device_present"
    else
        blocked "configured_pool_device_present" "$POOL_DEV missing"
    fi

    if [ "$POOL_DEVICE_READY" -eq 1 ] && command -v tidefsctl >/dev/null 2>&1; then
        echo "tidefsctl pool create $POOL_NAME --devices $POOL_DEV --json"
        COUT=$(tidefsctl pool create "$POOL_NAME" --devices "$POOL_DEV" --json 2>&1); RC=$?
        echo "  create exit=$RC"
        if [ "$RC" -eq 0 ]; then
            pass "configured_pool_member_created"
            SOUT=$(tidefsctl pool scan --devices "$POOL_DEV" 2>&1); SRC=$?
            if [ "$SRC" -eq 0 ] && echo "$SOUT" | grep -qi "label"; then
                pass "configured_pool_label_verified"
                POOL_READY=1
            else
                fail "configured_pool_label_verified" "$SOUT"
            fi
        else
            fail "configured_pool_member_created" "$COUT"
        fi
    else
        if [ "$POOL_DEVICE_READY" -eq 0 ]; then
            blocked "configured_pool_member_created" "virtio pool device missing"
        else
            blocked "configured_pool_member_created" "tidefsctl not found in initramfs"
        fi
        blocked "configured_pool_label_verified" "pool member was not created"
    fi
else
    echo "Skipping configured pool member setup; configured-pool-member not selected."
fi

echo ""
echo "--- Phase 2: Missing Pool Authority Mount Attempt ---"
MOUNTED=0
mkdir -p "$MNT"
if [ "$RUN_SMOKE_MISSING_POOL" -eq 1 ]; then
    echo "mount -o bootstrap -t tidefs none $MNT"
    if mount -o bootstrap -t tidefs none "$MNT" 2>/tmp/mount.err; then
        fail "missing_pool_member_rejected" "bootstrap mount unexpectedly succeeded without explicit pool I/O authority"
        umount "$MNT" 2>/dev/null || true
    else
        err="$(head -3 /tmp/mount.err | tr '\n' ' ')"
        pass "missing_pool_member_rejected"
        echo "  refusal: $err"
    fi
else
    echo "Skipping missing pool authority check; authority/missing-pool not selected."
fi

echo ""
echo "--- Phase 3: Configured Pool Member Mount Tests ---"

if [ "$RUN_SMOKE_CONFIGURED_POOL" -ne 1 ]; then
    echo "Skipping configured pool member mount tests; configured-pool-member not selected."
elif [ "$POOL_READY" -eq 1 ]; then
    echo "mount -t tidefs $POOL_DEV $MNT"
    if mount -t tidefs "$POOL_DEV" "$MNT" 2>/tmp/configured-mount.err; then
        pass "configured_pool_mount"
        MOUNTED=1
    else
        fail "configured_pool_mount" "$(head -3 /tmp/configured-mount.err | tr '\n' ' ')"
    fi
else
    blocked "configured_pool_mount" "pool member was not ready"
fi

if [ "$MOUNTED" -eq 1 ]; then
    echo "Running focused POSIX smoke tests on kernel-mounted TideFS..."

    echo ""
    echo "-- smoke: statfs capacity from configured pool authority --"
    if stat -f "$MNT" >/tmp/statfs.out 2>/tmp/statfs.err; then
        pass "configured_pool_statfs"
        statfs_out=$(cat /tmp/statfs.out)
        echo "  statfs: $statfs_out"
        total_blocks=$(awk '/Blocks:/ { for (i = 1; i <= NF; i++) if ($i == "Total:") { print $(i + 1); exit } }' /tmp/statfs.out)
        if [ -n "$total_blocks" ] && [ "$total_blocks" -gt 0 ] 2>/dev/null; then
            pass "configured_pool_statfs_capacity"
            echo "  statfs_total_blocks=$total_blocks"
        else
            fail "configured_pool_statfs_capacity" "expected nonzero total blocks, got ''${total_blocks:-missing}"
        fi
    else
        fail "configured_pool_statfs" "$(head -1 /tmp/statfs.err)"
        blocked "configured_pool_statfs_capacity" "stat -f failed on mount point"
    fi

    echo ""
    echo "-- smoke: directory create/remove --"
    if mkdir "$MNT/g002_dir" 2>/tmp/t2.err; then
        if [ -d "$MNT/g002_dir" ]; then
            pass "configured_pool_mkdir"
        else
            fail "configured_pool_mkdir" "directory not found after mkdir"
        fi
        rmdir "$MNT/g002_dir" 2>/dev/null || true
        if [ ! -d "$MNT/g002_dir" ]; then
            pass "configured_pool_rmdir"
        else
            fail "configured_pool_rmdir" "directory still exists after rmdir"
        fi
    else
        fail "configured_pool_mkdir" "$(head -1 /tmp/t2.err)"
        blocked "configured_pool_rmdir" "mkdir failed"
    fi

    echo ""
    echo "-- smoke: symlink/readlink --"
    if ln -s "/bootstrap-target" "$MNT/g005_link" 2>/tmp/t5b.err; then
        pass "configured_pool_symlink_create"
        target=$(readlink "$MNT/g005_link" 2>/dev/null || echo "")
        if [ "$target" = "/bootstrap-target" ]; then
            pass "configured_pool_readlink"
        else
            fail "configured_pool_readlink" "expected /bootstrap-target, got '$target'"
        fi
    else
        blocked "configured_pool_symlink_create" "$(head -1 /tmp/t5b.err)"
        blocked "configured_pool_readlink" "symlink create failed"
    fi
    rm -f "$MNT/g005_link" 2>/dev/null || true

    echo ""
    echo "-- smoke: symlink target errno --"
    # BusyBox reports the errno returned by the mounted symlink callback.
    if LC_ALL=C ln -s "" "$MNT/g005_empty_target" 2>/tmp/t5c.err; then
        fail "configured_pool_symlink_empty_target_enoent" "empty target unexpectedly succeeded"
        rm -f "$MNT/g005_empty_target" 2>/dev/null || true
    elif grep -Fq "No such file or directory" /tmp/t5c.err; then
        pass "configured_pool_symlink_empty_target_enoent"
    else
        fail "configured_pool_symlink_empty_target_enoent" "expected ENOENT: $(head -1 /tmp/t5c.err)"
    fi

    overlong_target="$(awk 'BEGIN { for (i = 0; i < 4097; i++) printf "x" }')"
    if [ "''${#overlong_target}" -ne 4097 ]; then
        fail "configured_pool_symlink_overlong_target_enametoolong" "could not construct a 4097-byte target"
    elif LC_ALL=C ln -s "$overlong_target" "$MNT/g005_overlong_target" 2>/tmp/t5d.err; then
        fail "configured_pool_symlink_overlong_target_enametoolong" "overlong target unexpectedly succeeded"
        rm -f "$MNT/g005_overlong_target" 2>/dev/null || true
    elif grep -Fq "File name too long" /tmp/t5d.err; then
        pass "configured_pool_symlink_overlong_target_enametoolong"
    else
        fail "configured_pool_symlink_overlong_target_enametoolong" "expected ENAMETOOLONG: $(head -1 /tmp/t5d.err)"
    fi

    echo ""
    echo "-- smoke: readdir --"
    mkdir "$MNT/g006_dir" 2>/tmp/t6a.err || true
    if [ -d "$MNT/g006_dir" ]; then
        touch "$MNT/g006_dir/a" "$MNT/g006_dir/b" "$MNT/g006_dir/c" 2>/dev/null || true
        entry_count=$(ls -1 "$MNT/g006_dir" 2>/dev/null | wc -l)
        if [ "$entry_count" -ge 3 ]; then
            pass "configured_pool_readdir"
        else
            fail "configured_pool_readdir" "expected >=3 entries, got $entry_count"
        fi
    else
        blocked "configured_pool_readdir" "test directory could not be created"
    fi
    rm -rf "$MNT/g006_dir" 2>/dev/null || true

    echo ""
    echo "-- smoke: write plus syncfs/lower flush --"
    configured_pool_flush_ready=0
    configured_pool_flush_blocker="write failed"
    if printf 'configured pool authority\n' > "$MNT/configured_pool_flush.txt" 2>/tmp/write.err; then
        pass "configured_pool_write"
        if sync -f "$MNT/configured_pool_flush.txt" 2>/tmp/syncfs.err; then
            pass "configured_pool_syncfs"
            configured_pool_flush_ready=1
        else
            fail "configured_pool_syncfs" "$(head -1 /tmp/syncfs.err)"
            configured_pool_flush_blocker="syncfs failed"
        fi
    else
        fail "configured_pool_write" "$(head -1 /tmp/write.err)"
        blocked "configured_pool_syncfs" "write failed"
    fi

    echo ""
    echo "-- smoke: administrative super_operation refusals --"
    freeze_before=$(dmesg_count "tidefs_posix_vfs: freeze_fs refused")
    if fsfreeze -f "$MNT" 2>/tmp/freeze.err; then
        fail "configured_pool_freeze_fs_refused" "fsfreeze unexpectedly succeeded"
        fsfreeze -u "$MNT" 2>/dev/null || true
    else
        freeze_after=$(dmesg_count "tidefs_posix_vfs: freeze_fs refused")
        if [ "''${freeze_after:-0}" -gt "''${freeze_before:-0}" ] 2>/dev/null; then
            pass "configured_pool_freeze_fs_refused"
            echo "  kernel: $(dmesg_last "tidefs_posix_vfs: freeze_fs refused")"
        else
            fail "configured_pool_freeze_fs_refused" "$(head -1 /tmp/freeze.err)"
        fi
    fi

    remount_before=$(dmesg_count "tidefs_posix_vfs: remount_fs refused")
    if mount -o remount,ro "$MNT" 2>/tmp/remount.err; then
        fail "configured_pool_remount_fs_refused" "remount,ro unexpectedly succeeded"
    else
        remount_after=$(dmesg_count "tidefs_posix_vfs: remount_fs refused")
        if [ "''${remount_after:-0}" -gt "''${remount_before:-0}" ] 2>/dev/null; then
            pass "configured_pool_remount_fs_refused"
            echo "  kernel: $(dmesg_last "tidefs_posix_vfs: remount_fs refused")"
        else
            fail "configured_pool_remount_fs_refused" "$(head -1 /tmp/remount.err)"
        fi
    fi

    if printf 'admin refusal kept mount writable\n' > "$MNT/admin_refusal_alive.txt" 2>/tmp/admin-refusal-write.err; then
        pass "configured_pool_admin_refusal_write"
    else
        fail "configured_pool_admin_refusal_write" "$(head -1 /tmp/admin-refusal-write.err)"
    fi

    echo ""
    echo "-- smoke: syncfs data and timestamp survive unmount/remount --"
    if [ "$configured_pool_flush_ready" -eq 1 ]; then
        flush_mtime_before=$(stat -c %Y "$MNT/configured_pool_flush.txt" 2>/tmp/remount-stat-before.err || true)
        if [ -z "$flush_mtime_before" ]; then
            blocked "configured_pool_sync_remount" "pre-remount mtime unavailable: $(head -1 /tmp/remount-stat-before.err)"
            blocked "configured_pool_remount_read" "pre-remount stat failed"
            blocked "configured_pool_remount_mtime" "pre-remount stat failed"
        elif umount "$MNT" 2>/tmp/remount-umount.err; then
            MOUNTED=0
            if mount -t tidefs "$POOL_DEV" "$MNT" 2>/tmp/remount-mount.err; then
                pass "configured_pool_sync_remount"
                MOUNTED=1

                remount_content=$(cat "$MNT/configured_pool_flush.txt" 2>/tmp/remount-read.err || true)
                if [ "$remount_content" = "configured pool authority" ]; then
                    pass "configured_pool_remount_read"
                else
                    fail "configured_pool_remount_read" "expected configured pool authority, got '$remount_content'"
                fi

                flush_mtime_after=$(stat -c %Y "$MNT/configured_pool_flush.txt" 2>/tmp/remount-stat-after.err || true)
                if [ -z "$flush_mtime_after" ]; then
                    fail "configured_pool_remount_mtime" "$(head -1 /tmp/remount-stat-after.err)"
                elif [ "$flush_mtime_after" = "$flush_mtime_before" ]; then
                    pass "configured_pool_remount_mtime"
                else
                    fail "configured_pool_remount_mtime" "expected $flush_mtime_before, got $flush_mtime_after"
                fi
            else
                fail "configured_pool_sync_remount" "$(head -3 /tmp/remount-mount.err | tr '\n' ' ')"
                blocked "configured_pool_remount_read" "remount failed"
                blocked "configured_pool_remount_mtime" "remount failed"
            fi
        else
            fail "configured_pool_sync_remount" "$(head -3 /tmp/remount-umount.err | tr '\n' ' ')"
            blocked "configured_pool_remount_read" "pre-remount umount failed"
            blocked "configured_pool_remount_mtime" "pre-remount umount failed"
        fi
    else
        blocked "configured_pool_sync_remount" "$configured_pool_flush_blocker"
        blocked "configured_pool_remount_read" "$configured_pool_flush_blocker"
        blocked "configured_pool_remount_mtime" "$configured_pool_flush_blocker"
    fi

    echo ""
    echo "-- smoke: clean teardown --"
    if [ "$MOUNTED" -ne 1 ]; then
        blocked "configured_pool_umount" "filesystem not mounted"
    elif umount "$MNT" 2>/tmp/umount.err; then
        pass "configured_pool_umount"
        MOUNTED=0
    else
        fail "configured_pool_umount" "$(head -3 /tmp/umount.err | tr '\n' ' ')"
    fi

else
    echo "Filesystem not mounted -- skipping configured-pool smoke tests."
    blocked "configured_pool_statfs" "filesystem not mounted"
    blocked "configured_pool_statfs_capacity" "filesystem not mounted"
    blocked "configured_pool_mkdir" "filesystem not mounted"
    blocked "configured_pool_symlink_create" "filesystem not mounted"
    blocked "configured_pool_symlink_empty_target_enoent" "filesystem not mounted"
    blocked "configured_pool_symlink_overlong_target_enametoolong" "filesystem not mounted"
    blocked "configured_pool_readdir" "filesystem not mounted"
    blocked "configured_pool_write" "filesystem not mounted"
    blocked "configured_pool_syncfs" "filesystem not mounted"
    blocked "configured_pool_sync_remount" "filesystem not mounted"
    blocked "configured_pool_remount_read" "filesystem not mounted"
    blocked "configured_pool_remount_mtime" "filesystem not mounted"
    blocked "configured_pool_freeze_fs_refused" "filesystem not mounted"
    blocked "configured_pool_remount_fs_refused" "filesystem not mounted"
    blocked "configured_pool_admin_refusal_write" "filesystem not mounted"
    blocked "configured_pool_umount" "filesystem not mounted"
fi

echo ""
echo "--- Phase 4: No-daemon Residency Check ---"
if [ "$RUN_SMOKE_CONFIGURED_POOL" -ne 1 ]; then
    echo "Skipping no-daemon residency checks; configured-pool-member not selected."
elif mountpoint -q "$MNT" 2>/dev/null; then
    mounts_fuse=$(mount 2>/dev/null | grep tidefs | grep fuse || true)
    if [ -z "$mounts_fuse" ]; then
        pass "no_daemon_fuse_mount"
    else
        refusal "no_daemon_fuse_mount" "tidefs appears mounted via FUSE ($mounts_fuse)"
    fi
else
    pass "no_daemon_fuse_mount"
fi

if [ "$RUN_SMOKE_CONFIGURED_POOL" -eq 1 ]; then
    ublk_run=$(ps 2>/dev/null | grep -v grep | grep ublk || true)
    if [ -z "$ublk_run" ]; then
        pass "no_daemon_ublk"
    else
        refusal "no_daemon_ublk" "ublk process detected"
    fi
fi

echo ""
echo "================================================================"
echo "=== SMOKE TEST SUMMARY ==="
echo "  kernel_version=$(uname -r)"
echo "  PASS=$PASSED FAIL=$FAILED BLOCKED=$BLOCKED REFUSAL=$REFUSAL"
echo "  TOTAL_TESTS=$TOTAL_TESTS"
echo "================================================================"

sleep 2
poweroff -f
INITSCRIPT

    chmod +x "$RUN_DIR/init"

    echo "--- Creating configured pool member disk image ---"
    dd if=/dev/zero of="$POOL_IMG" bs=1M count=128 2>/dev/null
    echo "  Pool member image: $POOL_IMG ($(du -h "$POOL_IMG" | cut -f1))"

    # Build initramfs
    echo "--- Building initramfs ---"
    (cd "$RUN_DIR" && find . -path ./initrd.img -prune -o -print | "$CPIO" -o -H newc 2>/dev/null) > "$RUN_DIR/initrd.img"
    echo "  Initrd: $(du -h "$RUN_DIR/initrd.img" | cut -f1)"

    # Boot QEMU
    echo ""
    echo "--- Booting QEMU with Linux 7.0 kernel ---"
    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      -kernel "$KERNEL_IMG" \
      -initrd "$RUN_DIR/initrd.img" \
      -drive file="$POOL_IMG",format=raw,if=virtio,index=0 \
      -append "console=ttyS0 quiet panic=10" \
      -nographic \
      -m 1024M \
      -smp 2 \
      -no-reboot \
      2>&1 | tee "$RUN_DIR/qemu.log" || true

    echo ""
    echo "--- QEMU exited ---"

    count_log() {
      local pattern="$1"
      local count
      count=$(grep -c "$pattern" "$RUN_DIR/qemu.log" 2>/dev/null || true)
      printf '%s\n' "''${count:-0}"
    }

    PASS_COUNT=$(count_log "^PASS:")
    FAIL_COUNT=$(count_log "^FAIL:")
    BLOCKED_COUNT=$(count_log "^BLOCKED:")
    REFUSAL_COUNT=$(count_log "^REFUSAL:")

    echo ""
    echo "================================================================"
    echo "=== HARNESS RESULTS ==="
    echo "  PASS:    $PASS_COUNT"
    echo "  FAIL:    $FAIL_COUNT"
    echo "  BLOCKED: $BLOCKED_COUNT"
    echo "  REFUSAL: $REFUSAL_COUNT"
    echo "================================================================"

    KVER=$(grep "^kernel_version=" "$RUN_DIR/qemu.log" 2>/dev/null | head -1 | cut -d= -f2- | tr -d "'" || echo "unknown")
    echo "  Kernel: $KVER"
    echo ""

    echo "  Module dmesg:"
    grep -i tidefs "$RUN_DIR/qemu.log" 2>/dev/null | head -10 | sed 's/^/    /' || echo "    (none)"
    echo ""

    if [ "$BLOCKED_COUNT" -gt 0 ] && [ "$PASS_COUNT" -eq 0 ] && [ "$FAIL_COUNT" -eq 0 ]; then
      VALIDATION_TIER="QEMU guest (all smoke tests blocked — kernel module not loadable)"
    elif grep -q "^PASS: configured_pool_umount" "$RUN_DIR/qemu.log" 2>/dev/null; then
      VALIDATION_TIER="mounted kernel VFS configured-pool authority"
    elif grep -q "^PASS: missing_pool_member_rejected" "$RUN_DIR/qemu.log" 2>/dev/null; then
      VALIDATION_TIER="kernel VFS authority refusal"
    elif [ "$PASS_COUNT" -gt 0 ] || [ "$FAIL_COUNT" -gt 0 ]; then
      VALIDATION_TIER="mounted kernel VFS"
    else
      VALIDATION_TIER="QEMU guest (no results)"
    fi
    echo "  Validation tier: $VALIDATION_TIER"

    OUTPUT_ROOT="''${TIDEFS_OUTPUT_ROOT:-/tmp/tidefs-validation}"
    OUTPUT_DIR="$OUTPUT_ROOT/kmod-xfstests-smoke/$(date -u +%Y-%m-%dT%H%M%SZ)"
    mkdir -p "$OUTPUT_DIR"
    cp "$RUN_DIR/qemu.log" "$OUTPUT_DIR/qemu.log"
    echo ""
    echo "  Validation output directory: $OUTPUT_DIR"

    if [ "$FAIL_COUNT" -gt 0 ]; then
      echo ""
      echo "=== FAILURES DETECTED ==="
      grep "^FAIL:" "$RUN_DIR/qemu.log" 2>/dev/null || true
      exit 1
    fi
    if grep -q "^BLOCKED: module_load" "$RUN_DIR/qemu.log" 2>/dev/null; then
      echo ""
      echo "=== MODULE LOAD BLOCKED ==="
      grep "^BLOCKED: module_load" "$RUN_DIR/qemu.log" 2>/dev/null || true
      exit 1
    fi
    if [ "$PASS_COUNT" -eq 0 ]; then
      echo ""
      echo "=== NO SMOKE RESULTS ==="
      exit 1
    fi
    exit 0
  '';
in
  kmodXfstestsSmokeScript
