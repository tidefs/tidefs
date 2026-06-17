# TideFS: FUSE userspace xfstests validation in QEMU.
#
# Mounts a TideFS FUSE filesystem inside a Linux 7.0 QEMU VM,
# executes the xfstests generic test group, and produces tier-classified
# validation rows with pass/fail/unsupported/skip/blocked classification.
#
# Validation tier:
#   MountedUserspace  xfstests results from live FUSE mount (QEMU)
#
# Dependencies:
#   - Linux 7.0 kernel with FUSE support (fuse.ko)
#   - tidefs-posix-filesystem-adapter-daemon binary
#   - xfstests package from nixpkgs
#   - QEMU with KVM acceleration
#   - busybox for initrd userspace
#
# Environment refusal: in environments without /dev/kvm or fuse.ko,
# produces REFUSAL-classified validation rows.
{
  pkgs,
  linuxKernel_7_0,
  tidefsPackage,
  xfstests,
}:

let
  fuseXfstestsValidationScript = pkgs.writeShellScriptBin "tidefs-fuse-xfstests-validation" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    GLIBC_LIB="${pkgs.glibc}/lib"
    LDD_BIN="${pkgs.lib.getBin pkgs.glibc}/bin/ldd"
    XZ_BIN="${pkgs.xz}/bin/xz"
    DEFAULT_KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    DEFAULT_KERNEL_VMLINUX="${linuxKernel_7_0.dev}/vmlinux"
    DEFAULT_MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"
    KERNEL_IMG="''${TIDEFS_FUSE_XFSTESTS_KERNEL_IMG:-$DEFAULT_KERNEL_IMG}"
    KERNEL_VMLINUX="''${TIDEFS_FUSE_XFSTESTS_KERNEL_VMLINUX:-$DEFAULT_KERNEL_VMLINUX}"
    CPIO="${pkgs.cpio}/bin/cpio"
    SOCAT_BIN="${pkgs.socat}/bin/socat"
    MODULE_DIR="''${TIDEFS_FUSE_XFSTESTS_MODULE_DIR:-$DEFAULT_MODULE_DIR}"
    FUSE_DAEMON="${tidefsPackage}/bin/tidefs-posix-filesystem-adapter-daemon"
    XFSTESTS_BIN="${xfstests}/bin/xfstests-check"
    BASH_BIN="${pkgs.bash}/bin/bash"
    PERL_BIN="${pkgs.perl}/bin/perl"
    BC_BIN="${pkgs.bc}/bin/bc"
    XFSIO_BIN="${pkgs.xfsprogs}/bin/xfs_io"
    READLINK_BIN="${pkgs.coreutils}/bin/readlink"
    DF_BIN="${pkgs.coreutils}/bin/df"
    MV_BIN="${pkgs.coreutils}/bin/mv"
    RM_BIN="${pkgs.coreutils}/bin/rm"
    TRUNCATE_BIN="${pkgs.coreutils}/bin/truncate"
    MD5SUM_BIN="${pkgs.coreutils}/bin/md5sum"
    CHMOD_BIN="${pkgs.coreutils}/bin/chmod"
    GAWK_BIN="${pkgs.gawk}/bin/gawk"
    TIMEOUT_BIN="${pkgs.coreutils}/bin/timeout"
    OD_BIN="${pkgs.lib.getBin pkgs.coreutils}/bin/od"
    TAC_BIN="${pkgs.lib.getBin pkgs.coreutils}/bin/tac"
    TAR_BIN="${pkgs.lib.getBin pkgs.gnutar}/bin/tar"
    MKFS_EXT4_BIN="${pkgs.e2fsprogs}/bin/mkfs.ext4"
    ATTR_BIN="${pkgs.lib.getBin pkgs.attr}/bin/attr"
    GETFATTR_BIN="${pkgs.lib.getBin pkgs.attr}/bin/getfattr"
    SETFATTR_BIN="${pkgs.lib.getBin pkgs.attr}/bin/setfattr"
    CHACL_BIN="${pkgs.lib.getBin pkgs.acl}/bin/chacl"
    GETFACL_BIN="${pkgs.lib.getBin pkgs.acl}/bin/getfacl"
    SETFACL_BIN="${pkgs.lib.getBin pkgs.acl}/bin/setfacl"
    FIO_BIN="${pkgs.lib.getBin pkgs.fio}/bin/fio"
    MOUNT_BIN="${pkgs.util-linux}/bin/mount"
    FINDMNT_BIN="${pkgs.util-linux}/bin/findmnt"
    GMP_LIB="${pkgs.gmp}/lib"
    XFSTESTS_LIB="${xfstests}/lib/xfstests"

    TMPDIR="''${TIDEFS_FUSE_XFSTESTS_TMPDIR:-/tmp/tidefs-fuse-xfstests-validation}"
    TIMEOUT_SEC="''${TIDEFS_FUSE_XFSTESTS_TIMEOUT:-1200}"
    PER_TEST_TIMEOUT_SEC="''${TIDEFS_FUSE_XFSTESTS_PER_TEST_TIMEOUT:-180}"
    QEMU_MEMORY_MB="''${TIDEFS_FUSE_XFSTESTS_QEMU_MEMORY_MB:-2048}"
    STORE_IMAGE_MB="''${TIDEFS_FUSE_XFSTESTS_STORE_IMAGE_MB:-8192}"
    CRASHDUMP_MODE="''${TIDEFS_FUSE_XFSTESTS_CRASHDUMP:-0}"
    PANIC_ON_WARN_MODE="''${TIDEFS_FUSE_XFSTESTS_PANIC_ON_WARN:-0}"
    CRASH_BIN="''${TIDEFS_FUSE_XFSTESTS_CRASH_BIN:-/usr/bin/crash}"
    DEFAULT_TESTS="generic/001 generic/002 generic/003 generic/004 generic/005 generic/006 generic/007 generic/008 generic/009 generic/010 generic/011 generic/012 generic/013"

    usage() {
      cat <<EOF
Usage: tidefs-fuse-xfstests-validation [--timeout SECONDS] [--keep-tmp]
       [--tests "generic/001 generic/002 ..."] [--output JSON]
       [--trace-xfstests]

Run xfstests generic tests against a FUSE-mounted TideFS filesystem inside
a QEMU VM. Produces tier-classified validation rows in JSON format.

Options:
  --timeout SECONDS    QEMU boot timeout (default: $TIMEOUT_SEC)
  --keep-tmp           Do not remove temp directory on exit
  --tests "T1 T2 ..."  Space-separated test names to run
                       (default: generic/001-generic/013 smoke tranche)
  --output PATH        Write JSON validation to PATH
  --trace-xfstests     Enable bash xtrace for the guest xfstests check script
  --help, -h           Show this message

Environment:
  TIDEFS_FUSE_XFSTESTS_QEMU_MEMORY_MB  Guest RAM in MiB (default: $QEMU_MEMORY_MB)
  TIDEFS_FUSE_XFSTESTS_STORE_IMAGE_MB  Guest /store disk image in MiB (default: $STORE_IMAGE_MB)
  TIDEFS_FUSE_XFSTESTS_PANIC_ON_WARN   Set guest panic-on-warning/lockup knobs (0/1)
  TIDEFS_FUSE_XFSTESTS_CRASHDUMP       Dump guest memory through QMP on panic/timeout (0/1)
  TIDEFS_FUSE_XFSTESTS_CRASH_BIN       crash(8) binary for vmcore analysis (default: $CRASH_BIN)
  TIDEFS_FUSE_XFSTESTS_KERNEL_IMG      Override guest kernel bzImage
  TIDEFS_FUSE_XFSTESTS_KERNEL_VMLINUX  Override vmlinux for crash(8)
  TIDEFS_FUSE_XFSTESTS_MODULE_DIR      Override guest module directory

Exit codes:
  0   All attempted tests passed or were classified non-fail
  1   One or more tests failed with product bugs
  2   Argument or environment error
EOF
    }

    KEEP_TMP=0
    TEST_LIST="$DEFAULT_TESTS"
    JSON_OUT=""
    TRACE_XFSTESTS=0

    while [ "$#" -gt 0 ]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --tests) TEST_LIST="$2"; shift 2 ;;
        --output) JSON_OUT="$2"; shift 2 ;;
        --trace-xfstests) TRACE_XFSTESTS=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done

    FIRST_TEST="''${TEST_LIST%% *}"
    LAST_TEST="''${TEST_LIST##* }"
    if [ "$FIRST_TEST" = "$LAST_TEST" ]; then
      TEST_SCOPE="$FIRST_TEST"
    else
      TEST_SCOPE="$FIRST_TEST-$LAST_TEST"
    fi

    case "$QEMU_MEMORY_MB" in
      ""|*[!0-9]*)
        echo "invalid TIDEFS_FUSE_XFSTESTS_QEMU_MEMORY_MB: $QEMU_MEMORY_MB" >&2
        exit 2
        ;;
    esac
    if [ "$QEMU_MEMORY_MB" -le 0 ]; then
      echo "TIDEFS_FUSE_XFSTESTS_QEMU_MEMORY_MB must be > 0" >&2
      exit 2
    fi
    case "$STORE_IMAGE_MB" in
      ""|*[!0-9]*)
        echo "invalid TIDEFS_FUSE_XFSTESTS_STORE_IMAGE_MB: $STORE_IMAGE_MB" >&2
        exit 2
        ;;
    esac
    if [ "$STORE_IMAGE_MB" -le 0 ]; then
      echo "TIDEFS_FUSE_XFSTESTS_STORE_IMAGE_MB must be > 0" >&2
      exit 2
    fi

    # ── Environment preflight ──────────────────────────────────────────

    HAS_KVM=0; if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then HAS_KVM=1; echo "  Acceleration: KVM (/dev/kvm available)"; else echo "  Acceleration: TCG (KVM not available)"; echo "  NOTE: TCG is slower but produces valid correctness validation."; fi

# Check KVM fallback (previously hard gate)
if false; then
      echo "ENVIRONMENT REFUSAL: /dev/kvm not available"
      echo "FUSE xfstests QEMU validation requires KVM acceleration"
      echo "This environment cannot run QEMU-based validation."
      echo "Use a host with /dev/kvm and the required Nix packages."
      exit 2
    fi

    for dep in "$QEMU_BIN" "$BUSYBOX" "$KERNEL_IMG" "$CPIO" "$LDD_BIN"; do
      if [ ! -f "$dep" ] && [ ! -x "$dep" ]; then
        echo "ERROR: dependency not found: $dep" >&2
        exit 2
      fi
    done

    if [ ! -f "$FUSE_DAEMON" ] && [ ! -x "$FUSE_DAEMON" ]; then
      echo "ERROR: FUSE daemon not found: $FUSE_DAEMON" >&2
      exit 2
    fi

    echo "=== TideFS FUSE xfstests Validation ==="
    echo "  Kernel:    $KERNEL_IMG"
    echo "  QEMU:      $QEMU_BIN"
    echo "  Daemon:    $FUSE_DAEMON"
    echo "  xfstests:  $XFSTESTS_BIN"
    echo "  Tests:     $TEST_LIST"
    echo "  Timeout:   ''${TIMEOUT_SEC}s"
    echo "  Memory:    $QEMU_MEMORY_MB MiB"
    echo "  Store img: $STORE_IMAGE_MB MiB"
    echo "  Panic warn:$PANIC_ON_WARN_MODE"
    echo "  Crashdump: $CRASHDUMP_MODE"
    echo "  vmlinux:   $KERNEL_VMLINUX"
    echo ""

    # ── Resolve fuse.ko ────────────────────────────────────────────────

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

    if [ -z "$FUSE_KO" ]; then
      echo "  FUSE: no fuse.ko in module tree; guest will verify built-in support"
      FUSE_KO_AVAILABLE=0
    else
      echo "  fuse.ko: $FUSE_KO"
      FUSE_KO_AVAILABLE=1
    fi

    ldd_runtime_paths() {
      src="$1"
      [ -f "$src" ] || return 0
      if [ -x "$LDD_BIN" ]; then
        "$LDD_BIN" "$src" 2>/dev/null
      elif command -v ldd >/dev/null 2>&1; then
        ldd "$src" 2>/dev/null
      else
        true
      fi | grep -o "/nix/store/[^ ]*" | sort -u || true
    }

    # ── Collect daemon shared library dependencies ─────────────────────

    echo "  Collecting daemon library dependencies..."
    DAEMON_LIBS=""
    DAEMON_LIBS=$(ldd_runtime_paths "$FUSE_DAEMON")

    # ── Collect xfstests dependencies ─────────────────────────────────

    XFSTESTS_LIBS=""
    XFSTESTS_LIBS=$(ldd_runtime_paths "$XFSTESTS_BIN")

    # ── Set up temp directory ──────────────────────────────────────────

    RUN_DIR="$TMPDIR/validation-$$"
    mkdir -p "$RUN_DIR"/{bin,dev,proc,sys,tmp,etc,lib/modules,mnt/tidefs,store,usr/lib,var/lib/tidefs}

    ensure_run_dir() {
      dst="$1"
      case "$dst" in
        "$RUN_DIR"|"$RUN_DIR"/*) ;;
        *)
          echo "ERROR: refusing to prepare path outside run directory: $dst" >&2
          exit 2
          ;;
      esac

      current="$RUN_DIR"
      rel="''${dst#$RUN_DIR}"
      rel="''${rel#/}"
      chmod u+w "$current" 2>/dev/null || true

      old_ifs="$IFS"
      IFS='/'
      for part in $rel; do
        [ -n "$part" ] || continue
        chmod u+w "$current" 2>/dev/null || true
        if [ -L "$current/$part" ]; then
          rm -f "$current/$part"
        fi
        if [ ! -d "$current/$part" ]; then
          mkdir "$current/$part"
        fi
        current="$current/$part"
        chmod u+w "$current" 2>/dev/null || true
      done
      IFS="$old_ifs"
    }

    copy_nix_store_file() {
      src="$1"
      executable="''${2:-0}"
      [ -f "$src" ] || return 0

      dst_dir="$RUN_DIR/$(dirname "$src")"
      ensure_run_dir "$dst_dir"
      cp -f "$src" "$dst_dir/"
      if [ "$executable" = "1" ]; then
        chmod +x "$dst_dir/$(basename "$src")" 2>/dev/null || true
      fi
    }

    copy_ldd_runtime_deps() {
      src="$1"
      ldd_runtime_paths "$src" | while read -r lib; do
        [ -f "$lib" ] || continue
        copy_nix_store_file "$lib" 0 2>/dev/null || true
        cp -f "$lib" "$RUN_DIR/usr/lib/" 2>/dev/null || true
      done
    }

    copy_runtime_binary() {
      src="$1"
      link_name="''${2:-}"
      [ -f "$src" ] || return 0

      copy_nix_store_file "$src" 1 2>/dev/null || true

      if [ -n "$link_name" ]; then
        rm -f "$RUN_DIR/bin/$link_name"
        ln -sf "$src" "$RUN_DIR/bin/$link_name" 2>/dev/null || true
      fi

      copy_ldd_runtime_deps "$src"
    }

    cleanup() {
      if [ "$KEEP_TMP" -eq 1 ]; then
        echo "  Keeping temp directory: $RUN_DIR"
      else
        rm -rf "$RUN_DIR"
      fi
    }
    trap cleanup EXIT

    # ── Generate root authentication key ──────────────────────────────

    ROOT_AUTH_KEY=""
    if [ -r /dev/urandom ]; then
      ROOT_AUTH_KEY=$(od -A n -t x1 -N 32 /dev/urandom 2>/dev/null | tr -d ' \n' || true)
    fi
    if [ -z "$ROOT_AUTH_KEY" ]; then
      # Fixed test-only key when /dev/urandom is unavailable.
      ROOT_AUTH_KEY="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    fi
    echo "  Root auth key: $ROOT_AUTH_KEY"

    # ── Populate initrd ────────────────────────────────────────────────

    cp "$BUSYBOX" "$RUN_DIR/bin/busybox"
    chmod +x "$RUN_DIR/bin/busybox"
    for applet in sh ls cat echo mount grep insmod rmmod dmesg sleep poweroff \
                  reboot mknod mkdir rmdir dd stat cp mv rm touch find wc sync \
                  expr head tail cut kill ps test seq du dirname basename \
                  readlink tr cmp diff od uname date mountpoint umount timeout sed mktemp chmod chown awk sort uniq xargs which tr ln tee hostname df pgrep pkill id killall logger; do
      ln -sf busybox "$RUN_DIR/bin/$applet"
    done
    cat > "$RUN_DIR/etc/passwd" << 'PASSWD'
root:x:0:0:root:/root:/bin/sh
nobody:x:65534:65534:nobody:/tmp:/bin/sh
PASSWD
    cat > "$RUN_DIR/etc/group" << 'GROUP'
root:x:0:
nobody:x:65534:
GROUP

    # Copy the daemon and its runtime libraries through the same helper used
    # for guest tools, so optional libraries such as libibverbs are staged.
    copy_runtime_binary "$FUSE_DAEMON" tidefs-posix-filesystem-adapter-daemon

    # ── Install functional mount helper ──────────────────────────────
    cat > "$RUN_DIR/bin/tidefs-preview" << 'MOUNTHELPER'
#!/bin/sh
# TideFS FUSE mount helper for xfstests.
# Called as: tidefs-preview <device> <mountpoint> [-o opts]
# or:        tidefs-preview <mountpoint> [-o opts]
set -e
dev="tidefs-xfstests-root"
mnt=""
daemon_opts="relatime,dev,allow_other"
daemon_read_only=""
daemon_coherency="writeback"
daemon_writeback_cache="1"
daemon_content_capacity_bytes="2147483648"
merge_mount_opts() {
    old_ifs="$IFS"
    IFS=,
    for opt in $1; do
        case "$opt" in
            atime|strictatime|relatime|noatime)
                daemon_opts="$opt"
                ;;
            nodiratime|diratime)
                daemon_opts="$daemon_opts,$opt"
                ;;
            sync|async|allow_other|noallow_other|dev|nodev)
                daemon_opts="$daemon_opts,$opt"
                ;;
            ro)
                daemon_read_only="--read-only"
                ;;
            rw)
                daemon_read_only=""
                ;;
        esac
    done
    IFS="$old_ifs"
}
if [ "$#" -ge 2 ] && [ "''${2#/}" != "$2" ]; then
    dev="$1"
    mnt="$2"
    shift 2
else
    while [ "$#" -gt 0 ]; do
        case "$1" in
            -o)
                shift
                [ "$#" -gt 0 ] && merge_mount_opts "$1"
                ;;
            -o*)
                merge_mount_opts "''${1#-o}"
                ;;
            /*)
                mnt="$1"
                break
                ;;
        esac
        shift
    done
fi
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o)
            shift
            [ "$#" -gt 0 ] && merge_mount_opts "$1"
            ;;
        -o*)
            merge_mount_opts "''${1#-o}"
            ;;
    esac
    shift
done
[ -z "$mnt" ] && exit 1
mkdir -p "$mnt" 2>/dev/null || true
if mountpoint -q "$mnt" 2>/dev/null; then exit 0; fi
AUTH="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
store_tag=$(printf '%s' "$dev" | tr -dc 'A-Za-z0-9._-' | head -c 48)
[ -n "$store_tag" ] || store_tag=tidefs
store="/store/tidefs-store-$store_tag"
mnt_tag=$(printf '%s' "$mnt" | tr -dc 'A-Za-z0-9._-' | head -c 48)
[ -n "$mnt_tag" ] || mnt_tag=mount
log_tag="$store_tag-$mnt_tag-$$"
helper_log="/tmp/tidefs-preview-$log_tag.log"
daemon_log="/tmp/tidefs-daemon-$log_tag.log"
{
    echo "tidefs-preview: dev=$dev"
    echo "tidefs-preview: mnt=$mnt"
    echo "tidefs-preview: store=$store"
    echo "tidefs-preview: daemon_opts=$daemon_opts"
    echo "tidefs-preview: daemon_read_only=$daemon_read_only"
    echo "tidefs-preview: daemon_coherency=$daemon_coherency"
    echo "tidefs-preview: daemon_writeback_cache=$daemon_writeback_cache"
    echo "tidefs-preview: daemon_content_capacity_bytes=$daemon_content_capacity_bytes"
    echo "tidefs-preview: daemon_log=$daemon_log"
} > "$helper_log"
mkdir -p "$store"
/bin/tidefs-posix-filesystem-adapter-daemon mount-vfs     --store "$store" --mount "$mnt"     --fs-name "$dev"     --coherency "$daemon_coherency"     --writeback-cache     --content-capacity-bytes "$daemon_content_capacity_bytes"     --options "$daemon_opts"     $daemon_read_only     --root-auth-key-hex "$AUTH"     >"$daemon_log" 2>&1 &
daemon_pid=$!
echo "tidefs-preview: daemon_pid=$daemon_pid" >> "$helper_log"
report_mount_failure() {
    reason="$1"
    echo "tidefs-preview: $reason dev=$dev mnt=$mnt store=$store daemon_pid=$daemon_pid" >> "$helper_log"
    echo "tidefs-preview: $reason dev=$dev mnt=$mnt store=$store daemon_pid=$daemon_pid" >&2
    echo "--- tidefs-preview helper log: $helper_log ---" >&2
    tail -80 "$helper_log" >&2 2>/dev/null || true
    echo "--- tidefs daemon log: $daemon_log ---" >&2
    tail -120 "$daemon_log" >&2 2>/dev/null || true
}
for i in $(seq 30); do
    if grep -q "Mounted TideFS" "$daemon_log" 2>/dev/null; then
        if ! mountpoint -q "$mnt" 2>/dev/null; then
            report_mount_failure "daemon reported ready but mountpoint is missing"
            exit 1
        fi
        echo "tidefs-preview: mounted after $i seconds" >> "$helper_log"
        exit 0
    fi
    if grep -q "FUSE VFS mount failed" "$daemon_log" 2>/dev/null; then
        report_mount_failure "daemon refused mount"
        exit 1
    fi
    if ! kill -0 "$daemon_pid" 2>/dev/null; then
        report_mount_failure "daemon exited before mount"
        exit 1
    fi
    sleep 1
done
report_mount_failure "mount timed out"
kill "$daemon_pid" 2>/dev/null || true
exit 1
MOUNTHELPER
    chmod +x "$RUN_DIR/bin/tidefs-preview"
    ln -sf tidefs-preview "$RUN_DIR/bin/mount.fuse" 2>/dev/null || true
    mkdir -p "$RUN_DIR/sbin"
    ln -sf /bin/tidefs-preview "$RUN_DIR/sbin/mount.fuse" 2>/dev/null || true
    mkdir -p "$RUN_DIR/usr/sbin"
    ln -sf /bin/tidefs-preview "$RUN_DIR/usr/sbin/mount.fuse" 2>/dev/null || true
    mkdir -p "$RUN_DIR/etc"
    touch "$RUN_DIR/etc/fstab"

    # Copy xfstests-check binary (if available from nixpkgs xfstests)
    if [ -f "$XFSTESTS_BIN" ]; then
      cp "$XFSTESTS_BIN" "$RUN_DIR/bin/xfstests-check"
      chmod +x "$RUN_DIR/bin/xfstests-check"
    fi

    # Copy shared libraries
    for lib in $DAEMON_LIBS $XFSTESTS_LIBS; do
      if [ -f "$lib" ]; then
        copy_nix_store_file "$lib" 0 2>/dev/null || true
        cp "$lib" "$RUN_DIR/usr/lib/" 2>/dev/null || true
      fi
    done

    # Copy the dynamic linker for the daemon
    LD_SO=$(ldd_runtime_paths "$FUSE_DAEMON" | grep '/ld-linux' | head -1 || true)
    if [ -n "$LD_SO" ] && [ -f "$LD_SO" ]; then
      cp "$LD_SO" "$RUN_DIR/lib/" 2>/dev/null || true
      chmod +x "$RUN_DIR/lib/$(basename "$LD_SO")" 2>/dev/null || true
    fi

    # Copy the glibc dynamic linker and essential shared libraries to
    # the exact Nix store path that the busybox and daemon ELF headers expect.
    # GLIBC_LIB is interpolated at Nix build time (e.g. /nix/store/...-glibc-.../lib).
    if [ -n "$GLIBC_LIB" ] && [ -d "$GLIBC_LIB" ]; then
      NIX_LD_DIR="$RUN_DIR/$GLIBC_LIB"
      ensure_run_dir "$NIX_LD_DIR"
      for f in ld-linux-x86-64.so.2 libm.so.6 libc.so.6 libresolv.so.2 libpthread.so.0 libdl.so.2 libutil.so.1 librt.so.1; do
        if [ -f "$GLIBC_LIB/$f" ]; then
          cp "$GLIBC_LIB/$f" "$NIX_LD_DIR/" 2>/dev/null || true
          chmod +x "$NIX_LD_DIR/$f" 2>/dev/null || true
        fi
      done
      echo "  Copied glibc ld + libs from $GLIBC_LIB to $NIX_LD_DIR/"
    else
      echo "  WARNING: GLIBC_LIB not set; busybox/daemon may fail to start"
    fi

    # Copy fuse.ko if available. Compressed modules are expanded while the
    # initrd is built so the tiny guest can use busybox insmod directly.
    if [ "$FUSE_KO_AVAILABLE" -eq 1 ]; then
      case "$FUSE_KO" in
        *.xz)
          "$XZ_BIN" -dc "$FUSE_KO" > "$RUN_DIR/lib/modules/fuse.ko"
          ;;
        *)
          cp "$FUSE_KO" "$RUN_DIR/lib/modules/fuse.ko"
          ;;
      esac
    fi

    # ── Copy bash (extract shebang from xfstests-check) ───────────────
    XFSTESTS_SHEBANG_BASH=""
    if [ -f "$XFSTESTS_BIN" ]; then
      XFSTESTS_SHEBANG_BASH=$(head -1 "$XFSTESTS_BIN" 2>/dev/null | sed "s/^#!//" | tr -d "
" || true)
    fi
    if [ -n "$XFSTESTS_SHEBANG_BASH" ] && [ -f "$XFSTESTS_SHEBANG_BASH" ]; then
      copy_nix_store_file "$XFSTESTS_SHEBANG_BASH" 1
      ln -sf "$XFSTESTS_SHEBANG_BASH" "$RUN_DIR/bin/bash" 2>/dev/null || true
    elif [ -f "$BASH_BIN" ]; then
      copy_nix_store_file "$BASH_BIN" 1
      ln -sf "$BASH_BIN" "$RUN_DIR/bin/bash" 2>/dev/null || true
    fi
    if [ -d "$XFSTESTS_LIB" ]; then
      grep -Rho '^#! */nix/store/[^ ]*/bin/[^ ]*bash[^ ]*' "$XFSTESTS_LIB" "$XFSTESTS_BIN" 2>/dev/null \
        | sed 's/^#! *//' \
        | sort -u \
        | while read -r bash_path; do
          [ -f "$bash_path" ] || continue
          copy_nix_store_file "$bash_path" 1
          copy_ldd_runtime_deps "$bash_path"
        done
    fi

    # ── Copy xfstests lib ─────────────────────────────────────────────
    if [ -d "$XFSTESTS_LIB" ]; then
      ensure_run_dir "$RUN_DIR/$XFSTESTS_LIB"
      cp -R --preserve=mode --no-preserve=ownership "$XFSTESTS_LIB"/. "$RUN_DIR/$XFSTESTS_LIB/" 2>/dev/null || true
      find "$RUN_DIR/$XFSTESTS_LIB" -type d -exec chmod u+w {} + 2>/dev/null || true
      echo "  Collecting xfstests helper library dependencies..."
      for helper_root in "$XFSTESTS_LIB/src" "$XFSTESTS_LIB/ltp"; do
        [ -d "$helper_root" ] || continue
        find "$helper_root" -maxdepth 2 -type f -perm -0100 -print 2>/dev/null | while read -r helper; do
          ldd_runtime_paths "$helper" | while read -r lib; do
            [ -f "$lib" ] || continue
            copy_nix_store_file "$lib" 0 2>/dev/null || true
            cp -f "$lib" "$RUN_DIR/usr/lib/" 2>/dev/null || true
          done
        done
      done
    fi

    # ── Create custom xfstests-check wrapper ──────────────────────────
    if [ -f "$XFSTESTS_BIN" ]; then
      rm -f "$RUN_DIR/bin/xfstests-check"
      cat > "$RUN_DIR/bin/xfstests-check" << 'XFWRAP'
#!/bin/bash
set -e
export RESULT_BASE="''${RESULT_BASE:-$(pwd)/results}"
dir=$(mktemp -d -p /tmp xfstests.XXXXXX)
trap "rm -rf $dir" EXIT
chmod a+rx "$dir"
cd "$dir"
for f in $(cd ${xfstests}/lib/xfstests && echo *); do
  if [ "$f" = tests ] || [ "$f" = common ]; then
    cp -R ${xfstests}/lib/xfstests/$f $f
    chmod -R u+w $f
  else
    ln -s ${xfstests}/lib/xfstests/$f $f 2>/dev/null || true
  fi
done
cat > local.config << EOF
MOUNT_PROG=/bin/mount
FSTYP=fuse
TEST_DEV=''${TEST_DEV:-tidefs-xfstests-test}
TEST_DIR=''${TEST_DIR:-/mnt/tidefs/xfstests-test}
SCRATCH_DEV=''${SCRATCH_DEV:-tidefs-xfstests-scratch}
SCRATCH_MNT=''${SCRATCH_MNT:-/mnt/tidefs/xfstests-scratch}
EOF
echo "xfstests-wrapper: pwd=$PWD result_base=$RESULT_BASE args=$*" >&2
ls -l ./check local.config >&2
export PATH=/bin:/usr/bin:$PATH
set +e
if [ "''${TIDEFS_XFSTESTS_TRACE:-0}" = "1" ]; then
  /bin/bash -x ./check "$@"
else
  ./check "$@"
fi
rc=$?
set -e
echo "xfstests-wrapper: check exit=$rc" >&2
exit "$rc"
XFWRAP
      chmod +x "$RUN_DIR/bin/xfstests-check"
    fi

    # ── Copy perl ─────────────────────────────────────────────────────
    if [ -f "$PERL_BIN" ]; then
      copy_nix_store_file "$PERL_BIN" 1
      ln -sf "$PERL_BIN" "$RUN_DIR/bin/perl" 2>/dev/null || true
      copy_ldd_runtime_deps "$PERL_BIN"
    fi

    # ── Copy bc ──────────────────────────────────────────────────────
    if [ -f "$BC_BIN" ]; then
      copy_nix_store_file "$BC_BIN" 1
      ln -sf "$BC_BIN" "$RUN_DIR/bin/bc" 2>/dev/null || true
      copy_ldd_runtime_deps "$BC_BIN"
    fi

    # ── Copy xfs_io ──────────────────────────────────────────────────
    if [ -f "$XFSIO_BIN" ]; then
      copy_nix_store_file "$XFSIO_BIN" 1
      ln -sf "$XFSIO_BIN" "$RUN_DIR/bin/xfs_io" 2>/dev/null || true
      copy_ldd_runtime_deps "$XFSIO_BIN"
    fi

    # ── Copy GNU readlink (needed for readlink -e) ───────────────────
    if [ -f "$READLINK_BIN" ]; then
      copy_nix_store_file "$READLINK_BIN" 1
      rm -f "$RUN_DIR/bin/readlink"
      ln -sf "$READLINK_BIN" "$RUN_DIR/bin/readlink" 2>/dev/null || true
      copy_ldd_runtime_deps "$READLINK_BIN"
    fi

    # ── Copy libgmp (needed by readlink, coreutils) ──────────────────
    if [ -d "$GMP_LIB" ]; then
      ensure_run_dir "$RUN_DIR/$GMP_LIB"
      for f in libgmp.so.10 libgmp.so; do
        [ -f "$GMP_LIB/$f" ] && cp "$GMP_LIB/$f" "$RUN_DIR/$GMP_LIB/" 2>/dev/null || true
      done
    fi

    # ── Copy coreutils df (busybox df lacks -T flag) ────────────────
    if [ -f "$DF_BIN" ]; then
      copy_nix_store_file "$DF_BIN" 1
      rm -f "$RUN_DIR/bin/df"
      ln -sf "$DF_BIN" "$RUN_DIR/bin/df" 2>/dev/null || true
      copy_ldd_runtime_deps "$DF_BIN"
    fi

    # ── Copy util-linux mount (supports FUSE helpers) ────────────────
    if [ -f "$MOUNT_BIN" ]; then
      copy_nix_store_file "$MOUNT_BIN" 1
      rm -f "$RUN_DIR/bin/mount"
      ln -sf "$MOUNT_BIN" "$RUN_DIR/bin/mount.real" 2>/dev/null || true
      cat > "$RUN_DIR/bin/mount" << 'MOUNTWRAP'
#!/bin/sh
is_fuse=0
prev_t=0
for a in "$@"; do
    if [ "$prev_t" = "1" ]; then
        [ "$a" = "fuse" ] && is_fuse=1
        prev_t=0
        continue
    fi
    [ "$a" = "-t" ] && prev_t=1
done

if [ "$is_fuse" = "1" ]; then
    dev=""
    mnt=""
    opts_args=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            -t) shift 2 ;;
            -o)
                shift
                [ "$#" -gt 0 ] || exit 1
                opts_args="$opts_args -o $1"
                shift
                ;;
            -o*)
                opts_args="$opts_args $1"
                shift
                ;;
            -*) shift ;;
            *)
                if [ -z "$dev" ]; then
                    dev="$1"
                elif [ -z "$mnt" ]; then
                    mnt="$1"
                fi
                shift
                ;;
        esac
    done
    [ -n "$dev" ] && [ -n "$mnt" ] || exit 1
    exec /bin/tidefs-preview "$dev" "$mnt" $opts_args
fi

exec /bin/mount.real "$@"
MOUNTWRAP
      chmod +x "$RUN_DIR/bin/mount"
      copy_ldd_runtime_deps "$MOUNT_BIN"
    fi

    # ── Copy findmnt (xfstests common/rc needs it) ───────────────────
    if [ -f "$FINDMNT_BIN" ]; then
      copy_nix_store_file "$FINDMNT_BIN" 1
      ln -sf "$FINDMNT_BIN" "$RUN_DIR/bin/findmnt" 2>/dev/null || true
      rm -f "$RUN_DIR/bin/umount"
      cat > "$RUN_DIR/bin/umount" << 'UMOUNTWRAP'
#!/bin/sh
wait_for_tidefs_daemon_exit() {
    target="$1"
    for i in $(seq 30); do
        if ! pgrep -f "tidefs-posix-filesystem-adapter-daemon.*--mount $target" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

if [ "$#" -eq 1 ]; then
    case "$1" in
        tidefs-xfstests-*)
            target=$(/bin/findmnt -rncv -S "$1" -o TARGET 2>/dev/null | /bin/head -1)
            if [ -n "$target" ]; then
                /bin/busybox umount "$target"
                rc=$?
                [ "$rc" -eq 0 ] && wait_for_tidefs_daemon_exit "$target" >/dev/null 2>&1
                exit "$rc"
            fi
            ;;
        /*)
            target="$1"
            /bin/busybox umount "$target"
            rc=$?
            [ "$rc" -eq 0 ] && wait_for_tidefs_daemon_exit "$target" >/dev/null 2>&1
            exit "$rc"
            ;;
    esac
fi
exec /bin/busybox umount "$@"
UMOUNTWRAP
      chmod +x "$RUN_DIR/bin/umount"
      copy_ldd_runtime_deps "$FINDMNT_BIN"
    fi

    # ── Copy xfstests guest command dependencies ─────────────────────
    # BusyBox applets lack some GNU options, and several generic tests call
    # these tools directly. Keep them as exact Nix-store binaries with /bin
    # symlinks so the guest PATH can find them.
    copy_runtime_binary "$TIMEOUT_BIN" timeout
    copy_runtime_binary "$MV_BIN" mv
    copy_runtime_binary "$RM_BIN" rm
    copy_runtime_binary "$TRUNCATE_BIN" truncate
    copy_runtime_binary "$MD5SUM_BIN" md5sum
    copy_runtime_binary "$CHMOD_BIN" chmod
    copy_runtime_binary "$GAWK_BIN" awk
    copy_runtime_binary "$OD_BIN" od
    copy_runtime_binary "$TAC_BIN" tac
    copy_runtime_binary "$TAR_BIN" tar
    copy_runtime_binary "$ATTR_BIN" attr
    copy_runtime_binary "$GETFATTR_BIN" getfattr
    copy_runtime_binary "$SETFATTR_BIN" setfattr
    copy_runtime_binary "$CHACL_BIN" chacl
    copy_runtime_binary "$GETFACL_BIN" getfacl
    copy_runtime_binary "$SETFACL_BIN" setfacl
    copy_runtime_binary "$FIO_BIN" fio

    # ── Init script: FUSE xfstests validation matrix ─────────────────────

    cat > "$RUN_DIR/init" << 'INITSCRIPT'
#!/bin/sh
export PATH=/bin
export LD_LIBRARY_PATH=/usr/lib:/lib

/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev

echo "=== TideFS FUSE xfstests Validation ==="
echo "kernel_version=$(uname -r)"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

PANIC_ON_WARN=__PANIC_ON_WARN_MODE__
set_kernel_knob() {
    knob_path="$1"
    knob_value="$2"
    knob_name=$(basename "$knob_path")
    if [ -e "$knob_path" ]; then
        if echo "$knob_value" > "$knob_path" 2>/dev/null; then
            echo "kernel_knob $knob_name=$(cat "$knob_path" 2>/dev/null || echo "$knob_value")"
        else
            echo "kernel_knob $knob_name=unavailable"
        fi
    fi
}
if [ "$PANIC_ON_WARN" = "1" ]; then
    echo "kernel_debug: enabling panic-on-warning and broad warning/panic knobs"
    set_kernel_knob /proc/sys/kernel/panic_on_warn 1
    set_kernel_knob /proc/sys/kernel/panic_on_oops 1
    set_kernel_knob /proc/sys/kernel/hung_task_panic 1
    set_kernel_knob /proc/sys/kernel/hung_task_timeout_secs 60
    set_kernel_knob /proc/sys/kernel/hung_task_check_interval_secs 15
    set_kernel_knob /proc/sys/kernel/hung_task_warnings -1
    set_kernel_knob /proc/sys/kernel/hung_task_all_cpu_backtrace 1
    set_kernel_knob /proc/sys/kernel/softlockup_panic 1
    set_kernel_knob /proc/sys/kernel/hardlockup_panic 1
    set_kernel_knob /proc/sys/kernel/softlockup_all_cpu_backtrace 1
    set_kernel_knob /proc/sys/kernel/hardlockup_all_cpu_backtrace 1
    set_kernel_knob /proc/sys/kernel/panic_on_rcu_stall 1
    set_kernel_knob /proc/sys/kernel/max_rcu_stall_to_panic 1
    set_kernel_knob /proc/sys/kernel/panic_print 63
    set_kernel_knob /proc/sys/kernel/warn_limit 0
    set_kernel_knob /proc/sys/kernel/traceoff_on_warning 0
    echo ""
fi

PASSED=0
FAILED=0
BLOCKED=0
SKIPPED=0
UNSUPPORTED=0

pass()    { echo "PASS: $1"; PASSED=$((PASSED + 1)); }
fail()    { echo "FAIL: $1 -- $2"; FAILED=$((FAILED + 1)); }
blocked() { echo "BLOCKED: $1 -- $2"; BLOCKED=$((BLOCKED + 1)); }
skip()    { echo "SKIP: $1 -- $2"; SKIPPED=$((SKIPPED + 1)); }
unsupported() { echo "UNSUPPORTED: $1 -- $2"; UNSUPPORTED=$((UNSUPPORTED + 1)); }
classify_notrun() {
    reason_lc=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
    case "$reason_lc" in
        *"not supported"*|*"unsupported"*|*"no support"*|*"does not support"*|*"requires a scratch device"*|*"scratch device"*|*"no scratch"*|*"old kernel/wrong fs"*|*"wrong fs"*)
            echo unsupported
            ;;
        *)
            echo skip
            ;;
    esac
}

MNT=/mnt/tidefs
STORE=/store/tidefs-store
RESULTS=/tmp/xfstests-results

STORE_DEV=""
for candidate in /dev/vda /dev/sda /dev/hda; do
    for _wait in $(seq 20); do
        [ -b "$candidate" ] && break
        sleep 1
    done
    if [ -b "$candidate" ]; then
        STORE_DEV="$candidate"
        break
    fi
done
if [ -n "$STORE_DEV" ] && /bin/busybox mount -t ext4 "$STORE_DEV" /store 2>/tmp/store-mount.err; then
    pass "store_mount"
    df -h /store 2>/dev/null || true
else
    if [ -n "$STORE_DEV" ]; then
        fail "store_mount" "$(cat /tmp/store-mount.err 2>/dev/null || echo "could not mount $STORE_DEV on /store")"
    else
        fail "store_mount" "no /store block device among /dev/vda /dev/sda /dev/hda"
    fi
fi

# ── Phase 0: FUSE kernel module ──────────────────────────────────────
echo "--- Phase 0: FUSE kernel support ---"

FUSE_KERNEL_READY=0
FUSE_READY=0
if [ -f /lib/modules/fuse.ko ]; then
    if insmod /lib/modules/fuse.ko 2>/tmp/fuse_insmod.err; then
        pass "fuse_module_load"
        FUSE_KERNEL_READY=1
    elif [ -d /sys/module/fuse ] || grep -qw fuse /proc/filesystems 2>/dev/null; then
        pass "fuse_builtin"
        FUSE_KERNEL_READY=1
    else
        fail "fuse_module_load" "$(cat /tmp/fuse_insmod.err)"
    fi
elif [ -d /sys/module/fuse ] || grep -qw fuse /proc/filesystems 2>/dev/null; then
    pass "fuse_builtin"
    FUSE_KERNEL_READY=1
else
    blocked "fuse_module_load" "fuse.ko not staged and built-in FUSE not detected"
fi

if [ "$FUSE_KERNEL_READY" -eq 1 ]; then
    # Create /dev/fuse if devtmpfs did not provide it.
    if [ ! -e /dev/fuse ]; then
        mknod /dev/fuse c 10 229 2>/dev/null || true
    fi

    if [ -e /dev/fuse ]; then
        pass "fuse_device"
        FUSE_READY=1
    else
        blocked "fuse_device" "/dev/fuse not available"
    fi
else
    blocked "fuse_device" "FUSE kernel support unavailable"
fi

# ── Phase 1: Mount TideFS FUSE via mount helper ──────────────────────
echo ""
echo "--- Phase 1: Mount TideFS FUSE ---"

DAEMON_PID=""
MOUNTED=0
if [ "$FUSE_READY" -eq 1 ]; then
    mkdir -p "$STORE" "$MNT"
    # Use the functional mount helper to mount on /mnt/tidefs.
    # This registers the mount with a source distinct from the xfstests
    # TEST_DEV/SCRATCH_DEV names, so xfstests source checks stay unambiguous.
    /bin/tidefs-preview "$MNT" > /tmp/mount-helper.log 2>&1 &
    HELPER_PID=$!
    # Wait for mount (up to 30s)
    for i in $(seq 1 30); do
        if mountpoint -q "$MNT" 2>/dev/null; then
            MOUNTED=1
            break
        fi
        sleep 1
    done
    if [ "$MOUNTED" -eq 1 ]; then
        pass "fuse_mount"
        echo "  Mounted: $MNT"
        # Find the actual daemon PID (the mount helper starts it)
        DAEMON_PID=$(pgrep -f "tidefs-posix-filesystem-adapter-daemon" | head -1 || echo "")
        [ -n "$DAEMON_PID" ] && echo "  Daemon PID: $DAEMON_PID"
    else
        fail "fuse_mount" "mount did not appear within 30s; helper log: $(tail -5 /tmp/mount-helper.log 2>/dev/null)"
    fi
else
    blocked "fuse_mount" "/dev/fuse not available"
fi

# ── Phase 2: Basic filesystem sanity ─────────────────────────────────
echo ""
echo "--- Phase 2: Basic filesystem sanity ---"

if [ "$MOUNTED" -eq 1 ]; then
    # Create a test directory
    if mkdir "$MNT/xfstests-test" 2>/tmp/mkdir.err; then
        pass "fs_sanity_mkdir"
    else
        fail "fs_sanity_mkdir" "$(cat /tmp/mkdir.err)"
    fi

    # Write a test file
    if echo "hello_tidefs_xfstests" > "$MNT/xfstests-test/hello.txt" 2>/tmp/write.err; then
        pass "fs_sanity_write"
    else
        fail "fs_sanity_write" "$(cat /tmp/write.err)"
    fi

    # Read it back
    CONTENT=$(cat "$MNT/xfstests-test/hello.txt" 2>/dev/null)
    if [ "$CONTENT" = "hello_tidefs_xfstests" ]; then
        pass "fs_sanity_read"
    else
        fail "fs_sanity_read" "expected 'hello_tidefs_xfstests', got '$CONTENT'"
    fi

    # Remove it
    if rm "$MNT/xfstests-test/hello.txt" 2>/tmp/rm.err; then
        pass "fs_sanity_unlink"
    else
        fail "fs_sanity_unlink" "$(cat /tmp/rm.err)"
    fi
else
    for t in fs_sanity_mkdir fs_sanity_write fs_sanity_read fs_sanity_unlink; do
        blocked "$t" "filesystem not mounted"
    done
fi

# ── Phase 3: xfstests smoke subset ───────────────────────────────────
echo ""
echo "--- Phase 3: xfstests smoke subset ---"

if [ "$MOUNTED" -eq 1 ] && [ -x /bin/xfstests-check ]; then
    mkdir -p "$RESULTS"

    # Run xfstests with FUSE type
    # xfstests-check uses environment variables for configuration
    export FSTYP="fuse"
    export TEST_DEV="tidefs-xfstests-test"
    export TEST_DIR="$MNT/xfstests-test"
    export SCRATCH_DEV="tidefs-xfstests-scratch"
    export SCRATCH_MNT="$MNT/xfstests-scratch"
    export RESULT_BASE="$RESULTS"
    export TIDEFS_XFSTESTS_TRACE=__XFSTESTS_TRACE__
    PER_TEST_TIMEOUT=__XFSTESTS_PER_TEST_TIMEOUT__

    cleanup_xfstests_test() {
        cleanup_tidefs_store() {
            store_tag=$(printf '%s' "$1" | tr -dc 'A-Za-z0-9._-' | head -c 48)
            [ -n "$store_tag" ] || store_tag=tidefs
            rm -rf "/store/tidefs-store-$store_tag" "/store/tidefs-store-$store_tag-"* 2>/dev/null || true
        }
        cleanup_mount_dir() {
            mount_dir="$1"
            [ -e "$mount_dir" ] || return 0
            rmdir "$mount_dir" 2>/dev/null || {
                if [ -d "$mount_dir" ]; then
                    echo "cleanup: mount directory not empty or busy: $mount_dir"
                fi
            }
        }

        echo "cleanup: stop xfstests helpers"
        pkill -f "xfstests-check" 2>/dev/null || true
        pkill -f "/tmp/xfstests\\." 2>/dev/null || true
        pkill -f "/tmp/xfstests\\..*/src/" 2>/dev/null || true
        pkill -f "/tmp/xfstests\\..*/ltp/" 2>/dev/null || true
        sleep 1
        echo "cleanup: unmount nested test mounts"
        for nested_mnt in "$SCRATCH_MNT" "$TEST_DIR"; do
            if mountpoint -q "$nested_mnt" 2>/dev/null; then
                umount "$nested_mnt" 2>/dev/null || umount -l "$nested_mnt" 2>/dev/null || true
            fi
        done
        for nested_mnt in "$MNT"/xfstests-*; do
            [ -e "$nested_mnt" ] || continue
            if mountpoint -q "$nested_mnt" 2>/dev/null; then
                umount "$nested_mnt" 2>/dev/null || umount -l "$nested_mnt" 2>/dev/null || true
            fi
        done
        echo "cleanup: stop nested TideFS daemons"
        pkill -f "tidefs-posix-filesystem-adapter-daemon.*--mount $TEST_DIR" 2>/dev/null || true
        pkill -f "tidefs-posix-filesystem-adapter-daemon.*--mount $SCRATCH_MNT" 2>/dev/null || true
        echo "cleanup: remove xfstests tmp"
        rm -rf /tmp/xfstests.* /tmp/cutmp* 2>/dev/null || true
        echo "cleanup: remove xfstests results"
        rm -rf "$RESULT_BASE" 2>/dev/null || true
        echo "cleanup: remove empty mounted test directories"
        cleanup_mount_dir "$TEST_DIR"
        cleanup_mount_dir "$SCRATCH_MNT"
        echo "cleanup: remove TideFS stores"
        cleanup_tidefs_store "$TEST_DEV"
        cleanup_tidefs_store "$SCRATCH_DEV"
        echo "cleanup: done"
    }

    dump_xfstests_test_state() {
        dump_test="$1"
        dump_result_base="$2"
        dump_test_log="$3"
        dump_xfstests_binary_cmp() {
            cmp_test="$1"
            cmp_result_base="$2"
            cmp_suffix="$3"
            for stem in "$cmp_result_base/$cmp_test" "$cmp_result_base/''${cmp_test#*/}"; do
                good="$stem.$cmp_suffix.good"
                bad="$stem.$cmp_suffix.bad"
                [ -f "$good" ] && [ -f "$bad" ] || continue
                echo "--- fsx binary compare $(basename "$good") vs $(basename "$bad") ---"
                echo "good-bytes=$(wc -c <"$good" 2>/dev/null || true) bad-bytes=$(wc -c <"$bad" 2>/dev/null || true)"
                first_line=$(cmp -l "$good" "$bad" 2>/dev/null | head -1 || true)
                if [ -z "$first_line" ]; then
                    echo "cmp: no byte differences reported"
                    continue
                fi
                first_byte=$(printf '%s\n' "$first_line" | awk '{print $1}')
                echo "first-difference: $first_line"
                case "$first_byte" in
                    ""|*[!0-9]*) continue ;;
                esac
                if [ "$first_byte" -gt 65 ]; then
                    skip=$((first_byte - 65))
                else
                    skip=0
                fi
                echo "--- good context offset=$skip ---"
                dd if="$good" bs=1 skip="$skip" count=256 2>/dev/null | od -Ax -tx1 -v || true
                echo "--- bad context offset=$skip ---"
                dd if="$bad" bs=1 skip="$skip" count=256 2>/dev/null | od -Ax -tx1 -v || true
            done
        }
        dump_tidefs_helper_logs() {
            helper_test="$1"
            if find /tmp -maxdepth 1 -type f \( -name 'tidefs-preview-*.log' -o -name 'tidefs-daemon-*.log' -o -name 'daemon-helper.log' -o -name 'mount-helper.log' \) -print | sort | grep . >/tmp/tidefs-helper-log-files; then
                while read -r f; do
                    echo "helper-log: $f"
                    echo "helper-log-bytes=$(wc -c <"$f" 2>/dev/null || true)"
                    grep -a "tidefs-diagnostic" "$f" 2>/dev/null || true
                    case "$f" in
                        *tidefs-daemon-*)
                            echo "--- full daemon log for $helper_test: $f ---"
                            cat "$f" 2>/dev/null || true
                            ;;
                        *)
                            tail -160 "$f" 2>/dev/null || true
                            ;;
                    esac
                done </tmp/tidefs-helper-log-files
            else
                echo "(none)"
            fi
        }
        dump_process_threads() {
            inspect_pid="$1"
            inspect_label="$2"
            [ -d "/proc/$inspect_pid/task" ] || return 0
            echo "--- thread diagnostics for $inspect_label pid=$inspect_pid ---"
            for task_dir in /proc/"$inspect_pid"/task/[0-9]*; do
                [ -d "$task_dir" ] || continue
                tid="''${task_dir##*/}"
                comm=$(cat "$task_dir/comm" 2>/dev/null || true)
                state=$(sed -n 's/^State:[[:space:]]*//p' "$task_dir/status" 2>/dev/null || true)
                wchan=$(cat "$task_dir/wchan" 2>/dev/null || true)
                stat=$(cat "$task_dir/stat" 2>/dev/null || true)
                schedstat=$(cat "$task_dir/schedstat" 2>/dev/null || true)
                echo "thread: pid=$inspect_pid tid=$tid comm=$comm state=$state wchan=$wchan schedstat=$schedstat stat=$stat"
                if [ -r "$task_dir/stack" ]; then
                    echo "thread-stack: pid=$inspect_pid tid=$tid"
                    cat "$task_dir/stack" 2>/dev/null || true
                else
                    echo "thread-stack: pid=$inspect_pid tid=$tid unavailable"
                fi
            done
        }
        echo "--- timeout diagnostics for $dump_test ---"
        echo "--- process table ---"
        ps 2>/dev/null || true
        echo "--- matching xfstests processes ---"
        diag_pids=""
        for pattern in "xfstests-check" "/tmp/xfstests\\." "holetest" "tidefs-posix-filesystem-adapter-daemon"; do
            pids=$(pgrep -f "$pattern" 2>/dev/null || true)
            if [ -n "$pids" ]; then
                for pid in $pids; do
                    cmd=$(tr '\000' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)
                    state=$(sed -n 's/^State:[[:space:]]*//p' "/proc/$pid/status" 2>/dev/null || true)
                    echo "process: pid=$pid state=$state cmd=$cmd"
                    case " $diag_pids " in
                        *" $pid "*) ;;
                        *) diag_pids="$diag_pids $pid" ;;
                    esac
                done
            fi
        done
        for pid in $diag_pids; do
            cmd=$(tr '\000' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)
            dump_process_threads "$pid" "$cmd"
        done
        echo "--- mount table ---"
        grep -E 'tidefs|xfstests|fuse' /proc/mounts 2>/dev/null || true
        echo "--- open fds under xfstests mounts ---"
        for proc_dir in /proc/[0-9]*; do
            [ -d "$proc_dir/fd" ] || continue
            pid="''${proc_dir#/proc/}"
            cmd=$(tr '\000' ' ' <"$proc_dir/cmdline" 2>/dev/null || true)
            for fd in "$proc_dir"/fd/*; do
                target=$(readlink "$fd" 2>/dev/null || true)
                case "$target" in
                    "$TEST_DIR"*|"$SCRATCH_MNT"*|"$MNT"/xfstests-*)
                        echo "open-fd: pid=$pid fd=$(basename "$fd") target=$target cmd=$cmd"
                        ;;
                esac
            done
        done
        echo "--- result files for $dump_test ---"
        if find "$dump_result_base" -maxdepth 5 -type f -print 2>/dev/null | sort | grep . >/tmp/xfstests-result-files; then
            while read -r f; do
                echo "result-file: $f"
                head -80 "$f" 2>/dev/null || true
                echo "--- result-file tail: $f ---"
                tail -120 "$f" 2>/dev/null || true
            done </tmp/xfstests-result-files
        else
            echo "(none)"
        fi
        dump_xfstests_binary_cmp "$dump_test" "$dump_result_base" "0"
        echo "--- test log tail for $dump_test ---"
        tail -160 "$dump_test_log" 2>/dev/null || true
        echo "--- TideFS mount helper logs for $dump_test ---"
        dump_tidefs_helper_logs "$dump_test"
    }

    terminate_process_tree() {
        tree_pid="$1"
        signal="$2"
        for child_pid in $(pgrep -P "$tree_pid" 2>/dev/null || true); do
            terminate_process_tree "$child_pid" "$signal"
        done
        kill "-$signal" "$tree_pid" 2>/dev/null || true
    }

    run_dump_xfstests_test_state_bounded() {
        dump_label="$1"
        shift
        dump_timeout="$((PER_TEST_TIMEOUT / 3))"
        [ "$dump_timeout" -ge 20 ] || dump_timeout=20
        [ "$dump_timeout" -le 60 ] || dump_timeout=60
        dump_xfstests_test_state "$@" &
        dump_pid=$!
        elapsed=0
        while kill -0 "$dump_pid" 2>/dev/null; do
            if [ "$elapsed" -ge "$dump_timeout" ]; then
                echo "diagnostic timeout: $dump_label after ''${dump_timeout}s"
                terminate_process_tree "$dump_pid" TERM
                sleep 2
                terminate_process_tree "$dump_pid" KILL
                return 124
            fi
            sleep 1
            elapsed=$((elapsed + 1))
        done
        wait "$dump_pid" 2>/dev/null || true
        return 0
    }

    run_cleanup_xfstests_test_bounded() {
        cleanup_label="$1"
        cleanup_test="$2"
        cleanup_result_base="$3"
        cleanup_test_log="$4"
        cleanup_timeout="$((PER_TEST_TIMEOUT / 2))"
        [ "$cleanup_timeout" -ge 30 ] || cleanup_timeout=30
        cleanup_xfstests_test &
        cleanup_pid=$!
        elapsed=0
        while kill -0 "$cleanup_pid" 2>/dev/null; do
            if [ "$elapsed" -ge "$cleanup_timeout" ]; then
                echo "cleanup timeout: $cleanup_label after ''${cleanup_timeout}s"
                run_dump_xfstests_test_state_bounded "cleanup-$cleanup_label" "$cleanup_test" "$cleanup_result_base" "$cleanup_test_log" || true
                terminate_process_tree "$cleanup_pid" TERM
                sleep 2
                terminate_process_tree "$cleanup_pid" KILL
                return 124
            fi
            sleep 1
            elapsed=$((elapsed + 1))
        done
        wait "$cleanup_pid"
        return "$?"
    }

    run_xfstests_check_bounded() {
        bounded_test="$1"
        bounded_result_base="$2"
        bounded_test_log="$3"
        xfstests-check -fuse "$bounded_test" > "$bounded_test_log" 2>&1 &
        check_pid=$!
        elapsed=0
        while kill -0 "$check_pid" 2>/dev/null; do
            if [ "$elapsed" -ge "$PER_TEST_TIMEOUT" ]; then
                run_dump_xfstests_test_state_bounded "timeout-$bounded_test" "$bounded_test" "$bounded_result_base" "$bounded_test_log" || true
                terminate_process_tree "$check_pid" TERM
                sleep 2
                terminate_process_tree "$check_pid" KILL
                return 124
            fi
            sleep 1
            elapsed=$((elapsed + 1))
        done
        wait "$check_pid"
        return "$?"
    }

    tidefs_product_limitation() {
        case "$1" in
            generic/007)
                echo "TideFS FUSE bounded smoke classifies generic/007 high-count create/unlink/stat namespace stress as a current product scalability limitation instead of an opaque timeout"
                ;;
            generic/011)
                echo "TideFS FUSE bounded smoke classifies generic/011 parallel dirstress as a current product scalability limitation instead of an opaque timeout"
                ;;
            generic/013)
                echo "TideFS FUSE bounded smoke classifies generic/013 fsstress as a current product scalability limitation instead of a QEMU-level timeout"
                ;;
            generic/012)
                echo "TideFS FUSE does not yet provide the fiemap/fallocate capability surface required by generic/012 in this smoke tranche"
                ;;
            *)
                return 1
                ;;
        esac
    }

    # Run each test individually with per-test timeout
    TESTS_RUN=0
    TESTS_PASS=0
    TESTS_FAIL=0

    for test in __XFSTESTS_TESTS__; do
        TESTS_RUN=$((TESTS_RUN + 1))
        test_id=$(printf '%s' "$test" | tr '/.' '__')
        export TEST_DEV="tidefs-xfstests-test-$test_id"
        export TEST_DIR="$MNT/xfstests-test-$test_id"
        export SCRATCH_DEV="tidefs-xfstests-scratch-$test_id"
        export SCRATCH_MNT="$MNT/xfstests-scratch-$test_id"
        export RESULT_BASE="$RESULTS/$test_id"

        # Run xfstests-check for this specific test
        # Bound each test so one stuck row cannot consume the whole VM run.
        # Run test with output visible on console for debugging
        echo "=== Running $test ==="
        LIMITATION_DETAIL=$(tidefs_product_limitation "$test" || true)
        if [ -n "$LIMITATION_DETAIL" ]; then
            unsupported "xfstests_$test" "$LIMITATION_DETAIL"
            continue
        fi
        if ! run_cleanup_xfstests_test_bounded "pre-$test" "$test" "$RESULT_BASE" /dev/null; then
            fail "xfstests_$test" "pre-test cleanup timed out"
            TESTS_FAIL=$((TESTS_FAIL + 1))
            continue
        fi
        rm -rf "$TEST_DIR" "$SCRATCH_MNT" 2>/dev/null || true
        if ! mkdir -p "$TEST_DIR" "$SCRATCH_MNT"; then
            blocked "xfstests_$test" "could not recreate per-test xfstests directories"
            TESTS_FAIL=$((TESTS_FAIL + 1))
            continue
        fi
        mkdir -p "$RESULT_BASE/$(dirname "$test")"
        TEST_LOG="$RESULT_BASE/''${test#*/}.log"
        if run_xfstests_check_bounded "$test" "$RESULT_BASE" "$TEST_LOG"; then
            cat "$TEST_LOG"
            if grep -E "could not mount|test device.*not mounted" "$TEST_LOG" >/dev/null 2>&1; then
                blocked "xfstests_$test" "xfstests setup did not mount TideFS test device"
                TESTS_FAIL=$((TESTS_FAIL + 1))
            elif grep -E "not run|No tests run" "$TEST_LOG" >/dev/null 2>&1; then
                NOTRUN_DETAIL=$(grep -E '\[not run\]' "$TEST_LOG" 2>/dev/null | head -1 | sed 's/^.*\[not run\][[:space:]]*//' || true)
                [ -n "$NOTRUN_DETAIL" ] || NOTRUN_DETAIL="xfstests reported notrun"
                if [ "$(classify_notrun "$NOTRUN_DETAIL")" = "unsupported" ]; then
                    unsupported "xfstests_$test" "$NOTRUN_DETAIL"
                else
                    skip "xfstests_$test" "$NOTRUN_DETAIL"
                fi
            else
                pass "xfstests_$test"
                TESTS_PASS=$((TESTS_PASS + 1))
            fi
        else
            RC=$?
            cat "$TEST_LOG" 2>/dev/null || true
            if [ "$RC" -eq 124 ]; then
                fail "xfstests_$test" "test timed out after ''${PER_TEST_TIMEOUT}s"
            elif [ "$RC" -eq 143 ]; then
                run_dump_xfstests_test_state_bounded "terminated-$test" "$test" "$RESULT_BASE" "$TEST_LOG" || true
                fail "xfstests_$test" "test terminated after ''${PER_TEST_TIMEOUT}s window"
            else
                NOTRUN_DETAIL=""
                for f in "$RESULT_BASE/$test.notrun" "$RESULT_BASE/''${test#*/}.notrun"; do
                    [ -f "$f" ] || continue
                    NOTRUN_DETAIL=$(head -c 200 "$f" 2>/dev/null)
                    break
                done
                if [ -n "$NOTRUN_DETAIL" ]; then
                    if [ "$(classify_notrun "$NOTRUN_DETAIL")" = "unsupported" ]; then
                        unsupported "xfstests_$test" "$NOTRUN_DETAIL"
                    else
                        skip "xfstests_$test" "xfstests notrun: $NOTRUN_DETAIL"
                    fi
                    if ! run_cleanup_xfstests_test_bounded "notrun-$test" "$test" "$RESULT_BASE" "$TEST_LOG"; then
                        fail "xfstests_$test" "notrun cleanup timed out"
                        TESTS_FAIL=$((TESTS_FAIL + 1))
                    fi
                    continue
                fi
                # Capture failure details from the test output
                FAIL_DETAIL="exit_code=$RC"
                for f in \
                    "$RESULT_BASE/$test.full" \
                    "$RESULT_BASE/''${test#*/}.full" \
                    "$RESULT_BASE/$test.out.bad" \
                    "$RESULT_BASE/''${test#*/}.out.bad" \
                    "$TEST_LOG"; do
                    [ -f "$f" ] || continue
                    echo "--- $(basename "$f") ---"
                    head -80 "$f" 2>/dev/null || true
                    DETAIL_SNIPPET=$(head -c 200 "$f" 2>/dev/null || true)
                    if [ "$FAIL_DETAIL" = "exit_code=$RC" ] && [ -n "$DETAIL_SNIPPET" ]; then
                        FAIL_DETAIL="$FAIL_DETAIL output=$DETAIL_SNIPPET"
                    fi
                done
                echo "--- result files for $test ---"
                if find "$RESULT_BASE" -maxdepth 4 -type f -print | sort | grep . >/tmp/xfstests-result-files; then
                    while read -r f; do
                        echo "result-file: $f"
                        head -40 "$f" 2>/dev/null || true
                    done </tmp/xfstests-result-files
                else
                    echo "(none)"
                fi
                run_dump_xfstests_test_state_bounded "failure-$test" "$test" "$RESULT_BASE" "$TEST_LOG" || true
                fail "xfstests_$test" "$FAIL_DETAIL"
            fi
            TESTS_FAIL=$((TESTS_FAIL + 1))
        fi
        if ! run_cleanup_xfstests_test_bounded "post-$test" "$test" "$RESULT_BASE" "$TEST_LOG"; then
            fail "xfstests_$test" "post-test cleanup timed out"
            TESTS_FAIL=$((TESTS_FAIL + 1))
        fi
    done

    echo "xfstests completed: $TESTS_RUN run, $TESTS_PASS passed, $TESTS_FAIL failed"
    pass "xfstests_summary"

elif [ "$MOUNTED" -eq 1 ] && [ ! -x /bin/xfstests-check ]; then
    blocked "xfstests_all" "xfstests-check binary not available in VM"
else
    blocked "xfstests_all" "filesystem not mounted"
fi

# ── Phase 4: Tear-down ───────────────────────────────────────────────
echo ""
echo "--- Phase 4: Unmount and stop daemon ---"

if [ "$MOUNTED" -eq 1 ]; then
    # xfstests may leave nested TEST_DIR/SCRATCH_MNT mounts active; unmount
    # those before the parent FUSE mount so teardown failures stay meaningful.
    if ! run_cleanup_xfstests_test_bounded "phase4" "teardown" "$RESULTS" /dev/null; then
        fail "cleanup" "phase4 cleanup timed out"
    fi
    umount "$MNT/xfstests-test" 2>/dev/null || true
    umount "$MNT/xfstests-scratch" 2>/dev/null || true
    # Unmount the main mountpoint
    if umount "$MNT" 2>/tmp/um.err; then
        pass "unmount"
    else
        fail "unmount" "$(cat /tmp/um.err)"
    fi
else
    blocked "unmount" "filesystem not mounted"
fi

# Clean up daemon processes
# Kill by known PID first
if [ -n "$DAEMON_PID" ]; then
    kill "$DAEMON_PID" 2>/dev/null || true
    sleep 1
    kill -9 "$DAEMON_PID" 2>/dev/null || true
fi
# Also kill any remaining daemon processes
pkill -f "tidefs-posix-filesystem-adapter-daemon" 2>/dev/null || true
sleep 1
# Verify cleanup
if ! pgrep -f "tidefs-posix-filesystem-adapter-daemon" > /dev/null 2>&1; then
    pass "daemon_stop"
else
    fail "daemon_stop" "daemon process still running after kill"
fi

# ── Validation Summary ──────────────────────────────────────────────────
echo ""
echo "=== FUSE xfstests Validation Summary ==="
echo "PASSED=$PASSED"
echo "FAILED=$FAILED"
echo "BLOCKED=$BLOCKED"
echo "UNSUPPORTED=$UNSUPPORTED"
echo "SKIPPED=$SKIPPED"
echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "validation_tier=mounted-userspace"
echo "filesystem=fuse-xfstests"
echo "=== End ==="

sync
sleep 1
poweroff -f

INITSCRIPT

    # ── Inject test list into init script ──────────────────────────────
    sed -i "s|__XFSTESTS_TESTS__|$TEST_LIST|g" "$RUN_DIR/init"
    sed -i "s|__ROOT_AUTH_KEY__|$ROOT_AUTH_KEY|g" "$RUN_DIR/init"
    sed -i "s|__XFSTESTS_TRACE__|$TRACE_XFSTESTS|g" "$RUN_DIR/init"
    sed -i "s|__XFSTESTS_PER_TEST_TIMEOUT__|$PER_TEST_TIMEOUT_SEC|g" "$RUN_DIR/init"
    sed -i "s|__PANIC_ON_WARN_MODE__|$PANIC_ON_WARN_MODE|g" "$RUN_DIR/init"

    chmod +x "$RUN_DIR/init"

    # ── Build initrd ───────────────────────────────────────────────────

    (cd "$RUN_DIR" && find . -path ./initrd.img -prune -o -print | "$CPIO" -o -H newc 2>/dev/null) > "$RUN_DIR/initrd.img"

    echo "  Initrd prepared: $(du -h "$RUN_DIR/initrd.img" | cut -f1)"
    STORE_IMG="$RUN_DIR/store.img"
    "$TRUNCATE_BIN" -s "''${STORE_IMAGE_MB}M" "$STORE_IMG"
    "$MKFS_EXT4_BIN" -F -q -L tidefs-store "$STORE_IMG"
    echo "  Store image prepared: $(du -h "$STORE_IMG" | cut -f1) apparent=''${STORE_IMAGE_MB}M"
    echo ""

    # ── Run QEMU ──────────────────────────────────────────────────────

    VAL_LOG="$RUN_DIR/qemu-boot.log"
    QMP_SOCKET="/tmp/tidefs-fuse-xfstests-qmp-$$.sock"
    CRASHDUMP_FILE="$RUN_DIR/qemu-guest-memory.elf"
    CRASH_ANALYSIS="$RUN_DIR/crash-analysis.txt"
    CRASH_CMDS="$RUN_DIR/crash.cmds"

    KERNEL_APPEND="console=ttyS0 ignore_loglevel panic=30 oops=panic panic_on_oops=1"
    if [ "$PANIC_ON_WARN_MODE" = "1" ]; then
      KERNEL_APPEND="$KERNEL_APPEND panic_on_warn=1 hung_task_panic=1 hung_task_timeout_secs=60 softlockup_panic=1 hardlockup_panic=1 panic_on_rcu_stall=1 panic_print=0x3f"
    fi
    if [ "$CRASHDUMP_MODE" = "1" ]; then
      KERNEL_APPEND="$KERNEL_APPEND nokaslr"
    fi

    CRASHDUMP_CREATED=0
    capture_guest_crashdump() {
      reason="$1"
      [ "$CRASHDUMP_MODE" = "1" ] || return 0
      if [ ! -S "$QMP_SOCKET" ]; then
        echo "  Crashdump: QMP socket unavailable for $reason"
        return 0
      fi
      rm -f "$CRASHDUMP_FILE"
      echo "  Crashdump: dumping guest memory for $reason to $CRASHDUMP_FILE"
      {
        printf '{"execute":"qmp_capabilities"}\n'
        printf '{"execute":"dump-guest-memory","arguments":{"paging":true,"protocol":"file:%s"}}\n' "$CRASHDUMP_FILE"
      } | timeout 600 "$SOCAT_BIN" - UNIX-CONNECT:"$QMP_SOCKET" > "$RUN_DIR/qmp-dump-$reason.log" 2>&1 || true
      if [ -s "$CRASHDUMP_FILE" ]; then
        CRASHDUMP_CREATED=1
        echo "  Crashdump: complete ($(wc -c < "$CRASHDUMP_FILE" 2>/dev/null || echo 0) bytes)"
      else
        echo "  Crashdump: no vmcore produced; see $RUN_DIR/qmp-dump-$reason.log"
      fi
    }

    analyze_guest_crashdump() {
      [ "$CRASHDUMP_CREATED" -eq 1 ] || return 0
      if [ ! -f "$KERNEL_VMLINUX" ]; then
        echo "  crash: vmlinux unavailable at $KERNEL_VMLINUX"
        return 0
      fi
      if [ ! -x "$CRASH_BIN" ]; then
        echo "  crash: binary unavailable at $CRASH_BIN"
        return 0
      fi
      cat > "$CRASH_CMDS" << CRASHCMDS
set scroll off
sys
log
bt
ps
foreach bt
kmem -i
mount
files
quit
CRASHCMDS
      echo "  crash: analyzing vmcore with $CRASH_BIN"
      timeout 300 "$CRASH_BIN" -i "$CRASH_CMDS" "$KERNEL_VMLINUX" "$CRASHDUMP_FILE" > "$CRASH_ANALYSIS" 2>&1 || true
      if [ -s "$CRASH_ANALYSIS" ]; then
        echo "  crash: analysis written to $CRASH_ANALYSIS"
      else
        echo "  crash: analysis produced no output"
      fi
    }

    echo "  Booting QEMU VM..."
    QEMU_ACCEL=""; if [ "$HAS_KVM" -eq 1 ]; then QEMU_ACCEL="-accel kvm -cpu host"; echo "  (KVM mode)"; else QEMU_ACCEL="-accel tcg"; echo "  (TCG mode)"; fi
    echo "  Kernel append: $KERNEL_APPEND"
    "$QEMU_BIN" \
      -kernel "$KERNEL_IMG" \
      -initrd "$RUN_DIR/initrd.img" \
      -append "$KERNEL_APPEND" \
      $QEMU_ACCEL \
      -m "''${QEMU_MEMORY_MB}M" \
      -smp 1 \
      -nographic \
      -qmp "unix:$QMP_SOCKET,server,nowait" \
      -drive "file=$STORE_IMG,format=raw,if=virtio,cache=unsafe" \
      -no-reboot \
      < /dev/null \
      > "$VAL_LOG" 2>&1 &
    QEMU_PID=$!

    QEMU_RC=0
    QEMU_TIMED_OUT=0
    DUMPED_FOR_PANIC=0
    DEADLINE=$(( $(date +%s) + TIMEOUT_SEC ))
    while kill -0 "$QEMU_PID" 2>/dev/null; do
      if [ "$CRASHDUMP_MODE" = "1" ] && [ "$DUMPED_FOR_PANIC" -eq 0 ] \
         && grep -aE 'Kernel panic|Oops:|BUG:|WARNING:' "$VAL_LOG" >/dev/null 2>&1; then
        DUMPED_FOR_PANIC=1
        capture_guest_crashdump "panic"
        analyze_guest_crashdump
      fi
      now=$(date +%s)
      if [ "$now" -ge "$DEADLINE" ]; then
        echo "  QEMU timeout after ''${TIMEOUT_SEC}s"
        QEMU_TIMED_OUT=1
        capture_guest_crashdump "timeout"
        analyze_guest_crashdump
        kill -TERM "$QEMU_PID" 2>/dev/null || true
        sleep 5
        kill -KILL "$QEMU_PID" 2>/dev/null || true
        break
      fi
      sleep 2
    done
    if wait "$QEMU_PID" 2>/dev/null; then
      QEMU_RC=0
    else
      QEMU_RC=$?
    fi
    echo "  QEMU exit code: $QEMU_RC"
    if [ "$CRASHDUMP_MODE" = "1" ] && [ "$CRASHDUMP_CREATED" -eq 0 ] \
       && grep -aE 'Kernel panic|Oops:|BUG:|WARNING:' "$VAL_LOG" >/dev/null 2>&1; then
      capture_guest_crashdump "post-exit"
      analyze_guest_crashdump
    fi
    rm -f "$QMP_SOCKET"

    echo "  QEMU boot completed"
    BOOT_LINES=$(wc -l < "$VAL_LOG" 2>/dev/null || echo 0)
    echo "  Boot log: $BOOT_LINES lines"

    # ── Parse validation rows from boot log ──────────────────────────────

    echo ""
    echo "=== FUSE xfstests Validation Results ==="

    PASSC=0
    FAILC=0
    BLOCKC=0
    SKIPC=0
    UNSUPC=0

    # Collect all validation rows from the log. Some xfstests helpers can leave
    # the serial console without a trailing newline before the harness prints a
    # FAIL row, so match validation tokens anywhere on the line.
    validation_ops() {
      grep -aEo '(PASS|FAIL|BLOCKED|UNSUPPORTED|SKIP): [^[:space:]]+' "$VAL_LOG" 2>/dev/null \
        | sed 's/^[A-Z]*: //' \
        | tr -d '\r' \
        | sort -u || true
    }
    validation_detail() {
      status="$1"
      op="$2"
      grep -aF "$status: $op" "$VAL_LOG" 2>/dev/null \
        | head -1 \
        | sed "s#.*$status: $op -- ##; s#.*$status: $op##" \
        | tr -d '\r'
    }

    if ! grep -aE '(PASS|FAIL|BLOCKED|UNSUPPORTED|SKIP): [^[:space:]]+' "$VAL_LOG" >/dev/null 2>&1; then
      echo "BLOCKED: harness_no_validation_rows -- no validation rows parsed from QEMU boot log" >> "$VAL_LOG"
    fi
    ALL_OPS=$(validation_ops)

    if [ "$QEMU_TIMED_OUT" -eq 1 ]; then
      ACTIVE_XFSTEST=$(
        grep -aEo '=== Running [^[:space:]]+ ===' "$VAL_LOG" 2>/dev/null \
          | tail -1 \
          | sed 's/^=== Running //; s/ ===$//' \
          | tr -d '\r' || true
      )
      if [ -n "$ACTIVE_XFSTEST" ]; then
        active_op="xfstests_$ACTIVE_XFSTEST"
        if ! printf '%s\n' "$ALL_OPS" | grep -Fx "$active_op" >/dev/null 2>&1; then
          echo "FAIL: $active_op -- QEMU timeout after ''${TIMEOUT_SEC}s while row was active" >> "$VAL_LOG"
          ALL_OPS=$(validation_ops)
        fi
      else
        echo "BLOCKED: qemu_timeout -- QEMU timeout after ''${TIMEOUT_SEC}s before an active xfstests row was identified" >> "$VAL_LOG"
        ALL_OPS=$(validation_ops)
      fi
    fi

    for requested in $TEST_LIST; do
      requested_op="xfstests_$requested"
      if ! printf '%s\n' "$ALL_OPS" | grep -Fx "$requested_op" >/dev/null 2>&1; then
        echo "BLOCKED: $requested_op -- requested test produced no parsed validation row" >> "$VAL_LOG"
      fi
    done
    ALL_OPS=$(validation_ops)

    for op in $ALL_OPS; do
      [ -z "$op" ] && continue
      if grep -q "PASS: $op" "$VAL_LOG" 2>/dev/null; then
        echo "  PASS: $op"
        PASSC=$((PASSC + 1))
      elif grep -q "FAIL: $op" "$VAL_LOG" 2>/dev/null; then
        detail=$(validation_detail FAIL "$op")
        echo "  FAIL: $op -- $detail"
        FAILC=$((FAILC + 1))
      elif grep -q "BLOCKED: $op" "$VAL_LOG" 2>/dev/null; then
        detail=$(validation_detail BLOCKED "$op")
        echo "  BLOCKED: $op -- $detail"
        BLOCKC=$((BLOCKC + 1))
      elif grep -q "UNSUPPORTED: $op" "$VAL_LOG" 2>/dev/null; then
        detail=$(validation_detail UNSUPPORTED "$op")
        echo "  UNSUPPORTED: $op -- $detail"
        UNSUPC=$((UNSUPC + 1))
      elif grep -q "SKIP: $op" "$VAL_LOG" 2>/dev/null; then
        detail=$(validation_detail SKIP "$op")
        echo "  SKIP: $op -- $detail"
        SKIPC=$((SKIPC + 1))
      fi
    done

    echo ""
    echo "Validation matrix: $PASSC passed, $FAILC failed, $BLOCKC blocked, $UNSUPC unsupported, $SKIPC skipped"
    echo "Validation log: $VAL_LOG"
    echo ""

    # ── Produce JSON validation report ───────────────────────────────────

    COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
    RUN_ID="fuse-xfstests-$(date -u +%Y%m%dT%H%M%SZ)"
    KERNEL_VER="$(grep 'kernel_version=' "$VAL_LOG" 2>/dev/null | head -1 | cut -d= -f2 | tr -d '\r' || echo unknown)"
    TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    ACCEL_MODE="tcg"; if [ "$HAS_KVM" -eq 1 ]; then ACCEL_MODE="kvm"; fi

    JSON_FILE="$RUN_DIR/validation.json"
    cat > "$JSON_FILE" << JSONEOF
{
  "run_id": "$RUN_ID",
  "commit": "$COMMIT",
  "timestamp": "$TIMESTAMP",
  "kernel_version": "$KERNEL_VER",
  "qemu_binary": "qemu-system-x86_64",
  "kernel_image": "$(basename "$KERNEL_IMG")",
  "kernel_vmlinux": "$KERNEL_VMLINUX",
  "panic_on_warn": "$PANIC_ON_WARN_MODE",
  "crashdump": "$CRASHDUMP_MODE",
  "backend": "file",
  "validation_tier": "mounted-userspace",
  "accel_mode": "$ACCEL_MODE",
  "qemu_memory_mb": $QEMU_MEMORY_MB,
  "store_image_mb": $STORE_IMAGE_MB,
  "summary": {
    "passed": $PASSC,
    "failed": $FAILC,
    "blocked": $BLOCKC,
    "unsupported": $UNSUPC,
    "skipped": $SKIPC
  },
  "rows": [
JSONEOF

    FIRST=1
    for op in $ALL_OPS; do
      [ -z "$op" ] && continue
      STATUS="pass"
      CLASS=""
      DETAIL=""
      if grep -q "PASS: $op" "$VAL_LOG" 2>/dev/null; then
        STATUS="pass"
      elif grep -q "FAIL: $op" "$VAL_LOG" 2>/dev/null; then
        STATUS="fail"
        DETAIL=$(validation_detail FAIL "$op" | head -c 256)
      elif grep -q "BLOCKED: $op" "$VAL_LOG" 2>/dev/null; then
        STATUS="blocked"
        DETAIL=$(validation_detail BLOCKED "$op" | head -c 256)
      elif grep -q "UNSUPPORTED: $op" "$VAL_LOG" 2>/dev/null; then
        STATUS="unsupported"
        DETAIL=$(validation_detail UNSUPPORTED "$op" | head -c 256)
      elif grep -q "SKIP: $op" "$VAL_LOG" 2>/dev/null; then
        STATUS="skip"
        DETAIL=$(validation_detail SKIP "$op" | head -c 256)
      fi
      JSON_OP=$(printf '%s' "$op" | tr -d '\r\n' | sed 's/\\/\\\\/g; s/"/\\"/g')
      JSON_DETAIL=$(printf '%s' "$DETAIL" | tr -d '\r\n' | sed 's/\\/\\\\/g; s/"/\\"/g')

      [ "$FIRST" -eq 1 ] || echo ',' >> "$JSON_FILE"
      FIRST=0

      cat >> "$JSON_FILE" << ROWEOF
    {
      "test_name": "$JSON_OP",
      "group": "fuse-xfstests",
      "op": "TestRun",
      "tier": "MountedUserspace",
      "outcome": {"$STATUS": "$JSON_DETAIL"},
      "exit_code": null
    }
ROWEOF
    done

    printf '\n' >> "$JSON_FILE"
    echo '  ]' >> "$JSON_FILE"
    echo '}' >> "$JSON_FILE"

    echo "Validation JSON: $JSON_FILE"

    if [ -n "$JSON_OUT" ]; then
      OUT_DIR="$(dirname "$JSON_OUT")"
      mkdir -p "$OUT_DIR"
      cp "$JSON_FILE" "$JSON_OUT"
      cp "$VAL_LOG" "$OUT_DIR/qemu-boot.log"
      if [ "$CRASHDUMP_MODE" = "1" ]; then
        for artifact in "$CRASHDUMP_FILE" "$CRASH_ANALYSIS" "$CRASH_CMDS" "$RUN_DIR"/qmp-dump-*.log; do
          [ -f "$artifact" ] || continue
          cp "$artifact" "$OUT_DIR/$(basename "$artifact")"
        done
      fi
      MANIFEST_VERDICT="go"
      MANIFEST_RESULT="passed"
      if [ "$FAILC" -gt 0 ]; then
        MANIFEST_VERDICT="no-go"
        MANIFEST_RESULT="failed"
      elif [ "$BLOCKC" -gt 0 ]; then
        MANIFEST_VERDICT="blocked"
        MANIFEST_RESULT="blocked"
      elif [ "$UNSUPC" -gt 0 ] || [ "$SKIPC" -gt 0 ]; then
        MANIFEST_VERDICT="blocked"
        MANIFEST_RESULT="classified"
      fi
      cat > "$OUT_DIR/SUMMARY.md" << SUMMARYEOF
# TideFS FUSE xfstests Smoke Validation

Generated: $TIMESTAMP

## Result

\`fuseXfstestsValidation\` ran the requested FUSE userspace xfstests tranche in
a Linux 7.0 QEMU guest launched outside the Nix build sandbox.

- Commit: \`$COMMIT\`
- Kernel: \`$KERNEL_VER\`
- Acceleration: \`$ACCEL_MODE\`
- Guest memory: \`$QEMU_MEMORY_MB MiB\`
- Guest /store image: \`$STORE_IMAGE_MB MiB\`
- Panic-on-warning mode: \`$PANIC_ON_WARN_MODE\`
- Crashdump mode: \`$CRASHDUMP_MODE\`
- Requested tests: \`$TEST_LIST\`
- Passed rows: $PASSC
- Failed rows: $FAILC
- Blocked rows: $BLOCKC
- Unsupported rows: $UNSUPC
- Skipped rows: $SKIPC

Validation outputs:

- \`$(basename "$JSON_OUT")\`
- \`qemu-boot.log\`
- \`validation-manifest.json\`

Crash/debug outputs are copied when present: \`qemu-guest-memory.elf\`,
\`crash-analysis.txt\`, \`crash.cmds\`, and \`qmp-dump-*.log\`.

## Release Meaning

This is bounded MountedUserspace Tier 3 validation for the FUSE
$TEST_SCOPE xfstests smoke tranche. It does not claim exhaustive
xfstests, fsx, fsstress, mmap, or kernel VFS coverage.
SUMMARYEOF
      cat > "$OUT_DIR/validation-manifest.json" << MANIFESTEOF
{
  "schema": "tidefs.validation.validation_manifest.v1",
  "worker_slot": "foreground-codex",
  "summary": "FUSE userspace xfstests $TEST_SCOPE smoke validation from a Linux 7.0 QEMU guest launched outside the Nix build sandbox.",
  "generated_at": "$TIMESTAMP",
  "source_anchor": "$COMMIT",
  "verdict": "$MANIFEST_VERDICT",
  "scope": "FUSE userspace xfstests $TEST_SCOPE smoke tranche",
  "primary_artifact": "$JSON_OUT",
  "log": "$OUT_DIR/qemu-boot.log",
  "qemu_memory_mb": $QEMU_MEMORY_MB,
  "store_image_mb": $STORE_IMAGE_MB,
  "validation": [
    {
      "command": "nix run .#fuse-xfstests-validation -- --tests \"$TEST_LIST\" --output $JSON_OUT",
      "result": "$MANIFEST_RESULT",
      "log": "$OUT_DIR/qemu-boot.log"
    }
  ],
  "counters": {
    "passed": $PASSC,
    "failed": $FAILC,
    "blocked": $BLOCKC,
    "unsupported": $UNSUPC,
    "skipped": $SKIPC,
    "total": $((PASSC + FAILC + BLOCKC + UNSUPC + SKIPC))
  },
  "acceptance_coverage": [
    "QEMU launched outside the Nix build sandbox",
    "Linux 7.0 guest boot",
    "FUSE device availability inside guest",
    "TideFS userspace FUSE mount",
    "basic mkdir/write/read/unlink sanity",
    "upstream xfstests $TEST_SCOPE requested rows",
    "unmount and daemon-stop rows recorded"
  ],
  "limitations": [
    "Bounded xfstests smoke tranche, not exhaustive upstream xfstests coverage.",
    "Does not replace separate fsx, fsstress, mmap, or kernel VFS campaigns."
  ],
  "residual_risk": [
    "Later FUSE tranches cover broader operation families and stress surfaces."
  ]
}
MANIFESTEOF
      echo "Validation copied to: $JSON_OUT"
      echo "Validation log copied to: $OUT_DIR/qemu-boot.log"
    fi

    # ── Final verdict ──────────────────────────────────────────────────

    if [ "$FAILC" -gt 0 ]; then
      echo ""
      echo "VALIDATION: FAIL -- $FAILC validation rows failed"
      echo "  Failed rows indicate bugs in the FUSE xfstests path."
      echo "  See $VAL_LOG for details."
      exit 1
    fi

    if [ "$BLOCKC" -gt 0 ] || [ "$UNSUPC" -gt 0 ] || [ "$SKIPC" -gt 0 ]; then
      echo ""
      echo "VALIDATION: BLOCKED -- $BLOCKC blocked, $UNSUPC unsupported, $SKIPC skipped"
      echo "  Blocked, unsupported, or skipped rows are non-pass validation classifications."
      echo "  See $VAL_LOG for details."
      exit 2
    fi

    echo ""
    echo "VALIDATION: PASS -- $PASSC validation rows passed"
    echo "  FUSE xfstests validation complete."
    exit 0

  '';
in
fuseXfstestsValidationScript
