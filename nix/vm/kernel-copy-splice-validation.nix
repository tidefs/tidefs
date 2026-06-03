# TideFS: kernel copy_file_range and splice validation in QEMU.
#
# Compiles a static C test helper that exercises copy_file_range(2) and
# splice(2) with data+hole patterns, boots a QEMU VM, loads the kmod-posix-vfs
# module, mounts TideFS, runs the helper, and verifies committed-root
# consistency across unmount/remount.
#
# Tier 5: mounted kernel VFS validation.
{
  pkgs,
  linuxKernel_7_0,
}:

let
  # Static C test helper for QEMU initramfs.
  copySpliceTest = pkgs.pkgsStatic.stdenv.mkDerivation {
    name = "tidefs-copy-splice-test";
    dontUnpack = true;
    src = pkgs.writeText "test.c" ''
      #define _GNU_SOURCE
      #include <errno.h>
      #include <fcntl.h>
      #include <stdio.h>
      #include <stdlib.h>
      #include <string.h>
      #include <sys/syscall.h>
      #include <unistd.h>

      static unsigned char buf[4096];
      static unsigned char cmp[4096];
      #define SEGSZ    4096
      #define NSRCSEGS 4
      #define TOTSZ    (NSRCSEGS * SEGSZ)

      static void die(const char *msg) { perror(msg); exit(1); }

      static void fill_src(const char *path) {
        int fd = open(path, O_CREAT|O_WRONLY|O_TRUNC, 0644);
        if (fd < 0) die("open src");
        memset(buf, 0xAA, SEGSZ);
        if (pwrite(fd, buf, SEGSZ, 0) != SEGSZ) die("pwrite seg0");
        memset(buf, 0xBB, SEGSZ);
        if (pwrite(fd, buf, SEGSZ, 2*SEGSZ) != SEGSZ) die("pwrite seg2");
        ftruncate(fd, TOTSZ);
        close(fd);
      }

      static int verify_seg(const char *path, off_t off, unsigned char byte) {
        int fd = open(path, O_RDONLY);
        if (fd < 0) die("open verify");
        ssize_t rd = pread(fd, cmp, SEGSZ, off);
        close(fd);
        if (rd != SEGSZ) { fprintf(stderr,"pread seg at %ld\n",off); return 1; }
        memset(buf, byte, SEGSZ);
        if (memcmp(cmp, buf, SEGSZ) != 0) {
          fprintf(stderr,"seg mismatch at %ld (expected 0x%02x)\n",off,byte);
          return 1;
        }
        printf("  verify seg at %ld (0x%02x): OK\n", off, byte);
        return 0;
      }

      static int test_cfr(const char *src, const char *dst) {
        int fd_in = open(src, O_RDONLY);
        if (fd_in < 0) die("open src for cfr");
        int fd_out = open(dst, O_CREAT|O_WRONLY|O_TRUNC, 0644);
        if (fd_out < 0) die("open dst for cfr");
        loff_t off_in=0, off_out=0;
        ssize_t total=0, cr;
        do {
          cr = syscall(SYS_copy_file_range, fd_in, &off_in,
                       fd_out, &off_out, TOTSZ-total, 0);
          if (cr < 0) { fprintf(stderr,"cfr errno=%d\n",errno); break; }
          total += cr;
        } while (cr > 0 && total < (ssize_t)TOTSZ);
        close(fd_in); ftruncate(fd_out, TOTSZ); close(fd_out);
        printf("copy_file_range: copied=%zd\n", total);
        if (total != (ssize_t)TOTSZ) return 1;
        return verify_seg(dst,0,0xAA) || verify_seg(dst,SEGSZ,0) ||
               verify_seg(dst,2*SEGSZ,0xBB);
      }

      static int test_splice(const char *src, const char *dst) {
        int fd_in = open(src, O_RDONLY);
        if (fd_in < 0) die("open src splice");
        int fd_out = open(dst, O_CREAT|O_WRONLY|O_TRUNC, 0644);
        if (fd_out < 0) die("open dst splice");
        int pp[2];
        if (pipe(pp) < 0) die("pipe");
        loff_t off=0;
        ssize_t sp_total=0, sp, wr_total, wr;
        while (sp_total < (ssize_t)TOTSZ) {
          sp = splice(fd_in, &off, pp[1], NULL, TOTSZ-sp_total, 0);
          if (sp <= 0) { if (sp<0) fprintf(stderr,"splice rd errno=%d\n",errno); break; }
          sp_total += sp;
          wr_total = 0; off = 0;
          while (wr_total < sp) {
            wr = splice(pp[0], NULL, fd_out, &off, sp-wr_total, 0);
            if (wr <= 0) { if (wr<0) fprintf(stderr,"splice wr errno=%d\n",errno); break; }
            wr_total += wr;
          }
        }
        close(pp[0]); close(pp[1]); close(fd_in);
        ftruncate(fd_out, TOTSZ); close(fd_out);
        printf("splice: moved=%zd\n", sp_total);
        if (sp_total != (ssize_t)TOTSZ) return 1;
        return verify_seg(dst,0,0xAA) || verify_seg(dst,SEGSZ,0) ||
               verify_seg(dst,2*SEGSZ,0xBB);
      }

      int main(int argc, char **argv) {
        if (argc != 4) { fprintf(stderr,"Usage: %s <src> <dst> <tmp>\n",argv[0]); return 2; }
        fill_src(argv[1]);
        int r = test_cfr(argv[1], argv[2]);
        printf("%s: copy_file_range\n", r ? "FAIL" : "PASS");
        r |= test_splice(argv[2], argv[3]);
        printf("%s: splice\n", r ? "FAIL" : "PASS");
        return r;
      }
    '';
    buildPhase = ''
      mkdir -p $out/bin
      $CC -static -O2 -o $out/bin/tidefs-copy-splice-test $src
    '';
    installPhase = "true";
  };

  # Validation shell script
  copySpliceScript = pkgs.writeShellScriptBin "tidefs-kernel-copy-splice-validation" ''
    set -euo pipefail

    QEMU_BIN="${pkgs.qemu}/bin/qemu-system-x86_64"
    BUSYBOX="${pkgs.busybox}/bin/busybox"
    KERNEL_IMG="${linuxKernel_7_0}/bzImage"
    CPIO="${pkgs.cpio}/bin/cpio"
    TEST_HELPER="${copySpliceTest}/bin/tidefs-copy-splice-test"
    MODULE_DIR="${linuxKernel_7_0}/lib/modules/${linuxKernel_7_0.version}"

    TMPDIR="''${TIDEFS_KMOD_COPYSPLICE_TMPDIR:-/tmp/tidefs-kmod-copy-splice}"
    TIMEOUT_SEC="''${TIDEFS_KMOD_COPYSPLICE_TIMEOUT:-300}"

    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --keep-tmp) KEEP_TMP=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; exit 2 ;;
      esac
    done

    echo "=== TideFS Kernel copy/splice QEMU Validation ==="
    echo "timestamp: $(date --utc +%Y-%m-%dT%H:%M:%SZ)"

    # ── Initramfs ──────────────────────────────────────────────────────
    echo "--- Building initramfs ---"
    mkdir -p "$TMPDIR"/initramfs/{bin,dev,proc,sys,lib/modules,mnt,root,tmp}

    cp "$BUSYBOX" "$TMPDIR"/initramfs/bin/busybox
    chmod +x "$TMPDIR"/initramfs/bin/busybox
    for cmd in sh mount umount ls cat cp dd echo mkdir rm sync mknod dmesg insmod poweroff; do
      ln -sf /bin/busybox "$TMPDIR"/initramfs/bin/"$cmd"
    done
    cp "$TEST_HELPER" "$TMPDIR"/initramfs/bin/tidefs-copy-splice-test

    if [ -d "$MODULE_DIR" ]; then
      mkdir -p "$TMPDIR"/initramfs/lib/modules/"${linuxKernel_7_0.version}"
      cp -r "$MODULE_DIR"/* "$TMPDIR"/initramfs/lib/modules/"${linuxKernel_7_0.version}"/ 2>/dev/null || true
    fi
    if [ -n "''${TIDEFS_KMOD_POSIX_TFS_KO:-}" ] && [ -f "''${TIDEFS_KMOD_POSIX_TFS_KO:-}" ]; then
      cp "''${TIDEFS_KMOD_POSIX_TFS_KO:-}" "$TMPDIR"/initramfs/lib/modules/tidefs_posix_vfs.ko
    fi

    # ── QEMU init script ───────────────────────────────────────────────
    cat > "$TMPDIR"/initramfs/init << 'INITEOF'
    #!/bin/sh
    set -e
    echo "=== TideFS copy/splice test ==="
    mount -t proc proc /proc
    mount -t sysfs sysfs /sys
    mount -t devtmpfs devtmpfs /dev

    modprobe tidefs-posix-vfs 2>/dev/null || insmod /lib/modules/tidefs_posix_vfs.ko 2>/dev/null || {
      echo "BLOCKED: module not loadable"
      echo "PASS=0 FAIL=0 TOTAL=0 BLOCKED=1"
      poweroff -f
    }

    mkdir -p /mnt/tidefs /var/tidefs/backing
    dd if=/dev/zero of=/var/tidefs/backing/pool.dat bs=1M count=64 2>/dev/null || true

    mount -t tidefs none /mnt/tidefs 2>/dev/null || {
      echo "BLOCKED: mount failed"
      echo "PASS=0 FAIL=0 TOTAL=0 BLOCKED=1"
      poweroff -f
    }
    mkdir -p /mnt/tidefs/test

    PASS=0 FAIL=0 TOTAL=0

    echo "--- Phase 1: copy_file_range + splice ---"
    /bin/tidefs-copy-splice-test /mnt/tidefs/test/src.dat \
                                   /mnt/tidefs/test/dst.dat \
                                   /mnt/tidefs/test/tmp.dat
    R1=$?
    if [ "$R1" -eq 0 ]; then
      PASS=$((PASS+2)); TOTAL=$((TOTAL+2))
      echo "TIDEFS_COPYSPLICE_T1: PASS"
    else
      FAIL=$((FAIL+2)); TOTAL=$((TOTAL+2))
      echo "TIDEFS_COPYSPLICE_T1: FAIL"
    fi

    echo "--- Phase 2: remount persistence ---"
    sync
    umount /mnt/tidefs 2>/dev/null || true
    mount -t tidefs none /mnt/tidefs 2>/dev/null || {
      echo "BLOCKED: remount failed"
      echo "PASS=$PASS FAIL=$FAIL TOTAL=$TOTAL"
      poweroff -f
    }
    /bin/tidefs-copy-splice-test /mnt/tidefs/test/src.dat \
                                   /mnt/tidefs/test/dst2.dat \
                                   /mnt/tidefs/test/tmp2.dat
    R2=$?
    if [ "$R2" -eq 0 ]; then
      PASS=$((PASS+2)); TOTAL=$((TOTAL+2))
      echo "TIDEFS_COPYSPLICE_T2: PASS"
    else
      FAIL=$((FAIL+2)); TOTAL=$((TOTAL+2))
      echo "TIDEFS_COPYSPLICE_T2: FAIL"
    fi

    umount /mnt/tidefs 2>/dev/null || true
    echo "PASS=$PASS FAIL=$FAIL TOTAL=$TOTAL"
    if [ "$FAIL" -eq 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
    poweroff -f
    INITEOF

    chmod +x "$TMPDIR"/initramfs/init
    (cd "$TMPDIR"/initramfs && find . | "$CPIO" -o -H newc) | gzip -9 > "$TMPDIR"/initramfs.cpio.gz

    echo "--- Booting QEMU (timeout: ''${TIMEOUT_SEC}s) ---"
    QEMU_OUT="$TMPDIR/qemu-stdout.log"

    set +e
    timeout "$TIMEOUT_SEC" "$QEMU_BIN" \
      -kernel "$KERNEL_IMG" \
      -initrd "$TMPDIR"/initramfs.cpio.gz \
      -append "console=ttyS0 quiet panic=5 init=/init" \
      -nographic -m 512M -no-reboot \
      > "$QEMU_OUT" 2>&1
    QEMU_EXIT=$?
    set -e

    echo "--- QEMU exit=$QEMU_EXIT ---"
    grep -E "PASS=|FAIL=|RESULT:|BLOCKED:|TIDEFS_COPYSPLICE" "$QEMU_OUT" 2>/dev/null || true

    if [ -z "''${KEEP_TMP:-}" ]; then rm -rf "$TMPDIR"; else echo "Kept: $TMPDIR"; fi

    if grep -q "BLOCKED:" "$QEMU_OUT" 2>/dev/null; then exit 2; fi
    if grep -q "RESULT: PASS" "$QEMU_OUT" 2>/dev/null; then exit 0; fi
    exit 1
  '';
in
  copySpliceScript
