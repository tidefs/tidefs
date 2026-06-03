# TideFS K7-VAL: kmod-posix-vfs out-of-tree kernel module Makefile.
#
# Usage (from repo root):
#   KDIR=/path/to/linux-7.0-source O=/path/to/linux-7.0-build \
#     MO=/path/to/module-out/posix-vfs KBUILD_JOBS=8 \
#     make -j8 -C crates/tidefs-kmod-posix-vfs
#
# Or via the compile script:
#   bash scripts/compile-kmod-posix-vfs.sh

ifneq ($(KERNELRELEASE),)
# Inside kbuild
obj-m := tidefs_posix_vfs.o
tidefs_posix_vfs-y := tidefs_posix_vfs_main.o tidefs_posix_vfs_shim.o
else
# Outside kbuild: delegate to the kernel build system
KDIR ?= /root/ai/state/tidefs/kernel-dev/hot-loop/linux-7.0/build
KBUILD_JOBS ?= 8
LLVM ?= 1
O ?=
MO ?=
REPO_ROOT := $(abspath $(CURDIR)/../..)
RUST_SYSROOT := $(shell cd "$(REPO_ROOT)" && rustc --print sysroot 2>/dev/null)
KBUILD_RUSTC ?= $(if $(RUST_SYSROOT),$(RUST_SYSROOT)/bin/rustc,rustc)
KBUILD_RUSTC_SYSROOT := $(shell "$(KBUILD_RUSTC)" --print sysroot 2>/dev/null)
KBUILD_RUSTC_BOOTSTRAP ?= 1
KBUILD_BINDGEN ?= bindgen
KBUILD_RUST_LIB_SRC ?= $(if $(KBUILD_RUSTC_SYSROOT),$(KBUILD_RUSTC_SYSROOT)/lib/rustlib/src/rust/library,)
KBUILD_CC ?=

KBUILD_LLVM_ARG := $(if $(LLVM),LLVM=$(LLVM),)
KBUILD_OUTPUT_ARG := $(if $(O),O=$(O),)
KBUILD_MODULE_OUTPUT_ARG := $(if $(MO),MO=$(MO),)
KBUILD_CC_ARG := $(if $(KBUILD_CC),CC=$(KBUILD_CC),)
KBUILD_RUSTC_ARG := RUSTC=$(KBUILD_RUSTC)
KBUILD_RUSTC_BOOTSTRAP_ARG := RUSTC_BOOTSTRAP=$(KBUILD_RUSTC_BOOTSTRAP)
KBUILD_BINDGEN_ARG := BINDGEN=$(KBUILD_BINDGEN)
KBUILD_RUST_LIB_SRC_ARG := $(if $(KBUILD_RUST_LIB_SRC),RUST_LIB_SRC=$(KBUILD_RUST_LIB_SRC),)

default:
	@# Regression gate: FS_ALLOW_IDMAP refused until Tier 7+ mounted-kernel
	@# idmap validation output written (#6651). Re-admission requires:
	@#   - Retained Linux 7.0 QEMU idmapped mount ownership translation
	@#   - Permission check, getattr/statx uid/gid mapping
	@#   - setattr/chown behavior, xattr/ACL ownership semantics
	@#   - Updated KNOWN_LIMITATIONS.md and FEATURE_MATRIX.md
	@if grep -q '^[[:space:]]*\.fs_flags.*FS_ALLOW_IDMAP' "$(CURDIR)/tidefs_posix_vfs_shim.c"; then \
		echo "ERROR: FS_ALLOW_IDMAP is set in tidefs_posix_vfs_shim.c .fs_flags." >&2; \
		echo "       Remove it or retain mounted-kernel Tier 7+ idmap validation (#6651)." >&2; \
		exit 1; \
	fi
	@if [ ! -f "$(KDIR)/Makefile" ]; then \
		echo "ERROR: KDIR=$(KDIR) is not a Linux kernel source/build tree." >&2; \
		echo "Use linux-prepare and set KDIR to linux_src, O to linux_build, and MO to module_out." >&2; \
		exit 1; \
	fi
	@if [ -n "$(MO)" ]; then mkdir -p "$(MO)"; fi
	$(MAKE) -j$(KBUILD_JOBS) -C $(KDIR) $(KBUILD_LLVM_ARG) $(KBUILD_OUTPUT_ARG) M=$(CURDIR) $(KBUILD_MODULE_OUTPUT_ARG) $(KBUILD_CC_ARG) $(KBUILD_RUSTC_ARG) $(KBUILD_BINDGEN_ARG) $(KBUILD_RUST_LIB_SRC_ARG) $(KBUILD_RUSTC_BOOTSTRAP_ARG) modules

clean:
	@if [ -f "$(KDIR)/Makefile" ]; then \
		$(MAKE) -j$(KBUILD_JOBS) -C $(KDIR) $(KBUILD_LLVM_ARG) $(KBUILD_OUTPUT_ARG) M=$(CURDIR) $(KBUILD_MODULE_OUTPUT_ARG) $(KBUILD_CC_ARG) $(KBUILD_RUSTC_ARG) $(KBUILD_BINDGEN_ARG) $(KBUILD_RUST_LIB_SRC_ARG) $(KBUILD_RUSTC_BOOTSTRAP_ARG) clean; \
	else \
		rm -f "$(CURDIR)"/*.o "$(CURDIR)"/*.ko "$(CURDIR)"/*.mod.c; \
		rm -f "$(CURDIR)"/.tidefs_posix_vfs.* "$(CURDIR)"/modules.order; \
		rm -f "$(CURDIR)"/Module.symvers; \
		echo "Kernel tree not available; manual cleanup done."; \
	fi

.PHONY: default clean
endif
