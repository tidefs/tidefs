# TideFS block-volume kernel module Makefile.
#
# Usage (from repo root):
#   KDIR=/path/to/linux-7.0-source O=/path/to/linux-7.0-build \
#     MO=/path/to/module-out/block-kmod KBUILD_JOBS=8 \
#     make -j8 -C crates/tidefs-block-kmod
#
# Or build directly from the kernel tree:
#   make -j8 -C <linux-src> O=<linux-build> M=crates/tidefs-block-kmod MO=<module-out> modules

ifneq ($(KERNELRELEASE),)
# Inside kbuild
obj-m := tidefs_block_kmod.o
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
KBUILD_RUSTC_BOOTSTRAP ?= 1
KBUILD_RUSTC_SYSROOT := $(shell "$(KBUILD_RUSTC)" --print sysroot 2>/dev/null)
KBUILD_CC ?=
KBUILD_BINDGEN ?= bindgen
KBUILD_RUST_LIB_SRC ?= $(if $(KBUILD_RUSTC_SYSROOT),$(KBUILD_RUSTC_SYSROOT)/lib/rustlib/src/rust/library,)

KBUILD_LLVM_ARG := $(if $(LLVM),LLVM=$(LLVM),)
KBUILD_OUTPUT_ARG := $(if $(O),O=$(O),)
KBUILD_MODULE_OUTPUT_ARG := $(if $(MO),MO=$(MO),)
KBUILD_RUSTC_ARG := RUSTC=$(KBUILD_RUSTC)
KBUILD_RUSTC_BOOTSTRAP_ARG := RUSTC_BOOTSTRAP=$(KBUILD_RUSTC_BOOTSTRAP)
KBUILD_CC_ARG := $(if $(KBUILD_CC),CC=$(KBUILD_CC),)
KBUILD_BINDGEN_ARG := BINDGEN=$(KBUILD_BINDGEN)
KBUILD_RUST_LIB_SRC_ARG := $(if $(KBUILD_RUST_LIB_SRC),RUST_LIB_SRC=$(KBUILD_RUST_LIB_SRC),)

# -Wno-unused-command-line-argument is needed because the kernel build system
# passes flags (e.g. -fno-strict-overflow, -nostdlibinc) that clang treats as
# unused during modfinal (.mod.o, .module-common.o) compilation.  ccflags-y
# from the Kbuild does not survive to the modfinal sub-make; the flag must
# reach it through KCFLAGS.
KBUILD_KCFLAGS_ARG := KCFLAGS=-Wno-unused-command-line-argument

default:
	@if [ ! -f "$(KDIR)/Makefile" ]; then \
		echo "ERROR: KDIR=$(KDIR) is not a Linux kernel source/build tree." >&2; \
		echo "Use linux-prepare and set KDIR to linux_src, O to linux_build, and MO to module_out." >&2; \
		exit 1; \
	fi
	@if [ -n "$(MO)" ]; then mkdir -p "$(MO)"; fi
	$(MAKE) -j$(KBUILD_JOBS) -C $(KDIR) $(KBUILD_LLVM_ARG) $(KBUILD_OUTPUT_ARG) M=$(CURDIR) $(KBUILD_MODULE_OUTPUT_ARG) $(KBUILD_CC_ARG) $(KBUILD_RUSTC_ARG) $(KBUILD_BINDGEN_ARG) $(KBUILD_RUST_LIB_SRC_ARG) $(KBUILD_RUSTC_BOOTSTRAP_ARG) $(KBUILD_KCFLAGS_ARG) modules

clean:
	@if [ -f "$(KDIR)/Makefile" ]; then \
		$(MAKE) -j$(KBUILD_JOBS) -C $(KDIR) $(KBUILD_LLVM_ARG) $(KBUILD_OUTPUT_ARG) M=$(CURDIR) $(KBUILD_MODULE_OUTPUT_ARG) $(KBUILD_CC_ARG) $(KBUILD_RUSTC_ARG) $(KBUILD_BINDGEN_ARG) $(KBUILD_RUST_LIB_SRC_ARG) $(KBUILD_RUSTC_BOOTSTRAP_ARG) clean; \
	else \
		rm -f "$(CURDIR)"/*.o "$(CURDIR)"/*.ko "$(CURDIR)"/*.mod.c; \
		rm -f "$(CURDIR)"/.tidefs_block_kmod.* "$(CURDIR)"/modules.order; \
		rm -f "$(CURDIR)"/Module.symvers; \
		echo "Kernel tree not available; manual cleanup done."; \
	fi

.PHONY: default clean
endif
