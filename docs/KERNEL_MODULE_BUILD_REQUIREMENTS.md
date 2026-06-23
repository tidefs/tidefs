# Kernel Module Build Requirements

Maturity: **current policy** for out-of-tree TideFS kernel module builds.

This document records the supported Linux kernel version range, required
kernel configuration options, compiler/linker flags, and local build
instructions for TideFS kernel modules.

Issue: [#1080](https://github.com/tidefs/tidefs/issues/1080)

## Supported kernel versions

| Component              | Minimum Version | Current Baseline |
|------------------------|-----------------|------------------|
| Linux kernel           | 7.0             | 7.0 (QEMU guest) |
| rustc                  | 1.78.0          | 1.88.0           |
| rust-src               | matching rustc  | matching rustc   |
| bindgen                | 0.65.1          | 0.69.4           |
| clang / LLVM           | 19              | 19               |

The modules use Rust-for-Linux (abstractions in `rust/kernel/`,
`rust/pin_init/` etc.) and require a kernel built with `CONFIG_RUST=y`.

## Required kernel configuration

These options must be enabled in the kernel `.config` before building the
modules. The symbols below use the `CONFIG_`-less format stored in
`nix/vm/kernel-7.0-config`.

### Rust support

```
RUST y
```

The kernel must pass `make rustavailable` and `make modules_prepare` before
out-of-tree module compilation. `modules_prepare` builds the Rust helper
crates (`core`, `alloc`, `kernel`, `bindings`, `pin_init`, `macros`, `uapi`).

### Module support

```
MODULES y
MODULE_UNLOAD y
```

`MODULE_FORCE_UNLOAD y` is recommended for development but not required in
production.

### Hardening (recommended, enabled in CI)

```
STACKPROTECTOR y
STACKPROTECTOR_STRONG y
FORTIFY_SOURCE y
```

These options are enabled in the TideFS QEMU validation kernel configs
(`nix/vm/kernel-7.0-config` and `nix/vm/kernel-7.0-config-instrumented`).
They are not strictly required for module compilation but are part of the
hardened build policy.

## Compiler and linker flags

### C compilation flags (subdir-ccflags-y)

Each Kbuild file sets:

```makefile
subdir-ccflags-y := -Wall -Wextra -Werror -Wno-unused-parameter
```

- `-Wall`: broad warning coverage standard across the kernel.
- `-Wextra`: additional diagnostics beyond `-Wall`.
- `-Werror`: promotes warnings to errors; the CI gate rejects any build
  that produces a warning.
- `-Wno-unused-parameter`: kernel APIs and Rust FFI shims routinely receive
  context parameters (e.g. `struct file *`, `struct inode *`,
  `struct block_device *`) that are forwarded to later layers and intentionally
  unused in the shim. The diagnostic is suppressed to avoid noise from this
  well-understood pattern.

### Rust compilation flags

Each Kbuild file sets:

```makefile
RUSTFLAGS_MODULE := -Dwarnings
```

This treats all Rust warnings as errors during kernel module compilation.
The primary Rust quality gate is `clippy`; `-Dwarnings` prevents new
warnings from silently accumulating in the Kbuild path.

### Linker

The kernel build uses `LLVM=1` to select the LLVM toolchain (`clang`,
`ld.lld`). This is mandated by the Linux 7.0 Rust-for-Linux toolchain
requirements.

## How to build locally

### Prerequisites

Prepare a Linux 7.0 kernel build tree with Rust support enabled:

```sh
nix run .#k7-kbuild-toolchain
```

Or use the shared Nexus baseline (if available):

```sh
/root/ai/bin/tidefs-nexus-worker-tool linux-prepare --slot <SLOT> --issue <N>
```

### Build the POSIX VFS kernel module

```sh
make -j8 -C crates/tidefs-kmod-posix-vfs \
  KDIR=/path/to/linux-7.0-source \
  O=/path/to/linux-7.0-build \
  MO=/path/to/module-out/posix-vfs \
  LLVM=1
```

Or use the compile script:

```sh
bash scripts/compile-kmod-posix-vfs.sh
```

### Build the block-volume kernel module

```sh
make -j8 -C crates/tidefs-block-kmod \
  KDIR=/path/to/linux-7.0-source \
  O=/path/to/linux-7.0-build \
  MO=/path/to/module-out/block-kmod \
  LLVM=1
```

### Smoke test the block module with in-memory backend

```sh
make -j8 -C crates/tidefs-block-kmod \
  KDIR=/path/to/linux-7.0-source \
  O=/path/to/linux-7.0-build \
  MO=/path/to/module-out/block-kmod \
  LLVM=1 \
  RUSTFLAGS_MODULE='--cfg=tidefs_block_kmod_bringup_backend'
```

The `RUSTFLAGS_MODULE` assignment on the command line overrides the Kbuild
default (`-Dwarnings`) so the smoke-test cfg is the only flag. The warning
gate is relaxed intentionally for bringup-only smoke builds.

### Nix build (CI parity)

```sh
nix build -L .#packages.x86_64-linux.tidefsPosixVfsKmod
```

This builds the module against the Nix Linux 7.0 guest kernel and catches
any warning-as-error regression.

## CI gating

The `Nix Checks` workflow (`.github/workflows/nix-checks.yml`) builds
`tidefsPosixVfsKmod` as part of every PR. A non-zero warning or a Kbuild
failure blocks the PR.

## Warning policy

- All kernel module Kbuild and C source files must compile with zero
  warnings under `-Wall -Wextra -Werror` (with the `-Wno-unused-parameter`
  exception documented above).
- Rust sources must compile with zero warnings under `-Dwarnings`.
- New warnings introduced by a PR are treated as CI failures.

## References

- [k7-kbuild-toolchain.md](k7-kbuild-toolchain.md): toolchain preparation
- [KERNEL_MODULE_DEVELOPMENT_WORKFLOW_P7-05.md](KERNEL_MODULE_DEVELOPMENT_WORKFLOW_P7-05.md): kernel-source development loop
- [crates/tidefs-kmod-posix-vfs/Kbuild](../crates/tidefs-kmod-posix-vfs/Kbuild)
- [crates/tidefs-block-kmod/Kbuild](../crates/tidefs-block-kmod/Kbuild)
