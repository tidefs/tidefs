# K7 Kbuild Toolchain Preparation

Reproducible Linux 7.0 Rust Kbuild toolchain preparation for TideFS kernel
module workers.

Issue: [#6066](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/6066)

## Prerequisites

The Linux 7.0 Rust-for-Linux Kbuild requires (minimum versions per
`scripts/min-tool-version.sh`):

| Component | Minimum Version | Purpose |
|-----------|----------------|---------|
| rustc     | 1.78.0         | Rust compiler (TideFS uses 1.88.0) |
| rust-src  | matching rustc  | Core/alloc library source for kernel |
| bindgen   | 0.65.1         | C header to Rust binding generation |
| clang     | any recent     | C compiler for kernel and bindgen |
| ld.lld    | any recent     | LLVM linker for LTO and Rust |

## Reproducible Command

### Nix (preferred)

From a clean TideFS worktree:

```
nix run .#k7-kbuild-toolchain
```

This provides all prerequisites in a single command.

### Non-Nix fallback

```
source scripts/k7-kbuild-toolchain-prepare.sh
```

The script checks each prerequisite on PATH and reports any missing
components.


The following produced a passing `modules_prepare` with rustc 1.88.0,
matching rust-src, the repo `rust-bindgen-0.69.4-linux-kbuild` wrapper,
clang 19, and ld.lld 19:

```
RUSTC=/path/to/rustc-1.88.0/bin/rustc
BINDGEN=/path/to/bindgen
RUST_LIB_SRC=/path/to/rust-src-1.88.0/library

export RUSTC BINDGEN RUST_LIB_SRC RUSTC_BOOTSTRAP=1
unset RUSTUP_TOOLCHAIN

make -j8 -C <linux-src> O=<linux-build> LLVM=1 \
    RUSTC="$RUSTC" BINDGEN="$BINDGEN" RUST_LIB_SRC="$RUST_LIB_SRC" \
    olddefconfig rustavailable modules_prepare
```

Key invariants:
- Pass RUSTC, BINDGEN, and RUST_LIB_SRC both as environment variables and
  make variables.
- Unset `RUSTUP_TOOLCHAIN` to avoid rustup default-toolchain interference.
- After `olddefconfig`, verify `CONFIG_RUSTC_VERSION=108800` (1.88.0)
  and `CONFIG_RUST=y` in `.config`.
- Use `-j8` or higher for Kbuild commands. Do not use `make -j1` for Linux
  7.0 work; if the host is loaded, run fewer concurrent builds rather than
  making kernel compiles serial.
- Linux source and build artifacts must reside outside the TideFS repo
  (use `linux-prepare`).
- Ordinary module workers use the shared Nexus baseline under
  `/root/ai/state/tidefs/kernel-dev/shared/linux-7.0`; use writable
  per-issue Linux trees only with `linux-prepare --mode patch`.
- Pass `MO=<module-out>` for external modules so `.ko`, `.o`, `.cmd`, and
  `Module.symvers` products are written outside the repo source tree.
- For direct external-module Kbuild commands, pass an absolute repo-pinned
  rustc path plus `RUSTC_BOOTSTRAP=1`. `MO=` builds execute from the module
  output directory, outside the repository rustup override, so a bare `rustc`
  can silently select the wrong toolchain.

## Next Steps for Kmod Workers

After toolchain preparation:

1. Prepare the shared Linux source/build baseline and per-slot output dirs:
   ```
   /root/ai/bin/tidefs-nexus-worker-tool linux-prepare --slot <SLOT> --issue <N>
   ```
   Use the returned `linux_src`, `linux_build`, and `module_out` paths.

2. If `linux_build_prepared` is false, stop and report the shared baseline
   bootstrap blocker. Do not start a per-worker full Nix rebuild as the normal
   module loop.

3. Build TideFS kernel modules with the returned paths:
   ```
   make -j8 -C "$LINUX_SRC" LLVM=1 O="$LINUX_BUILD" M=$PWD MO="$MODULE_OUT/posix-vfs" \
     RUSTC="$(cd <tidefs-worktree> && rustc --print sysroot)/bin/rustc" RUSTC_BOOTSTRAP=1 modules
   ```

## Troubleshooting

**"bindgen not found"**
The Nix app provides bindgen automatically. For non-Nix, install from
nixpkgs (0.69.4 confirmed working with Linux 7.0):
```
nix-shell -p rust-bindgen
```
Or via cargo:
```
cargo install bindgen-cli --version 0.72.1
```

**"rust-src not found"**
Download the matching rust-src tarball:
```
curl -L "https://static.rust-lang.org/dist/rust-src-$(rustc --version | cut -d' ' -f2).tar.gz" | tar xz
```
Then set `RUST_LIB_SRC=<extracted>/rust-src/lib/rustlib/src/rust/library`.

**"CONFIG_RUST is not set"**
The kernel `.config` must have `CONFIG_RUST=y`. After copying the baseline
config (`nix/vm/kernel-7.0-config`), append `CONFIG_RUST=y` and run
`make LLVM=1 olddefconfig`.

**Linux artifacts in TideFS repo**
Linux source and build artifacts must reside outside the TideFS repo.
Use `linux-prepare`, which returns the shared baseline and per-slot
`module_out` path under `/root/ai/state/tidefs/kernel-dev/`.

**libclang version mismatch warning**
The kernel build warns when bindgen's libclang version differs from the
system clang. The Nix Linux 7.0 package uses a pinned bindgen 0.69.4 wrapper
from NixOS 24.05, backed by libclang 17, with clang/LLVM 19 for Kbuild. The
wrapper strips only the Linux 7.0 warning flags that libclang 17 rejects:
`-Wno-format-overflow-non-kprintf`,
`-Wno-format-truncation-non-kprintf`, and `-Wno-format-overflow`. Using the
current nixpkgs bindgen 0.72.1/libclang 21 path may fail earlier because
newer clang treats `-nostdlibinc` as an error.


Proven on 2026-05-19: `make -j8 rustavailable` passes, `make -j8
modules_prepare` builds all Rust helpers (core, alloc, kernel, bindings,
pin_init, macros, uapi) cleanly with the matched rustc 1.88.0 / rust-src
1.88.0 pair.

must come from a fresh external command log for the clean worktree,
`rustavailable`, and `modules_prepare` runs. Schema and cargo rows are not
runtime acceptance.
