# Linux 7.0 kernel source development workflow (P7-05)

Maturity: **current policy** for Linux 7.0 kernel development workflow.

Authority note: this is a development-loop and acceptance-workflow policy, not
kernel runtime maturity evidence. It does not claim a production kernel module,
full-kernel readiness, or a broader validation obligation for documentation-only
slices.

This document fixes the development loop for TideFS kernel work. The kernel
delivery may be out-of-tree modules, in-tree Linux patches, or a combination of
both. Workers must not assume that all kernel work is only `kmod` work.

It answers one concrete question:

**How do TideFS workers develop Linux 7.0 kernel work quickly without turning
Nix into the per-edit full-kernel rebuild loop, while still keeping Nix and
QEMU as the reproducible acceptance authority?**

See also:

- `docs/KERNEL_RESIDENCY_AUTHORITY.md`
- `docs/KERNEL_RESIDENT_POOL_ENGINE_ARCHITECTURE.md`
- `docs/PREVIEW_UAPI_ABI_BOUNDARY_OW202.md`

## 1. Decision

Nix is the reproducible kernel acceptance layer, not the per-edit kernel hot
loop.

The TideFS Linux source mirror is private operator-owned infrastructure outside
this public repository. The baseline branch is `tidefs/linux-7.0`, rooted at the
signed `v7.0` Linux tag. TideFS kernel source changes belong on issue-bound
branches in that Linux repository, not as vendored Linux trees, submodules, or
hidden local patches in the TideFS repository.

The hot loop for kernel work is:

1. use `nix/kmod-hot-loop.sh prepare` or explicit `KERNEL_TREE`,
   `KERNEL_BUILD`, and `MODULE_OUT` paths to prepare a Linux 7.0 source/build
   baseline outside the TideFS repository;
2. use per-slot `module-out` and `qemu-runs` directories for ordinary external
   module build products and disposable guest artifacts;
3. for external modules, build with
   `make -j8 -C <linux-src> LLVM=1 O=<linux-build> M=<tidefs-worktree>/<module-dir> MO=<module-out> RUSTC=$(cd <tidefs-worktree> && rustc --print sysroot)/bin/rustc RUSTC_BOOTSTRAP=1 modules`
   or a higher job count. Direct Kbuild commands must pass the absolute
   repo-pinned rustc path because `MO=` builds execute outside the repo
   rustup override;
4. use a writable per-issue Linux source/build pair only when an in-tree Linux
   patch is actually required;
5. for in-tree Linux patches, run targeted Kbuild commands against the changed
   subtree or object through that patch build directory;
6. boot, load, or exercise the result only in a disposable Linux 7.0 QEMU
   guest;
7. run the Nix Linux 7.0 acceptance target before publication, issue closure,
   or admission.

The anti-regression rule is direct:

**Nix and QEMU are the reproducible admission gate, not the per-edit kernel
loop.** Full acceptance targets remain mandatory when a kernel slice is ready
for admission, but they are too expensive and too broad to be the inner loop
for ordinary kernel edits.

## 2. Source ownership

The TideFS repository owns filesystem code, userspace control utilities, and
TideFS-owned module/crate code that is part of the product tree.

The private Linux mirror owns Linux source changes needed by TideFS. Use this
branch shape for Linux work:

```text
tidefs/linux-7.0
codex/tidefs-linux/issue-<issue-number>-<short-slug>
```

Issue closeout for kernel-source work must record:

- the TideFS commit or branch, if a paired TideFS change exists;
- the Linux repository branch and commit;
- why the Linux patch is required instead of an external module or exported
  interface;
- the targeted Kbuild command used in the hot loop;
- the Nix acceptance command and result when the work is being admitted.

A Linux patch must never exist only in a prepared build directory. If it is
needed, commit it to the private Linux mirror on an issue branch and make the
TideFS issue or acceptance note point at that branch.

## 3. Nix role

Nix owns:

- the reproducible Linux 7.0 kernel acceptance build;
- the reproducible kernel package and tool surface;
- the Linux 7.0 QEMU acceptance target;

Nix may build a full Linux 7.0 kernel when the acceptance target requires it.
That cost is expected at gate time.

Nix must not become the edit/compile/test loop for individual `.rs`, `.c`,
Kbuild, or Linux source changes.

## 4. Hot-loop role

The fast loop owns developer throughput.

The default public hot-loop helper uses one Linux 7.0 baseline plus lightweight
per-issue output directories:

```text
/root/ai/state/tidefs/kernel-dev/shared/linux-7.0/source
/root/ai/state/tidefs/kernel-dev/shared/linux-7.0/build
/root/ai/state/tidefs/kernel-dev/<slot>/issue-<issue>/module-out
/root/ai/state/tidefs/kernel-dev/<slot>/issue-<issue>/qemu-runs
```

Workers may let the helper prepare its default paths:

```sh
nix/kmod-hot-loop.sh prepare
```

Workers may also pass explicit paths when a prepared baseline already exists:

```sh
KERNEL_TREE=<linux-src> KERNEL_BUILD=<linux-build> MODULE_OUT=<module-out> \
  nix/kmod-hot-loop.sh prepare
```

The source path is a clean Linux 7.0 checkout. The build path is out-of-tree
Kbuild output/cache state: it may be deleted and recreated, must not be
committed, and must not be treated as the source of any Linux patch.

External module edit loop:

```sh
LINUX_SRC=<linux-src>
LINUX_BUILD=<linux-build>
MODULE_OUT=<module-out>
KERNEL_TREE="$LINUX_SRC" KERNEL_BUILD="$LINUX_BUILD" MODULE_OUT="$MODULE_OUT" \
  nix/kmod-hot-loop.sh prepare
RUSTC="$(cd <tidefs-worktree> && rustc --print sysroot)/bin/rustc" RUSTC_BOOTSTRAP=1 \
make -j8 -C "$LINUX_SRC" LLVM=1 O="$LINUX_BUILD" \
  M="<tidefs-worktree>/crates/tidefs-kmod-posix-vfs" \
  MO="$MODULE_OUT/posix-vfs" modules
RUSTC="$(cd <tidefs-worktree> && rustc --print sysroot)/bin/rustc" RUSTC_BOOTSTRAP=1 \
make -j8 -C "$LINUX_SRC" LLVM=1 O="$LINUX_BUILD" \
  M="<tidefs-worktree>/crates/tidefs-block-kmod" \
  MO="$MODULE_OUT/block-kmod" modules
```

Writable Linux patch setup is private-infra work: create or use an
issue-scoped writable Linux checkout/build pair from the operator-owned Linux
mirror, then pass those paths explicitly as `KERNEL_TREE` and `KERNEL_BUILD`.

In-tree Linux patch edit loop:

```sh
make -j8 -C <linux-src> O=<linux-build> <changed-object>.o
make -j8 -C <linux-src> O=<linux-build> <changed-subtree>/
make -j8 -C <linux-src> O=<linux-build> bzImage modules
```

Use the narrowest Kbuild target that proves the changed surface. Run broader
kernel builds and the Nix acceptance target only when the patch is ready for
admission.

Kernel compile parallelism is mandatory for throughput. Do not run `make -j1`
for Linux 7.0 builds. For full Nix acceptance, keep derivation concurrency
bounded while giving the kernel build jobs:

```sh
nix build --max-jobs 1 --cores 8 .#linuxKernel_7_0
```

Use a higher `--cores` or `-j` count when the host has capacity. Do not run
multiple overlapping full-kernel builds as a substitute for in-build
parallelism.

## 4a. Disk and cache ownership

The shared Linux baseline is the only normal full source/build copy. Per-issue
state is limited to module outputs, QEMU run artifacts, and rare writable patch
checkouts created through the private-infra process.

There is no public-repo garbage-collection command for TideFS kernel-dev state.
Clean only paths owned by the current issue after checking live process,
worktree, and Git state. Do not manually delete another slot's kernel-dev
directory or a dirty/ahead Linux checkout.

## 5. QEMU load/test rule

Experimental TideFS kernel modules and patched TideFS kernels must not be
loaded into the host kernel.

The hot loop must use a disposable Linux 7.0 QEMU guest that can be destroyed
after each run. Each smoke result must record:

- the Linux kernel version and commit;
- the module path and module metadata, or the patched kernel branch and commit;
- `insmod`/`modprobe` result for external modules, when applicable;
- QEMU boot result for patched kernels;
- `dmesg` excerpt relevant to TideFS;
- the focused smoke command result;

Host-only compile checks are useful, but they do not prove module loadability,
patched-kernel bootability, or mounted kernel behavior.

For external module load smoke, `nix/kmod-hot-loop.sh smoke` accepts any
already-built module through `KO_PATH=/path/to/module.ko`; `MODULE_NAME` may be
set explicitly, otherwise the helper reads `modinfo -F name` from the `.ko`.
`tidefs_posix_vfs` or `tidefs_block_kmod`.

For POSIX VFS registration smoke, set `EXPECT_FS_TYPE=tidefs` with
`KO_PATH=<module-out>/tidefs_posix_vfs.ko`. The hot-loop guest then verifies
`/proc/filesystems`, attempts the requested `mount -t tidefs`, records the
mount result, unloads the module, and destroys the guest.

Unbound product mounts must fail closed even when `EXPECT_FS_OPTIONS=bootstrap`
is supplied. A block-device-backed product mount may proceed only after the
C/Rust mounted path binds explicit kernel pool I/O authority for read, write,
flush, capacity, and teardown as described in
`docs/KERNEL_RESIDENT_POOL_ENGINE_ARCHITECTURE.md`.

The standing `nix run .#kmod-xfstests-smoke` QEMU row now covers both sides of
that rule. It keeps the bootstrap/no-device refusal, then creates a disposable
128 MiB virtio pool member with `tidefsctl pool create`, mounts `/dev/vda`
with `mount -t tidefs`, verifies statfs capacity from the configured pool
authority, writes and calls `sync -f` through the mounted path, and unmounts
cleanly.
Passing that row is the minimum no-daemon configured-pool evidence; broader
xfstests, crash-recovery, and final object/extent replay claims still need
their own issue-scoped rows.

## 6. Required first proofs

Before `kmod.posix_filesystem_adapter.vfs.k0` or
`kmod.block_volume_adapter.block.k0` can depend on the loop, the repo must have
a focused proof that a trivial Rust-for-Linux external module:

- builds against the prepared Linux 7.0 tree;
- produces a `.ko` outside the repo source tree;
- loads in a disposable Linux 7.0 QEMU guest;
- then passes the Nix Linux 7.0 acceptance target.

Before an in-tree Linux patch can be treated as a shipping requirement, the
paired Linux branch must prove that the patched kernel:

- builds through the prepared Linux 7.0 build tree without a full Nix rebuild
  in the edit loop;
- boots in a disposable Linux 7.0 QEMU guest;
- exposes the TideFS kernel surface without a userspace support daemon for the
  I/O path being admitted;
- then passes the Nix Linux 7.0 acceptance target.

## 7. Forbidden shortcuts

The following shortcuts are forbidden:

- running the full Nix Linux 7.0 kernel/QEMU target for every kernel edit;
- creating mutable kernel build directories under the TideFS repo or worker
  worktree;
- committing prepared kernel trees, generated `.ko` files, generated kernel
  images, or Cargo/Nix build outputs;
- loading experimental TideFS modules or patched TideFS kernels on the host;
- vendoring Linux into the TideFS repository;
- carrying required Linux patches only in local build trees;
- relying on a non-exported kernel symbol without an explicit Linux branch and
  architecture decision;
- using Linux patches as a hidden substitute for the documented VFS, block,
  UAPI, authority, and rollback boundaries.

If TideFS needs a Linux patch, a non-exported symbol, or a different kernel
configuration to make forward progress, that is valid kernel-source work only
when it is visible in the private Linux mirror, tied to the TideFS issue or
release packet, and proven through QEMU and Nix acceptance.

## 8. Issue implications

Kernel issues must interpret the build surfaces this way:

- `K7-02` owns reproducible Linux 7.0 Nix/QEMU acceptance, not the per-edit
  kernel loop.
- `K7-04` owns the common bridge substrate.
- `K7-04B` owns the missing Linux 7.0 out-of-tree Rust-for-Linux hot-loop
  proof; it does not prohibit later in-tree Linux patch work.
- `K7-05` and `K7-08` must use the hot loop for focused compile/load/smoke
  work and must run Nix acceptance only as a gate.
- Nix acceptance must exist for admission; it must not be used as the ordinary
  edit loop.
- Any issue that discovers a real Linux source requirement must either push a
  Linux issue branch to the private Linux mirror or split a child issue that
  owns that branch.

Completed work stays completed unless the Linux 7.0 hot-loop proof exposes a
specific incompatibility. The purpose of this rule is to keep throughput high
without discarding accepted repo work.
