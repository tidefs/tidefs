# Nix CI Output Contract

**Last updated**: 2026-06-23
**Source**: bounded inspection of `flake.nix` and `.github/workflows/nix-checks.yml`

This document inventories the Nix outputs currently built by the standing
`Nix Checks` workflow and maps the remaining flake outputs to their validation
intent and dispatch surface. It does not change any Nix derivation, workflow,
or package behaviour.

Terms used below:

- **Standing CI gate**: built on every qualifying push to `master` and every
  ready-for-review PR targeting `master` (as well as on manual dispatch).
  Success is required for merge readiness.
- **Manual/focused dispatch**: must be triggered explicitly via
  `workflow_dispatch`, `nix build`, `nix run`, or a separate GitHub Actions
  workflow such as `Focused Rust`, `QEMU Smoke`, or `Focused Claim Validation`.
- **Validation tier**: the evidence class a successful build or run provides.
  None of the tiers below are mounted-runtime, distributed, or
  release-readiness claims on their own.
  - **Build smoke**: `nix build` succeeds; the derivation's build-phase
    tests pass inside the Nix sandbox.
  - **Unit test**: Rust or shell-level unit/integration tests pass inside
    the sandbox (no kernel, no QEMU, no FUSE mount).
  - **QEMU / NixOS test**: a `runNixOSTest` or out-of-sandbox NixOS VM
    test boots a kernel, loads TideFS modules, and exercises
    filesystem or block operations.
  - **Release-candidate gate**: reserved for broad xfstests, RDMA,
    long-haul soak, or multi-node cluster campaigns that the project
    gates releases on.

---

## 1. Standing Nix CI outputs

These six outputs are built by [`.github/workflows/nix-checks.yml`](/.github/workflows/nix-checks.yml:47)
and gate every qualifying push and ready PR.

| Flake output | Category | Builds | Validation intent |
|---|---|---|---|
| `checks.x86_64-linux.rdmaCarrierTwoNode` | Check | Source grep | Verifies that the `rdmaCarrierTwoNodeTest` NixOS test definition and its expected strings are present in `flake.nix` |
| `packages.x86_64-linux.default` | Core package | Full workspace Rust build | All workspace binaries compile; basic workspace-level build smoke |
| `packages.x86_64-linux.tidefsFuseRuntime` | Core package | FUSE runtime subset | FUSE daemon and adapter binaries compile |
| `packages.x86_64-linux.tidefsUblkRuntime` | Core package | ublk runtime subset | ublk daemon and block-volume adapter binaries compile |
| `packages.x86_64-linux.tidefsPosixVfsKmod` | Kernel module | Out-of-tree Rust kernel module | `tidefs_posix_vfs.ko` compiles against the configured kernel |
| `packages.x86_64-linux.tidefsBlockKmod` | Kernel module | Out-of-tree Rust kernel module | `tidefs_block.ko` compiles against the configured kernel |

Together these six items form the **compile gate**: they confirm that the
full workspace, both runtime slices, and both out-of-tree kernel modules
build without errors. They do not boot a kernel, mount a filesystem, run
xfstests, exercise RDMA, or validate runtime correctness.

---

## 2. Checks not in standing CI

These `checks.<system>.<name>` outputs are defined in `flake.nix` but are
**not** built by `nix-checks.yml`.

| Flake output | Validation intent | Dispatch surface |
|---|---|---|
| `checks.x86_64-linux.workspace` | Rust workspace compilation + `tidefs-validation.sh` unit tests | Manual `nix build`; superseded by the standing `default` package build + per-workflow Rust coverage |
| `checks.x86_64-linux.kernelValidationMatrix` | Rust `kernel_validation_matrix` unit tests (no kernel boot) | Manual `nix build` or `nix run .#kernel-validation-matrix` |
| `checks.x86_64-linux.formatting` | `alejandra` formatting check over the entire source tree | Manual `nix build`; formatting is not a merge gate today |

---

## 3. Packages not in standing CI

All packages below are defined under `packages.x86_64-linux.*` and are
available via `nix build` or `nix run` (through corresponding apps).

### 3.1 Additional core packages

Not built by standing CI because they are subsets of `default`, are
build-tooling helpers, or are exercised through narrower workflows.

| Package | Intent | Why not in standing CI |
|---|---|---|
| `tidefsStorageNode` | Storage-node-only binary | Subset of `default`; exercised by cluster E2E dispatch |
| `tidefsCtlRuntime` | `tidefsctl` binary | Subset of `default`; exercised by kernel teardown and focused validation dispatches |
| `tidefsXtaskRuntime` | `tidefs-xtask` binary | Subset of `default`; exercised by `Focused Claim Validation` and kernel teardown dispatches |
| `tidefsUblkCompletionRuntime` | ublk completion artifact validation binary | Subset of `default`; exercised by `ublkCompletionArtifactValidation` dispatch |
| `rustBindgenLinuxKbuild` | Rust `bindgen` 0.69 toolchain for Linux kernel builds | Build-tooling helper consumed by kmod derivations; not an end-user artifact |

### 3.2 Support / tooling packages

| Package | Intent | Dispatch surface |
|---|---|---|
| `tidefsFsx` | Compiled `fsx/fsx.c` (filesystem exerciser) | Consumed by FUSE fsx validation and kernel xfstests dispatches |
| `tidefsXfstestsScripts` | Mount, runner, and exclude scripts for xfstests | Consumed by all xfstests dispatches |
| `tidefsMmapWorkload` | Compiled `scripts/tidefs-mmap-workload.c` | Consumed by kernel mmap validation dispatch |
| `xfstests` | Patched `xfstests` with TideFS filesystem support | Consumed by all xfstests dispatches |

### 3.3 Kernel builds

These are standalone kernel derivations, not validation tests.

| Package | Intent | Dispatch surface |
|---|---|---|
| `linuxKernel_7_0` | Linux 7.0 kernel with TideFS config | Consumed by kernel validation NixOS tests |
| `linuxKernel_7_0_instrumented` | Linux 7.0 kernel with lockdep/kcsan/kasan | Consumed by `kernelLockdepKcsanKasanValidation` |
| `k7KbuildToolchain` | Rust-for-Linux kbuild toolchain for out-of-tree module development | Manual `nix build`; also available via `nix run .#k7-kbuild-toolchain` |

### 3.4 Kernel / VFS validation (QEMU / NixOS tests)

Every item below boots a kernel under QEMU, loads TideFS kernel modules,
and exercises filesystem operations. All require **manual dispatch** through
`nix run` or a dedicated GitHub Actions workflow.

**POSIX VFS syscall coverage:**

| Package | Syscalls exercised |
|---|---|
| `kernelReadWriteValidation` | read, write, lseek |
| `kernelCopySpliceValidation` | copy_file_range, splice, sendfile |
| `kernelReaddirValidation` | getdents64, lseek-on-dir |
| `kernelLookupValidation` | lookup, path resolution |
| `kernelRenameValidation` | rename, RENAME_NOREPLACE, RENAME_EXCHANGE |
| `kernelSymlinkValidation` | symlink, readlink |
| `kernelMkdirRmdirValidation` | mkdir, rmdir |
| `kernelLinkUnlinkValidation` | link, unlink |
| `kernelLinkCrashValidation` | link/unlink crash consistency |
| `kernelFallocateValidation` | fallocate (modes 0, FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE) |
| `kernelTruncateValidation` | truncate, ftruncate |
| `kernelFsyncValidation` | fsync, fdatasync |
| `kernelInotifyFanotifyValidation` | inotify, fanotify |
| `kernelStatfsValidation` | statfs, fstatfs |
| `kernelConcurrentValidation` | Concurrent multi-process syscall interleaving |
| `kernelCrossPathEquivalence` | Cross-directory path equivalence |

**Aggregate / stress validation:**

| Package | Intent |
|---|---|
| `kernel7Validation` | Combined syscall battery (legacy aggregate) |
| `kernelNoDaemonValidation` | kmod residency without a userspace daemon |
| `kernelNoDaemonTeardownValidation` | Teardown path without daemon |
| `kernelLockdepKcsanKasanValidation` | Lockdep / KCSAN / KASAN instrumented kernel boot |
| `kernelDirNamespaceValidation` | Directory namespace isolation |
| `kernelWritebackValidation` | Writeback path correctness |
| `kernelMmapValidation` | mmap read/write/msync |
| `kernelTruncateFallocateValidation` | Truncate + fallocate combined (legacy aggregate) |
| `kernelPerformanceBudgetValidation` | Performance budget assertions |
| `kernelMountCycleStressValidation` | Repeated mount/unmount cycles |
| `kernelMountNamespaceValidation` | Mount namespace isolation |
| `kernelTeardownValidation` | Full teardown sequence with kmod, daemon, and xtask |
| `kernelLongHaulSoakValidation` | Multi-hour soak under continuous filesystem load |
| `kernelXfstestsValidation` | xfstests battery against the kernel module (broad gate) |
| `kernelXfstestsCrashConsistency` | xfstests crash-consistency group |
| `k7VfsXfstestsValidation` | xfstests against k7 kernel (release-candidate gate) |
| `kmodAcceptance` | Nix/QEMU acceptance validation for a hot-loop-built module |
| `kmodValidation` | kmod build + validation matrix |
| `kmodXfstestsSmoke` | kmod build + xfstests smoke subset |

**Block device validation:**

| Package | Intent |
|---|---|
| `kernelBlockValidation` | ublk block device syscall battery |
| `kernelBlockQueueDepthValidation` | Block queue depth performance + correctness |
| `kernelBlockCrashConsistency` | Block device crash consistency under fio |
| `kernelBlockNoDaemonAudit` | Block device operations without userspace daemon |
| `kernelBlockFioPowercutCampaign` | Fio-based powercut consistency campaign |
| `kernelBlockGuestFilesystemMatrix` | Guest filesystem matrix (ext4, xfs, btrfs on ublk) |
| `blockKmodIoDispatchValidation` | Block kmod IO dispatch path validation |

### 3.5 FUSE validation (QEMU / NixOS tests)

Every item below boots a kernel, mounts a TideFS FUSE filesystem, and
exercises FUSE protocol operations. All require **manual dispatch**.

| Package | Intent |
|---|---|
| `fuseExtentValidation` | FUSE extent (read/write range) correctness |
| `fuseInodeMetadataValidation` | Inode metadata operations (stat, chmod, chown, utimes) |
| `fuseFallocateValidation` | fallocate through FUSE |
| `fuseCreateOpenReleaseValidation` | Create, open, and release FUSE operations |
| `fuseWritebackCacheValidation` | FUSE writeback cache coherence (full) |
| `fuseWritebackCacheValidationFast` | FUSE writeback cache coherence (fast subset) |
| `fuseOpenUnlinkRenameSoak` | Open/unlink/rename soak under load |
| `fuseProductDemoSoak` | Product-demo scenario soak |
| `fuseNamespaceScaleStress` | Namespace scaling stress (VM) |
| `fuseNamespaceScaleStressHost` | Namespace scaling stress (host) |
| `fuseXfstestsValidation` | xfstests battery against FUSE (broad gate) |
| `fuseFsxValidation` | fsx exerciser against FUSE |
| `fuseFioBaselineValidation` | Fio performance baseline against FUSE |
| `fuseUblkStorageIntegratedWorkflow` | Integrated FUSE + ublk storage workflow |

### 3.6 ublk validation

| Package | Intent |
|---|---|
| `qemuUblkSmoke` | Minimal ublk block device smoke |
| `qemuUblkExt4Smoke` | ublk + ext4 smoke |
| `qemuUblkMultiDevicePlacement` | Multi-device placement correctness |
| `qemuUblkCrashConsistency` | ublk crash consistency |
| `qemuUblkFsMatrix` | ublk filesystem matrix (ext4, xfs, btrfs) |
| `ublkProductDemoWorkflow` | ublk product-demo workflow |
| `ublkDiscardValidation` | ublk discard/trim correctness |
| `ublkPerformanceBaseline` | ublk performance baseline |
| `ublkCompletionArtifactValidation` | ublk completion artifact validation |

### 3.7 Pool / storage validation

| Package | Intent |
|---|---|
| `poolCreateBlockdevValidation` | Pool create + block device allocation lifecycle |
| `kernelPoolImportValidation` | Pool import correctness (kernel module) |
| `poolE2EBlockdevValidation` | End-to-end pool + block device workflow |
| `poolRemountLifecycleValidation` | Pool remount lifecycle (create, stop, remount, verify) |

### 3.8 Cluster / RDMA validation

All cluster and RDMA items require **two or more nodes** and manual
dispatch. They are not standing CI gates.

| Package | Intent |
|---|---|
| `multiNodeCluster` | Multi-node TideFS cluster NixOS test |
| `clusterE2EValidation` | End-to-end cluster validation |
| `qemuRdmaGuestSystem` | QEMU RDMA guest system image |
| `rdmaCarrierTwoNodeTest` | RDMA carrier two-node NixOS test (ping, rping, Rust RDMA carrier tests) |
| `rdmaTwoNodeValidation` | RDMA two-node validation runner |

### 3.9 QEMU smoke / early tests

| Package | Intent | Notes |
|---|---|---|
| `qemuSmoke` | Minimal QEMU boot smoke | Legacy `runNixOSTest` |
| `tidefsFuseVmTest` | FUSE VM boot smoke | Legacy `runNixOSTest` |
| `qemuXfstestsLockSymlinkFallocate` | xfstests lock + symlink + fallocate subset under QEMU | Legacy `runNixOSTest` |
| `tidefsXfstestsLockGroup` | xfstests lock group under QEMU | Out-of-sandbox runner |

### 3.10 Deprecated

| Package | Status |
|---|---|
| `tidefsFuseFioBenchmark` | Deprecated; shell warns to use `fuseFioBaselineValidation` instead |
| `tidefsFuseFioBenchmarkNixOSTestDeprecated` | Deprecated legacy `runNixOSTest` wrapper |

---

## 4. Dev shells

| Shell | Intent | Contents |
|---|---|---|
| `devShells.x86_64-linux.default` | Full TideFS development shell | Rust toolchain, FUSE, RDMA, QEMU, kmod, xfstests, fio, cargo-deny, git, and all support tooling |
| `devShells.x86_64-linux.ci` | Minimal CI shell | Rust toolchain, cargo-deny, FUSE, RDMA, pkg-config, jq |

Neither dev shell is a CI gate. `.#ci` is consumed by `Rust Fast`,
`Clippy`, `Focused Rust`, and `Dependency License` workflows at
job-execution time.

---

## 5. Apps

The `apps.x86_64-linux.*` namespace contains `nix run` script wrappers
that correspond to the packages listed above plus a few extras:

| App | Wraps | Notes |
|---|---|---|
| `validate` | `checks.workspace` build-phase tests | Primary Rust gate for manual validation |
| `posix-scoreboard` | External-suite pass/fail/skip runner | Live FUSE validation against external test suites |
| `xfstests-runner`, `xfstests-generic`, `xfstests-lock-symlink-fallocate`, `xfstests-lock-group` | xfstests dispatches with preset test groups | |
| `qemu-direct` | Direct QEMU launch helper | |
| `kmod-hot-loop` | Rust-for-Linux out-of-tree kmod hot loop | Developer iteration loop |
| `rdma-probe` | Non-mutating RDMA host probe | |
| `rdma-carrier-test` | RDMA carrier validation script | Combines probe + two-node dry-run + Rust RDMA carrier tests |
| `qemu-rdma-two-node`, `qemu-rdma-two-node-nixos`, `qemu-rdma-guest-system` | RDMA two-node QEMU topology runners | |

Every other app entry is a one-to-one script wrapper for its corresponding
validation package and shares the same dispatch requirements.

---

## 6. Formatter

`formatter.x86_64-linux` points to `alejandra`. It is not a CI gate;
formatting is currently checked only by the manual `checks.formatting`
derivation.

---

## 7. Evidence limits

- A successful `nix build` of any package listed here is a **build smoke**
  gate only. It confirms the derivation's build steps completed inside the
  Nix sandbox. It does **not** confirm:
  - That the binary runs correctly on a real kernel.
  - That the kernel module loads, mounts, or survives teardown.
  - That any FUSE, ublk, RDMA, or cluster protocol works.
  - That filesystem operations are correct, crash-consistent, or
    performant.
  - That the artifact is suitable for distribution or release.
- Validation tiers are defined by the specific QEMU/NixOS test, xfstests
  campaign, RDMA two-node run, or long-haul soak that exercises the
  relevant code path. Each dispatch records its own evidence artifact.
- The standing `Nix Checks` workflow is a **compile gate**, not a
  correctness, performance, or release-readiness gate. A green Nix Checks
  run means only that the six listed outputs built.

---

## 8. Follow-up observations

These are recorded as potential future improvements, not fixed in this
slice.

1. **Stale naming**: `kernelTruncateFallocateValidation` is a legacy
   aggregate; the individual `kernelTruncateValidation` and
   `kernelFallocateValidation` packages supersede it. Consider retiring
   or marking the aggregate as a wrapper-only alias.
2. **Legacy `runNixOSTest` packages**: `qemuSmoke`, `tidefsFuseVmTest`,
   `qemuXfstestsLockSymlinkFallocate`, and the deprecated fio benchmarks
   use the older `runNixOSTest` API. The dev shell shellHook already
   warns that legacy `runNixOSTest` QEMU apps are refused until ported
   to outside-sandbox runners. A future slice could audit and remove the
   remaining legacy packages once migrated.
3. **Checks not gating**: `checks.workspace`, `checks.kernelValidationMatrix`,
   and `checks.formatting` are defined but not wired into any standing CI
   workflow. If they should gate PRs, a follow-up workflow change is needed.
4. **Missing kernel validation packages in apps**: A few kernel validation
   packages (e.g. `kernelTruncateValidation`, `kernelReadWriteValidation`)
   may not have corresponding `apps` entries for `nix run` convenience.
   This is low priority since the validation matrix app covers batch dispatch.
5. **Deprecated packages**: `tidefsFuseFioBenchmark` and
   `tidefsFuseFioBenchmarkNixOSTestDeprecated` exist only to warn users
   toward `fuseFioBaselineValidation`. A future cleanup slice could remove
   them once no callers remain.
