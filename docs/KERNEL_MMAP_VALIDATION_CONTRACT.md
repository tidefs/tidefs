# Kernel mmap validation contract

Last updated: 2026-06-23

Source evidence: `.github/workflows/kernel-mmap-validation.yml`,
`flake.nix` (`.#kernel-mmap-validation`),
`nix/vm/kernel-mmap-validation.nix`, and `docs/GITHUB_CI.md`.

## Workflow trigger

- **Name**: `Kernel mmap validation` (workflow-level `name` in the YAML).
- **Trigger**: `workflow_dispatch` only (no push, schedule, or
  `pull_request` trigger).
- **Concurrency**: one run per branch at a time (`cancel-in-progress: false`;
  a new dispatch for the same ref queues behind an in-progress run).

## Dispatch inputs

| Input              | Required | Default | Description                |
| ------------------ | -------- | ------- | -------------------------- |
| `timeout_seconds`  | No       | `900`   | QEMU boot timeout (string) |

No other dispatch inputs are defined. The input is passed as
`--timeout <value>` to the `.#kernel-mmap-validation` flake script.

## Runner requirements

- **Labels**: `self-hosted`, `linux`, `x64`, `tidefs`, `nix`, `kvm`.
- **Privileges**: `/dev/kvm` must be a character device (checked by the
  `Host preflight` step).
- **Group**: `tidefs-ci` (the only TideFS self-hosted runner group).
- **Job timeout**: 120 minutes (`timeout-minutes: 120`). The inner QEMU
  invocation has its own `timeout --foreground 7200s` (also 120 minutes);
  the outer job timeout is the definitive gate.

## Flake target and dependencies

- **Nix target**: `.#kernel-mmap-validation` (a `script` flake output).
- **Source derivation**: `nix/vm/kernel-mmap-validation.nix`.
- **Transitive inputs**: `bash`, `coreutils`, `busybox`, `kmod`, `cpio`,
  `qemu`, `kernelMmapValidation` (the compiled C mmap exerciser plus the
  Nix wrapper), and `tidefsPosixVfsKmod` (the out-of-tree kernel module
  `.ko`).
- The resulting wrapper launches the self-contained C test binary
  `tidefs-kmod-mmap-test` inside a QEMU VM booted with a Linux 7.0 kernel,
  the `tidefs_posix_vfs.ko` module, a minimal initramfs, and a 128 MiB
  virtio pool disk.

## Artifact shape

After an **always** step, the workflow uploads a single artifact:

| Property          | Value                                                       |
| ----------------- | ----------------------------------------------------------- |
| Artifact name     | `kernel-mmap-validation`                                    |
| Source path       | `/tmp/tidefs-validation/kernel-mmap-validation/**`          |
| If no files found | `ignore` (skips without failing the job)                    |
| Retention         | 7 days                                                      |

The flake wrapper writes into `$TIDEFS_OUTPUT_ROOT/kernel-mmap-validation/<iso8601-timestamp>/`
(default `$TIDEFS_OUTPUT_ROOT` = `/tmp/tidefs-validation`).  Each run
produces three artifact files under the timestamp directory:

- `qemu.log` -- full QEMU serial console log.
- `row-summary.txt` -- one line per operation (PASS/FAIL/BLOCKED/UNSUPPORTED).
- `summary.env` -- machine-parseable key=value summary
  (`pass`, `fail`, `blocked`, `unsupported`, `validation_log`, `row_summary`).

The workflow summary step reads the newest `summary.env` and renders it
into the GitHub job summary.

## Rows exercised

The first-boot mmap workload exercises these operations against a TideFS
kernel mount point inside the VM:

1. Module load, lsmod, and pool-device presence.
2. Pool member creation, pool label verification, missing-member rejection.
3. Mount, create-and-write-initial.
4. mmap MAP_SHARED read (fault-read coherence).
5. mmap MAP_SHARED write (fault-write + Linux dirty-folio tracking).
6. Write-read coherence through the mapping.
7. msync MS_SYNC (durability flush).
8. munmap (dirty-page writeback and cleanup).
9. Post-sync read(2) visibility check.
10. truncate-down discard, truncate-extend zero-read.
11. Mapped-dirty-truncate-down followed by msync, munmap, remount, readback.
12. Buffered overwrite after prior mapping plus remount readback.
13. Unmount and module unload.

## What this validation covers

- Mounted first-boot kernel VFS mmap correctness: a self-contained POSIX
  VFS kernel module path with no userspace daemon.
- Page-fault read/write through the kernel C `address_space_operations`
  table registered by `tidefs_posix_vfs.ko`.
- Durability-flush semantics via msync MS_SYNC.
- Page-cache invalidation across truncate-down, truncate-extend, and
  mapped-dirty-truncate cycles.
- Post-remount readback verifying that buffered-overwrite and
  mapped-dirty-truncate data reach durable storage.

## What this validation does NOT cover

- **xfstests**: no xfstests harness, no generic/filesystem test suites.
- **RDMA**: no transport, cluster, or remote-mmap coherence.
- **Broad kernel release-candidate**: single-boot, single-module,
  single-filesystem; no long-running stress, no multi-module interaction,
  no kernel-upgrade regression suite.
- **FUSE mmap**: userspace-daemon mmap coverage belongs to other workflows
  (QEMU Smoke, xfstests lanes).
- **Kernel crash-consistency**: the Nix derivation explicitly classifies
  crash-consistency and the custom Rust `vm_operations_struct` bridge as
  unsupported rows; the C test binary reports them as `UNSUPPORTED`.
- **Performance**: no latency or throughput budget checks.
- **Teardown / no-daemon**: handled by `Kernel teardown validation` and
  `Kernel no-daemon teardown validation`, not this workflow.

## When to require this workflow in a validation tier

- An issue modifies the kernel `a_ops` table, the C `address_space`
  integration, the `tidefs_posix_vfs.ko` page-fault path, the mounted
  mmap/writeback logic, or the kernel-facing truncate/mmap locking in the
  TideFS kernel module.
- An issue changes the `kernelMmapValidation` Nix derivation, the
  `tidefs-kmod-mmap-test` C exerciser, or the `.#kernel-mmap-validation`
  flake target.
- An issue that touches Linux page-cache writeback interaction (e.g.,
  `writepages`, `read_folio`, dirty-folio tracking).

Do **not** require this workflow for:

- Pure userspace (daemon, control-plane, protocol) changes that do not
  affect the kernel module.
- Documentation-only, Nix-infra, or CI-policy slices that do not touch
  the mmap validation code.
- Issues scoped to FUSE, xfstests, RDMA, or release-candidate validation;
  those lanes have their own focused or broad workflows (QEMU Smoke targets,
  `xfstests` dispatch, `RDMA`, `Release Candidate`).

## Relationship to other workflows

| Workflow                       | Scope                                                      | Overlap                  |
| ------------------------------ | ---------------------------------------------------------- | ------------------------ |
| QEMU Smoke                     | Mounted-kernel-vfs smoke (default target)                  | None; QEMU Smoke does not exercise mmap/writeback rows. |
| Kernel teardown validation     | Mount/write/sync/teardown/unmount lifecycle                | Distinct row set.        |
| Kernel no-daemon teardown      | Full-kernel no-daemon crash/recovery                       | Distinct row set.        |
| xfstests                       | xfstests harness against FUSE or kernel mount              | xfstests may exercise broad mmap but is a separate lane. |
| Focused Rust                   | Per-crate Rust tests                                       | No runtime mmap.         |
| Release Candidate              | Aggregated acceptance gate                                 | May include mmap row as one lane; this workflow is the mmap lane. |

## Mismatch notes

The following differences between the documented sources are recorded as
follow-up observations (not fixed in this contract slice):

1. `docs/GITHUB_CI.md` does not mention the `timeout_seconds` dispatch input
   or its default of 900 seconds. A reader who only consults
   `docs/GITHUB_CI.md` would not know the input exists.
2. `docs/GITHUB_CI.md` does not record the 7-day artifact retention or
   the `if-no-files-found: ignore` behavior.
3. The workflow YAML step `Run kernel mmap validation` uses a hard-coded
   `timeout --foreground 7200s` (120 minutes) that shadows the outer
   `timeout-minutes: 120` job timeout; when either expires the job will
   be killed, but the duplicated bounds could drift if the job timeout
   or inner timeout is adjusted independently.
4. The flake target description line in `flake.nix` reads
   `tidefs-kmod-mmap-validation`, matching the Nix derivation name but
   not the workflow-level GitHub name `Kernel mmap validation`. This is
   a cosmetic naming inconsistency, not a functional mismatch.
