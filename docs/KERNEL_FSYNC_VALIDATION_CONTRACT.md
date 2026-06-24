# Kernel fsync validation contract

Last updated: 2026-06-24

Source evidence: `.github/workflows/kernel-fsync-validation.yml`,
`docs/GITHUB_CI.md`, `.github/workflows/qemu-smoke.yml`,
`flake.nix` (`.#kernel-fsync-validation`), and
`nix/vm/kernel-fsync-validation.nix`.

## Purpose

The `Kernel fsync/syncfs validation` workflow is a focused durability lane
that exercises fsync(2), fdatasync(2), and syncfs(2) across a real QEMU
power-loss cycle with persistent virtio-blk backing storage. It produces
`kernel.fsync.durability.v1` evidence under the claim id
`kernel.fsync.durability.v1`. This is a **standalone workflow** separate
from the QEMU Smoke `kernel-fsync-validation` matrix target, with
independent dispatch inputs, concurrency rules, evidence-manifest
richness, and claims-gate authority.

## Workflow trigger

- **Name**: `Kernel fsync/syncfs validation` (workflow-level `name` in the YAML).
- **Trigger**: `workflow_dispatch` only (no push, schedule, or `pull_request` trigger).
- **Concurrency**: serial per branch (`cancel-in-progress: false`; a new
  dispatch for the same ref queues behind an in-progress run).

## Dispatch inputs

| Input              | Required | Default | Description                                |
| ------------------ | -------- | ------- | ------------------------------------------ |
| `timeout_seconds`  | No       | `600`   | QEMU boot timeout per phase in seconds     |
| `pool_size_mb`     | No       | `256`   | Backing pool disk size in MB               |

Both inputs are passed as strings (`type: string`) and consumed by the
`nix run .#kernel-fsync-validation` invocation as `--timeout <value>`
and `--pool-size <value>`.

## Runner requirements

- **Labels**: `self-hosted`, `linux`, `x64`, `tidefs`, `nix`, `kvm`.
- **Privileges**: `/dev/kvm` must be a character device (checked by the `Host
  preflight` step).
- **Group**: `tidefs-ci` (the only TideFS self-hosted runner group visible
  from the org-level endpoint).
- **Job timeout**: 120 minutes (`timeout-minutes: 120`). The inner QEMU
  invocations have their own `timeout --foreground 7200s` (also 120 minutes);
  the outer job timeout is the definitive gate.

## Flake target and dependencies

- **Nix target**: `.#kernel-fsync-validation` (a `script` flake output).
- **Source derivation**: `nix/vm/kernel-fsync-validation.nix`.
- **Transitive inputs**: `bash`, `coreutils`, `busybox`, `kmod`, `cpio`,
  `qemu`, `kernelFsyncValidation` (the compiled Nix derivation wrapping the
  C guest helper), and `tidefsPosixVfsKmod` (the out-of-tree kernel module
  `.ko`).
- The script boots a Linux 7.0 kernel, loads `tidefs_posix_vfs.ko` inside a
  QEMU guest, exercises fsync/fdatasync/syncfs, forces a `poweroff -f`
  (crash), then reboots with the same backing storage and verifies the
  written data survived.

## Artifact shape

After an **always** step, the workflow uploads a single artifact:

| Property          | Value                                                          |
| ----------------- | -------------------------------------------------------------- |
| Artifact name     | `kernel-fsync-validation`                                      |
| Source paths      | `/tmp/tidefs-kmod-fsync-validation/**` and `/tmp/tidefs-validation/kernel-fsync-validation/**` |
| If no files found | `ignore` (skips without failing the job)                       |
| Retention         | 7 days                                                         |

The flake wrapper writes into
`$TIDEFS_FSYNC_SUMMARY_DIR/validation-<iso8601>-<pid>/` (default base
`/tmp/tidefs-validation/kernel-fsync-validation`). Each run produces:

- `phase1.log` -- full QEMU serial console log for the write+fsync+crash phase.
- `phase2.log` -- full QEMU serial console log for the reboot+verify phase.
- `summary.env` -- machine-parseable key=value summary:

  ```
  TIDEFS_FSYNC_STATUS=PASS|FAIL|BLOCKED
  TIDEFS_FSYNC_PASSED=<count>
  TIDEFS_FSYNC_FAILED=<count>
  TIDEFS_FSYNC_BLOCKED=<count>
  TIDEFS_FSYNC_KERNEL=<version>
  TIDEFS_FSYNC_TIMESTAMP=<iso8601>
  ```

- `blocker.log` -- present only when a blocker prevents both phases from
  starting; single-line `BLOCKED: <reason> -- <detail>`.

The `Write evidence manifest` step produces `evidence-manifest.json` at the
summary directory root:

```json
{
  "manifest_version": 1,
  "claim_id": "kernel.fsync.durability.v1",
  "evidence_class": "runtime-kernel-fsync-validation",
  "validation_tier": "full-kernel-no-daemon",
  "source": "kernel-fsync-validation",
  "scope": "kernel-fsync-syncfs-durability-across-qemu-power-loss-cycle status=<status> passed=<n> failed=<n> blocked=<n> run=<id> source=<sha> timeout=<t>s pool=<mb>MB summary_path=<path> log_paths=<paths>",
  "artifact_path": "summary.env",
  "content_digest": "blake3:<hash>",
  "generated_at": "<iso8601>"
}
```

The workflow summary step renders the evidence manifest JSON and the newest
`summary.env` content into the GitHub job summary.

### Manifest field semantics

| Field              | Source                                             |
| ------------------ | -------------------------------------------------- |
| `manifest_version` | Hard-coded to `1`                                  |
| `claim_id`         | `kernel.fsync.durability.v1`                       |
| `evidence_class`   | `runtime-kernel-fsync-validation`                  |
| `validation_tier`  | `full-kernel-no-daemon` (no userspace daemon)      |
| `source`           | `kernel-fsync-validation` (distinct from QEMU Smoke source label) |
| `scope`            | Aggregated run identity including pass/fail/blocked counts, run id, source SHA, timeout, pool size, summary path, and log paths |
| `artifact_path`    | Path to the summary file relative to the summary directory |
| `content_digest`   | Blake3 hash of the summary file                    |
| `generated_at`     | UTC ISO 8601 timestamp of manifest generation      |

## Rows exercised

The validation exercises these operations inside the QEMU guest across a
two-phase crash-consistency protocol:

**Phase 1** (mount, write, fsync, crash):
1. Virtio-blk device presence.
2. Module load (`insmod`) and `lsmod` verification.
3. Pool member creation against the virtio-blk backing device.
4. Pool label verification.
5. Mount (`mount -t tidefs`).
6. Per-fd fsync (`fsync(fd)`) durability.
7. Per-fd fdatasync (`fdatasync(fd)`) durability.
8. Filesystem-wide syncfs (`syncfs(fd)`) durability.
9. `poweroff -f` (simulated crash, no clean unmount).

**Phase 2** (reboot with same backing storage, verify survival):
10. Virtio-blk device rediscovery.
11. Module reload and `lsmod` re-verification.
12. Remount of the pool-backed filesystem.
13. Data survival verification for the fsync'd file.
14. Data survival verification for the fdatasync'd file.
15. Data survival verification for the syncfs'd file.
16. Post-crash dmesg integrity (no BUG, kernel panic, Oops, or WARNING).

Each operation reports one of `PASS`, `FAIL`, or `BLOCKED`. The `summary.env`
counts and the overall `TIDEFS_FSYNC_STATUS` aggregate these into a single
verdict. Infrastructure failures (missing `/dev/kvm`, missing kernel image,
missing module) produce a `BLOCKED` status with a `blocker.log` and do not
start either QEMU phase.

## What `kernel.fsync.durability.v1` evidence supports

- Mounted first-boot kernel VFS durability: a self-contained POSIX VFS
  kernel module path with no userspace daemon.
- Fsync(2), fdatasync(2), and syncfs(2) durability across a simulated
  power-loss cycle with persistent virtio-blk backing storage.
- Post-crash data survival for each of the three sync primitives.
- Post-crash dmesg integrity (detection of kernel BUG, panic, Oops, or
  WARNING fallout from the TideFS kernel module).

## What `kernel.fsync.durability.v1` evidence does NOT cover

- **xfstests**: no xfstests harness, no generic/filesystem test suites, no
  stress workloads.
- **RDMA**: no transport, cluster, or remote-durability coherence.
- **Broad filesystem correctness**: single-fd, single-directory,
  single-pool. No rename, link, xattr, ACL, snapshot, lock-range, or
  multi-client consistency coverage.
- **Release-candidate readiness**: single-boot, single-module,
  single-filesystem. No long-running stress, no multi-module interaction,
  no kernel-upgrade regression suite. Release-candidate gates use the
  `Release Candidate` workflow, not this focused lane.
- **FUSE durability**: userspace-daemon fsync/syncfs coverage belongs to
  other workflows (QEMU Smoke, xfstests lanes).
- **Kernel crash-consistency beyond fsync/syncfs**: no `sync()`, no
  `sync_file_range()`, no AIO fsync, no io_uring fsync, no torn-write
  analysis, no multi-file atomic-durability.
- **Block-device correctness**: the virtio-blk backing store is a raw
  single-file pool disk. It does not exercise NVMe, SCSI, or ublk device
  durability.
- **Performance**: no latency, throughput, or IOPS budgets are checked.
- **Teardown / no-daemon / mmap**: handled by `Kernel teardown validation`,
  `Kernel no-daemon teardown validation`, and `Kernel mmap validation`
  respectively.

## When to dispatch this workflow versus the QEMU Smoke target

The `kernel-fsync-validation` workload exists on **two surfaces**:

| Surface                           | Workflow                              | Concurrency           | Evidence Manifest    |
| --------------------------------- | ------------------------------------- | --------------------- | -------------------- |
| Focused standalone                | `Kernel fsync/syncfs validation`      | Serial (`cancel-in-progress: false`) | Rich: includes pass/fail/blocked counts, source `kernel-fsync-validation` |
| QEMU Smoke matrix target          | `QEMU Smoke` target `kernel-fsync-validation` | Parallel (`cancel-in-progress: true`) | Lean: no pass/fail/blocked counts, source `qemu-smoke-kernel-fsync-validation`, scope records smoke origin |

**Use the focused workflow** when:

- An issue modifies the TideFS kernel module fsync/fdatasync/syncfs code
  path, the C guest helper (`tidefs-fsync-guest-helper.c`), the
  `kernelFsyncValidation` Nix derivation, or the `.#kernel-fsync-validation`
  flake target.
- An issue changes kernel VFS durability semantics (e.g., `fsync` inode
  locking, page-cache writeback integration, or dentry/inode sync ordering).
- The acceptance criteria require `kernel.fsync.durability.v1` evidence
  with machine-readable pass/fail/blocked counts and serial concurrency
  (so a new dispatch does not cancel an in-progress run).
- The claim id `kernel.fsync.durability.v1` must appear in evidence
  manifests produced by standalone claims-gate authority, not through
  QEMU Smoke proxy evidence.

**Use the QEMU Smoke `kernel-fsync-validation` target** when:

- The fsync validation is one row in a broader smoke or regression run
  (e.g., `target=all`).
- The acceptance criteria do not require the richer evidence manifest
  fields (pass/fail/blocked counts) or serial concurrency.
- The evidence consumer is a QEMU Smoke run summary, not a standalone
  claims-gate authority audit.

**Do not dispatch both** for the same ref and purpose. If the acceptance
criteria explicitly require standalone claims-gate authority, dispatch only
the focused workflow. If the acceptance criteria only require that the
fsync row ran somewhere in the smoke matrix, dispatch only the QEMU Smoke
target. When in doubt, prefer the focused workflow: it produces richer
evidence and does not risk cancellation by a newer smoke dispatch.

## Relationship to other workflows

| Workflow                        | Scope                                                     | Overlap |
| ------------------------------- | --------------------------------------------------------- | ------- |
| QEMU Smoke                      | Mounted-kernel-vfs smoke matrix; can run the same flake target | Same flake target but different workflow, concurrency, and manifest. |
| Kernel mmap validation          | Mounted mmap/writeback correctness                        | Distinct row set. |
| Kernel teardown validation      | Mount/write/sync/teardown/unmount lifecycle               | Distinct row set. |
| Kernel no-daemon teardown       | Full-kernel no-daemon crash/recovery                      | Distinct row set. |
| xfstests                        | xfstests harness against FUSE or kernel mount             | xfstests may exercise fsync but is a separate lane with its own dispatch contract. |
| Focused Rust                    | Per-crate Rust tests                                      | No runtime QEMU. |
| Release Candidate               | Aggregated acceptance gate                                | May include fsync row as one lane; this workflow is the fsync lane. |

## Mismatch notes

The following differences between the documented sources are recorded as
follow-up observations (not fixed in this contract slice):

1. `docs/GITHUB_CI.md` does not mention the standalone `Kernel fsync/syncfs
   validation` workflow or its dispatch inputs (`timeout_seconds`,
   `pool_size_mb`). A reader who only consults `docs/GITHUB_CI.md` would not
   know the workflow exists. The QEMU Smoke section mentions
   `kernel-fsync-validation` as a QEMU Smoke target but not as a standalone
   workflow.

2. `docs/GITHUB_CI.md` does not mention `kernel-fsync-validation` in the
   QEMU Smoke target list. The smoke dispatch options described there are
   "the default target, the mounted `kernel-mmap-validation` target, or
   both" when the actual workflow YAML exposes seven individual targets
   plus `all`, including `kernel-fsync-validation`.

3. The flake target description line in `flake.nix` reads
   `tidefs-kmod-fsync-validation`, matching the Nix derivation name but
   not the workflow-level GitHub name `Kernel fsync/syncfs validation`.
   This is a cosmetic naming inconsistency, not a functional mismatch.

4. The workflow YAML `Run kernel fsync/syncfs validation` step uses a
   hard-coded `timeout --foreground 7200s` (120 minutes) that shadows the
   outer `timeout-minutes: 120` job timeout; when either expires the job
   will be killed, but the duplicated bounds could drift if the job timeout
   or inner timeout is adjusted independently.

5. The `kernel-fsync-validation` flake target accepts `--module` and
   `--kernel` overrides from the CLI, but neither workflow surface exposes
   dispatch inputs for these. Future contract updates may need to record
   these if the dispatch inputs expand.

6. The Nix derivation defines `BLOCKED` status with `VALIDATION: BLOCKED
   -- N setup or durability rows blocked` exit code 1 (non-zero), while the
   `Write evidence manifest` step treats `BLOCKED` as a distinct status
   label separate from `FAIL`. The workflow summary and evidence manifest
   correctly distinguish blocked from failed, but the derivation exit code
   does not differentiate them for downstream callers that only read `$?`.
