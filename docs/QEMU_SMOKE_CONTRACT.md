# QEMU Smoke Contract

This document records the QEMU Smoke workflow targets, their dispatch
selectors, runner requirements, expected outputs, and evidence limits.
It is a documentation-only contract derived from source inspection of
`docs/GITHUB_CI.md`, `.github/workflows/qemu-smoke.yml`, and the
referenced `flake.nix` outputs.

## Standing Smoke Gate

`kmod-xfstests-smoke` is the **standing smoke target**.

- **Runs on**: every push to `master`.
- **Manual dispatch**: available as the default `target` input value.
- **What it exercises**: loads `tidefs_posix_vfs.ko`, mounts the explicit
  bootstrap VFS root, exercises supported directory, symlink, readdir,
  statfs, write, and syncfs operations, and checks that unsupported
  administrative VFS operations fail closed for freeze and remount
  reconfiguration.
  Engine-backed storage checks are kept in longer filesystem lanes.
- **Evidence claim**: narrow kernel-module smoke.  It does not claim
  xfstests, RDMA, release-candidate, or broad filesystem-correctness
  coverage.

Broader `target=all` and every non-default target are **manual-only**
and reserved for issue or PR validation tiers that explicitly require
them.  Do not dispatch `all` or a non-default target as a substitute for
`master` smoke gating unless the issue validation tier records why.

## Target Reference

Each target is a matrix entry in `.github/workflows/qemu-smoke.yml`.
All targets share the same runner label set and the same 120-minute job
timeout.  The concurrency group
`qemu-smoke-${{ github.event.pull_request.number || github.ref }}` uses
`cancel-in-progress: true` for the workflow as a whole, so a new
dispatch for the same ref cancels a still-running earlier one.
Manual `workflow_dispatch` accepts these `target` choices:
`kmod-xfstests-smoke`, `kernel-fsync-validation`,
`kernel-mmap-validation`, `kernel-teardown-validation`,
`kernel-no-daemon-teardown-validation`, `two-node-carrier-validation`,
`fuse-vm-test`, `fuse-inode-metadata-validation`, `qemu-ublk-smoke`,
`qemu-ublk-qid-tag-runtime`, `receipt-bound-reclaim-runtime`,
`scrub-foreground-read-runtime`, and `all`.

### Runner Labels

```text
self-hosted, linux, x64, tidefs, nix, kvm
```

The runner must provide KVM (`/dev/kvm`) and FUSE (`/dev/fuse`), which
are checked by the `Host preflight` step before any target runs.

---

### 1. `kmod-xfstests-smoke` (default)

| Field              | Value |
|--------------------|-------|
| Dispatch           | push to `master`, manual `workflow_dispatch` |
| Nix flake ref      | `.#kmod-xfstests-smoke` |
| Command arguments  | `--timeout 1800` |
| Output directory   | `/tmp/tidefs-validation/kmod-xfstests-smoke` |
| Uploaded artifact  | `qemu-smoke-kmod-xfstests-smoke` (7-day retention) |
| Evidence class     | kernel-module smoke (directory, symlink, readdir, statfs, write/syncfs, administrative freeze/remount-reconfigure refusal) |

### 2. `kernel-fsync-validation`

| Field              | Value |
|--------------------|-------|
| Dispatch           | manual `workflow_dispatch` only |
| Nix flake ref      | `.#kernel-fsync-validation` |
| Command arguments  | `--timeout 600 --pool-size 256` |
| Output directory   | `/tmp/tidefs-validation/kernel-fsync-validation` |
| Uploaded artifact  | `qemu-smoke-kernel-fsync-validation` (7-day retention) |
| Extra step         | Writes and validates a v2 `evidence-manifest.json` with claim `kernel.fsync.durability.v1`, explicit outcome, source label `qemu-smoke-kernel-fsync-validation`, and non-pass missing-summary state |
| Evidence class     | runtime-kernel-fsync-validation (syncfs durability across QEMU power-loss cycle) |

A separate dedicated workflow, `Kernel fsync/syncfs validation`
(`.github/workflows/kernel-fsync-validation.yml`), also runs
`.#kernel-fsync-validation` with configurable `timeout_seconds` and
`pool_size_mb` inputs, serial concurrency (`cancel-in-progress: false`),
and a standalone v2 evidence manifest that includes pass/fail/blocked counts.

### 3. `kernel-mmap-validation`

| Field              | Value |
|--------------------|-------|
| Dispatch           | manual `workflow_dispatch` only |
| Nix flake ref      | `.#kernel-mmap-validation` |
| Command arguments  | `--timeout 900` |
| Output directory   | `/tmp/tidefs-validation/kernel-mmap-validation` |
| Uploaded artifact  | `qemu-smoke-kernel-mmap-validation` (7-day retention) |
| Evidence class     | mounted mmap/writeback QEMU row |

A separate dedicated workflow, `Kernel mmap validation`
(`.github/workflows/kernel-mmap-validation.yml`), also runs
`.#kernel-mmap-validation` with a configurable `timeout_seconds` input
and serial concurrency.

### 4. `kernel-teardown-validation`

| Field              | Value |
|--------------------|-------|
| Dispatch           | manual `workflow_dispatch` only |
| Nix flake ref      | `.#kernel-teardown-validation` |
| Command arguments  | `--timeout 600` |
| Output directory   | `/tmp/tidefs-validation/kernel-teardown-validation` |
| Uploaded artifact  | `qemu-smoke-kernel-teardown-validation` (7-day retention) |
| Evidence class     | T5 mounted-kernel-vfs teardown (mount, write, sync, teardown, unmount, module-unload with tracefs/ftrace or dmesg markers) |
| Artifacts          | `kernel-teardown-runtime.json`, `evidence-manifest.json` |

### 5. `kernel-no-daemon-teardown-validation`

| Field              | Value |
|--------------------|-------|
| Dispatch           | manual `workflow_dispatch` only |
| Nix flake ref      | `.#kernel-no-daemon-teardown-validation` |
| Command arguments  | `--timeout 600` |
| Output directory   | `/tmp/tidefs-validation/kernel-no-daemon-teardown-validation` |
| Uploaded artifact  | `qemu-smoke-kernel-no-daemon-teardown-validation` (7-day retention) |
| Evidence class     | T6 full-kernel-no-daemon teardown (zero userspace daemons, post-final refusal probes, no-daemon crash/recovery cycles) |
| Artifacts          | `kernel-teardown-runtime.json`, `evidence-manifest.json` |

### 6. `two-node-carrier-validation`

| Field              | Value |
|--------------------|-------|
| Dispatch           | manual `workflow_dispatch` only |
| Nix flake ref      | `.#two-node-carrier-validation` |
| Command arguments  | `--timeout 600 --validation-dir /tmp/tidefs-validation/two-node-carrier-validation` |
| Output directory   | `/tmp/tidefs-validation/two-node-carrier-validation` |
| Uploaded artifact  | `qemu-smoke-two-node-carrier-validation` (7-day retention) |
| Evidence class     | two-node QEMU carrier state-transfer scenario |
| Artifacts          | `carrier-report.json`, `qemu.log`, `summary.json`, environment metadata |

### 7. `fuse-vm-test`

| Field              | Value |
|--------------------|-------|
| Dispatch           | manual `workflow_dispatch` only |
| Nix flake ref      | `.#fuse-vm-test` |
| Command arguments  | `--timeout 900 --validation-dir /tmp/tidefs-validation/fuse-vm-test --queue-depth-artifact /tmp/tidefs-validation/fuse-vm-test/performance/queue-depth-runtime.json` |
| Output directory   | `/tmp/tidefs-validation/fuse-vm-test` |
| Uploaded artifact  | `qemu-smoke-fuse-vm-test` (7-day retention) |
| Evidence class     | FUSE VM test with queue-depth measurement |

### 8. `fuse-inode-metadata-validation`

| Field              | Value |
|--------------------|-------|
| Dispatch           | manual `workflow_dispatch` only |
| Nix flake ref      | `.#fuse-inode-metadata-validation` |
| Command arguments  | `--timeout 900 --validation-dir /tmp/tidefs-validation/fuse-inode-metadata-validation --keep-tmp`, with `TIDEFS_SOURCE_COMMIT` and non-secret `TIDEFS_ROOT_AUTHENTICATION_KEY_HEX` set by the workflow |
| Output directory   | `/tmp/tidefs-validation/fuse-inode-metadata-validation` |
| Uploaded artifact  | `qemu-smoke-fuse-inode-metadata-validation` (7-day retention) |
| Evidence class     | mounted FUSE inode metadata clean/readback row observations inside a Linux 7.0 QEMU guest with explicit crash-window and committed-root blockers |

### 9. `qemu-ublk-smoke`

| Field              | Value |
|--------------------|-------|
| Dispatch           | manual `workflow_dispatch` only |
| Nix flake ref      | `.#qemu-ublk-smoke` |
| Command arguments  | `--timeout 3600` |
| Output directory   | `/tmp/tidefs-validation/ublk` |
| Uploaded artifact  | `qemu-smoke-qemu-ublk-smoke` (7-day retention) |
| Evidence class     | ublk completion artifact validation |

### 10. `qemu-ublk-qid-tag-runtime`

| Field              | Value |
|--------------------|-------|
| Dispatch           | manual `workflow_dispatch` only |
| Nix flake ref      | `.#qemu-ublk-qid-tag-runtime` |
| Command arguments  | `--timeout 3600 --validation-dir /tmp/tidefs-validation/ublk-qid-tag-runtime` |
| Output directory   | `/tmp/tidefs-validation/ublk-qid-tag-runtime` |
| Uploaded artifact  | `qemu-smoke-qemu-ublk-qid-tag-runtime` (7-day retention) |
| Evidence class     | bounded qid/tag ublk completion runtime row |
| Artifacts          | `qid-tag-completion-runtime.json`, `qid-tag-completion-error-injection-runtime.json`, `started-export-admission-runtime.json`, `started-export-admission-error-injection-runtime.json`, `qemu-ublk-completion.json` |

### 11. `receipt-bound-reclaim-runtime`

| Field              | Value |
|--------------------|-------|
| Dispatch           | manual `workflow_dispatch` only |
| Command            | `nix develop .#ci --command cargo run --locked -p tidefs-validation --bin receipt-bound-reclaim-validation -- --row receipt-bound-obsolete-location-trim --output-dir /tmp/tidefs-validation/receipt-bound-reclaim-runtime` |
| Output directory   | `/tmp/tidefs-validation/receipt-bound-reclaim-runtime` |
| Uploaded artifact  | `qemu-smoke-receipt-bound-reclaim-runtime` (7-day retention) |
| Evidence class     | receipt-bound reclaim runtime row for obsolete-location trim gating |
| Artifacts          | `receipt-bound-reclaim-runtime.json`, `evidence-manifest.json` |

### 12. `scrub-foreground-read-runtime`

| Field              | Value |
|--------------------|-------|
| Dispatch           | manual `workflow_dispatch` only |
| Nix flake ref      | `.#scrub-foreground-read-runtime` |
| Command arguments  | `--row scrub-foreground-read-runtime --output-dir /tmp/tidefs-validation/scrub-foreground-read-runtime` |
| Output directory   | `/tmp/tidefs-validation/scrub-foreground-read-runtime` |
| Uploaded artifact  | `qemu-smoke-scrub-foreground-read-runtime` (7-day retention) |
| Evidence class     | scrub foreground-read runtime row |
| Artifacts          | `scrub-foreground-read-runtime.json`, `evidence-manifest.json` |

### 13. `all`

| Field              | Value |
|--------------------|-------|
| Dispatch           | manual `workflow_dispatch` only |
| Effect             | Runs every matrix entry (targets 1-12) concurrently (`fail-fast: false`) |

## Evidence Limits

QEMU Smoke artifacts are **not** xfstests, RDMA, release-candidate,
broad filesystem-correctness, product-readiness, or
performance-comparator evidence unless the issue or PR validation tier
explicitly says so and the relevant dedicated workflow (e.g.
`xfstests.yml`, `rdma.yml`, `release-candidate.yml`) is also dispatched.

- `kmod-xfstests-smoke` exercises basic VFS operations and fail-closed
  administrative freeze/remount refusal; it does not run xfstests test
  cases.
- `kernel-fsync-validation` and `kernel-mmap-validation` exercise
  specific QEMU Smoke runtime rows; the standalone workflows with the same
  flake refs remain separate validation lanes when an issue tier requires
  them.
- `kernel-teardown-validation` and
  `kernel-no-daemon-teardown-validation` exercise lifecycle teardown;
  they do not claim general kernel stability or production readiness.
- `two-node-carrier-validation` exercises one live carrier state-transfer
  scenario; it is not a distributed-system correctness or recovery proof.
- `fuse-vm-test` measures queue depth under a FUSE VM workload; it is
  not a filesystem stress or correctness run.
- `fuse-inode-metadata-validation` records mounted FUSE inode metadata
  clean/readback rows inside a Linux 7.0 QEMU guest and explicit blockers
  for unexercised crash-window and committed-root rows; it is not POSIX
  completeness, xfstests, or broad crash-safety evidence.
- `qemu-ublk-smoke` validates ublk completion artifacts; it is not a
  block-storage correctness or performance benchmark.
- `qemu-ublk-qid-tag-runtime` validates a bounded multi-queue qid/tag
  completion row, including success and validation-only negative-write
  artifacts.  It is not block-device product readiness, release readiness,
  broad filesystem correctness, or successor/comparator evidence.
- `receipt-bound-reclaim-runtime` proves the receipt-bound dead-object
  queue gate and durable queue replay boundary only; it is not mounted
  FUSE, kernel, xfstests, RDMA, allocator, segment-cleaner, or parent
  tracker closure evidence.
- `scrub-foreground-read-runtime` exercises the focused foreground-read scrub
  row only; it is not a general scrub/rebuild, allocator, or release-candidate
  proof.

## Follow-Up Notes (dispatch and evidence boundaries)

These notes summarize the current source-inspected dispatch surface. They
are documentation boundaries, not requests for workflow or runtime changes.

1. **Manual dispatch surface.**  Manual QEMU Smoke dispatch can select
   `kmod-xfstests-smoke`, `kernel-fsync-validation`,
   `kernel-mmap-validation`, `kernel-teardown-validation`,
   `kernel-no-daemon-teardown-validation`, `two-node-carrier-validation`,
   `fuse-vm-test`, `fuse-inode-metadata-validation`, `qemu-ublk-smoke`,
   `qemu-ublk-qid-tag-runtime`, `receipt-bound-reclaim-runtime`,
   `scrub-foreground-read-runtime`, or `all`.  Pushes to `master` still run
   only `kmod-xfstests-smoke`.

2. **Dual-surface targets.**  `kernel-fsync-validation` and
   `kernel-mmap-validation` exist both as QEMU Smoke matrix targets and
   as separate dedicated workflows with different concurrency behavior
   and, for fsync, a richer evidence manifest.  The QEMU Smoke rows are
   focused runtime evidence surfaces; standalone workflows or other
   validation lanes remain separate when an issue validation tier requires
   them.

3. **uBLK qid/tag runtime row.**  `qemu-ublk-qid-tag-runtime` is a distinct
   QEMU Smoke target for issue #1793.  It broadens runtime completion evidence
   beyond focused smoke by requiring at least two hardware queues, queue depth
   64, all-slot initial fetch and teardown coverage, read/write/flush/discard
   and write-zeroes terminal operations, and a separate validation-only
   negative write artifact.  It deliberately keeps block-device product,
   release, and successor/comparator claims blocked behind the claim registry.

4. **Receipt-bound reclaim row.**  `receipt-bound-reclaim-runtime` is a
   QEMU Smoke matrix target that runs the validation binary through
   `nix develop .#ci --command cargo run`; it does not have a same-named
   flake app and does not widen the evidence boundary beyond the focused
   receipt-bound runtime row.
