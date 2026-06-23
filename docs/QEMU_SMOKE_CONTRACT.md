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
  bootstrap VFS root, and exercises supported directory, symlink, readdir,
  and statfs operations. Engine-backed storage checks are kept in longer
  filesystem lanes.
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
| Evidence class     | kernel-module smoke (directory, symlink, readdir, statfs) |

### 2. `kernel-fsync-validation`

| Field              | Value |
|--------------------|-------|
| Dispatch           | manual `workflow_dispatch` only |
| Nix flake ref      | `.#kernel-fsync-validation` |
| Command arguments  | `--timeout 600 --pool-size 256` |
| Output directory   | `/tmp/tidefs-validation/kernel-fsync-validation` |
| Uploaded artifact  | `qemu-smoke-kernel-fsync-validation` (7-day retention) |
| Extra step         | Writes `evidence-manifest.json` with claim `kernel.fsync.durability.v1`, source label `qemu-smoke-kernel-fsync-validation` |
| Evidence class     | runtime-kernel-fsync-validation (syncfs durability across QEMU power-loss cycle) |

A separate dedicated workflow, `Kernel fsync/syncfs validation`
(`.github/workflows/kernel-fsync-validation.yml`), also runs
`.#kernel-fsync-validation` with configurable `timeout_seconds` and
`pool_size_mb` inputs, serial concurrency (`cancel-in-progress: false`),
and a richer evidence manifest that includes pass/fail/blocked counts.

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

### 6. `fuse-vm-test`

| Field              | Value |
|--------------------|-------|
| Dispatch           | manual `workflow_dispatch` only |
| Nix flake ref      | `.#fuse-vm-test` |
| Command arguments  | `--timeout 900 --validation-dir /tmp/tidefs-validation/fuse-vm-test --queue-depth-artifact /tmp/tidefs-validation/fuse-vm-test/performance/queue-depth-runtime.json` |
| Output directory   | `/tmp/tidefs-validation/fuse-vm-test` |
| Uploaded artifact  | `qemu-smoke-fuse-vm-test` (7-day retention) |
| Evidence class     | FUSE VM test with queue-depth measurement |

### 7. `qemu-ublk-smoke`

| Field              | Value |
|--------------------|-------|
| Dispatch           | manual `workflow_dispatch` only |
| Nix flake ref      | `.#qemu-ublk-smoke` |
| Command arguments  | `--timeout 3600` |
| Output directory   | `/tmp/tidefs-validation/ublk` |
| Uploaded artifact  | `qemu-smoke-qemu-ublk-smoke` (7-day retention) |
| Evidence class     | ublk completion artifact validation |

### 8. `all`

| Field              | Value |
|--------------------|-------|
| Dispatch           | manual `workflow_dispatch` only |
| Effect             | Runs every matrix entry (targets 1–7) concurrently (`fail-fast: false`) |

## Evidence Limits

QEMU Smoke artifacts are **not** xfstests, RDMA, release-candidate, or
broad filesystem-correctness evidence unless the issue or PR validation
tier explicitly says so and the relevant dedicated workflow (e.g.
`xfstests.yml`, `rdma.yml`, `release-candidate.yml`) is also dispatched.

- `kmod-xfstests-smoke` exercises basic VFS operations; it does not run
  xfstests test cases.
- `kernel-fsync-validation` and `kernel-mmap-validation` exercise
  specific kernel rows; they are not broad kernel-validation-matrix
  coverage.
- `kernel-teardown-validation` and
  `kernel-no-daemon-teardown-validation` exercise lifecycle teardown;
  they do not claim general kernel stability or production readiness.
- `fuse-vm-test` measures queue depth under a FUSE VM workload; it is
  not a filesystem stress or correctness run.
- `qemu-ublk-smoke` validates ublk completion artifacts; it is not a
  block-storage correctness or performance benchmark.

## Follow-Up Notes (documentation mismatches, not source changes)

These mismatches between `docs/GITHUB_CI.md`, the workflow YAML, and the
flake outputs are recorded for follow-up but are **not** fixed in this
slice:

1. **GITHUB_CI.md dispatch description is stale.**  The doc says manual
   QEMU Smoke dispatch can select "the default target, the mounted
   `kernel-mmap-validation` target, or both."  The workflow YAML
   actually exposes 7 individual targets plus `all`.

2. **GITHUB_CI.md omits three targets.**  `kernel-fsync-validation`,
   `fuse-vm-test`, and `qemu-ublk-smoke` are valid QEMU Smoke dispatch
   options but are not mentioned in the QEMU Smoke section of
   `docs/GITHUB_CI.md`.

3. **Dual-surface targets.**  `kernel-fsync-validation` and
   `kernel-mmap-validation` exist both as QEMU Smoke matrix targets and
   as separate dedicated workflows with different concurrency behaviour
   and, for fsync, a richer evidence manifest.  The documentation does
   not explain when to prefer one surface over the other.
