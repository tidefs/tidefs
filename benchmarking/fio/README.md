# TideFS fio benchmarking harness

Standardised I/O benchmarking for the TideFS FUSE and ublk paths using fio.
This directory contains local job presets and a runner harness for collecting
throughput and latency observations against either a FUSE mount or a raw ublk
block device.

This README is an orientation for the local harness only. It is not a CI,
release-readiness, block-device admission, successor/comparator, crash
durability, online-resize, mkfs/mount, or product-readiness authority surface.
Project-facing capability wording is governed by `validation/claims.toml`,
generated `docs/CLAIM_REGISTRY.md`, `docs/CLAIMS_GATE_POLICY.md`,
`docs/GITHUB_CI.md`, and the release-readiness contracts.

## Profile taxonomy

Three local profiles are available, ordered by runtime and destructiveness:

**smoke** — shortest local fio sampling profile (< 30 s)
- Single-queue-depth read/write latency (seq + rand, 4K, QD1)
- High-queue-depth sequential throughput (128K, QD32)

**quick-required** — broader local fio sampling profile (~2-5 min)
- Mixed read/write (70/30 and 50/50 at QD4, 4K)
- Queue-depth sweep (QD 1, 4, 16, 64 for seq read and write, 4K)
- Block-size sweep (512B, 4K, 64K, 1M seq read at QD4)
- Sync-heavy writes (fsync and fdatasync per I/O at QD1, 4K)

**pressure** — stress and degradation sampling profile (~1-3 min)
- Mixed read/write storm (70/30, QD64, rate-limited 5000 IOPS, 30 s)
- Discard/TRIM pressure (unmap then write-after, 4K QD4)
- Overlapping read/write within the same region (50/50, QD16, 15 s)

## Usage

The harness `run-benchmarks.sh` accepts a mode, a target, and an optional
profile name (defaults to `smoke`):

```
# FUSE path — creates a test file inside the mount
./run-benchmarks.sh fuse /mnt/tidefs smoke
./run-benchmarks.sh fuse /mnt/tidefs quick-required

# ublk path — operates directly on the block device
./run-benchmarks.sh ublk /dev/ublkb0 smoke
./run-benchmarks.sh ublk /dev/ublkb0 pressure

# Run all profiles
./run-benchmarks.sh fuse /mnt/tidefs all
```

Environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `TIDEFS_FIO_OUT_DIR` | `/tmp/tidefs-fio-benchmarks` | Output directory for run artifacts |
| `TIDEFS_FIO_SIZE_MULT` | `1` | Size multiplier for small-device tuning |

## Output structure

Each run creates a timestamped directory under `$TIDEFS_FIO_OUT_DIR`:

```
/tmp/tidefs-fio-benchmarks/20260430T143022Z-fuse-smoke/
  environment.env          # host/kernel/fio version, mount or device info
  smoke__latency-read.json # fio JSON output (one per job)
  smoke__latency-read.log  # fio stderr log
  smoke__latency-write.json
  smoke__throughput.json
  ...
```

The harness prints a summary and aggregate perf metrics extracted from JSON.
Exit code 0 = all jobs passed; non-zero = one or more failures with a list
of failed job names.

## Job file inventory

### smoke (3 jobs)

| File | Sections | Description |
|---|---|---|
| `latency-read.fio` | seq-read-qd1, rand-read-qd1 | 4K sequential and random read at QD1 |
| `latency-write.fio` | seq-write-qd1, rand-write-qd1 | 4K sequential and random write at QD1 |
| `throughput.fio` | seq-read-qd32, seq-write-qd32 | 128K sequential throughput at QD32 |

### quick-required (5 jobs)

| File | Sections | Description |
|---|---|---|
| `mixed-rw.fio` | randrw-70r30w-qd4, randrw-50r50w-qd4 | Mixed workloads at 4K QD4 |
| `qd-sweep-read.fio` | seq-read-qd1/4/16/64 | Sequential read queue-depth sweep, 4K |
| `qd-sweep-write.fio` | seq-write-qd1/4/16/64 | Sequential write queue-depth sweep, 4K |
| `bs-sweep-read.fio` | seq-read-512b/4k/64k/1m | Sequential read block-size sweep at QD4 |
| `sync-write.fio` | sync-write-qd1, dsync-write-qd1 | fsync + fdatasync writes at QD1 |

### pressure (3 jobs)

| File | Sections | Description |
|---|---|---|
| `mixed-storm.fio` | randrw-storm | Rate-limited randrw (70/30), QD64, 30 s |
| `discard.fio` | trim-pressure, write-after-trim | Discard then immediate write-after |
| `overlap-rw.fio` | overlap-randrw | Overlapping read/write same region, QD16, 15 s |

## Common includes

Files under `common/` hold shared fio settings in INI-style includes.
The current job files are self-contained; the includes are kept as
reference templates for future profile development:

| File | Purpose |
|---|---|
| `global.inc` | Shared ioengine, direct, latency-log, verification defaults |
| `fuse-workload.inc` | FUSE-path directory/ioengine defaults |
| `ublk-workload.inc` | ublk-path block-device/ioengine defaults |

When a new profile benefits from shared settings, include them in the
job file with `include common/global.inc` (paths relative to the job file).

## Relationship to block claims

The three benchmarking profiles are local fio presets for smoke and pressure
experiments. They do not establish block-device product admission by
themselves; project-facing block wording is gated by `validation/claims.toml`
and generated `docs/CLAIM_REGISTRY.md`.

| Benchmark profile | Acceptance profile | Purpose |
|---|---|---|
| `smoke` | Historical local profile 0 | Shortest fio sampling run |
| `quick-required` | Historical local profile 1 | Broader fio sampling run |
| `pressure` | Historical local profile 2 | Stress and degradation sampling |

The historical block-acceptance matrix lineage was deleted by #1614. Broader
fio workload breadth, mkfs/mount acceptance, online resize, crash durability,
and production block-device readiness remain outside these local presets.

These benchmarking profiles are distinct from the ublk fio verification jobs in
`validation/fio/`, which target correctness verification rather than
throughput/latency characterisation.

## Adding a new profile

1. Create a directory `benchmarking/fio/jobs/<profile-name>/`.
2. Add `.fio` job files. Each file can contain multiple `[section]` blocks.
   Use `ioengine=psync`, `direct=1`, `group_reporting=1` for consistent results.
3. Optionally include `common/global.inc` for shared defaults.
4. The harness discovers jobs via `find jobs/<profile>/ -name '*.fio'`.
   Profile `all` runs every `.fio` under `jobs/`.
