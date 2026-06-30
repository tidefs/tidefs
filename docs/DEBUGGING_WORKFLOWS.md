# Common Debugging Workflows (v0.422)

Maturity: **implemented-source** developer guide for debugging TideFS.

This document covers common debugging workflows for TideFS developers: how to
isolate failures, enable diagnostics, inspect traces, debug the FUSE daemon,
use the deterministic test harness, and work with distributed storage,

## 1. Quick debug builds

Enter the Nix shell for a reproducible toolchain:

    nix develop

Build with debug symbols and no optimization:

    cargo build --workspace

Run a single test binary with backtraces:

    RUST_BACKTRACE=1 cargo test -p tidefs-local-filesystem --lib

Run one specific test:

    RUST_BACKTRACE=1 cargo test -p tidefs-local-filesystem --lib -- my_test_name

Show test stdout (suppressed by default):

    cargo test -- --nocapture

## 2. Tracing and logging

The workspace uses the `tracing` crate with `tracing-subscriber` (features:
`env-filter`, `fmt`, `json`). Set the `RUST_LOG` environment variable to
control span verbosity:

    RUST_LOG=debug cargo run -p tidefs-store-demo
    RUST_LOG=tidefs_local_filesystem=trace cargo run -p tidefs-filesystem-demo

### JSON output

Switch to structured JSON logs for ingestion or grep:

    RUST_LOG=info cargo run -p tidefs-store-demo 2>&1 | grep -E '{'

### Tracing spans in tests

When running tests, spans are only collected if a subscriber is registered.
Wrap `#[test]` with `tracing_subscriber::fmt::init()` to see spans:

    #[test]
    fn my_test() {
        tracing_subscriber::fmt::init();
        // ... test body
    }

## 3. Isolating test failures

### Run a single Rust test

    cargo test -p <crate> --lib -- <test_name_substring>

### Filter by test module

    cargo test -p tidefs-local-filesystem --lib tests::

### Run benchmarks (Criterion)

    cargo bench -p tidefs-local-filesystem

### Debug with println-style output

    cargo test -p tidefs-local-filesystem -- --nocapture

## 4. xtask invariant checks

The `tidefs-xtask` tool runs gate checks against the workspace. Run a single
group to narrow down a failure:

    cargo run -p tidefs-xtask -- check-group policy
    cargo run -p tidefs-xtask -- check-group platform
    cargo run -p tidefs-xtask -- check-group storage
    cargo run -p tidefs-xtask -- check-group ublk-surface
    cargo run -p tidefs-xtask -- check-group cluster

Individual sub-checks:

    cargo run -p tidefs-xtask -- check-workspace-policy
    cargo run -p tidefs-xtask -- check-terminology
    cargo run -p tidefs-xtask -- check-trace-oracle

See `docs/GETTING_STARTED.md` for the full group-to-gate mapping.

## 5. Debugging the FUSE daemon

The POSIX filesystem adapter daemon supports the following subcommands:

| Subcommand | Purpose |
|---|---|
| `mount` | Foreground FUSE mount with persistent store |
| `smoke-mount` | In-memory smoke mount (no persistent store) |
| `mount-vfs` | FUSE mount through the abstract VFS engine boundary |
| `score-posix` | POSIX pass/fail/skip scoreboard |
| `charter` | Print the POSIX Filesystem Adapter surface charter |
| `receipt-demo` | Product-wake receipt lifecycle demo |

### Mount with foreground output

    mkdir -p /tmp/tidefs-store /tmp/tidefs-mnt
    export TIDEFS_ROOT_AUTHENTICATION_KEY_HEX="$(openssl rand -hex 32)"
    cargo run -p tidefs-posix-filesystem-adapter-daemon -- \
      mount --store /tmp/tidefs-store --mount /tmp/tidefs-mnt

### Mount via VFS engine

Mount through the abstract VFS engine boundary (`mount-vfs`), which routes
through `VfsLocalFileSystem` instead of the direct `LocalFileSystem` adapter:

    cargo run -p tidefs-posix-filesystem-adapter-daemon -- \
      mount-vfs --store /tmp/tidefs-store --mount /tmp/tidefs-mnt \
      --root-auth-key $TIDEFS_ROOT_AUTHENTICATION_KEY_HEX

### Smoke mount (no persistent store)

    cargo run -p tidefs-posix-filesystem-adapter-daemon -- smoke-mount

### Inspect FUSE traffic with strace

    strace -e trace=read,write fusermount3 -u /tmp/tidefs-mnt &
    strace -f -e trace=read,write,openat,ioctl \
      -p $(pgrep tidefs-posix-filesystem)

### POSIX scoreboard (local, with optional xfstests)

    cargo run -p tidefs-posix-filesystem-adapter-daemon -- \
      score-posix --store /tmp/tidefs-score-store --scoreboard /tmp/tidefs-score-out

Output artifacts: `scoreboard.md`, `scoreboard.tsv`, and `harness-env.txt`.

### Coverage gap analysis

systematic gap report. Requires a previous scoreboard run:

    cargo run -p tidefs-posix-filesystem-adapter-daemon -- \
      coverage-gap --scoreboard-dir /tmp/tidefs-score-out --out /tmp/tidefs-gap-out

Output artifacts: `gap-report.md` and `gap-report.tsv` under the output

### Charter and receipt-demo

Print the POSIX Filesystem Adapter surface charter:

    cargo run -p tidefs-posix-filesystem-adapter-daemon -- charter

Run the product-wake receipt demo (visible/refusal receipt lifecycle):

    cargo run -p tidefs-posix-filesystem-adapter-daemon -- receipt-demo

### Unmount cleanly

    fusermount3 -u /tmp/tidefs-mnt

## 6. Environment variables for debugging

Tunable environment variables for development and debugging:

| Variable | Purpose | Default |
|---|---|---|
| `RUST_LOG` | `tracing` verbosity (`trace`, `debug`, `info`, `warn`, `error`) | `error` |
| `RUST_BACKTRACE` | Emit backtraces on panic (`1` or `full`) | unset |
| `TIDEFS_ROOT_AUTHENTICATION_KEY_HEX` | Root authentication key (64 hex chars, 32 bytes) | required for mount |
| `TIDEFS_CONTENT_CHUNK_SIZE` | Override content chunk size in bytes (512–1 MiB, multiple of 512) | 131072 (128 KiB) |

Example: test with 4 KiB chunks to stress the chunking path:

    TIDEFS_CONTENT_CHUNK_SIZE=4096 cargo test -p tidefs-local-filesystem --lib

Set `RUST_LOG` to `trace` for maximum detail on a single crate:

    RUST_LOG=tidefs_local_filesystem=trace cargo run -p tidefs-store-demo

## 7. Deterministic replay and trace oracle

The `tidefs-trace-oracle` crate replays JSONL trace files through
`LocalFileSystem` to produce deterministic, diffable logical fingerprints.
Use it to isolate semantic regressions after internal refactors.

Run the trace oracle gate:

    cargo run -p tidefs-xtask -- check-trace-oracle

The oracle compares Rust semantics against golden traces under
`traces/golden/`. The deleted trace-oracle design from #1174 remains in git
history as historical input.

## 8. Deterministic distributed test harness

`tidefs-test-harness` runs full distributed stack scenarios under a
deterministic seed and simulates faults:

    cargo test -p tidefs-test-harness

### Debug a specific scenario

    cargo test -p tidefs-test-harness -- --nocapture membership_test

### Key scenarios

| Scenario | What it exercises |
|---|---|
| `membership_test` | Epoch advancement, join/drain |
| `replication_test` | Quorum writes, degraded reads |
| `split_brain_prevention_test` | Partition + quorum refusal |
| `cascading_failure_recovery_test` | Domain failure + rebuild |
| `soak_test` | Long-running random fault injection |

Each scenario runs inside `DeterministicTestRunner` with fault injection
enabled by default. Use `RUST_LOG=debug` to see per-step events, and inspect
`RunnerResult` for the step-by-step event log.

## 9. Crash and corruption debugging

### Recovery model

TideFS follows the no-production-fsck failure model (see
`docs/NO_PRODUCTION_FSCK_FAILURE_MODEL.md`). On crash recovery, the system
converges to one of: previous committed root, new committed root, or an
explicit error. It never mounts partial truth.

### Inspecting recovery behavior

Run recovery-focused tests:

    cargo test -p tidefs-local-filesystem --lib recovery

### Online verifier

The non-mutating online verifier scans committed data for integrity:

    cargo test -p tidefs-local-filesystem --lib verifier

### Scrub and repair inspection

    cargo test -p tidefs-local-filesystem --lib scrub
    cargo test -p tidefs-local-filesystem --lib repair

## 10. Metrics and observability

`tidefs-observe-core-runtime` provides a metrics registry with counters, gauges,
histograms, and Prometheus text-format exposition.

### Inspect metrics in a test

```rust
use tidefs_observe_runtime::{MetricsRegistry, render_prometheus};

let registry = MetricsRegistry::new();
let counter = registry.counter("my_counter", "Description");
counter.inc();
println!("{}", render_prometheus(&registry));
```

### Structural observability

Every metric is tagged with a `BudgetDomain`, `ExactnessClass`, and
`FreshnessClass`. Use the `with_labels` methods to add these dimensions:

```rust
let registry = MetricsRegistry::new();
registry.counter_with_labels(
    "tidefs_read_total",
    "Total reads served",
    &[("exactness", ExactnessClass::Exact.as_label())],
).inc();
```

### Observability daemon

    cargo run -p tidefs-observe-cored

## 11. Storage node debugging

`tidefs-storage-node` runs a network-accessible replicated object store for
distributed storage testing. Start a local server:

    cargo run -p tidefs-storage-node -- server --node-id 1 --bind 127.0.0.1:9100 \
      --store /tmp/tidefs-node-store

With a local filesystem backing:

    cargo run -p tidefs-storage-node -- server --node-id 1 --bind 127.0.0.1:9100 \
      --fs-root /tmp/tidefs-node-fs --root-auth-key $TIDEFS_ROOT_AUTHENTICATION_KEY_HEX

Client operations against a running server:

    cargo run -p tidefs-storage-node -- client --node-id 2 --server-node-id 1 \
      --connect 127.0.0.1:9100 put mykey myvalue
    cargo run -p tidefs-storage-node -- client --node-id 2 --server-node-id 1 \
      --connect 127.0.0.1:9100 get mykey
    cargo run -p tidefs-storage-node -- client --node-id 2 --server-node-id 1 \
      --connect 127.0.0.1:9100 list
    cargo run -p tidefs-storage-node -- client --node-id 2 --server-node-id 1 \
      --connect 127.0.0.1:9100 stats

Send/receive between nodes:

    cargo run -p tidefs-storage-node -- client --node-id 2 --server-node-id 1 \
      --connect 127.0.0.1:9100 send
    cargo run -p tidefs-storage-node -- client --node-id 2 --server-node-id 1 \
      --connect 127.0.0.1:9100 receive \
      $TIDEFS_ROOT_AUTHENTICATION_KEY_HEX

## 12. Block volume adapter debugging

The block-volume adapter daemon (`tidefs-block-volume-adapter-daemon`) exposes
the OW-301 block-volume surface through dry-run projections and ublk
control/data-plane boundaries. Run without arguments for a summary:

    cargo run -p tidefs-block-volume-adapter-daemon

### Host preflight check

    cargo run -p tidefs-block-volume-adapter-daemon -- preflight-host

### ABI inspection

    cargo run -p tidefs-block-volume-adapter-daemon -- ublk-abi-plan

### ublk control boundaries (require `/dev/ublk-control`)

    cargo run -p tidefs-block-volume-adapter-daemon -- ublk-control-open
    cargo run -p tidefs-block-volume-adapter-daemon -- ublk-control-readonly-probe
    cargo run -p tidefs-block-volume-adapter-daemon -- ublk-control-add-dev
    cargo run -p tidefs-block-volume-adapter-daemon -- ublk-control-set-params
    cargo run -p tidefs-block-volume-adapter-daemon -- ublk-control-start-dev

### ublk data-plane boundaries

    cargo run -p tidefs-block-volume-adapter-daemon -- ublk-data-queue-commit-fetch
    cargo run -p tidefs-block-volume-adapter-daemon -- ublk-data-queue-fetch-req
    cargo run -p tidefs-block-volume-adapter-daemon -- ublk-data-queue-fetch-req-submit
    cargo run -p tidefs-block-volume-adapter-daemon -- ublk-data-queue-open

### File backing smoke

    cargo run -p tidefs-block-volume-adapter-daemon -- backing-file-smoke
    cargo run -p tidefs-block-volume-adapter-daemon -- resize-smoke

## 13. Control plane operator CLI (`tidefsctl`)

`tidefsctl` is the route-bound control-plane operator CLI. Every command
routes through declared control-plane route classes and produces
receipt-backed responses for auditability.

Query cluster state:

    cargo run -p tidefsctl -- health
    cargo run -p tidefsctl -- members
    cargo run -p tidefsctl -- replicas
    cargo run -p tidefsctl -- budget
    cargo run -p tidefsctl -- truth
    cargo run -p tidefsctl -- recall

Administrative operations:

    cargo run -p tidefsctl -- write-policy
    cargo run -p tidefsctl -- runbook
    cargo run -p tidefsctl -- secret
    cargo run -p tidefsctl -- membership
    cargo run -p tidefsctl -- transport

See `docs/CONTROL_PLANE_SERVICE_API_CLI_TOPOLOGY_P9-01.md` for the full
route grammar (r0–r7) and component class (g0–g10) topology.


To audit a failed run:


Individual command logs are numbered. To find the first failure:


The POSIX scoreboard writes `harness-env.txt` next to `scoreboard.md` and
`scoreboard.tsv` under the scoreboard output directory.

## 15. Lint and formatting checks

    cargo fmt --check
    cargo clippy --workspace --all-targets

To automatically apply formatting:

    cargo fmt

## 16. Profiling with perf (Linux)

From inside `nix develop`:

    perf record -g cargo run -p tidefs-store-demo
    perf report

The debug build includes frame pointers (`debuginfo` profile), so `perf`
call-graphs resolve correctly.

## 17. Where to go next

- Deleted trace-oracle lineage (#1174) -- historical design input in git history
- `docs/NO_PRODUCTION_FSCK_FAILURE_MODEL.md` -- crash recovery model
- `docs/CONTROL_PLANE_SERVICE_API_CLI_TOPOLOGY_P9-01.md` -- control-plane route topology
- `docs/THREE_CONTRACT_ARCHITECTURE.md` -- three-contract architecture
- `docs/INDEX.md` -- full documentation index
