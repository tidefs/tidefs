# Named Coherency Profiles — Design Specification

**Issue**: [#1184](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1184)
**Status**: design-spec
**Priority**: P1
**Lane**: storage-core (FUSE daemon caching behavior)
**Depends on**: #1145 (FUSE daemon topology), #1127 (FUSE request worker queue)
**Related**: #1176 (cache-lattice views), #827 (structural observability), P4-02 (cache taxonomy)

## Abstract

The current FUSE daemon (`fuse_preview.rs`) has no systematic way to configure
caching behaviour. A single `const TTL: Duration = Duration::from_secs(1)` is
used for all attribute, entry, and create replies. Individual caching dimensions
(attribute timeout, entry timeout, negative timeout, data caching mode,
higher-level concept that bundles them into a semantically meaningful contract.

This creates two problems:

- **Correctness risk**: A knob misconfiguration can silently break POSIX
  semantics (e.g., stale attribute caching causing xfstests failures).
- **Operator burden**: The operator must understand 4+ independent caching
  parameters and their interactions.

The old v0.262 Python design solved this with **named coherency profiles** —
single meaningful name. This document adapts that design to the Rust codebase,
integrating it with the existing `projection_charter.rs` (ExactnessClass /
FreshnessClass / BudgetDomain) and the cache-lattice views framework (#1176).

---

## 1. Architecture Overview

### 1.1 The Four Profiles

| Profile   | Use case                         | Primary contract                                |
|-----------|----------------------------------|-------------------------------------------------|
| `strict`  | xfstests gate, correctness-first | POSIX-exact: every answer is authoritative      |
| `perf`    | Single-node, exclusive writer    | Read-your-writes with bounded-staleness windows |
| `cluster` | Multi-node, lease-driven         | Lease-gated: validity is bounded by lease epoch |
| `auto`    | Derives from topology/lease state| Observes runtime state to select profile        |

### 1.2 Relationship to Projection Charter

The existing `PosixProjectionCharter` defines per-FUSE-op contracts with fixed
`ExactnessClass` and `FreshnessClass`. Coherency profiles add a **user-facing
configuration layer** that determines how the charter's exactness/freshness
declarations translate into runtime caching decisions:

- `strict` profile → Every `ExactnessClass::Exact` op bypasses caching entirely;
  `ExactnessClass::BoundedStaleness` ops use minimal TTL windows (~0.1s).
- `perf` profile → `ExactnessClass::Exact` ops may use moderate TTL with
  `FreshnessClass::ReadYourWrites` enforcement; `BoundedStaleness` ops use
  full page-cache semantics.
- `cluster` profile → Exactness/freshness are gated by lease-epoch validity;
  answers carry lease-epoch tokens that the cache-lattice view system can
- `auto` profile → Derives from runtime state: if no peer nodes → `perf`;
  if shared leases exist → `cluster`; if xfstests harness detected → `strict`.

### 1.3 Relationship to Cache-Lattice Views (#1176)

Coherency profiles determine the **validity window** for cached views:

- Under `perf`, views carry `FreshnessToken` with longer validity windows
  (validity window = moderate, e.g. 1s).
- Under `cluster`, lease epochs gate view validity: a view is valid only
  within the lease epoch in which it was built.

The cache-lattice `ViewMeta.seen_generation` field becomes the carrier for the
freshness token under `perf` and the lease-epoch tracker under `cluster`.

---

## 2. Data Structures

### 2.1 `CoherencyProfile` Enum

```rust
/// Named coherency profile for the FUSE daemon.
///
/// into a single meaningful name, eliminating the risk of knob
/// misconfiguration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum CoherencyProfile {
    /// POSIX-exact: every answer is authoritative.
    /// Target: pass xfstests `generic/quick` without knob tuning.
    Strict = 0,
    /// Single-node, exclusive writer.
    /// Moderate TTL (~1s), full page cache, explicit write-through.
    /// Target: measurably reduce metadata RPCs vs strict.
    Perf = 1,
    /// Multi-node, lease-driven.
    /// Target: correct multi-node coherency under lease-protocol semantics.
    Cluster = 2,
    /// Derives from topology/lease state at runtime.
    /// Inspects peer-node count, lease state, and xfstests harness flag.
    Auto = 3,
}
```

### 2.2 Per-Profile Defaults

```rust
/// Caching parameters derived from a [`CoherencyProfile`].
///
/// These replace the current `const TTL: Duration = Duration::from_secs(1)`.
#[derive(Clone, Copy, Debug)]
pub struct CoherencyProfileParams {
    /// Attribute cache TTL (reported in `ReplyAttr` and `ReplyEntry`).
    pub attr_ttl: Duration,
    /// Entry cache TTL (reported in `ReplyEntry` for directory entries).
    pub entry_ttl: Duration,
    /// Negative cache TTL (for ENOENT responses).
    pub negative_ttl: Duration,
    /// Data caching mode: how the kernel page cache is used.
    pub data_caching: DataCachingMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataCachingMode {
    /// Direct I/O: bypass kernel page cache (FUSE `direct_io`).
    DirectIo,
    /// Write-through: page cache used for reads; writes go straight to backing store.
    WriteThrough,
    /// Full page cache: kernel may cache reads and writes (FUSE `writeback_cache`).
    FullPageCache,
    /// Lease-gated: page cache enabled only while a valid lease is held.
    LeaseGated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
    Aggressive,
    OpenToClose,
    LeaseRecall,
    Explicit,
}
```

### 2.3 Profile-to-Params Mapping

```rust
impl CoherencyProfile {
    pub fn params(self) -> CoherencyProfileParams {
        match self {
            CoherencyProfile::Strict => CoherencyProfileParams {
                attr_ttl:     Duration::from_millis(100),
                entry_ttl:    Duration::from_millis(100),
                negative_ttl: Duration::ZERO,       // disabled — no negative caching
                data_caching: DataCachingMode::DirectIo,
            },
            CoherencyProfile::Perf => CoherencyProfileParams {
                attr_ttl:     Duration::from_secs(1),
                entry_ttl:    Duration::from_secs(1),
                negative_ttl: Duration::from_secs(5), // 5s negative cache
                data_caching: DataCachingMode::FullPageCache,
            },
            CoherencyProfile::Cluster => CoherencyProfileParams {
                // Lease-dependent values are set at runtime; these are
                // conservative defaults used before the first lease grant.
                attr_ttl:     Duration::from_millis(500),
                entry_ttl:    Duration::from_millis(500),
                negative_ttl: Duration::ZERO,
                data_caching: DataCachingMode::LeaseGated,
            },
            CoherencyProfile::Auto => {
                // `auto` returns `perf` parameters by default;
                // the caller MUST call `derive_profile()` to resolve.
                CoherencyProfile::Perf.params()
            },
        }
    }

    /// Human-readable name for logging and metrics.
    pub fn as_str(self) -> &'static str {
        match self {
            CoherencyProfile::Strict  => "strict",
            CoherencyProfile::Perf    => "perf",
            CoherencyProfile::Cluster => "cluster",
            CoherencyProfile::Auto    => "auto",
        }
    }
}
```

---

## 3. The `auto` Profile — Runtime Derivation

### 3.1 Derivation Algorithm

The `auto` profile resolves at mount time (and re-resolves on topology changes):

```
auto_profile(state) =
    if xfstests_harness_active(state) → Strict
    else if shared_leases_exist(state)   → Cluster
    else if peer_nodes_exist(state)      → Cluster
    else                                   → Perf
```

### 3.2 Runtime State Inputs

```rust
/// Runtime state inspected by the `auto` profile derivation.
pub struct CoherencyTopologyState {
    /// Whether the xfstests harness flag is set (via `TIDEFS_XFSTESTS=1` env var
    /// or `--xfstests` mount option).
    pub xfstests_active: bool,
    /// Number of peer nodes visible in the membership view.
    pub peer_node_count: usize,
    /// Whether this node holds any shared leases (implies multi-node).
    pub has_shared_leases: bool,
    /// Whether the cluster transport layer is active.
    pub cluster_transport_active: bool,
}
```

### 3.3 Derivation Function

```rust
impl CoherencyProfile {
    /// Resolve the `Auto` variant into a concrete profile based on runtime state.
    pub fn resolve_auto(self, state: &CoherencyTopologyState) -> CoherencyProfile {
        match self {
            CoherencyProfile::Auto => {
                if state.xfstests_active {
                    CoherencyProfile::Strict
                } else if state.has_shared_leases || state.peer_node_count > 0 {
                    CoherencyProfile::Cluster
                } else {
                    CoherencyProfile::Perf
                }
            }
            other => other, // non-Auto profiles pass through
        }
    }
}
```

### 3.4 Re-resolution Triggers

The resolved profile is cached but re-evaluated on:

- Membership change events (peer join/leave) — previously `Perf` may become `Cluster`.
- Lease acquisition or recall events — transitions between `Perf` and `Cluster`.
- xfstests harness toggle — `strict` ↔ `perf` transition.

The daemon subscribes to membership-change notifications from
`tidefs-membership-live` and lease-lifecycle events from `tidefs-lease`. When a
trigger fires, the daemon:

1. Re-derives the effective profile.
   `fuser::Notifier::inval_inode` (for `Perf`→`Strict`) or emits a profile-
   change metric counter.
3. Updates the `CoherencyProfileParams` used for subsequent FUSE replies.

---

## 4. Integration with Projection Charter

### 4.1 Charter-Aware Caching Decisions

The existing `PosixProjectionCharter` assigns a static `ExactnessClass` and
`FreshnessClass` to every FUSE operation. Coherency profiles add a dynamic
override layer:

| Profile   | `ExactnessClass::Exact` behaviour        | `ExactnessClass::BoundedStaleness` behaviour |
|-----------|------------------------------------------|----------------------------------------------|
| `strict`  | TTL ≈ 0.1s, direct_io for data           | TTL ≈ 0.1s, direct_io                        |
| `perf`    | TTL ≈ 1s, page cache for data             | TTL ≈ 5s, page cache                          |
| `cluster` | Lease-gated TTL, lease-gated page cache   | Lease-gated TTL, lease-gated page cache       |
| `auto`    | Resolved to one of the above              | Resolved to one of the above                  |

### 4.2 TTL Selection Matrix

The effective TTL for a FUSE reply is computed as:

```rust
fn effective_ttl(
    profile: CoherencyProfile,
    params: &CoherencyProfileParams,
    exactness: ExactnessClass,
    is_negative: bool,
) -> Duration {
    if is_negative {
        return params.negative_ttl;
    }
    match (profile, exactness) {
        (CoherencyProfile::Strict, _) => params.attr_ttl,
        (CoherencyProfile::Perf, ExactnessClass::Exact) => params.attr_ttl,
        (CoherencyProfile::Perf, _) => params.entry_ttl,
        (CoherencyProfile::Cluster, _) => {
            // Under cluster, TTL is capped by remaining lease term.
            params.attr_ttl.min(remaining_lease_term())
        }
        (CoherencyProfile::Auto, _, _) => unreachable!("auto resolved before use"),
    }
}
```

### 4.3 Data Caching Mode Selection

```rust
fn effective_data_caching(
    profile: CoherencyProfile,
    params: &CoherencyProfileParams,
    exactness: ExactnessClass,
) -> DataCachingMode {
    match (profile, exactness) {
        (CoherencyProfile::Strict, _) => DataCachingMode::DirectIo,
        (CoherencyProfile::Perf, ExactnessClass::Exact) => params.data_caching,
        (CoherencyProfile::Perf, ExactnessClass::BoundedStaleness) => {
            DataCachingMode::FullPageCache
        }
        (CoherencyProfile::Cluster, _) => params.data_caching,
        (CoherencyProfile::Auto, _, _) => unreachable!(),
    }
}
```

---

## 5. Integration with Cache-Lattice Views (#1176)

### 5.1 Validity Windows

Coherency profiles control the validity-window policy for cache-lattice views:

| Profile   | Validity window policy                                  |
|-----------|--------------------------------------------------------|
| `perf`    | FreshnessToken with TTL = `params.attr_ttl`             |
| `cluster` | Lease-epoch-gated: view valid within same lease epoch   |
| `auto`    | Resolved to one of the above                            |

### 5.2 Freshness Token Integration

Under `perf`, views carry a `FreshnessToken`:

```rust
/// Freshness token carried by cache-lattice views under non-strict profiles.
///
/// Under `cluster`, the lease epoch serves as the freshness gate.
#[derive(Clone, Copy, Debug)]
pub struct FreshnessToken {
    /// Monotonic generation counter from the authoritative store
    /// at the time this view was built.
    pub build_generation: u64,
    /// Wall-clock time when this view was built.
    pub build_time: Instant,
    /// Profile under which this view was built.
    pub profile: CoherencyProfile,
}

impl FreshnessToken {
    /// Check whether this token is still valid under the given profile.
    pub fn is_valid(&self, current_generation: u64, params: &CoherencyProfileParams) -> bool {
        match self.profile {
            CoherencyProfile::Perf => {
                // Valid if within TTL and generation matches.
                self.build_time.elapsed() < params.attr_ttl
                    && self.build_generation == current_generation
            }
            CoherencyProfile::Cluster => {
                // Valid if within same lease epoch.
                // Lease-epoch validity is checked by the caller.
                self.build_generation == current_generation
            }
            CoherencyProfile::Auto => unreachable!(),
        }
    }
}
```

---

## 6. Mount Option and Configuration

### 6.1 CLI Mount Option

Add `--cache-profile` to the `mount` subcommand:

```
tidefs-posix-filesystem-adapter-daemon mount \
  --store /mnt/tidefs/store \
  --mount /mnt/tidefs \
  --cache-profile strict|perf|cluster|auto
```

Default: `auto`.

### 6.2 Environment Variable Override

For test harness integration, the profile can be overridden via:

```bash
TIDEFS_CACHE_PROFILE=strict   # force strict for xfstests
TIDEFS_CACHE_PROFILE=perf     # force perf for benchmarks
```

The `--cache-profile` CLI flag takes precedence over the environment variable.

### 6.3 `PreviewFuseMountConfig` Extension

```rust
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreviewFuseMountConfig {
    pub store_root: PathBuf,
    pub mountpoint: PathBuf,
    pub root_authentication_key: RootAuthenticationKey,
    /// Coherency profile for caching behaviour.
    /// Default: `CoherencyProfile::Auto`.
    pub cache_profile: CoherencyProfile,
}
```

### 6.4 FUSE Filesystem Integration

`PreviewFuseFilesystem` gains a `cache_profile` field and a `profile_params`
field:

```rust
pub struct PreviewFuseFilesystem {
    // ... existing fields ...
    /// Current effective coherency profile (resolved from `Auto` at mount).
    cache_profile: CoherencyProfile,
    /// Caching parameters derived from the profile.
    profile_params: CoherencyProfileParams,
}
```

All existing `reply.entry(&TTL, ...)` and `reply.attr(&TTL, ...)` calls are
replaced with `reply.entry(&self.profile_params.entry_ttl, ...)` and
`reply.attr(&self.profile_params.attr_ttl, ...)`. Negative replies (ENOENT)
use `self.profile_params.negative_ttl` (which is zero under `strict` and
`cluster`, disabling negative caching).

---

## 7. Observability

### 7.1 Metrics

```rust
// In MetricsRegistry:
pub fn coherency_profile_gauge(&self) -> Arc<Gauge>;
  // → tidefs_fuse_coherency_profile{profile="strict|perf|cluster|auto"}

pub fn coherency_profile_switch_counter(&self) -> Arc<Counter>;
  // → tidefs_fuse_coherency_profile_switches_total

pub fn coherency_profile_ttl_seconds(&self, op: &str) -> Arc<Histogram>;
  // → tidefs_fuse_coherency_ttl_seconds{operation="lookup|getattr|readdir"}
```

### 7.2 Logging

```text
[INFO] tidefs_fuse: coherency_profile=auto resolved=perf
[INFO] tidefs_fuse: coherency_profile_switch from=perf to=strict reason=xfstests_harness
[INFO] tidefs_fuse: attr_ttl=0.100s entry_ttl=0.100s negative_ttl=0.000s profile=strict
```

### 7.3 Profile Observable in Daemon Status

The `charter` subcommand output is extended:

```text
$ tidefs-posix-filesystem-adapter-daemon charter
projection_charter.policy_version=1
projection_charter.spec=design rule item Rule 6 projection charter...
coherency_profile=strict
coherency_profile_params.attr_ttl_ms=100
coherency_profile_params.entry_ttl_ms=100
coherency_profile_params.negative_ttl_ms=0
coherency_profile_params.data_caching=direct_io
```

---

## 8. Implementation Strategy

### Phase 1: Type Definition (no behaviour change)

1. Add `CoherencyProfile` enum, `CoherencyProfileParams`, `DataCachingMode`,
   new `tidefs-types-coherency-profile-core` crate.
2. Add `--cache-profile` parsing to `main.rs` and extend `PreviewFuseMountConfig`.
3. Add `TIDEFS_CACHE_PROFILE` env var support.
4. Replace `const TTL: Duration` with profile-derived params in `fuse_preview.rs`.

### Phase 2: Profile Behaviour Differentiation

5. Implement TTL selection matrix (different TTLs for attr vs entry vs negative).
6. Implement `auto` profile derivation with `CoherencyTopologyState`.
7. Wire membership-change and lease-lifecycle event handlers for profile re-resolution.

### Phase 3: Cache-Lattice Integration

8. Integrate `FreshnessToken` with cache-lattice view validity checks.
9. Implement lease-epoch-gated validity under `cluster` profile.


11. Add profile gauge, switch counter, and TTL histogram metrics.
12. Extend `charter` subcommand output.
13. Run xfstests `generic/quick` under `strict` profile — must pass without manual
    knob tuning.
14. Measure metadata RPC reduction under `perf` vs `strict` on single-node workloads.
15. Verify `auto` resolves to `strict` under xfstests harness and `perf` otherwise.

---

## 9. Crate Placement

| Component | Crate |
|-----------|-------|
| `CoherencyProfile` enum, `CoherencyProfileParams` | `tidefs-types-posix-filesystem-adapter-core` (new or existing) |
| `CoherencyTopologyState` | `apps/tidefs-posix-filesystem-adapter-daemon` |
| `FreshnessToken` | `tidefs-types-cache-lattice-core` (extends #1176) |
| `auto` derivation + re-resolution | `apps/tidefs-posix-filesystem-adapter-daemon` |
| Profile selection metrics | `tidefs-observe-core-runtime` (new counter/gauge labels) |
| TTL-selection logic in FUSE replies | `apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs` |

---

## 10. Tradeoffs and Risks

### 10.1 `strict` Profile and Performance

The `strict` profile uses `direct_io` (bypasses kernel page cache) and
but imposes a significant performance penalty on metadata-heavy workloads.
This is intentional: `strict` is the correctness gate, not the performance
profile. Operators are expected to use `perf` or `auto` for production.

### 10.2 Negative Caching Under `strict`

Negative caching (remembering ENOENT) is disabled under `strict` because a
negative entry could become positive between the cached reply and the next
lookup. This is necessary for xfstests correctness but increases lookup
latency for frequently-missed names. A future optimisation could add a
"bounded negative cache" with a generation counter per directory, but this
is out of scope for the initial implementation.

### 10.3 `cluster` Profile Depends on Lease Infrastructure

The `cluster` profile requires a working lease subsystem (`tidefs-lease`) and
membership layer (`tidefs-membership-live`). Until these are integrated with
the FUSE daemon, `cluster` will behave identically to `perf` (the pre-lease
default). This is acceptable because the `cluster` profile is a forward-looking
is operational.

### 10.4 `auto` Profile Ambiguity

The `auto` profile's derivation is straightforward for the cases defined
(xfstests → strict, peers → cluster, solo → perf). However, edge cases exist:

- **xfstests running on a cluster node**: The xfstests harness flag takes
  precedence, yielding `strict`. This is correct because xfstests tests local
  semantics, not cluster semantics.
- **Transient membership flapping**: If nodes join and leave rapidly, the
  `auto` profile could oscillate between `perf` and `cluster`. Mitigation:
  a 5-second hysteresis window prevents rapid profile switching.

### 10.5 Compatibility with Existing Behaviour

The current hardcoded `TTL = 1s` maps most closely to the `perf` profile.
Making `auto` the default ensures that single-node deployments see no
regression in caching behaviour. The `strict` profile is strictly more
conservative, so no existing workload will break when switching to it —
it will only become slower.

---

## 11. Testing Strategy

### 11.1 Unit Tests

- `CoherencyProfile::params()` returns correct `CoherencyProfileParams` for each variant.
- `CoherencyProfile::resolve_auto()` returns correct profile for each topology state.
- `effective_ttl()` returns correct duration for each profile/exactness/negative combination.
- `effective_data_caching()` returns correct mode for each profile/exactness combination.
- `FreshnessToken::is_valid()` returns correct validity under each profile.

### 11.2 Integration Tests

- xfstests `generic/quick` pass under `strict` profile without manual knob tuning.
- Metadata RPC count under `perf` is lower than under `strict` for the same workload.
- `auto` resolves to `strict` when `TIDEFS_XFSTESTS=1` is set.
- `auto` resolves to `perf` in single-node deployment with no peers.
- Profile switch metric increments when topology changes.

### 11.3 Regression Gates

- Existing `smoke-mount` test passes under all profiles.
- Existing `score-posix` test passes under `strict` profile.
- `coverage-gap` report shows no new uncovered operations.

---

## 12. Acceptance Criteria Mapping

| Criterion | How Verified |
|-----------|-------------|
| `strict` passes xfstests `generic/quick` | Run xfstests harness with `--cache-profile strict` |
| `perf` reduces metadata RPCs vs `strict` | Compare Prometheus counters under identical workload |
| `auto` derives `strict` under xfstests | Unit test + integration test with env var |
| Profile selection observable in metrics | Check `/metrics` endpoint for `tidefs_fuse_coherency_profile` gauge |
| `--cache-profile` mount option works | CLI integration test |
| `TIDEFS_CACHE_PROFILE` env var works | CLI integration test |

---

## 13. Future Extensions

### 13.1 Per-Filesystem Profile Override

Individual pools or datasets may benefit from different profiles (e.g., a
database volume uses `strict` while a media volume uses `perf`). This can
be added as a pool config field in a continuation.

### 13.2 Profile-Aware Writeback Tuning

Under `perf`, the page-cache writeback parameters (dirty ratio, writeback
interval) could be tuned per workload signature. This is out of scope for
the initial implementation.

### 13.3 Operator-Defined Custom Profiles

A future extension could allow operators to define custom profiles with
explicit TTL and data-caching parameters, stored in the pool configuration.
This would allow fine-tuning without losing the safety of named profiles.

### 13.4 Profile Transition Smoothing

When the `auto` profile switches between `perf` and `cluster` (or vice versa),
a gradual TTL ramp could smooth the transition, preventing a sudden spike in
authoritative-store reads. This is a performance optimisation and not required
for correctness.

---

## References

- Old v0.262 design: `~/tidefs_old/docs/tidefs_design_book.md` §"Coherency profiles and mmap are part of correctness"
- Old FUSE notes: `~/tidefs_old/docs/notes/2026-02-06-fuse-userspace-api-and-mmap.md`
- `crates/tidefs-types-cache-lattice-core/src/lib.rs` — CacheClass, MemoryDomain, CacheEntryHeader
- `crates/tidefs-types-continuity-charter/src/lib.rs` — ExactnessClass, FreshnessClass, ProjectionContractRecord
- `crates/tidefs-lease/src/types.rs` — LeaseGrant, LeaseClass, lease lifecycle
- `apps/tidefs-posix-filesystem-adapter-daemon/src/projection_charter.rs` — PosixProjectionCharter
- `apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs` — PreviewFuseFilesystem, TTL constant
- `docs/design/cache-lattice-views.md` — Cache-lattice views design (#1176)
- `docs/POSIX_FILESYSTEM_ADAPTER_DAEMON_TOPOLOGY_P5-01.md` — FUSE daemon topology
