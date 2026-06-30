# Three-Contract Architecture: The TideFS Organizing Principle

**Issue**: [#1250](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1250)
**Maturity**: **design-law** — meta-architecture tying together the on-media format,
**Lane**: docs
**Priority**: P1 (foundational for multi-implementation correctness)

## Abstract

TideFS is organized around three stable, cross-cutting contracts. Every
implementation — the Python v0.262 reference, the current Rust rewrite, and any
Together they form the architectural spine that makes multi-implementation
correctness provable rather than aspirational.

The three contracts are:

1. **On-media format** — what bytes go to stable storage and how they are
   encoded, versioned, and upgraded.
2. **VFS semantic contract** — what every filesystem operation means across all
   access surfaces (FUSE, ublk, admin, cluster RPC).
3. **Trace emission contract** — a deterministic JSONL trace format that captures
   every operation and its outcome for cross-implementation comparison.

These contracts are not three separate subsystems. They are three facets of a
single correctness strategy: if two implementations read the same on-media
format and produce equivalent traces for equivalent operations, then they are
semantically equivalent.

---


```
Python reference ──produces──> traces ──compared──> Rust traces
        │                                            │
        └──reads/writes──> on-media format <──reads/writes──┘
```

Both implementations reading the same on-media format must produce equivalent
traces. This is the **core regression oracle**.

Each contract is independently specifiable and testable. Together they form a
implementations signals a contract violation in one of the other two pillars.

### 1.1 Why three contracts, not one?

A single implementation spec (e.g., "behave like POSIX") is insufficient for
multi-implementation correctness because:

- **Format drift**: implementations that share no common on-media format cannot
- **Semantic ambiguity**: "behave like POSIX" leaves errno choice, ordering
  guarantees, and durability semantics implicit, allowing implementations to
  diverge in untestable ways.
- **Observability gaps**: without a common trace format, divergences are
  discovered through user bug reports rather than automated regression gates.

Three separable contracts solve each problem: the format contract makes data
portable, the semantic contract makes behavior exact, and the trace contract
makes divergence observable.

---

## 2. Contract 1: On-Media Format

### 2.1 Purpose

The on-media format contract defines exactly what bytes go to stable storage and
how they are encoded, interpreted, versioned, and upgraded. Every implementation
that mounts a TideFS dataset must obey this contract.

### 2.2 Scope

- **Record families**: six canonical V1 record families (DatasetRecord, InodeRecord,
  NamespaceEntry, ExtentMapRecord, ChunkManifest, SnapshotRecord) with fixed-width
  `(family_id, type_id)` prefixes for mechanical dispatch.
- **TLV extensions**: every record carries a TLV extension area. Unknown extensions
  are skipped; known extensions are parsed. This is the forward-compatibility
  mechanism inside a record family.
- **Feature flags**: per-dataset `compat` / `ro_compat` / `incompat` feature
  bitmaps gate format changes. An unknown `incompat` feature refuses mount;
  `ro_compat` permits read-only mount; `compat` is safe to ignore.
- **Deterministic encoding**: all numerics are little-endian fixed-width scalars.
  No host-endian layouts, no compiler-implicit struct layouts, no varints.
  Canonical binary representation ensures byte-for-byte reproducibility.
- **Upgrade gates**: the unified format lifecycle (Define → Gate → Evolve →
  by CI and review.

### 2.3 Authoritative documents

| Document | Role |
|---|---|
| `docs/design/on-media-format-strategy.md` (#1220) | Canonical V1 record family catalog, TLV rules, encoding |
| `docs/DATASET_FEATURE_FLAGS_DESIGN.md` (#1223) | Feature class model, mount gating, compatibility matrix |
| `docs/CANONICAL_BINARY_ENCODE_DECODE_ENDIAN_CHECKSUM_LAW_P2-03.md` | Byte-order, envelope, and checksum law |
| `docs/FORMAT_IDENTITY_UPGRADE_REPLAY_CONTINUITY_LAW_P2-04.md` | Identity tuple and upgrade/replay continuity |
| `docs/LOCAL_OBJECT_STORE_ON_DISK_FORMAT.md` | Segment format, record versions, tombstones, trailers |

### 2.4 Key invariants

- Every on-media record carries a `family_id` and `type_id` prefix.
- TLV extensions are forward-compatible: unknown extensions are skipped, never
  cause mount failure (unless gated by an `incompat` feature flag).
  is byte-for-byte deterministic.
- No implementation may "innovate" on the format without updating feature flags,
  golden vectors, and trace coverage.

---

## 3. Contract 2: VFS Semantic Contract

### 3.1 Purpose

The VFS semantic contract defines what every filesystem operation **means**
across all access surfaces. It is the single source of truth for errno mapping,
ordering guarantees, durability semantics, and the canonical operation catalog.

### 3.2 Scope

- **Canonical operation catalog**: every VFS operation (namespace, file I/O,
  directory, extended attribute) is defined with exact preconditions,
  postconditions, errno mappings, and ordering guarantees.
- **Unified across surfaces**: the same semantics serve the FUSE daemon (local
  userspace), VFS_RPC (cluster forwarding), ublk (block volume), and admin
  proxy (management). No surface gets a different semantic contract.
- **Inode space, not path space**: the engine operates on `InodeId`, not paths.
  Path resolution is the adapter's responsibility.
- **Errno mapping**: every error condition maps to a specific `Errno` value.
  The mapping is exhaustive and deterministic.
- **Durability semantics**: `fsync`, `fdatasync`, `O_DSYNC`, and transaction
  commit boundaries are defined in terms of the intent log and COMMIT_GROUP state machine.
- **POSIX semantics checklist**: the FUSE binding maps POSIX requirements
  (atomic rename, `RENAME_NOREPLACE`, `RENAME_EXCHANGE`, `O_EXCL`, sticky bit,
  setgid inheritance, etc.) to VfsEngine operations.

### 3.3 Authoritative documents

| Document | Role |
|---|---|
| `docs/VFS_ENGINE_API_CONTRACT.md` (#1213) | Canonical VFS Engine API: types, ops, semantics |
| `docs/design/vfs-rpc-wire-protocol.md` (#1234) | VFS_RPC wire protocol: method IDs, framing, dedup |
| `docs/FUSE_BINDING_STRATEGY_AND_FEATURE_MATRIX_P1-05.md` | FUSE adapter binding strategy |
| `docs/POSIX_SEMANTICS_OW106.md` | POSIX semantics coverage for the FUSE surface |
| `docs/FUSE_OPERATION_COVERAGE_MATRIX.md` | Per-op FUSE coverage and gaps |

### 3.4 Key invariants

- Every mutating operation receives a `RequestCtx` with uid, gid, pid, umask,
  and supplementary groups for ownership/permission checks.
- Names are raw bytes; no adapter may assume UTF-8.
- Operations are synchronous at the engine boundary; async batching happens below.
- Generation counters track inode lifetime for ESTALE detection.
- The same `Errno` values are used across all surfaces.

---

## 4. Contract 3: Trace Emission Contract

### 4.1 Purpose

The trace emission contract defines a deterministic JSONL trace format that
captures every operation and its outcome. It is the mechanism by which
implementations are compared: if two implementations produce equivalent traces
for equivalent inputs, they are semantically equivalent.

### 4.2 Scope

- **JSONL format**: one JSON object per line, terminated by `\n`. Keys sorted,
  no whitespace after `:` or `,`. Lines starting with `#` are comments and
  skipped by the reader.
- **Deterministic ordering**: operations are emitted in the order they execute.
  Allowed nondeterminism (timestamps, generation counters, inode allocation
  order) is explicitly declared in the trace schema.
- **Cross-implementation comparison**: the `tidefs-trace-oracle` crate replays
  JSONL trace files and compares outputs against expected values and fingerprints.
- **RFP-Core translation**: the Python → Rust translation methodology depends on
  trace parity. Every Python semantic op has a corresponding Rust implementation
- **Semantic op name registry**: all op names are centralized in
  `crates/tidefs-semantic-op-registry/` as wire-stable `snake_case` constants.

### 4.3 Authoritative documents

| Document | Role |
|---|---|
| Deleted trace-oracle lineage (#1174) | Historical trace oracle design input retained in git history |
| Deleted semantic-op registry lineage (#1200) | Historical canonical op-name registry input retained in git history |
| `docs/RFP_CORE.md` (#1236) | Python → Rust translation methodology |

### 4.4 Key invariants

- Every trace begins with a `trace_meta` op declaring schema and version.
- Binary values are base64-encoded using RFC 4648.
- Op names are wire-stable snake_case from the canonical registry.
- Schema version bumps (e.g., `pool_trace_v1` → `pool_trace_v2`) are required
  when op semantics change.
- Golden traces are committed under `traces/golden/` with MANIFEST.json
  tracking sha256 and expected fingerprints.

---

## 5. Cross-Cutting Rules

These rules apply across all three contracts and are the architectural
enforcement mechanism:

### 5.1 Format → Trace

- Every on-media format change must have trace coverage. A new record family
  or TLV extension is not accepted without golden traces that exercise its
  encode/decode path and its effect on VFS operations.
- Golden vectors for format encoding are distinct from trace oracle vectors.
  semantic behavior.

### 5.2 Semantic → Trace

- Every VFS semantic change must update the trace contract. A new errno
  condition, changed ordering guarantee, or new operation must be reflected
  in the trace schema, the op registry, and the golden trace corpus.
- The trace oracle's `expect` assertions must cover every new semantic path.

### 5.3 RFP-Core → All three

- The Python → Rust translation methodology preserves all three contracts.
  Every Python class maps to a Rust struct/enum; every method maps to a trait
  method or inherent impl; every error is a `Result`.
  a correct translation produces equivalent traces.

### 5.4 Innovation discipline

- No implementation may "innovate" on any one contract without updating the
  other two. A format change without trace coverage is rejected. A semantic
  change without trace schema update is rejected. A trace format change without
  corresponding semantic and format alignment is rejected.
- This discipline is enforced by the review process and, where possible, by CI
  gates (`tidefs-xtask check-trace-oracle`, golden vector tests, format
  lifecycle gate checks).

### 5.5 Contract evolution

- Each contract evolves through its own lifecycle:
  - Trace: Schema → Producer → Consumer → Minimizer
- Contract version bumps are coordinated: a format `incompat` feature flag,
  a semantic schema version, and a trace schema version bump must be proposed
  together when any one contract changes incompatibly.

---

## 6. Relationship to TideFS Design rule

The three-contract architecture is the operational expression of the TideFS
design rule's core commitments:

| Design rule rule | Contract embodiment |
|---|---|
| **The graph is authoritative** | On-media format: the graph of records is the authoritative truth; paths, inode numbers, and caches are projections |
| **Authority is scarce and explicit** | VFS semantic: mutating operations carry explicit `RequestCtx` with authority credentials |
| **Continuity is first-class, but never sovereign** | VFS semantic: POSIX is a projection charter over inode-space operations, not the architecture itself |
| **Observability is structural** | Trace emission: every operation is traceable; every outcome is comparable across implementations |
| **Repair publishes trusted successor state** | On-media format: repair produces findings and receipts, not in-place patching |

The three contracts are not an alternative to the design rule — they are the
mechanism by which the design rule's rules are made testable across implementations.

---

## 7. Issue Map

### 7.1 Format contract issues

| Issue | Title | Status |
|---|---|---|
| #1220 | On-media record format strategy | design-spec |
| #1223 | Dataset feature flags architecture | design-spec |
| #1238 | Unified on-media format lifecycle | design-spec |
| #1225 | V1 extent map tristate model | design-spec |

### 7.2 Semantic contract issues

| Issue | Title | Status |
|---|---|---|
| #1213 | VFS Engine API contract | spec-draft |
| #1234 | VFS_RPC wire protocol | design-spec |
| #1244 | ADMIN protocol | pending |
| #1229 | BULK plane | pending |
| #1233 | POSIX semantics checklist (FUSE binding) | pending |

### 7.3 Trace contract issues

| Issue | Title | Status |
|---|---|---|
| #1174 | Deterministic trace oracle system | design-spec |
| #1200 | Semantic op canonical name registry | design-spec |
| #1235 | Trace emission contract | pending |
| #1236 | RFP-Core Python → Rust translation methodology | design-law |

### 7.4 Cross-cutting

| Issue | Title | Role |
|---|---|---|
| #1250 | Three-contract architecture (this doc) | Meta-architecture |
| #1284 | Dependency matrix | Cross-issue dependency tracking |

---



| Gate | What it proves | CI command |
|---|---|---|
| Golden vector tests | Format encoding is byte-for-byte deterministic | Per-crate `#[test]` functions |
| Trace oracle replay | Rust semantics match Python reference traces | `tidefs-xtask check-trace-oracle` |
| Format lifecycle check | Every format change follows the five-phase lifecycle | `tidefs-xtask check-format-lifecycle` |
| Op registry check | All op names are centralized and wire-stable | `tidefs-xtask check-semantic-op-registry` |
| Feature flag check | Feature flags are registered and classified | `tidefs-xtask check-feature-flags` |
| Cross-implementation compare | Python and Rust traces are equivalent | `tidefs-xtask compare-traces` |

These gates are the operational proof that the three contracts hold. A passing
gate run means the format, semantic, and trace contracts are consistent.

---

## 9. Design Precedence

When a design decision affects multiple contracts, this order wins:

1. **Format integrity** — the on-media format must never be ambiguous or
   silently corruptible.
2. **Semantic determinism** — the VFS semantic contract must never allow
   two implementations to produce different results from the same inputs.
3. **Trace completeness** — the trace must capture enough information to
   reproduce and compare any operation outcome.
4. **Implementation convenience** — ease of implementation is a legitimate
   concern but may not override the first three.

This precedence ladder is applied at review time and, where possible, enforced
by CI.
