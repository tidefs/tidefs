# Inline and Post-Process Deduplication — Block-Level Hash Index, DDT Sharding, Cluster-Aware Dedup

**Issue**: [#1255](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1255)
**Status**: design-spec
**Priority**: P2
**Lane**: storage-core
**Milestone**: DESIGN-M3: Data Services + Integrity (Layers 6-7)
**Depends on**: #1180 (refcount delta queues), #1192 (weighted ARC), #1220 (record format),
  #1226 (unified cache), #1239 (universal incremental cursor), #1241 (BACKGROUND lane),
  #1246 (encryption model), #1285 (extent maps & locator tables)
**Related**: #1209 (cluster membership), #1248 (lock service)

> **Implementation note (#5966, 2026-05-19)**: This DDT/scanner design is a deferred
> aspirational architecture and is **not** the live write-path production authority.
> The current production dedup path (live as of this note) is content-addressed chunk
> dedup in `crates/tidefs-local-filesystem/src/content.rs`, gated by the
> `org.tidefs:dedup` dataset feature flag (default off, matching the
> `integrity.dedup=Bool(false)` dataset-properties registry default). When enabled,
> chunk writes compute BLAKE3 fingerprints of uncompressed chunk content, probe an
> in-memory `DedupIndex` and the cross-session canonical-object store, and write
> dedup redirects instead of duplicate inline chunk data. Session-level accounting
> is exposed via `LocalFileSystem::dedup_stats()` (`DedupStats`: `dedup_hits`,
> `dedup_bytes_saved`, `total_chunks`, `dedup_ratio()`). The `tidefs-dedup` crate
> (`DedupTable`, `DedupScanner`) is testable in isolation but has no production
> consumer; its `resume(Some(checkpoint))` rejects the cursor and
> `persist_checkpoint()` is a no-op. This doc remains the design target for
> post-process DDT-based dedup when the feature matures.


## Abstract

This document specifies the tidefs deduplication subsystem: a block-level, content-hashed
dedup engine that operates inline (during write) or post-process (background scanner), with
a shardable, tiered Dedup Table (DDT) that bounds memory usage and distributes across
cluster nodes. The design beats ZFS's RAM-hungry DDT and Ceph's lack of filesystem-level
dedup by combining: (a) hash-prefix sharding across cluster nodes, (b) three-tier L1→L2→L3
DDT storage, (c) bounded-memory hot-set management via ARC, and (d) integration with the
tidefs extent/locator architecture.

---

## 1. Motivation and Design Constraints

### 1.1 Why dedup matters for beating ZFS

ZFS deduplication is powerful but limited by the DDT (Dedup Table) memory requirement:
every unique block hash must reside in RAM for acceptable performance. On a 100 TiB pool
with 8 KiB records, the DDT can consume tens of GB of RAM. Ceph has no native
filesystem-level dedup — only RADOS-level object dedup in recent releases, which operates
at much coarser granularity.

tidefs can beat both by designing dedup from first principles:

- **Shardable across the cluster**: hash-prefix partitioning distributes the DDT across
  nodes, so no single node carries the full memory burden.
- **Spillable to SSD**: the DDT lives primarily on fast NVMe, with only the hot set in RAM.
- **Bounded-memory**: the L1 (in-memory) tier is ARC-managed and fixed-size; cold entries
  spill to L2/L3 transparently.
- **Integrated with the cache hierarchy**: the DDT L1 reuses the ARC infrastructure from
  #1192/#1226 rather than inventing a separate cache.

### 1.2 Design rule alignment

Per tidefs design rule:

- **The DDT is not authoritative truth.** It is a rebuildable materialized product. The
  authority is the extent map + locator table. The DDT is a performance optimization that
  can be rebuilt from a full scan of the locator table.
- **Identity and revision are separate.** A hash identifies content, not location. The
  DDT maps content identity (hash) to canonical extent identity (extent_id/locator_id).
- **Materialization is a governed economy.** The DDT is a governed materialized product
  with explicit budgets, freshness contracts, and observability.
- **Writer locality is the default fast path.** Inline dedup pays a hash-lookup cost;
  post-process dedup defers that cost to a BACKGROUND lane scanner.

### 1.3 Design decisions

| Decision | Rationale |
|---|---|
| Block-level, content-hashed | Matches extent granularity; enables cross-file, cross-dataset dedup |
| Hash-prefix sharding (not range or round-robin) | Deterministic routing; no central coordinator for lookup |
| Three-tier DDT (L1 RAM → L2 NVMe → L3 on-media) | Bounds memory; ZFS's all-RAM DDT is the failure mode we avoid |
| Two modes (inline + post-process) | User chooses latency vs. immediate space savings per dataset |
| DDT is never correctness-critical | Crash-safety property: dedup is a space optimization, not a correctness requirement |
| Convergent encryption option | Enables dedup on encrypted datasets without plaintext exposure |
| BLAKE3 default hash | Speed (hardware-accelerated) and 256-bit output; SHA-256 as configurable alternative |

---

## 2. Dedup Table (DDT) Architecture

### 2.1 Core data structures

#### 2.1.1 DdtEntryV1 — the on-media authoritative DDT entry

```rust
/// Canonical V1 DDT entry. Stored in the on-media DDT B+tree (L3)
/// and cached in L2 (SSD) and L1 (RAM hot set).
///
/// Schema family: DDT (family_id=17)
/// Schema type: DdtEntryV1 (type_id=1)
///
/// Total size: 32 + 16 + 8 + 8 + 8 + 8 + 4 + 12 = 96 bytes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdtEntryV1 {
    /// Content hash (BLAKE3-256 or SHA-256). This is the primary key.
    pub hash: [u8; 32],

    /// Locator ID of the canonical extent that holds this content.
    /// Points into ExtentLocatorTable (#1285).
    pub locator_id: [u8; 16],

    /// Number of extent-map references to this canonical extent.
    /// Incremented on dedup hit (CoW clone), decremented on extent
    /// deletion. When refcount reaches 0, the entry is a candidate
    /// for DDT pruning.
    pub refcount: u64,

    /// Total logical bytes saved by dedup hits against this entry.
    /// Used for operator-visible dedup ratio reporting:
    ///   dedup_ratio = (saved_bytes + logical_bytes) / logical_bytes
    pub saved_bytes: u64,

    /// COMMIT_GROUP when this entry was created (first insert).
    pub birth_commit_group: u64,

    /// COMMIT_GROUP when this entry was last used (hit or insert).
    /// Drives pruning: entries with stale last_seen_commit_group are candidates.
    pub last_seen_commit_group: u64,

    /// Flags bitmap:
    ///   bit 0: hash_algo (0=BLAKE3, 1=SHA-256)
    ///   bit 1: encrypted_content (convergent encryption in use)
    ///   bits 2-7: reserved
    pub flags: u32,

    /// Reserved for TLV extension anchor.
    pub reserved: [u8; 12],
}
```

#### 2.1.2 DdtShard — a hash-prefix partition

```rust
/// A single DDT shard, covering one hash-prefix range.
///
/// The DDT is partitioned into 2^shard_bits shards by the high bits
/// of the content hash. Each shard is an independent B+tree.
///
/// In cluster mode, each shard is owned by exactly one node.
/// Shard ownership is tracked in ClusterMembership (#1209).
#[derive(Debug, Clone)]
pub struct DdtShard {
    /// Shard index [0, 2^shard_bits).
    pub shard_id: u32,

    /// Hash prefix this shard covers.
    /// All hashes h where h[0..prefix_bytes] == prefix belong here.
    pub prefix: Vec<u8>,

    /// Number of prefix bits (shard_bits for uniform sharding).
    pub prefix_bits: u8,

    /// Root page locator for the shard's B+tree in the locator table.
    /// The B+tree is keyed by the full 32-byte content hash.
    pub root_locator: [u8; 16],

    /// Number of entries in this shard.
    pub entry_count: u64,

    /// Cached bloom filter for "definitely not present" fast-path.
    /// 512 KiB default, ~4 Mbit, ~0.05% false-positive rate at
    /// 1 million entries. Rebuilt periodically from the B+tree.
    pub bloom_filter: Option<BloomFilter>,

    /// Current owner node in cluster mode (None = local).
    pub owner_node_id: Option<u64>,

    /// Epoch of last ownership change. Matches membership epoch.
    pub ownership_epoch: u64,
}
```

#### 2.1.3 DdtConfig — dataset-level dedup policy

```rust
/// Per-dataset dedup configuration.
/// Stored in DatasetMetaV1 feature_flags and extended attributes.
#[derive(Debug, Clone)]
pub struct DdtConfig {
    /// Dedup mode: Inline, PostProcess, or Disabled.
    pub mode: DedupMode,

    /// Hash algorithm: Blake3 or Sha256.
    pub hash_algo: HashAlgo,

    /// Number of hash prefix bits used for sharding.
    /// 0 = single shard (no sharding), 8 = 256 shards, 12 = 4096 shards.
    pub shard_bits: u8,

    /// Maximum entries in L1 (in-memory hot set). 0 = use default.
    pub l1_max_entries: u64,

    /// DDT pruning threshold: entries with last_seen_commit_group older than
    /// (current_commit_group - prune_after_commit_groups) are candidates for removal
    /// when refcount == 0.
    pub prune_after_commit_groups: u64,

    /// Minimum logical bytes per extent to consider for dedup.
    /// Tiny extents (e.g., 512 bytes) have high hash-to-data ratio;
    /// skipping them reduces DDT churn.
    pub min_dedup_bytes: u64,

    /// Whether to use convergent encryption for encrypted datasets.
    pub convergent_encryption: bool,

    /// Total dataset DDT entry capacity target (for sizing L2/L3).
    pub capacity_target: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupMode {
    /// Dedup disabled entirely.
    Disabled = 0,

    /// Inline dedup: hash during write, lookup before commit.
    Inline = 1,

    /// Post-process dedup: write normally, background scanner merges.
    PostProcess = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgo {
    Blake3 = 0,
    Sha256 = 1,
}
```

### 2.2 Three-tier storage model

```
┌─────────────────────────────────────────────────────────────┐
│                      DDT STORAGE TIERS                       │
├──────────┬──────────────┬──────────────┬────────────────────┤
│   Tier   │   Location   │   Latency    │   Eviction          │
├──────────┼──────────────┼──────────────┼────────────────────┤
│    L1    │   RAM (ARC)  │   < 1 µs     │   ARC (LRU + LFU)  │
│    L2    │   SSD/NVMe   │   < 100 µs   │   LRU, size-capped │
│    L3    │   On-media   │   < 1 ms     │   Never (pruned)   │
│          │   (B+tree)   │              │                    │
└──────────┴──────────────┴──────────────┴────────────────────┘
```

**L1 — In-memory hot set:**
- Lives in `memory_domain_0.authority_immutable` (sealed, read-only cached entries).
- Managed by the ARC from #1192/#1226: balances LRU (recency) and LFU (frequency).
- Ghost lists prevent polluting the hot set with one-hit-wonder entries.
- Maximum size configured via `l1_max_entries`; default 256K entries (~24 MiB at 96 bytes/entry).
- An L1 hit incurs no IO; the lookup returns the cached `DdtEntryV1` directly.

**L2 — SSD-backed spill:**
- Full DDT cached on fast NVMe device, accessed as a page cache over the L3 B+tree.
- Uses the unified cache infrastructure from #1226 with `CacheClassification::Ddt`.
- Page-sized (4 KiB) B+tree nodes cached; typically 40+ entries per page.
- LRU eviction when the SSD cache budget is exhausted.
- An L2 hit incurs one NVMe read (~100 µs).

**L3 — On-media B+tree:**
- The canonical persistent DDT. One B+tree per shard, stored in the pool locator
  table namespace.
- Keyed by the full 32-byte content hash.
- Checkpointed with every commit_group alongside other metadata.
- An L3 miss (hash not in DDT) means the content is new; proceed with write.
- An L3 hit that misses L1 and L2 incurs ~1 B+tree traversal (~1 ms).

### 2.3 DDT sharding

The DDT is sharded by hash prefix for deterministic, coordinator-free routing:

```
shard_id = hash[0..shard_bytes] interpreted as big-endian u16/u32
```

**Uniform sharding** (cluster default, `shard_bits=10`, 1024 shards):
- Every node in a 4-node cluster owns ~256 shards.
- Expanding the cluster redistributes shards via the membership protocol (#1209).
- Shard ownership is a soft assignment: any node can read any shard, but the
  owning node is authoritative for inserts and refcount updates.

**Local-only sharding** (single-node, `shard_bits=8`, 256 shards):
- All shards local; sharding provides B+tree parallelism and smaller individual trees.
- A 1B-entry DDT with 256 shards averages ~3.9M entries per shard, keeping
  B+tree depth manageable (depth 3-4 at 4096-byte pages).

**Bloom filter fast-path (cluster mode):**
Every node maintains a per-shard bloom filter for its owned shards. A cross-node
DDT lookup first checks the destination node's bloom filter:

1. Compute hash, determine `shard_id`, route to owning node.
2. Owning node checks bloom filter. If "definitely not present," return MISS
   immediately (~network RTT only).
3. If "possibly present," perform full L1→L2→L3 lookup.

Bloom filter parameters:
- Size: 512 KiB per shard (~4 Mbit).
- Hash functions: 4 (optimal for ~0.05% FPR at 1M entries).
- Rebuild: periodically from the B+tree, triggered by the BACKGROUND scheduler.

---

## 3. Write Path Design

### 3.1 Inline dedup write path

```
Application write(N bytes)
        │
        ▼
┌─ Extent split ──────────────────────────────────────┐
│  Split N bytes into extent-aligned chunks            │
│  (minimum: recordsize; typical: 4 KiB – 1 MiB)       │
└──────────────────────┬──────────────────────────────┘
                       │
        ┌──────────────▼──────────────┐
        │  For each chunk:            │
        │    compute hash (BLAKE3)    │
        └──────────────┬──────────────┘
                       │
        ┌──────────────▼──────────────┐
        │  DDT lookup: L1 → L2 → L3   │
        │  (cluster: route by shard)  │
        └──────┬──────────────┬───────┘
               │              │
          HIT  │              │  MISS
               ▼              ▼
   ┌─────────────────┐   ┌──────────────────┐
   │ Increment       │   │ Write extent to   │
   │ DDT refcount    │   │ physical storage  │
   │ Update saved_   │   │ Insert hash →     │
   │   bytes         │   │   locator_id      │
   │ Skip write      │   │   into DDT        │
   │ Create CoW      │   │ Set refcount = 1  │
   │   extent map    │   │ Create extent     │
   │   entry pointing│   │   map entry       │
   │   to canonical  │   │                   │
   │   extent        │   │                   │
   └────────┬────────┘   └────────┬──────────┘
            │                     │
            └──────────┬──────────┘
                       │
        ┌──────────────▼──────────────┐
        │  Commit in current commit_group      │
        │  (#1190 commit_group state machine)  │
        └─────────────────────────────┘
```

**Key invariants during inline dedup write:**

1. The DDT lookup and extent write are not atomic — crash safety is handled
   by the idempotent nature of the DDT (see §7).
2. The DDT `refcount` increment on a HIT and the extent map entry creation
   occur within the same commit_group, ensuring they commit or rollback together.
3. On a HIT, no new extent is written; the new extent map entry points to
   the existing canonical `locator_id`. The DDT `saved_bytes` accumulates
   the logical length of this avoided write.
4. On a MISS, the extent and the DDT entry are committed in the same commit_group.

### 3.2 Post-process dedup write path

```
Application write(N bytes)
        │
        ▼
┌─ Extent split + write normally (no hash check) ───┐
│  Every extent is written to physical storage       │
│  Extent map entries point to unique locators       │
└──────────────────────┬────────────────────────────┘
                       │
                       ▼
               Commit in commit_group (immediate)
                       │
                       ▼
         ┌─────────────────────────────┐
         │  BACKGROUND lane scanner     │
         │  (runs per tick, budgeted)  │
         │                             │
         │  1. Scan extents written    │
         │     since last scan cursor  │
         │  2. Compute hash for each   │
         │  3. DDT lookup              │
         │  4. On HIT: CoW-merge       │
         │     extent map entries to   │
         │     canonical locator       │
         │  5. On MISS: insert into    │
         │     DDT                     │
         │  6. Advance scan cursor     │
         └─────────────────────────────┘
```

**Post-process scanner design:**

- **Scheduling**: BACKGROUND lane priority 4 (lowest), resumable. Budgeted
  via the unified background service framework (#1179).
- **Cursor**: Uses universal incremental cursor (#1239) keyed by
  `(dataset_id, birth_commit_group, locator_id)`. Survives restart.
- **Batch size**: Configurable, default 1000 extents per tick.
- **Throttling**: Respects `ServiceBudget`; yields when DEMAND lane has
  backpressure.
- **Dedup eligibility**: Only extents with `ExtentMapEntryV2.flags & DEDUP_ELIGIBLE`
  are scanned. Inline-dedup'ed extents (already in DDT) have this flag cleared
  to avoid rehashing.
- **Convergence**: The scanner eventually processes all eligible extents.
  When no more work exists, it idles until new extents are written.

---

## 4. DDT Pruning

### 4.1 Pruning policy

DDT entries with `refcount == 0` and stale `last_seen_commit_group` are candidates
for removal:

```
prune_candidate = (refcount == 0) AND (current_commit_group - last_seen_commit_group > prune_after_commit_groups)
```

**Why deferred, not immediate?** Immediate removal on refcount→0 risks
thrashing: a file deleted and recreated within a short window would
recompute the hash and reinsert. The `prune_after_commit_groups` grace period
(default: 1000 commit_groups, ~16 minutes at 1 commit_group/s) absorbs this.

### 4.2 Pruner design

- **Scheduling**: BACKGROUND lane priority 4, starvation-prevented.
- **Cursor**: Universal incremental cursor (#1239) keyed by
  `(shard_id, hash)`.
- **Batch size**: Default 1000 entries per tick.
- **Algorithm**:
  1. Scan DDT B+tree in key order from last cursor position.
  2. For each entry: check `refcount == 0` and `last_seen_commit_group` staleness.
  3. If candidate: remove from DDT B+tree, release bloom filter entry.
  4. Advance cursor. If budget exhausted, yield and resume next tick.

### 4.3 Pruning safety

- **Refcount > 0 entries are never pruned**, even if `last_seen_commit_group` is ancient.
  These entries are the canonical reference for live extents.
- **Refcount underflow is a bug, not a pruner concern.** The refcount delta
  queue (#1180) guarantees refcount correctness.
- **Pruning is idempotent.** If the pruner crashes mid-batch, the next tick
  resumes from the last committed cursor position.

---

## 5. Cluster-Aware Dedup

### 5.1 Cross-node DDT lookup protocol

In cluster mode, the write path may need to consult a DDT shard owned by
another node:

```
┌──────────────┐                         ┌──────────────┐
│  Writer Node │                         │  Owner Node  │
│  (local)     │                         │  (remote)    │
├──────────────┤                         ├──────────────┤
│              │  ── DDT_LOOKUP(hash) ──▶ │              │
│  1. Compute │                         │  2. Bloom    │
│     hash    │                         │     filter    │
│  2. Route   │                         │     check     │
│     by      │                         │  3. L1→L2→L3 │
│     shard   │                         │     lookup    │
│              │  ◀── DDT_RESPONSE ────  │              │
│  4. HIT:    │     (entry or MISS)     │              │
│     incr    │                         │              │
│     refcount│                         │              │
│  5. MISS:   │                         │              │
│     write   │                         │              │
│     locally │                         │              │
└──────────────┘                         └──────────────┘
```

**Wire protocol** — `DDT_LOOKUP` / `DDT_RESPONSE`:
- Service ID: `0x0B` (DDT service).
- Message format: fixed 32-byte hash payload + 8-byte request ID.
- Response: `DdtEntryV1` (96 bytes) or MISS sentinel (4 bytes).
- Transport: CONTROL lane (#1241) for low latency.
- Timeout: 5 ms default; on timeout, fall through to write (treat as MISS).
  Dedup is a space optimization, not a correctness requirement — a missed
  dedup opportunity is not a failure.

### 5.2 Shard ownership and migration

- **Ownership**: Shard ownership is a field in `ClusterMembership` (#1209).
  Each node advertises which shards it owns.
- **Migration**: When a node joins or leaves, shards are redistributed.
  Migration is a BACKGROUND-lane bulk transfer:
  1. Source node snapshots the shard B+tree.
  2. Destination node receives the snapshot via BULK plane (#1229).
  3. Destination replays commit_group log to catch up.
  4. Membership epoch increments; ownership transfers.
  5. Source node drops the shard.

---

## 6. Interaction with Encryption (#1246)

### 6.1 Three dedup-encryption models

| Model | Dedup ratio | Security | When to use |
|---|---|---|---|
| **Plaintext dedup** | High | Plaintext accessible to dedup engine | Unencrypted datasets or trusted enclave |
| **Ciphertext dedup** | Near zero | Strong — encryption randomizes output | Maximum security; dedup effectively disabled |
| **Convergent encryption** | High | Weaker — identical plaintext → identical ciphertext | Encrypted datasets that still want dedup |

### 6.2 Convergent encryption flow

Convergent encryption derives the encryption key from the content hash:

```
plaintext_key = BLAKE3(content)[0..32]     // deterministic key
ciphertext = AES-256-GCM(plaintext_key, nonce, content)
stored_hash = BLAKE3(ciphertext)[0..32]    // hash for DDT
```

- **Identical plaintext produces identical ciphertext**, enabling dedup.
- **The plaintext is never stored in the DDT**; only the hash of the
  ciphertext is stored.
- **Security caveat**: An attacker who knows (or guesses) the plaintext
  can confirm its presence by recomputing the hash (confirmation attack).
  This is an inherent tradeoff of convergent encryption — documented as a
  dataset feature flag so operators make an informed choice.

### 6.3 Per-dataset policy

The `DdtConfig.convergent_encryption` flag controls which model is used
when both dedup and encryption are enabled. The default is `false`
(ciphertext dedup, which effectively disables dedup). Operators must
explicitly opt into convergent encryption.

---

## 7. Crash Safety

### 7.1 The DDT is never correctness-critical

This is the central crash-safety property: **the DDT is a space optimization,
not a correctness requirement.** If the DDT is lost, corrupted, or inconsistent,
no data is lost. A full scan of the extent map + locator table can rebuild it.

### 7.2 Crash scenarios and recovery

**Crash after DDT insert but before extent write:**
- DDT entry exists with refcount=1, pointing to locator_id.
- The locator_id has no actual extent on disk (birth_commit_group > current committed commit_group).
- On next lookup: DDT says HIT, but extent read fails → fall through to write.
- Post-process dedup eventually corrects the DDT entry.

**Crash after extent write but before DDT insert:**
- Extent exists on disk with a locator entry.
- DDT has no entry for this hash.
- Consequence: a future write of identical content will MISS and create a
  duplicate extent.
- Post-process dedup scanner finds the duplicate and merges.

**Crash during refcount increment (HIT case):**
- Extent map entry points to canonical locator.
- DDT refcount may be stale (too low).
- Refcount delta queue (#1180) corrects this; DDT refcount is eventually
  consistent.

**Corrupted DDT:**
- Detection via B+tree checksums and DDT checksum verification.
- Recovery: drop the DDT, rebuild from a full extent map + locator table scan.
- Rebuild is a BACKGROUND-lane operation, budgeted per tick.

---

## 8. Performance Budget

### 8.1 Latency targets

| Operation | Target | Notes |
|---|---|---|
| DDT L1 hit | < 1 µs | In-memory hash table lookup, ARC ghost-list check |
| DDT L2 hit | < 100 µs | Single NVMe 4 KiB page read |
| DDT L3 hit | < 1 ms | B+tree traversal (depth 3-4), on-media reads |
| DDT insert (amortized) | < 10 µs | Batched in commit_group commit, not synchronous |
| Cross-node DDT lookup | < 500 µs | RTT + remote L1/L2/L3 + bloom filter |
| Hash computation (BLAKE3) | ~0.3 µs/KiB | Hardware-accelerated on x86-64 and ARM |
| Post-process batch (1000 extents) | < 100 ms | Budgeted per BACKGROUND tick |

### 8.2 Memory budget

| Component | Default size | Configurable |
|---|---|---|
| L1 hot set (ARC) | 256K entries (~24 MiB) | `l1_max_entries` |
| L2 SSD page cache | 10% of NVMe cache budget | Unified cache config |
| Bloom filter (per shard) | 512 KiB × N shards | Shard-level config |
| ARC ghost lists | ~10% of L1 | Fixed ratio |

### 8.3 Space overhead

| Component | Overhead |
|---|---|
| DDT entry on media | 96 bytes per unique extent hash |
| B+tree internal nodes | ~8 bytes per entry (amortized) |
| Per-extent overhead (dedup enabled) | 0 bytes (dedup reduces space) |
| DDT rebuild cost | O(unique extents) full scan |

### 8.4 Comparison with ZFS DDT

| Metric | ZFS DDT | tidefs DDT |
|---|---|---|
| Memory requirement | All entries in RAM | L1 bounded (hot set only) |
| 100 TiB pool, 8K records, 50% dedup | ~75 GB RAM | ~24 MiB L1 + SSD |
| NVMe spill | No (degraded performance) | Yes (L2, transparent) |
| Cluster sharding | N/A (local only) | 1024 shards across N nodes |
| Pruning | Manual (`zpool trim`) | Automatic, cursor-driven |
| Rebuild | Full pool scan | Background-lane incremental |

---

## 9. DDT Observability

### 9.1 Metrics

All metrics are exposed via the `explanation_query` product surface (#827) and
the ADMIN service (#1243):

| Metric | Description |
|---|---|
| `ddt.entries` | Total DDT entries across all shards |
| `ddt.l1_hits` | L1 (RAM) hit count |
| `ddt.l2_hits` | L2 (SSD) hit count |
| `ddt.l3_hits` | L3 (on-media) hit count |
| `ddt.misses` | DDT miss count (new content) |
| `ddt.dedup_ratio` | (saved_bytes + logical_bytes) / logical_bytes |
| `ddt.saved_bytes` | Total logical bytes saved by dedup |
| `ddt.pruned_entries` | Entries pruned since last reset |
| `ddt.l1_evictions` | L1 entries evicted |
| `ddt.shard_count` | Active shard count |
| `ddt.cross_node_lookups` | Cross-node DDT lookups (cluster) |
| `ddt.cross_node_timeouts` | Cross-node DDT timeouts (failsafe fallthrough) |

### 9.2 Feature flag

Dedup is a per-dataset feature controlled via `DatasetMetaV1.feature_flags`:
- `ddt_enabled`: DDT is active for this dataset.
- `ddt_mode`: `inline` or `post_process`.
- `ddt_hash`: `blake3` or `sha256`.
- `ddt_shard_bits`: Number of shard bits.
- `ddt_convergent_encryption`: Convergent encryption enabled.

These are set at dataset creation time via the ADMIN API and can be changed
on an unmounted dataset.

---

## 10. Integration Points

### 10.1 Existing infrastructure reused

| Component | Issue | How dedup uses it |
|---|---|---|
| Extent refcounting | #1180 | DDT refcount mirrors locator refcount; delta queues keep them synchronized |
| Weighted ARC | #1192 | DDT L1 uses ARC for hot-set management |
| Unified cache | #1226 | DDT L2 uses unified cache page-cache infrastructure |
| Record format | #1220 | `DdtEntryV1` follows V1 record family rules with TLV extension anchor |
| Universal cursor | #1239 | Post-process scanner and pruner use incremental cursors |
| BACKGROUND lane | #1241 | Scanner and pruner scheduled at BACKGROUND priority |
| Extent maps | #1285 | `ExtentMapEntryV2.flags.dedup_eligible` controls scanner eligibility |
| Locator table | #1285 | DDT `locator_id` points into `ExtentLocatorTable` |
| Encryption | #1246 | Convergent encryption integration |
| Cluster membership | #1209 | DDT shard ownership tracking |
| Cluster transport | #1210 | Cross-node DDT_LOOKUP/DDT_RESPONSE messages |
| BULK plane | #1229 | Shard migration bulk transfer |
| B+tree crate | `tidefs-btree` | DDT shard B+trees reuse the existing B+tree implementation |
| Binary schema | `tidefs-binary_schema-core` | `DdtEntryV1` uses `U64Le`, fixed-width arrays, checksum framing |
| Dataset lifecycle | `tidefs-dataset-lifecycle` | DDT root pointer in `DatasetMetaV1`; feature flag gating |
| FUSE adapter | #1173 | Write path integration in the FUSE daemon |

### 10.2 New crates

| Crate | Purpose |
|---|---|
| `tidefs-types-ddt-core` | `DdtEntryV1`, `DdtShard`, `DdtConfig`, `DedupMode`, `HashAlgo` authority types |
| `tidefs-ddt` | DDT runtime: L1/L2/L3 management, lookup, insert, prune |
| `tidefs-ddt-scanner` | Post-process dedup scanner (BACKGROUND service) |
| `tidefs-ddt-pruner` | DDT pruner (BACKGROUND service) |

---

## 11. On-Media Format

### 11.1 DDT B+tree in the locator table namespace

DDT shards are stored as B+trees within the pool's locator table. The
DDT root pointers live in `DatasetMetaV1`:

```rust
// Additions to DatasetMetaV1 (existing fields omitted for clarity)
pub struct DatasetMetaV1 {
    // ... existing fields ...
    pub ddt_root_locator: [u8; 16],    // Root locator for DDT metadata B+tree
    pub ddt_config_block_ref: [u8; 16],     // BlockRef to serialized DdtConfig
}
```

The DDT metadata B+tree maps `shard_id → DdtShardMetadata`:

```rust
pub struct DdtShardMetadata {
    pub shard_id: u32,
    pub prefix: [u8; 4],            // First 4 bytes of hash prefix
    pub prefix_bits: u8,
    pub root_locator: [u8; 16],     // Root of shard's DDT entry B+tree
    pub entry_count: u64,
    pub ownership_epoch: u64,
    pub owner_node_id: u64,         // 0 = local
    pub reserved: [u8; 15],
}
```

### 11.2 DDT feature flag in dataset

```
FeatureClass::Ddt with FeatureName::DdtEnabled → DatasetMetaV1.ro_compat_features bit N
```

Mounting a dataset with DDT enabled but without DDT support in the binary
is allowed (ro_compat, not incompat): the DDT is not correctness-critical.

---

## 12. Implementation Phases

### Phase 1: Core types and on-media format (3-4 days)
- Define `DdtEntryV1`, `DdtShard`, `DdtConfig`, `DedupMode`, `HashAlgo` in
  `tidefs-types-ddt-core`.
- Add DDT root pointers to `DatasetMetaV1`.
- Define DDT feature flag.
- Implement DDT B+tree create/read/write using `tidefs-btree`.
- Gate: `cargo check --workspace` + unit tests for B+tree insert/lookup/delete.

### Phase 2: Inline dedup write path (3-4 days)
- Implement `tidefs-ddt` runtime: L1 (ARC), L2 (unified cache), L3 (on-media).
- Integrate hash computation (BLAKE3) into the write path.
- Implement DDT lookup (L1→L2→L3 fallthrough).
- Implement HIT refcount increment and MISS insert in commit_group.
- Add checksum verification on lookup.
- Gate: synthetic write workload, verify dedup ratio.

### Phase 3: Post-process dedup scanner (2-3 days)
- Implement `tidefs-ddt-scanner` as a BACKGROUND service.
- Implement incremental cursor (#1239) for extent scanning.
- Implement hash→lookup→merge pipeline.
- Gate: fill dataset, run scanner, verify duplicate merging.

### Phase 4: DDT pruner (1-2 days)
- Implement `tidefs-ddt-pruner` as a BACKGROUND service.
- Implement cursor-driven stale-entry removal.
- Gate: delete files, verify pruner removes orphaned DDT entries.

### Phase 5: Cluster dedup (3-4 days)
- Define DDT_LOOKUP/DDT_RESPONSE wire protocol.
- Implement cross-node routing by shard prefix.
- Implement bloom filter fast-path.
- Implement shard migration on membership change.
- Gate: 2-node QEMU cluster, verify cross-node dedup.

### Phase 6: Encryption integration (1-2 days)
- Implement convergent encryption mode.
- Respect per-dataset `convergent_encryption` flag.
- Gate: encrypted dataset with dedup, verify dedup ratio > 1.0.

### Phase 7: Observability and operator surface (1-2 days)
- Expose DDT metrics via explanation_query.
- Add ADMIN commands for DDT status, rebuild trigger, prune trigger.
- Gate: manual verification of metric accuracy.

---


### 13.1 Unit tests
- `DdtEntryV1` encode/decode roundtrip (golden vectors per #1185).
- B+tree insert/lookup/delete for single shard.
- ARC ghost list behavior: one-hit-wonder does not enter L1.
- Hash prefix sharding: correct shard routing for boundary hashes.

### 13.2 Integration tests
- Write identical content to two files, verify single extent on disk.
- Delete one file, verify DDT refcount decrements to 1.
- Delete both files, verify DDT entry eventually pruned.
- Crash midway through write, verify DDT consistency after recovery.
- Post-process scanner: fill with duplicates, run scanner, verify merging.

### 13.3 Cluster tests
- 2-node QEMU cluster: cross-node dedup works.
- Node failure during cross-node DDT lookup: timeout fallthrough, no data loss.
- Shard migration: redistribute shards, verify DDT integrity.

- `ddt.l1_hit_latency_p99 < 1 µs` (microbenchmark).
- `ddt.l2_hit_latency_p99 < 100 µs` (NVMe benchmark).
- `ddt.dedup_ratio` tracking over sustained write workload.
- Memory: L1 stays within configured `l1_max_entries` under load.

---

## 14. Design Review Checklist

- [x] Authority integrity: DDT is rebuildable, not authoritative.
- [x] Trusted successor publication: DDT entries are immutable; pruning publishes
      successor states.
- [x] Named exactness contracts: DDT entries carry `birth_commit_group` and `last_seen_commit_group`
      for freshness reasoning.
- [x] Reserve safety: L1 bounded by ARC budget; L2 bounded by cache budget.
- [x] Writer locality: Inline dedup pays local hash cost; cluster dedup is an
      explicit cross-node operation.
- [x] Materialization utility: DDT is a high-utility materialized product that
      directly reduces storage consumption.
- [x] Continuity convenience: Post-process mode defers dedup cost for low-latency
      write workloads.
- [x] Observability: DDT metrics exposed via explanation_query and ADMIN service.
