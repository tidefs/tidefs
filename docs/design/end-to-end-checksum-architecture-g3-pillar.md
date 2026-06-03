**Issue**: [#1785](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1785)
**Status**: design-spec
**Lane**: storage-core (Layer 6: Data Services)
**Maturity**: design-spec — Rust implementation deferred to wire-up issues
**Originating issue**: #1559
**Depends on**: #1223 (dataset feature flags), #1220 (on-media record format)
**Interacts with**: #1285 (extent maps + locator tables), #1288 (scrub/repair), #787 (encryption), #905 (compression), #620 (observability), #1230 (crash injection), #110 (online verifier)

# End-to-End Checksum Architecture (G3 Pillar)

Maturity: **design-spec** for mandatory end-to-end checksum framing, read-time
verification, corruption detection, and integrity-invariant enforcement across
TideFS metadata and data paths.

This document is the **canonical design specification** for the G3 checksum
architecture pillar.

## Abstract

TideFS implements mandatory end-to-end checksums as a non-negotiable data
integrity guarantee. Every record payload carries a BLAKE3-256 cryptographic
digest domain-separated by record type; every read path verifies the digest
before returning data; every mismatch triggers repair or explicit error
reporting. A persistent SuspectLog tracks detected corruption, a
SegmentIntegrityFooter forms a hash chain from root to segment, and a
four-tier ChecksumProfile system stratifies integrity strength across framing,
transport, metadata, and data. This document defines all data structures,
algorithms, pipeline ordering, integration contracts, and the tradeoffs
underlying the canonical G3 checksum architecture.


## 1. Motivation and Scope

ZFS provides end-to-end checksums as its defining data-integrity feature:
every block pointer carries a 256-bit checksum, every read verifies it, and
a mismatch triggers self-healing from a redundant copy. This is table-stakes
for any filesystem aspiring to exceed ZFS.

Ceph provides per-object checksums at the RADOS layer (crc32c default,
optional xxhash64), but they are optional per-pool and silent corruption can
persist when checksums are disabled.

TideFS mandates **non-optional** end-to-end checksums at the framing layer.
A checksum-verified read must never return corrupt data. Mismatch must
trigger repair or explicit error reporting. Three axes define the
architecture:

1. **What is checksummed.** Every record header, every data shard, and every
   aggregating structure (manifest, root record, intent log entry).
2. **When verification happens.** Synchronously on every read path;
   asynchronously via background scrub.
3. **What happens on mismatch.** Suspect-mark the record, attempt repair
   from a healthy replica, surface the event through the observability
   pipeline.

## 2. Relationship to Existing Code

### 2.1 Module Map

```
crates/tidefs-binary_schema-core/        → ChecksumProfile, DomainTag, SchemaFamilyId,
                                            SchemaTypeId, SchemaVersion, BinarySchemaError
crates/tidefs-binary_schema-checksum/    → crc32c(), blake3_domain_digest(),
                                            seal_checksums(), verify_seal(),
                                            envelope_header_crc32c()
crates/tidefs-binary_schema-framing/     → EnvelopeHeader (CRC32C on header bytes 0..60)
crates/tidefs-transport/                 → FrameEnvelope (BLAKE3 payload + CRC32C frame)
crates/tidefs-local-object-store/        → ProductionIntegrityDigest, IntegrityDigest64,
                                            production_integrity_payload_digest(),
                                            production_integrity_record_digest(),
                                            IntegrityTrailer (80-byte V3, magic "VLOSINT3")
crates/tidefs-local-filesystem/          → root_authentication_digest(), RootCommit encoding
crates/tidefs-extent-map/                → ExtentMapEntry data_digest field
crates/tidefs-online-verifier/           → verify_online(), verify_online_with_root_auth()
```

### 2.2 Current State and Refinements

| Current state | Refined by this design | Notes |
|---|---|---|
| `PRODUCTION_INTEGRITY_TRAILER_LEN=80` | Extended to `IntegrityTrailerV2` (112 bytes) with EC shard fields | See §3.2; magic changes from "VLOSINT3" to "VLOSINT4" |
| `tidefs-binary_schema-checksum` crate | Extended with record-type domain contexts | Provides `crc32c`, `blake3_domain_digest`, `seal_checksums`, `verify_seal` |
| Per-segment BLAKE3-256 in format strategy (#1220) | Refined: segment-level digest becomes `SegmentIntegrityFooter` | See §3.4 |

## 3. Canonical Checksum Types

### 3.1 Header Checksum: CRC32C (Per-Record Framing Sanity)

Every record header carries a CRC32C (Castagnoli) over the fixed prefix
fields (magic, record kind, format version, payload length). This is a
**fast, local sanity check**, not an end-to-end data integrity guarantee.

```
RecordHeader {
    magic:       [u8; 8],    // "VLOSREC1"
    kind:        u16,         // RecordKind discriminant
    format_ver:  u16,         // 1=no-footer, 2=V2, 3=V3
    sequence:    u64,
    payload_len: u64,
    key:         [u8; 32],    // ObjectKey
    // ... padding to 96 bytes total
}
// CRC32C over bytes 0..11 (magic[0..8] + kind + format_ver + payload_len u32 prefix)
// Stored as u32 LE within the header's payload_checksum field
```

CRC32C is hardware-accelerated on x86-64 (`crc32` instruction; ~0.15
cycles/byte on Zen 4), making header verification essentially free.

**Covered by CRC32C**: record framing (magic, type, length, format version).
**Not covered by CRC32C**: record payload bytes, semantic fields.

CRC32C mismatch is a **framing error**, distinct from data corruption. It
indicates the record header is structurally invalid — the record cannot
be interpreted because its framing fields are corrupt (e.g., a bit-flip in
the record type field causes the wrong decoder to be selected).

### 3.2 Payload Digest: BLAKE3-256 (Per-Record End-to-End)

Every record payload carries a BLAKE3-256 digest over the payload bytes,
domain-separated by record type. This is the **canonical end-to-end
integrity guarantee**.

```
IntegrityTrailerV2 {
    magic: [u8; 8],               // "VLOSINT4"
    digest_suite: u16,            // 1 = BLAKE3-256
    payload_digest: [u8; 32],     // BLAKE3-256 over payload bytes
    record_digest: [u8; 32],      // BLAKE3-256 over header + payload
    shard_count: u8,              // for EC shards
    shard_index: u8,              // 0-based index within shard group
    ec_k: u8,                     // data shards in group
    ec_m: u8,                     // parity shards in group
    reserved: [u8; 28],           // future extensions
}
// Total: 112 bytes (up from 80 in V3 trailer)
```

**Domain separation.** Each record type uses a unique domain-separation
context for BLAKE3 key derivation, preventing cross-type collision attacks.
The context string follows the format
`"vbfs:fam={}:type={}:ver={}.{}:role={}"` as implemented in
`tidefs-binary_schema-checksum/src/lib.rs:build_domain_context()`.

| Record type | Domain context |
|---|---|
| InodeRecord | `"tidefs.inode.v1"` |
| ExtentMapEntry | `"tidefs.extent_map.v1"` |
| DirEntry | `"tidefs.dir_entry.v1"` |
| CommitRecord | `"tidefs.commit.v1"` |
| XattrEntry | `"tidefs.xattr.v1"` |
| Data shard | `"tidefs.data_shard.v1"` |
| IntentLogEntry | `"tidefs.intent_log.v1"` |

### 3.3 Shard-Level Digest (For EC)

When a data extent is erasure-coded into k+m shards, each shard carries its
own BLAKE3-256 digest. The shard digest covers:

- `shard_index` (which shard this is)
- `shard_payload` (the encoded shard bytes)
- `ec_k`, `ec_m` (the erasure-coding parameters)

This is stored in the `IntegrityTrailerV2.shard_*` fields. The
`LocatorTable` entry references all shard digests for reconstruction
verification.

### 3.4 Segment Integrity Footer

Each object-store segment file carries a footer with:

```
SegmentIntegrityFooter {
    magic: [u8; 8],               // "VLOSSEGF"
    segment_id: u64,
    segment_digest: [u8; 32],     // BLAKE3-256 over segment payload
    chain_digest: [u8; 32],       // BLAKE3-256(prev_chain_digest || segment_digest)
    record_count: u64,
    segment_len: u64,
    footer_offset: u64,
    commit_group_start: u64,
    commit_group_end: u64,
    reserved: [u8; 40],
}
// Total: 192 bytes
```

The `chain_digest` links each segment to its predecessor, forming a hash
chain from the current segment back to the system area root. This is
analogous to ZFS's root_record-to-block-tree chain of trust, but at segment
granularity.

### 3.5 Root Authentication

The mount-time root-slot verification uses keyed BLAKE3-256:

```
RootAuth {
    root_slot_id: u64,
    root_auth_digest: [u8; 32],   // BLAKE3-256(key, root_record)
    key_id: u32,
    auth_scheme: u16,              // 1 = keyed BLAKE3-256
}
```

This is the top of the trust chain. The root authentication key is
derived from the dataset's integrity key material, providing a binding
between the physical segment chain and the logical root record.

## 4. Checksum Pipeline Ordering

The canonical pipeline for data at rest is:

```
data → compress → encrypt → checksum → write
```

Checksum is computed **after** both compression and encryption, ensuring
the checksum covers the exact bytes stored on media. This prevents attacks
that swap compressed representations or exploit gaps between encryption
and integrity verification.

On read, the pipeline reverses:

```
read → checksum-verify → decrypt → decompress → data
```

Verification happens on ciphertext before decryption, catching on-media
corruption at the earliest possible point.

## 5. Detection and Response

### 5.1 Read-Time Detection

Every read path verifies:
1. **CRC32C** on the record header (framing sanity)
2. **BLAKE3-256** on the record payload (end-to-end integrity)
3. **BLAKE3-256** on the full record (header + payload, for chaining)

A mismatch at any level prevents data from being returned to the caller.
In the FUSE adapter, this surfaces as `EIO` to the application.

### 5.2 SuspectLog

Each segment maintains a persistent ring buffer of suspect records:

```
SuspectLog {
    magic: [u8; 8],               // "VLSUSPCT"
    capacity: u32,
    head: u32,
    entries: [SuspectEntry; capacity],
}

SuspectEntry {
    record_offset: u64,
    detection_time: u64,           // monotonic timestamp
    detection_source: u8,          // 1=read, 2=scrub, 3=deep_scrub
    mismatch_type: u8,             // 1=crc32c, 2=payload_digest, 3=record_digest
    expected_digest: [u8; 32],
    actual_digest: [u8; 32],
}
```

The SuspectLog is:
- **Append-only**: new suspect entries are appended at `head`.
- **Bounded**: when full, the oldest entry is overwritten.
- **Per-segment**: each segment file has its own SuspectLog.

### 5.3 SuspectSet

The in-memory `SuspectSet` aggregates suspect entries across all segments:

```
SuspectSet {
    entries: BTreeMap<LocatorId, SuspectStatus>,
}

SuspectStatus {
    entry: SuspectEntry,
    replica_health: ReplicaHealth,  // Healthy / Degraded / Lost
    repair_attempts: u32,
    last_repair_attempt: u64,
}
```

The SuspectSet drives:
- **Replica health transitions** in the LocatorTable
- **Repair prioritization** in the repair planner
- **Observability events** for operator visibility

### 5.4 Repair Flow

On mismatch detection:
1. Mark record as suspect in SuspectLog
2. Query LocatorTable for healthy replicas
3. If healthy replica exists: read from replica, verify its digest,
   overwrite corrupt copy
4. If no healthy replica: for EC data, attempt reconstruction from k
   healthy shards
5. If unrecoverable: emit `integrity:unrecoverable` event, surface EIO
6. On repair success: emit `integrity:repair_success`, clear suspect entry

## 6. Transport Integrity

The transport layer provides independent per-message integrity:

```
FrameEnvelope {
    header: EnvelopeHeader,        // CRC32C-protected
    payload: Vec<u8>,              // BLAKE3-256-protected
}
```

The `EnvelopeHeader` uses CRC32C over its 60-byte prefix (magic, version,
frame type, payload length, stream id, sequence number), stored as LE
bytes at `[60..64]`. The payload is verified with BLAKE3-256 domain-separated
by the frame type.

This is a separate integrity layer from the storage checksums. A transport
CRC32C mismatch indicates a network corruption event; a storage BLAKE3-256
mismatch indicates an on-media corruption event. The two layers are
independent and complementary.

## 7. Algorithm Rationale

### 7.1 BLAKE3-256 as the Single Algorithm

BLAKE3 was selected because it provides:

- **Cryptographic strength** (256-bit security against collision)
- **Hardware acceleration** via SIMD (AVX2, AVX-512, NEON)
- **Keyed mode** for authenticated data structures (root auth)
- **Streaming + tree hashing** for parallel verification of large extents
- **Single algorithm** for both integrity and content-addressing (no
  dual-hash complexity)

ZFS uses a pluggable checksum table (fletcher2, fletcher4, sha256, edonr,
blake3 via OpenZFS 2.3+). TideFS simplifies by committing to a single
algorithm. If BLAKE3 is ever broken, the dataset feature-flag system (#1223)
allows migration to a successor.

### 7.2 CRC32C for Headers

is not a data-integrity checksum. The rationale:

- CRC32C detects bit-flips in the framing fields that would cause the
  record to be misinterpreted (wrong type, wrong length).
- It is ~50x faster than BLAKE3-256 for tiny (12-byte) inputs.
- It provides a clear discrimination between "structurally invalid record"
  (CRC32C fail) and "corrupt data" (BLAKE3-256 fail).

## 8. ChecksumProfile System

The `tidefs-binary_schema-core` crate defines four `ChecksumProfile` levels
used across the binary schema system:

| Profile | Description | Use |
|---|---|---|
| `None` | No checksum or digest | Development-only; not for production data |
| `Crc32c` | CRC32C only | Transport headers, framing sanity |
| `Blake3_256` | BLAKE3-256 only | Record payloads, metadata |
| `Crc32cPlusBlake3_256` | CRC32C + BLAKE3-256 | Full production integrity |

The `tidefs-binary_schema-checksum` crate provides `seal_checksums()` and
`verify_seal()` that operate generically over all four profiles, with
domain-separated BLAKE3 key derivation via the `build_domain_context()`
function.

## 9. Integration Points

### 9.1 With On-Media Format (#1220)

- Record header CRC32C is defined in the format strategy
- IntegrityTrailerV2 replaces the current 80-byte trailer
- Segment integrity footer is a new segment-level structure

### 9.2 With Extent Maps (#1300) and Locator Tables (#1305)

- ExtentMapEntry stores a `data_digest: [u8; 32]` (BLAKE3-256 of extent data)
- LocatorTable stores per-shard digests for replica verification
- Resolve-and-verify is a single logical operation in the read path

### 9.3 With Scrub/Repair (#1288)

- Scrub walks all records and verifies all digests
- Repair uses healthy replicas to reconstruct corrupt ones
- SuspectLog is the persistent input to the repair planner (#1294)

### 9.4 With Observability (#620)

- `integrity:payload_mismatch` events carry locator_id, expected/actual
  digests
- `integrity:unrecoverable` events trigger operator alerts
- `integrity:repair_success` events clear suspect entries

### 9.5 With Crash Injection (#1230)

- Injectors can corrupt: CRC32C, payload_digest, record_digest, shard_digest
- Each corruption point maps to a specific detection path
- Crash injection tests verify that every corruption is detected

### 9.6 With Encryption (#787) and Compression (#905)

- Checksum is computed **after** compression, **after** encryption
- The pipeline is: data → compress → encrypt → checksum → write
- This ensures the checksum covers the exact bytes stored on media

### 9.7 With Online Verifier (#110)

`tidefs-online-verifier` performs non-mutating verification at mount time:
namespace invariants, and snapshot references. The verifier uses the
segment hash chain as its trust anchor.

## 10. ZFS / Ceph Comparative Analysis

| Aspect | ZFS | Ceph (RADOS) | TideFS |
|---|---|---|---|
| Algorithm | Pluggable table | crc32c (default) / xxhash64 (optional) | BLAKE3-256 only, with migration path |
| Mandatory? | Optional (`checksum=on\|off`) | Optional (per-pool) | **Mandatory, non-optional** |
| Location | In block pointer (128-256 bits) | Per-object attribute | Record trailer + segment footer |
| Verification | Synchronous on read | Configurable | Synchronous on read + async scrub |
| Silent corruption | Impossible with checksum=on | Possible when disabled | Impossible (always on) |
| Self-healing | From mirror/parity_raid | From replica OSDs | From replica + EC parity |
| Header integrity | Implicit in block pointer | N/A | Explicit CRC32C |
| Domain separation | N/A | N/A | Per-record-type BLAKE3 context |
| Chain of trust | RootRecord → block tree | N/A | Segment chain → system area → root auth |
| Suspect tracking | Implicit (failed reads retry) | N/A | Explicit SuspectLog + SuspectSet |
| Performance cost | 0.5–3% (sha256) | <1% (crc32c) | 0.5–3% (BLAKE3-256) |

TideFS improves over both ZFS and Ceph by:

- **Mandatory checksums** — no silent-corruption footgun
- **Domain separation** — cross-type collision attacks prevented
- **Explicit suspect tracking** — persistent SuspectLog enables repair
  planning and operator visibility
- **Segment-level hash chaining** — trust anchor beyond ZFS root_record
- **Single algorithm** with formal migration path — no dual-hash complexity

## 11. Performance Budget

| Operation | Latency budget | Notes |
|---|---|---|
| CRC32C header verify | < 5 ns | Single `crc32` instruction |
| BLAKE3-256 4 KB payload | < 1 µs | SIMD-accelerated |
| BLAKE3-256 1 MB extent | < 250 µs | Tree-hash parallelizable |
| Segment chain verify (10K segments) | < 100 ms | Mount-time only |
| SuspectLog entry append | < 10 µs | Ring buffer write |

Overall throughput overhead of checksumming is estimated at 0.5–3% for
data paths and negligible for metadata paths (under 0.1%), consistent
with ZFS with edonr/sha256 checksums.

## 12. Tradeoffs and Design Decisions

### 12.1 Single Algorithm vs Pluggable Table

**Decision:** BLAKE3-256 as the single canonical algorithm.

**Rationale:** ZFS supports a pluggable checksum table (fletcher2/4,
sha256, edonr, blake3), giving operators flexibility but introducing
complexity in checksum negotiation, migration, and verification
consistency. TideFS simplifies by committing to a single algorithm.

**Migration path:** If BLAKE3 is ever broken, the dataset feature-flag
system (#1223) allows per-dataset algorithm migration. The
`IntegrityTrailerV2.digest_suite` field encodes the algorithm, so old
and new digests coexist during migration.

### 12.2 CRC32C for Headers vs BLAKE3 for Everything

**Decision:** Use CRC32C for record-header framing sanity, BLAKE3-256
for payload integrity.

**Rationale:** CRC32C is ~50x faster than BLAKE3-256 for tiny (12-byte)
inputs and provides clear discrimination between "structurally invalid
record" (CRC32C fail) and "corrupt data" (BLAKE3-256 fail). CRC32C is
not a substitute for cryptographic integrity.

### 12.3 Domain Separation vs Flat Hashing

**Decision:** Every record type uses a unique BLAKE3 domain-separation
context via `derive_key`.

**Rationale:** Without domain separation, two records of different types
could collide on the same BLAKE3-256 digest, making cross-type semantic
confusion possible. Domain separation binds the digest to both the
content and the record type, preventing this attack.

### 12.4 SuspectLog as Ring Buffer vs Full Index

**Decision:** SuspectLog is a persistent ring buffer per segment, not a
full database index.

**Rationale:** A full index of every suspect record across every segment
would be disk-expensive. A per-segment ring buffer holds recent suspect
entries; older entries are reconstructed during scrub. The ring buffer
design bounds SuspectLog storage to O(segments × ring_capacity).

### 12.5 Segment Hash Chain vs Per-Segment Isolation

**Decision:** Each segment footer includes a hash chain linking to the
previous segment's footer digest.

**Rationale:** Without a chain, a segment could be replaced wholesale
and go undetected if its internal records are self-consistent. The hash
chain extends the trust anchor from the system area through every
segment to every record, similar to ZFS's root_record→block-tree chain.

### 12.6 Checksum Before vs After Encryption

**Decision:** Checksum is computed after encryption (ciphertext checksum).

**Rationale:** If checksum covered plaintext, an attacker could corrupt
ciphertext bytes and the corruption would only be detected after
decryption, wasting decryption work and potentially leaking information
through error oracles. Ciphertext checksum catches corruption before
decryption. This is consistent with ZFS's encrypted dataset behavior.

## 13. Implementation Phases

| Phase | Description | Status |
|---|---|---|
| 1 | `IntegrityTrailerV2` encoding/decoding. Extend 80-byte V3 trailer to 112-byte V2 with EC shard fields. Backward compatibility with V1/V3. | planned |
| 2 | Domain separation. Wire per-record-type BLAKE3 domain contexts into all record write paths. | partial — checksum crate ready |
| 3 | Read-time verification. Add `verify_payload()` to every read path in local filesystem and object store. | planned |
| 4 | `SuspectLog`. Implement persistent suspect tracking ring buffer. Wire into LocatorTable replica health transitions. | planned |
| 5 | Segment chain of trust. Implement `SegmentIntegrityFooter` and segment hash chaining. Wire into mount-time verification. | planned |
| 7 | EC shard verification. Add per-shard digest verification to EC read path. Integrate with repair planner. | planned |
| 8 | Scrub integration. Wire architecture into background scrub pipeline (#1288). | planned |

Phase details:

**Phase 1:** IntegrityTrailerV2 encoding/decoding. Extend the current 80-byte
trailer to the 112-byte V2 format with shard fields. Maintain backward
compatibility: V1 trailers still verify.

**Phase 2:** Domain separation. Add per-record-type BLAKE3 domain contexts.
Wire into all record write paths (object-store `append_record`). The
`tidefs-binary_schema-checksum` crate already provides `blake3_domain_digest()`
with family/type/version/tag domain context construction.

**Phase 3:** Read-time verification. Add `verify_payload()` to every read
path in local filesystem and object store.

**Phase 4:** SuspectLog. Implement persistent suspect tracking. Wire into
LocatorTable replica health transitions.

**Phase 5:** Segment chain of trust. Implement `SegmentIntegrityFooter` and
segment hash chaining. Wire into mount-time verification.

**Phase 6:** Crash injection coverage. Add checksum-corruption injectors to

**Phase 7:** EC shard verification. Add per-shard digest verification to
the EC read path. Integrate with repair planner.

**Phase 8:** Scrub integration. Wire the checksum architecture into the
background scrub pipeline (#1288).

## 14. Residual Risks

1. **BLAKE3 cryptanalysis**: If BLAKE3 is broken, the dataset feature-flag
   system (#1223) provides migration. Risk window: detection-to-migration
   latency.
2. **Concurrent SuspectLog access**: Multiple scrub threads writing to the
   same segment's SuspectLog require careful synchronization. Mitigated by
   per-segment locking.
3. **Segment chain length**: Very long chains (100K+ segments) increase
   mount-time chain verification. Mitigated by checkpointing intermediate
   chain digests in the system area.
4. **EC shard collision**: Two different shards with the same BLAKE3-256
   digest is astronomically unlikely (2⁻²⁵⁶) but not impossible. The
   defense-in-depth response is to also compare shard index and EC
   parameters as part of verification.


```
cargo xtask check-checksum-architecture
```

Required structural markers across the codebase:

- `CHECKSUM_ARCHITECTURE_SPEC`
- `IntegrityTrailerV2` (magic "VLOSINT4")
- `BLAKE3-256` (in constants and digest output)
- `domain_separation` (derive_key contexts)
- `SuspectLog` (persistent ring buffer)
- `SegmentIntegrityFooter` (segment hash chaining)
- `PRODUCTION_INTEGRITY_POLICY_SPEC` (OW-006 policy anchor)

## Appendix A: Checksum Pipeline Ordering

The canonical pipeline is: **data → compress → encrypt → checksum → write**.
This ensures the checksum covers exact on-media bytes, preventing attacks
that swap compressed representations or exploit encryption gaps.

## Appendix B: Domain Context Construction

The domain context string used for BLAKE3 `derive_key` follows the format
implemented in `tidefs-binary_schema-checksum/src/lib.rs`:

```
"vbfs:fam={family}:type={type_id}:ver={major}.{minor}:role={tag}"
```

For storage-level digests in the local object store, the constants in
`tidefs-local-object-store/src/constants.rs` define:

- `PRODUCTION_INTEGRITY_PAYLOAD_DOMAIN`:
  `"tidefs.local-object-store.production-integrity.payload.v1"`
- `PRODUCTION_INTEGRITY_RECORD_DOMAIN`:
  `"tidefs.local-object-store.production-integrity.record.v1"`

These domain strings are passed to BLAKE3's `derive_key` mode, ensuring
that a payload digest cannot be confused with a record digest even if
the underlying bytes are identical.
