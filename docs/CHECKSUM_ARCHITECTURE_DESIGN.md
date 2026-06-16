# End-to-End Checksum Architecture Design (G3 Pillar)

Maturity: **historical input** — imported G3 target design, not current TideFS
implementation status or publishing-facing capability authority.

Authority classification: TFR-019 / GitHub issue #332 leaves this document as
historical input. The current tree contains object-store integrity pieces,
binary-schema checksum profiles, read-only scrub reporting, segment-chain
helpers, and root-authentication helpers. `validation/claims.toml` does not
validate production end-to-end checksum, scrub self-heal, erasure-coded repair,
or tamper-proof committed-root claims. Use live source and the claim registry
for current status.

Historical note: this imported document recorded a Forgejo issue #1287 closeout.
It does not close any current GitHub storage-integrity item.

**See also**: `docs/BLAKE3_USAGE_POLICY.md` — binding policy on where BLAKE3-256
belongs in the codebase and where simpler mechanisms (CRC32C, generation
counters) must be used instead.

## 1. Motivation

ZFS provides end-to-end checksums as its defining data-integrity feature.
Every block pointer carries a 256-bit checksum; every read verifies it; a
mismatch triggers self-healing from a redundant copy. This is table-stakes
for any filesystem aspiring to exceed ZFS.

Ceph provides per-object checksums at the RADOS layer (crc32c default,
optional xxhash64), but they are optional per-pool, per-object granularity,
and silent corruption can persist when checksums are disabled.

The target design proposed **mandatory, non-optional** end-to-end checksums at
the framing layer. In that design, a checksum-verified read would not return
corrupt data, and a mismatch would trigger repair or explicit error reporting.
This is not a current production guarantee.

Three axes define the architecture:

1. **What is checksummed.** Every record header, every data shard, and every
   aggregating structure (manifest, root record, intent log entry).
2. **When verification happens.** Synchronously on every read path;
   asynchronously via background scrub.
3. **What happens on mismatch.** Suspect-mark the record, attempt
   repair from a healthy replica, and surface the event through the
   observability pipeline.

## 2. Relationship to Existing Code

| Current state | Refined by this design | Notes |
|---|---|---|
| `PRODUCTION_INTEGRITY_TRAILER_LEN=80` (superseded by `IntegrityTrailerV2` 112-byte) | Replaced by `IntegrityTrailerV2` with shard fields | See SS3.1 |
| Per-segment BLAKE3-256 in format strategy (#1220) | Refined: segment-level digest becomes `SegmentIntegrityFooter` | See SS3.4 |

## 3. Canonical Checksum Types

### 3.1 Header Checksum: CRC32C (Per-Record Sanity)

The target record header carries a CRC32C (Castagnoli) over the fixed prefix
fields. This is a **fast, local sanity check**, not an end-to-end guarantee.

```
RecordHeader {
    magic: [u8; 4],
    record_type: u16,
    record_len: u32,
    crc32c: u32,         // CRC32C over bytes 0..11 (magic + type + len)
    commit_group: u64,
    // ... type-specific fields
}
```

CRC32C is hardware-accelerated on x86-64 (`crc32` instruction; ~0.15
cycles/byte on Zen 4), making header verification essentially free.

**Covered by CRC32C**: record framing only (magic, type, length).
**Not covered by CRC32C**: record payload, semantic fields.

CRC32C mismatch is a framing error, not a data-corruption event. It means
the record header is structurally invalid.

### 3.2 Payload Digest: BLAKE3-256 (Per-Record End-to-End)

Target record payloads carry a BLAKE3-256 digest over the payload bytes,
domain-separated by record type. This is target design language, not proof that
every current mounted read path enforces the guarantee.

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
    reserved: [u8; 28],
}
// Total: 112 bytes (up from 80 in V1 trailer)
```

**Domain separation.** Each record type uses a unique domain-separation
context for BLAKE3 key derivation, preventing cross-type collision attacks:

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

The target erasure-coded data extent carries a BLAKE3-256 digest per shard. The
shard digest covers:

- `shard_index` (which shard this is)
- `shard_payload` (the encoded shard bytes)
- `ec_k`, `ec_m` (the erasure-coding parameters)

The design stores this in the `IntegrityTrailerV2.shard_*` fields and has the
`LocatorTable` entry reference all shard digests for reconstruction
verification.

### 3.4 Segment Integrity Footer

The target object-store segment file carries a footer with:

```
SegmentIntegrityFooter {
    magic: [u8; 8],               // "VLOSSEGF"
    segment_id: u64,
    record_count: u64,
    total_payload_bytes: u64,
    segment_digest: [u8; 32],     // BLAKE3-256 over all committed records
    previous_segment_digest: [u8; 32],  // chain trust to prior segment
    reserved: [u8; 48],
}
// Total: 192 bytes
```

The target segment chain forms a Merkle-like hash chain: each footer references
the previous segment's digest, creating a tamper-evident log. Current docs must
not publish this as a tamper-proof root guarantee without matching evidence.

## 4. Read-Time Verification

### 4.1 Metadata Reads

The target metadata record read (inode, directory entry, extent map entry,
commit record) follows this pipeline:

```
1. Read record header from segment
2. Verify CRC32C -> framing error? -> StoreError::FramingError, stop
3. Read payload bytes
4. Read integrity trailer
5. Compute BLAKE3-256(payload, domain=record_type)
6. Compare against trailer.payload_digest
   -> match: return verified record
   -> mismatch: enter mismatch path (S5)
```

**Performance budget.** BLAKE3-256 on a 512-byte metadata record costs
~120 ns on Zen 4 (~0.23 cycles/byte). With ~10 metadata reads per FUSE
operation, the checksum overhead is ~1.2 us per op -- negligible against
FUSE round-trip time (~5-10 us).

### 4.2 Data Reads

Target data reads follow the same pipeline but operate on the resolved shard:

```
1. Lookup extent in ExtentMap -> get LocatorId
2. Resolve LocatorId in LocatorTable -> get replica placement
3. Read shard bytes from device at placement offset
4. Verify shard-level BLAKE3-256 against LocatorTable entry
   -> match: return data to client
   -> mismatch: try next healthy replica; if none, enter repair path
```

**Performance budget.** BLAKE3-256 on a 128 KiB data shard costs ~29 us on
Zen 4 (~0.23 cycles/byte). Against a typical NVMe read latency of ~10-50 us,
this is a ~60% overhead for 4 KiB reads but only ~3% for 128 KiB reads. The
cost was considered acceptable in the design because integrity was mandatory.

### 4.3 Parallel Verification

For target multi-shard reads (striped EC), all shard verifications run in
parallel using a dedicated I/O thread pool. Verification completes before the
slowest I/O returns.

## 5. Mismatch Handling

### 5.1 Detection Classification

| Severity | Trigger | Action |
|---|---|---|
| `integrity:header_corrupt` | CRC32C mismatch in record header | Record is unreadable; log error |
| `integrity:payload_mismatch` | BLAKE3-256 mismatch on payload | Mark replica suspect, try next |
| `integrity:record_mismatch` | BLAKE3-256 mismatch on full record | Mark replica suspect, try next |
| `integrity:shard_mismatch` | BLAKE3-256 mismatch on data shard | Mark replica suspect, try next healthy |

### 5.2 Suspect Tracking

The target design records a suspect replica in:

```
SuspectEntry {
    locator_id: LocatorId,
    replica_index: u8,
    detection_time: u64,       // monotonic clock or commit_group
    mismatch_kind: MismatchKind,
    expected_digest: [u8; 32],
    actual_digest: [u8; 32],
}
```

Suspect entries are target design state persisted in a `SuspectLog` segment
(separate from data segments). On mount, the design replays the suspect log into
an in-memory `SuspectSet` used by the read path to skip known-bad replicas.

### 5.3 Repair Attempt

The target repair flow for exhausted healthy replicas is:

1. If EC with parity shards available: attempt reconstruction from k
   healthy shards
2. If no healthy replicas remain and no EC parity: return `EIO` to client
3. Emit `integrity:unrecoverable` event to observability pipeline

## 6. Target Integrity Invariants

These invariants are design targets. They are not current product claims unless
live source behavior and claim-registry evidence cover the specific path.

1. **No silent corruption.** A checksum-verified read that returns data
   SHALL have matching digests at every layer (header CRC32C, payload
   BLAKE3-256, shard BLAKE3-256).
2. **Metadata before data.** Metadata records are always verified before
   using them to locate data. A corrupt metadata record cannot cause a
   wild data read.
3. **Domain separation.** Each record type uses a unique BLAKE3 domain
   digest, and vice versa.
4. **Replica independence.** Each replica carries an independently
   verifiable digest. A corrupt replica cannot poison a healthy one.
5. **Suspect persistence.** Once a replica is marked suspect, it remains
   suspect until explicitly cleared by a successful repair operation. A
   suspect replica is never returned to a client.
6. **Chain of trust.** Segment footers chain to previous segments. Root
   authentication (keyed BLAKE3-256 over the system area) anchors the
   entire chain. Tampering with any segment is detectable.

## 7. Algorithm Selection

### 7.1 Why BLAKE3-256

| Property | BLAKE3-256 | SHA-256 | xxHash128 | CRC32C |
|---|---|---|---|---|
| Collision resistance | 128-bit | 128-bit | 64-bit | 16-bit |
| Speed (Zen 4, cycles/byte) | 0.23 | 3.5 | 0.08 | 0.15 |
| Hardware acceleration | AVX-512 | SHA-NI | None | SSE4.2 |
| Keyed mode | Yes | Yes (HMAC) | No | No |
| Streaming | Yes | Yes | Yes | Yes |
| Tree hashing | Yes | No | No | No |

BLAKE3 is the only algorithm that simultaneously provides:

- **Collision resistance** (128-bit security) sufficient for content-addressing
- **Speed** within 3x of xxHash (the fastest non-cryptographic hash)
- **Keyed mode** for authenticated data structures (root auth)
- **Streaming + tree hashing** for parallel verification of large extents
- **Single algorithm** for both integrity and content-addressing (no
  dual-hash complexity)

ZFS uses a pluggable checksum table (fletcher2, fletcher4, sha256, edonr,
blake3 via OpenZFS 2.3+). The target TideFS design simplifies by committing to a
single algorithm. If BLAKE3 is ever broken, algorithm migration needs current
dataset feature-flag authority before it can be claimed.

### 7.2 CRC32C for Headers

is not a data-integrity checksum. The rationale:

- CRC32C detects bit-flips in the framing fields that would cause the
  record to be misinterpreted (wrong type, wrong length).
- It is ~50x faster than BLAKE3-256 for tiny (12-byte) inputs.
- It provides a clear discrimination between "structurally invalid record"
  (CRC32C fail) and "corrupt data" (BLAKE3-256 fail).

## 8. Target Integration Points

### 8.1 With On-Media Format (#1220)

- Record header CRC32C is defined in the format strategy
- `IntegrityTrailerV2` replaces earlier trailer sketches in the target design
- Segment integrity footer is a target segment-level structure

### 8.2 With Extent Maps (#1300) and Locator Tables (#1305)

- `ExtentMapEntry` stores a `data_digest: [u8; 32]` (BLAKE3-256 of extent data)
  in the target design
- `LocatorTable` stores per-shard digests for replica verification in the target
  design
- Resolve-and-verify is a single target logical operation in the read path

### 8.3 With Scrub/Repair (#1288)

- Target scrub walks all records and verifies all digests
- Target repair uses healthy replicas to reconstruct corrupt ones
- `SuspectLog` is the target persistent input to the repair planner (#1294)

### 8.4 With Observability (#620)

- Target `integrity:payload_mismatch` events carry locator_id, expected/actual
  digests
- Target `integrity:unrecoverable` events trigger operator alerts
- Target `integrity:repair_success` events clear suspect entries

### 8.5 With Crash Injection (#1230)

- Target injectors can corrupt: CRC32C, payload_digest, record_digest,
  shard_digest
- Each target corruption point maps to a specific detection path
- Crash injection tests are required before publishing detection coverage

### 8.6 With Encryption (#787) and Compression (#905)

- The target checksum is computed **after** compression, **after** encryption
- The target pipeline is: data -> compress -> encrypt -> checksum -> write
- This target ordering ensures the checksum covers the exact bytes stored on
  media

## 9. ZFS Comparison

This comparison is historical target-design material. It must not be cited as a
current OpenZFS/Ceph-class integrity claim.

| Aspect | ZFS | Target TideFS design |
|---|---|---|
| Algorithm choice | Pluggable (fletcher2/4, sha256, edonr, blake3) | Single (BLAKE3-256) |
| Checksum location | In block pointer (128-256 bits) | In record trailer + segment footer |
| Verification timing | Synchronous on read | Target: synchronous on read + async scrub |
| Silent corruption | Impossible with checksum=on | Target, not current validated claim |
| Self-healing | From mirror/parity_raid parity | Target: from replica + EC parity |
| Header integrity | Implicit in block pointer | Explicit CRC32C on record header |
| Domain separation | Not applicable | Per-record-type BLAKE3 context |
| Chain of trust | RootRecord -> block tree | Target: segment chain -> system area -> root auth |
| Suspect tracking | Implicit (failed reads retry) | Target: explicit SuspectLog + SuspectSet |
| Performance cost | ~0.5-3% (sha256) / ~0.1-1% (edonr) | Target estimate: ~0.5-3% for data, negligible for metadata |

The target design aimed to improve on ZFS by:

- Making checksums **mandatory** (no checksum=off footgun)
- Adding **domain separation** preventing cross-type attacks
- Adding **explicit suspect tracking** with persistent SuspectLog
- Using a **single algorithm** with a formal migration path
- Providing **segment-level hash chaining** beyond ZFS root_record anchoring

## 10. Historical Implementation Phases

This imported phase list is not the current work queue and does not create
compatibility promises for unreleased TideFS data.

Phase 1: IntegrityTrailerV2 encoding/decoding. Extend the prior 80-byte
trailer to the 112-byte V2 format with shard fields.

Phase 2: Domain separation. Add per-record-type BLAKE3 domain contexts.
Wire into all record write paths (object-store `append_record`).

Phase 3: Read-time verification. Add `verify_payload()` to every read
path in local filesystem and object store.

Phase 4: SuspectLog. Implement persistent suspect tracking. Wire into
LocatorTable replica health transitions.

Phase 5: Segment chain of trust. Implement `SegmentIntegrityFooter` and
segment hash chaining. Wire into mount-time verification.

Phase 6: Crash injection coverage. Add checksum-corruption injectors to

Phase 7: EC shard verification. Add per-shard digest verification to the
EC read path. Integrate with repair planner.

Phase 8: Scrub integration. Wire the checksum architecture into the
background scrub pipeline (#1288).


```
tidefs-xtask check-checksum-architecture
```

Required markers:

- `CHECKSUM_ARCHITECTURE_SPEC`
- `IntegrityTrailerV2`
- `BLAKE3-256`
- `domain_separation`
- `SuspectLog`
- `SegmentIntegrityFooter`
