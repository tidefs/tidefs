# Dataset Send/Receive Protocol: Incremental Stream Format, Resume-After-Interrupt, Cross-Cluster Migration — Design Specification

**Issue**: [#1251](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1251)
**Status**: design-spec
**Priority**: P2
**Lane**: storage-core
**Milestone**: DESIGN-M4: Cluster Infrastructure (Layers 8–11)
**Depends on**: #1232 (snapshot deadlist pinning), #1219 (dataset lifecycle), #1241 (COMMIT_GROUP scheduling), #1239 (cursor framework), #1237 (resource governor), #1229 (BULK plane), #1221 (integrity/checksums), #1246 (encryption key wrapping), #1223 (dataset feature flags), #1240 (derived views)


## Abstract

This document defines the dataset send/receive protocol for tidefs: a self-describing,
incremental binary stream format for transferring dataset state between pools and clusters;
a resume-after-interrupt mechanism using checkpoint cursors; cross-cluster compatibility
negotiation via feature flags; incremental send optimization through the snapshot deadlist;

ZFS send/recv is the gold standard for dataset migration and backup. tidefs must match
and exceed it with cross-cluster operation, true resumability, block-level dedup
awareness, and integration with tidefs's cluster architecture.

---

## 1. Architecture and Design Overview

### 1.1 Relationship to Existing Code

The existing VFSSEND1 stream in crates/tidefs-local-filesystem/src/send_receive.rs
(OW-109) implements local changed-record export/import for manifest-backed committed
roots. It provides the core structural vocabulary and the encode/decode path in
crates/tidefs-local-filesystem/src/encoding.rs.

This design extends VFSSEND1 to VFSSEND2, adding:

| Capability | VFSSEND1 (v0.417) | VFSSEND2 (this design) |
|---|---|---|
| Stream format version | stream_version=1 (full), 2 (incremental) | stream_version=3 (canonical self-describing) |
| Incremental | O(manifest) diff on (object_key, checksum) | O(log n) deadlist-driven extent identification (#1232) |
| Checkpoint/resume | Not supported | Cursor-based checkpoint every N records (#1239) |
| Cross-cluster | Not supported | Feature-flag negotiation, property reconciliation, key wrapping |
| Encryption | Not supported | Wrapped dataset key (#1246) |
| Record types | 7 (manifest, superblock, inode, directory, content, chunk, snap-catalog) | 11 (+ OBJECT_BEGIN, OBJECT_END, FREE_RANGE, SNAPSHOT_BOUNDARY, STREAM_END, STREAM_TRAILER) |
| Transport | In-memory Vec<u8> | BULK plane (#1229) with BACKGROUND lane (#1241) |

### 1.2 High-Level Protocol Flow

Sender emits records in order; Receiver acknowledges checkpoints:

    Sender                                  Receiver
      |                                       |
      |--- STREAM_HEADER (identity, range,    |
      |    feature flags, wrapped key) ------>|
      |                                       |
      |--- SNAPSHOT_BOUNDARY (snap meta) ---->|
      |--- OBJECT_BEGIN (object identity) --->|
      |--- OBJECT_DATA (extent payload) ----->|
      |--- OBJECT_DATA (extent payload) ----->|
      |--- OBJECT_END ----------------------->|
      |--- [... more objects ...]             |
      |--- CHECKPOINT (cursor position) ----->|
      |<--- ACK_CHECKPOINT -------------------|
      |--- [... if interrupted, resume ...]   |
      |--- FREE_RANGE (for incremental) ----->|
      |--- STREAM_END ----------------------->|
      |--- STREAM_TRAILER (stream checksum) ->|
      |<--- RECEIVE_COMPLETE -----------------|

### 1.3 Architecture Layers

    +--------------------------------------------------+
    |  tidefsctl send / tidefsctl receive                   |  CLI layer
    +--------------------------------------------------+
    |  SendJob / ReceiveJob                             |  Admin plane
    |  (IncrementalJob trait, BACKGROUND lane)           |  (#1179, #1241)
    +--------------------------------------------------+
    |  SendStream / ReceiveStream                       |  Protocol engine
    |  (stream framing, record emit/parse, checkpoints) |
    +--------------------------------------------------+
    |  SendCursor / ReceiveCursor                       |  Resume layer
    |  (checkpoint persistence, ack tracking)           |  (#1239)
    +--------------------------------------------------+
    |  ExtentEnumerator (deadlist-driven for incr)      |  Content selection
    |  (#1232 snapshot deadlist)                        |
    +--------------------------------------------------+
    |  BULK plane (#1229)                               |  Transport
    |  TCP_STREAM mode, BACKGROUND lane                 |
    +--------------------------------------------------+

---
## 2. Stream Format: VFSSEND2

### 2.1 Stream Header

Every VFSSEND2 stream opens with a fixed-size header followed by variable-length fields.

    StreamHeaderV2 {
        magic:           [u8; 8],   // "VFSSEND2"
        stream_version:  u16,       // 3
        flags:           u16,       // bitmask (see 2.1.1)

        // Dataset identity
        dataset_uuid:    [u8; 16],  // globally unique dataset identifier
        dataset_name_len: u16,
        dataset_name:    [u8; dataset_name_len],

        // Snapshot range
        from_snapshot_guid: [u8; 16],  // zero-filled for full send
        to_snapshot_guid:   [u8; 16],
        from_snapshot_name_len: u16,
        from_snapshot_name: [u8; from_snapshot_name_len],
        to_snapshot_name_len: u16,
        to_snapshot_name: [u8; to_snapshot_name_len],

        // Feature compatibility (from #1223)
        features_compat:     u64,
        features_ro_compat:  u64,
        features_incompat:   u64,

        // Encryption key material (#1246)
        key_wrapping_suite:  u8,    // 0=none, 1=AES-256-KWP, 2=HPKE-BASE
        wrapped_key_len:     u16,
        wrapped_key:         [u8; wrapped_key_len],

        // Stream configuration
        checkpoint_interval_records: u32,
        compression_algorithm:       u8,   // 0=none, 1=lz4, 2=zstd
        max_record_payload:          u32,  // max bytes per OBJECT_DATA record

        // Sender identity
        sender_cluster_id:  [u8; 16],
        sender_node_id:     u64,

        // Reserved for future expansion
        header_extension_len: u16,
        header_extension:     [u8; header_extension_len],

        // CRC32C over all preceding header bytes
        header_crc32c:     u32,
    }
    // Minimum fixed size: ~141 bytes + variable fields

#### 2.1.1 Stream Flags

| Bit | Name | Description |
|-----|------|-------------|
| 0 | INCREMENTAL | Stream is an incremental delta between two snapshots |
| 1 | CROSS_CLUSTER | Sender and receiver are in different clusters |
| 2 | ENCRYPTED_KEY | Stream carries a wrapped dataset encryption key |
| 3 | EMBEDDED_PROPERTIES | Stream carries dataset property records |
| 4 | RESUMABLE | Stream supports checkpoint/resume |
| 5-7 | compression | 3-bit compression algorithm |
| 8-15 | reserved | Must be zero |

### 2.2 Record Type Enumeration

Each record is framed by a 12-byte record header:

    RecordHeader {
        record_type:  u16,
        record_flags: u16,   // bitmask
        record_len:   u32,   // payload length (excludes header)
        record_crc32c: u32,  // CRC32C over header bytes 0..7
    }

Record types:

| Type ID | Name | Direction | Description |
|---------|------|-----------|-------------|
| 0x0000 | INVALID | -- | Reserved; never appears in valid stream |
| 0x0001 | OBJECT_BEGIN | S->R | Begin a new object; carries identity and metadata |
| 0x0002 | OBJECT_DATA | S->R | Extent payload chunk for the current object |
| 0x0003 | OBJECT_END | S->R | End current object; carries cumulative checksum |
| 0x0004 | FREE_RANGE | S->R | Extent range deleted between snapshots (incremental) |
| 0x0005 | PROPERTY_SET | S->R | Dataset property record |
| 0x0006 | SNAPSHOT_BOUNDARY | S->R | Mark boundary between snapshots |
| 0x0007 | CHECKPOINT | S->R | Sender checkpoint for resume |
| 0x0008 | ACK_CHECKPOINT | R->S | Receiver acknowledges checkpoint |
| 0x0009 | STREAM_END | S->R | End of stream |
| 0x000A | STREAM_TRAILER | S->R | Stream-level checksum and verification |
| 0x000B | RECEIVE_COMPLETE | R->S | Receiver confirms successful import |
| 0x000C-0x000F | reserved | -- | For future record types |
| 0x0010-0xFFFF | reserved | -- | For feature-flagged extensions |

#### 2.2.1 Record Flags

| Bit | Name | Description |
|-----|------|-------------|
| 0 | COMPRESSED | Payload is compressed |
| 1 | LAST_CHUNK | For OBJECT_DATA: last chunk of current object |
| 2 | CHECKPOINT_CANDIDATE | Sender hints this record is a good checkpoint point |
| 3-15 | reserved | Must be zero |

### 2.3 Detailed Record Payloads

#### 2.3.1 OBJECT_BEGIN (0x0001)

    ObjectBeginV2 {
        object_type:       u8,
        object_id:         [u8; 32],
        total_object_len:  u64,
        birth_commit_group:         u64,
        object_checksum:   [u8; 32],   // BLAKE3-256 of full object payload
        parent_object_id:  [u8; 32],
        object_flags:      u32,
        object_meta_len:   u16,
        object_meta:       [u8; object_meta_len],
    }

Object types: inode(0), directory(1), extent(2), xattr(3), snapshot_catalog(4).

Object meta for extents carries: logical offset, logical length,
physical length, compression algo, birth_commit_group, death_commit_group (from ExtentLocatorValueV1).

#### 2.3.2 OBJECT_DATA (0x0002)

    ObjectDataV2 {
        object_id:        [u8; 32],
        chunk_offset:     u64,
        chunk_seq:        u32,
        payload_len:      u32,
        payload_checksum: [u8; 32],   // BLAKE3-256
        payload:          [u8; payload_len],
    }

Chunking rules: max payload_len is max_record_payload (default 1 MiB).
Chunks must be in chunk_offset order. LAST_CHUNK flag marks end of object.
payload_checksum covers uncompressed payload.

#### 2.3.3 OBJECT_END (0x0003)

    ObjectEndV2 {
        object_id:           [u8; 32],
        total_payload_len:   u64,
        chunk_count:         u32,
        reassembled_checksum: [u8; 32],  // BLAKE3-256 of reassembled payload
        object_crc32c:       u32,
    }

#### 2.3.4 FREE_RANGE (0x0004)

For incremental sends: communicates extents deleted between from-snapshot and
to-snapshot.

    FreeRangeV2 {
        object_id:       [u8; 32],
        logical_offset:  u64,
        logical_length:  u64,
        birth_commit_group:       u64,
        death_commit_group:       u64,
        flags:           u32,  // 0x01=PUNCH_HOLE, 0x02=TRUNCATE
    }

#### 2.3.5 PROPERTY_SET (0x0005)

    PropertySetV2 {
        property_count: u16,
        // Repeated:
        //   name_len:  u16, name: [u8; name_len]
        //   value_len: u16, value: [u8; value_len]
        //   source:    u8   // 0=local, 1=inherited, 2=received, 3=temporary
    }

Property reconciliation rules for cross-cluster: see section 4.3.

#### 2.3.6 SNAPSHOT_BOUNDARY (0x0006)

    SnapshotBoundaryV2 {
        snapshot_guid:       [u8; 16],
        snapshot_name_len:   u16,
        snapshot_name:       [u8; snapshot_name_len],
        snap_commit_group:            u64,
        snapshot_flags:      u32,
        cluster_snapshot_id: [u8; 16],  // zero if local-only (#1258)
        participating_nodes: u32,
    }

Objects between two SNAPSHOT_BOUNDARY records belong to the most recently
declared snapshot.

#### 2.3.7 CHECKPOINT (0x0007) and ACK_CHECKPOINT (0x0008)

    CheckpointV2 {
        cursor_position:       [u8; 48],
        records_emitted:       u64,
        payload_bytes_emitted: u64,
        stream_offset:         u64,
        checkpoint_crc32c:     u32,
    }

    AckCheckpointV2 {
        cursor_position:        [u8; 48],
        records_received:       u64,
        payload_bytes_received: u64,
        ack_result:             u8,  // 0=OK, 1=STALE_CURSOR, 2=CORRUPT_CURSOR
    }

#### 2.3.8 STREAM_END (0x0009)

    StreamEndV2 {
        total_records:       u64,
        total_payload_bytes: u64,
        total_objects:       u64,
        snapshot_count:      u32,
        final_flags:         u32,
    }

#### 2.3.9 STREAM_TRAILER (0x000A)

    StreamTrailerV2 {
        stream_blake3:     [u8; 32],
        stream_crc32c:     u32,
        record_count:      u64,
        stream_len:        u64,
        sender_signature:  [u8; 64],  // Ed25519
    }

Stream integrity verified by: (1) CRC32C per record header, (2) BLAKE3-256
per record payload, (3) CRC32C + BLAKE3-256 of entire stream in trailer,
(4) Ed25519 signature authenticating sender.

#### 2.3.10 RECEIVE_COMPLETE (0x000B)

    ReceiveCompleteV2 {
        stream_id:          [u8; 16],
        objects_imported:   u64,
        bytes_imported:     u64,
        snapshots_created:  u32,
        result:             u8,  // 0=SUCCESS, 1=PARTIAL, 2=ABORTED
        error_code:         u32,
        error_message_len:  u16,
        error_message:      [u8; error_message_len],
    }

---

## 3. Resume-After-Interrupt

### 3.1 Design Principles

ZFS send/recv has no built-in resume. If a pipeline is interrupted, the entire
transfer must restart. For multi-terabyte datasets over WAN links this is
catastrophic. tidefs implements resume through the IncrementalJob trait (#1239),
making the send operation a cursor-driven, crash-resumable background job.

### 3.2 SendCursor

The sender maintains a SendCursor encoding the precise position in the
dataset traversal:

    SendCursor {
        current_object_id:      [u8; 32],
        current_snapshot_index: u32,
        records_emitted:        u64,
        payload_offset:         u64,
        traversal_state:        u64,  // internal ExtentEnumerator position
    }

The cursor is checkpointed to stable storage via
IncrementalJob::persist_checkpoint().

### 3.3 Checkpoint Protocol

Sender emits up to checkpoint_interval_records records, then a CHECKPOINT.
Receiver persists the cursor to staging and replies ACK_CHECKPOINT.
On interrupt, sender reconnects with RESUMABLE flag + resume_cursor in header
if OK, sender resumes from cursor.

### 3.4 Reconnection Handshake

On reconnection, sender sends STREAM_HEADER with RESUMABLE flag set and

1. dataset_uuid matches partially received dataset.
2. resume_cursor matches last persisted checkpoint.
3. stream_version and feature flags identical to original stream.
4. No staging data corruption (CRC32C of cursor state).


### 3.5 Receiver-Side Checkpointing

Receiver persists checkpoint state to staging directory:

    <dataset>/.__tidefs_receive_staging/
        stream_header
        checkpoint
        objects/
            <object_id>.partial
        snapshot_catalog.partial
        property_state.partial

Staging is atomically renamed into place only after STREAM_TRAILER
verification and full stream integrity check.

### 3.6 Bounded Resume Overhead

Resume does not rescan the entire dataset. Sender ExtentEnumerator is
positioned at cursor traversal_state. Maximum re-sent data is the partial
object at the interruption boundary (at most max_record_payload bytes,
default 1 MiB).

---

## 4. Cross-Cluster Operation

### 4.1 Cluster Identity and Trust

Cross-cluster send/receive preconditions:

1. Mutual TLS: clusters exchange CA certificates or use shared PKI.
2. Admin-plane connectivity: sender connects to receiver admin service (#1243).
3. Dataset naming: identified by dataset_uuid. Receiver may receive into
   differently named dataset.

### 4.2 Feature Flag Compatibility (#1223)


    receiver_supported = receiver_cluster.feature_mask
    stream_incompat    = stream_header.features_incompat

    if (stream_incompat & ~receiver_supported) != 0:
        reject("unsupported incompat features")

    // ro_compat: receiver can mount read-only without these
    // compat: receiver can safely ignore unknown compat features

Receiver records stream feature flags into received dataset.

### 4.3 Property Reconciliation

Three categories during cross-cluster receive:

| Category | Properties | Behavior |
|----------|-----------|----------|
| Stream-carried | recordsize, compression, checksum, dedup, acltype, xattr | Set from stream |
| Receiver-local | mountpoint, readonly, canmount, zoned | Preserve from receive command |
| Reconciled | quota, reservation, refquota, refreservation | Cap by receiver pool capacity |

Reconciliation runs during STREAM_HEADER parsing, before object data written.

### 4.4 Encryption Key Wrapping (#1246)

For cross-cluster transfer of encrypted datasets:

1. Sender unwraps dataset master key using local KEK.
2. Sender re-wraps master key for receiver using AES-256-KWP (pre-shared
   symmetric) or HPKE-BASE (receiver public key).
3. Wrapped key placed in STREAM_HEADER.wrapped_key.
4. Receiver unwraps and re-wraps for local storage.

Key wrapping suite negotiated out-of-band per cross-cluster relationship.

### 4.5 Transport

Uses BULK plane (#1229) TCP_STREAM mode. Entire send/receive stream is one
BULK transfer (OFFER->ACCEPT->CREDIT->DONE). BULK OFFER metadata carries

---

## 5. Incremental Send Optimization

### 5.1 Deadlist-Driven Extent Selection (#1232)

Incremental send uses snapshot deadlist to identify only extents that changed
between from_snapshot and to_snapshot.

Algorithm:

    fn incremental_extents(from_snap, to_snap) -> (Vec<Extent>, Vec<FreeRange>):
        deadlist = to_snap.deadlist
        new_extents = []
        free_ranges = []

        // Extents born after from_snap and alive at to_snap:
        for extent in dataset.extent_iterator():
            if extent.birth_commit_group > from_snap.snap_commit_group
               and (extent.death_commit_group == 0 or extent.death_commit_group > to_snap.snap_commit_group):
                new_extents.push(extent)

        // Extents alive at from_snap but dead by to_snap:
        for entry in deadlist.iterate():
            if entry.birth_commit_group <= from_snap.snap_commit_group
               and entry.death_commit_group > from_snap.snap_commit_group
               and entry.death_commit_group <= to_snap.snap_commit_group:
                free_ranges.push(FreeRange {
                    extent_id: entry.locator_id,
                    death_commit_group: entry.death_commit_group,
                })

        return (new_extents, free_ranges)

ExtentEnumerator wraps this as an IncrementalJob, processing extents in
bounded WorkBudget ticks.

### 5.2 FREE_RANGE Semantics

FREE_RANGE records instruct receiver to apply deletions:

1. Locate object (inode) by object_id.
2. Apply removal: punch hole or truncate.
3. Release freed space through receiver allocator.

FREE_RANGE records are idempotent: applying for already-freed extent is no-op.

### 5.3 Dedup Awareness

Each OBJECT_DATA carries its own object_id and chunk_offset. On receive,
receiver writes each object independently. If receiver has dedup enabled,
its inline dedup path (#1181) naturally coalesces identical payloads.

No special send-side dedup awareness needed.

---

## 6. Integration with Derived Views (#1240)



1. On STREAM_END, receiver increments dataset dir_rev to new epoch.
2. All ValidityTokens tied to previous dir_rev become stale.
3. Views lazily rebuilt on next access (per #1240 budgeted refresh).

View rebuild is deferred until demand IO requests data.




All follower nodes with SHARED leases drop stale derived views and rebuild
on next access.

---

## 7. Back-Pressure and Scheduling

### 7.1 BACKGROUND Lane Execution

Send/receive runs in Background lane (#1241):

- Priority: 4 (lowest), below CONTROL, METADATA, DEMAND, SPECULATIVE.
- Starvation prevention: starvation_timeout_ms guarantees at least one tick.
- Preemptible: CONTROL can preempt BACKGROUND mid-tick.
- Droppable + resumable: paused under extreme memory pressure; resumed via
  checkpoint.

### 7.2 Resource Governor Integration (#1237)

Send job consumes from cluster_queues budget category:

| Resource | Limit | Enforcement |
|----------|-------|-------------|
| BULK tokens | max_inflight_bulk_tokens | Sender backs off on NO_CREDITS |
| Memory | cluster_queues category | BULK credit flow control |
| IOPS | BACKGROUND lane budget | WorkBudget per tick |
| CPU | Cooperative yielding | WorkBudget.max_ms |

### 7.3 Throttling via Receiver ACK Rate

Sender paces emission based on receiver acknowledgement:

1. Emit up to checkpoint_interval_records records.
2. Emit CHECKPOINT, wait for ACK_CHECKPOINT.
3. Timely ACK: continue at current rate.
4. Slow ACK: reduce emission rate via inter-tick delay.
5. Rate adaptation uses AIMD:
   - Timely ACK: rate *= 1.1
   - Late ACK: rate *= 0.5

Ensures send does not starve client IO during active send.

### 7.4 Budget Enforcement

Every SendJob::step() receives a WorkBudget:

    WorkBudget {
        max_items: 1024,
        max_bytes: 64 MiB,
        max_ms: 100,
    }

Send job must not exceed any active limit. When step() returns incomplete,
background scheduler calls step() again next round after persisting checkpoint.

---

## 8. Use Cases

### 8.1 Backup: Periodic Snapshot to Backup Pool

    # Full send (first time):
    tidefsctl snapshot create poolA/dataset@daily-2026-05-03
    tidefsctl send poolA/dataset@daily-2026-05-03 | \
      ssh backup-host tidefsctl receive poolB/backups/dataset

    # Incremental backup (next day):
    tidefsctl snapshot create poolA/dataset@daily-2026-05-04
    tidefsctl send -i poolA/dataset@daily-2026-05-03 poolA/dataset@daily-2026-05-04 | \
      ssh backup-host tidefsctl receive poolB/backups/dataset

### 8.2 Migration: Full Dataset to New Cluster

    # Source cluster:
    tidefsctl send --cross-cluster poolA/dataset@migrate \
      --receiver admin.target-cluster:8420

    # Target cluster:
    tidefsctl receive --new-name poolX/imported-dataset

### 8.3 Replication: Continuous Incremental for DR

    # Initial seed:
    tidefsctl send poolA/dataset@seed | ssh dr-site tidefsctl receive poolDR/dataset

    # Periodic delta loop:
    while true; do
      tidefsctl snapshot create poolA/dataset@replica-$(date +%s)
      tidefsctl send -i poolA/dataset@last-sent poolA/dataset@latest | \
        ssh dr-site tidefsctl receive poolDR/dataset
      tidefsctl snapshot destroy poolA/dataset@last-sent
      sleep 300
    done

### 8.4 Clone Promotion (ZFS promote equivalent)

    tidefsctl send -i origin@base origin@current | \
      tidefsctl receive -o origin=promoted clone-dataset

Merges incremental changes from origin into clone, severing dependency.

---

## 9. Error Handling and Edge Cases

### 9.1 Stream Corruption Detection

| Layer | Detection | Action on mismatch |
|-------|-----------|--------------------|
| Record header | CRC32C over magic+type+len | Discard record; abort stream |
| Record payload | BLAKE3-256 domain-separated | Mark suspect; abort stream |
| Object reassembly | BLAKE3-256 in OBJECT_END | Discard object; abort stream |
| Full stream | BLAKE3-256 + CRC32C in STREAM_TRAILER | Abort receive; clean staging |
| Sender authenticity | Ed25519 signature in STREAM_TRAILER | Reject stream entirely |

### 9.2 Receiver Disk Full

If receiver runs out of space mid-stream: step() detects ENOSPC from allocator,
job transitions to BLOCKED state, ReceiveCompleteV2(result=PARTIAL) sent,
staging preserved, resume after space freed.

### 9.3 Snapshot Already Exists

If receiver already has snapshot with same GUID:
- Full send: reject (snapshot collision).
  if not, reject.

### 9.4 Interrupted Incremental Delta

Receiver staging contains partially applied delta. On resume, sender re-sends
from last ACK_CHECKPOINT. Receiver re-applies partial object (idempotent for

---


### 10.1 Development Gate

    cargo test -p tidefs-local-filesystem -- send_receive
    cargo run -p tidefs-xtask -- check-send-receive

### 10.2 Production Gate (pre-merge)


### 10.3 Cluster Gate (for cross-cluster)

    cargo test -p tidefs-cluster-simnet -- send_receive_cross_cluster

---

## 11. Open Questions and Future Extensions

### 11.1 Deferred

- Differential compression: send delta between two versions of same extent.
- Send bookmark: named send progress marker for admin-plane exposure.
- Parallel send: multiple BULK streams for multi-link aggregation.

### 11.2 Out of Scope for V1

- Per-file send: send individual files rather than whole datasets.
- Send from snapshot clone to origin (recursive send). Incremental algorithm
  supports this but clone promotion needs additional design.
- Thin send: dedup against common base present on receiver.

---

## 12. Relationship to Existing Designs

| Design | Integration point | This design provides |
|--------|-------------------|---------------------|
| OW-109 (VFSSEND1) | Local send/receive baseline | VFSSEND2 extends record vocabulary |
| #1232 (snapshot deadlist) | Incremental extent selection | ExtentEnumerator consumes deadlist B+tree |
| #1219 (dataset lifecycle) | Dataset identity in stream header | dataset_uuid from lifecycle state |
| #1239 (cursor framework) | Resume/checkpoint | SendJob implements IncrementalJob |
| #1241 (lane scheduling) | Background execution | Send runs in BACKGROUND lane |
| #1237 (resource governor) | Memory budget | Consumes cluster_queues budget |
| #1229 (BULK plane) | Transport | TCP_STREAM mode, single BULK transfer |
| #1221 + #1287 (integrity) | Checksums | BLAKE3-256 per-record, per-object, per-stream |
| #1246 (encryption) | Key wrapping | STREAM_HEADER carries wrapped dataset key |
| #1223 (feature flags) | Cross-cluster compatibility | Feature flag negotiation on receive |
| #1258 (cluster snapshots) | Cluster-level send unit | SNAPSHOT_BOUNDARY carries cluster_snapshot_id |

---

*End of design specification.*
