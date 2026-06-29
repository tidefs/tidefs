# Cluster BULK Plane Protocol — Design Specification

**Issue**: [#1666](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1666)
**Status**: design-spec
**Priority**: P2
**Lane**: transport
**Depends on**: #1210 (transport boundedness), #1211 (daemon memory budget), #1227 (security model), #1666 (unified scheduling classes)
**Related**: #1213 (VFS Engine/VFS_RPC), #1216 (ublk), #1228 (security model), #1241 (COMMIT_GROUP sync scheduling)

## Abstract

This document defines the Cluster BULK Plane: a shared byte-transfer layer that
provides bounded, credit-scheduled bulk data movement between cluster nodes. The
protocol runs as service_id `0x07` on the tidefs cluster transport (#1210). The
first live implementation target is TCP_STREAM under a unified
OFFER/ACCEPT/CREDIT/DONE/ABORT state machine. RDMA direct-memory modes remain
disabled design entries until the transport, security, memory-accounting,
credit-lifecycle, abort-cleanup, and runtime-validation gates in §9.3 are all
satisfied. Higher-level services (VFS_RPC, COMMIT_GROUP, BLOCK_EXPORT) never
invent their own byte-mover; they speak only in terms of `BulkOffer` and
`BulkToken`.

---

## 1. Problem Statement

#1210 defines per-connection bulk token limits (`max_inflight_bulk_tokens`) for
boundedness, but does not specify the BULK protocol itself. Large data transfers
(writes, reads, commit_group replication) need a well-defined protocol that maps cleanly
to RDMA without redesign. Without this, higher-level services would each invent
their own byte-mover, leading to:

- Inconsistent credit accounting across the daemon memory budget (#1211)
- Duplicated or conflicting RDMA memory registration paths
- No single point for fairness scheduling or backpressure
- Ad-hoc error recovery per service

The BULK plane solves this by providing one wire protocol, one credit pool, one
scheduler, and one failure model for all byte transfers larger than the inline
frame threshold.

---

## 2. Scope and Non-Scope

### In scope

- OFFER/ACCEPT/CREDIT/DONE/ABORT state machine and wire encoding
- `BulkToken` opaque handle and `PinnedPool` for RDMA buffer management
- Credit scheduling: fairness across streams, priority ordering, backpressure
- TCP_STREAM mode with optional chunking and pipelining
- RDMA_WRITE and RDMA_READ modes with rkey+addr credit lifecycle
- Failure handling: connection drop, partial writes, abort propagation
- Integration contract with `InlineOrBulkV1` from VFS_RPC (#1213)

### Explicitly out of scope

- COMMIT_GROUP replication protocol (COMMIT_GROUP delegates its own ordering/consensus; BULK only moves bytes)
- BLOCK_EXPORT device registration (ublk uses BULK as a transport; device lifecycle is separate)
- Per-stream encryption or authentication (delegated to transport TLS layer)
- Zero-copy filesystem splice (the BULK plane moves bytes from sender memory to receiver memory)

---

## 3. Service Definition

### 3.1 Wire identity

```text
service_id   = 0x07
service_name = "bulk"
```

Each BULK frame is a standard cluster message (#1210) with `service_id = 0x07`.
The method is encoded in the low 6 bits of the message-type byte. The high 2
bits distinguish request (0b00) from response (0b01).

### 3.2 Method ID table

| Method | ID   | Direction          | Purpose |
|--------|------|--------------------|---------|
| OFFER  | 0x00 | Sender → Receiver  | Propose a transfer: `stream_id`, `total_len`, `mode`, `priority` |
| ACCEPT | 0x01 | Receiver → Sender  | Accept or reject an OFFER; on accept, returns `BulkToken` + `max_chunk` |
| CREDIT | 0x02 | Sender → Receiver  | Request credit for a chunk on `stream_id`; receiver grants `offset` (and `rkey`+`addr` for RDMA) |
| DONE   | 0x03 | Sender → Receiver  | Signal all bytes transferred; receiver finalizes |
| ABORT  | 0x04 | Either direction   | Cancel transfer; all credits released immediately |

Reserved: 0x05–0x3F (59 slots for future BULK control messages).

---

## 4. Wire Message Format

All BULK messages use the standard `FrameHeaderV1` (#1210) with `service_id = 0x07`.
The payload for each method follows.

### 4.1 OFFER (0x00)

```text
OfferV1:
  stream_id: u32        -- fresh per transfer, sender-assigned
  total_len: u64         -- total bytes to transfer
  mode: u8               -- 0=TCP_STREAM, 1=RDMA_WRITE, 2=RDMA_READ, 3-255=reserved
  priority: u8           -- 0=CONTROL, 1=METADATA, 2=BULK, 3=BACKGROUND
  metadata_len: u16      -- length of optional metadata blob
  metadata: [u8; metadata_len] -- opaque metadata for higher-level service (e.g., commit_group epoch, inode)
```

**stream_id uniqueness**: Sender-assigned, must be unique across all active
transfers on this connection. The sender is responsible for not reusing a
`stream_id` until the previous transfer with that id has reached DONE or ABORT.

**mode negotiation**: TCP_STREAM is the baseline mode. The receiver may reject
an unsupported mode via ACCEPT with `result=MODE_UNSUPPORTED`. A sender may
request RDMA_WRITE or RDMA_READ only when the connection has explicit
RDMA-capable policy and evidence. If RDMA is unavailable, a new TCP_STREAM
transfer is valid only when the higher-level service allows an explicit
downgrade and records that downgrade as TCP evidence. Silent RDMA → TCP
demotion is not RDMA success.

**priority semantics**: Priority affects credit scheduling order (see §7). It
does not guarantee preemption of in-progress credits.

### 4.2 ACCEPT (0x01)

```text
AcceptV1:
  stream_id: u32         -- echoed from OFFER
  result: u8             -- 0=ACCEPTED, 1=NO_CREDITS, 2=MODE_UNSUPPORTED, 3=REJECTED
  // if result=ACCEPTED:
  bulk_token: BulkToken  -- opaque 32-byte handle scoped to this connection
  max_chunk: u32         -- maximum bytes per CREDIT grant
  // if result=NO_CREDITS:
  retry_after_us: u32    -- hint for sender retry delay (0 = no hint)
```

**Result codes**:

| Code | Name             | Meaning |
|------|------------------|---------|
| 0    | ACCEPTED         | Transfer accepted; `bulk_token` and `max_chunk` are valid |
| 1    | NO_CREDITS       | PinnedPool exhausted or `max_inflight_bulk_tokens` reached |
| 2    | MODE_UNSUPPORTED | Requested `mode` not available on this connection |
| 3    | REJECTED         | Generic rejection (security policy, administrative block) |

### 4.3 CREDIT (0x02)

```text
CreditRequestV1:
  stream_id: u32         -- transfer identifier
  bulk_token: BulkToken  -- from ACCEPT
  chunk_seq: u32         -- monotonically increasing per transfer, starting at 0
  len: u32               -- bytes requested for this chunk

CreditGrantV1:
  stream_id: u32
  chunk_seq: u32         -- echoed from request
  result: u8             -- 0=GRANTED, 1=WAIT, 2=REJECTED
  // if result=GRANTED:
  offset: u64            -- byte offset in receiver buffer
  // if mode=RDMA_WRITE:
  rkey: u32              -- RDMA remote key
  addr: u64              -- RDMA virtual address (receiver-pinned)
  // if mode=TCP_STREAM:
  // (no extra fields; sender transmits framed bytes on stream_id)
```

**Chunk sequencing**: `chunk_seq` starts at 0 and increments by 1 for each
duplicate or out-of-order chunk_seq values with `result=REJECTED`.

**WAIT semantics**: `result=WAIT` means the credit scheduler has the request
queued but cannot grant immediately (pinned pool pressure or fairness delay).
The sender SHOULD retry the CREDIT request after a backoff interval. To avoid
thundering-herd, the receiver does not push credit-granted notifications;
credit is always sender-pulled.

### 4.4 DONE (0x03)

```text
DoneV1:
  stream_id: u32
  bulk_token: BulkToken
  total_transferred: u64   -- actual bytes transferred (must match total_len from OFFER)
  checksum: u32            -- CRC32C of the entire transfer payload
```

Mismatch causes the receiver to discard the transfer and log a protocol error.
The optional `checksum` provides end-to-end data integrity at the BULK layer,
independent of TCP checksums or RDMA transport integrity.

### 4.5 ABORT (0x04)

```text
AbortV1:
  stream_id: u32
  bulk_token: BulkToken
  reason: u8   -- 0=SENDER_CANCEL, 1=RECEIVER_CANCEL, 2=TIMEOUT, 3=PROTOCOL_ERROR, 4=CONNECTION_LOST
```

ABORT may be sent by either side. On receipt, all credits for the transfer are
released immediately. The receiver unpins any RDMA memory. No response is sent
for ABORT; it is fire-and-forget.

**Implicit ABORT on connection drop**: When a transport session closes, all
active BULK transfers on that session are implicitly aborted. The local BULK
state machine transitions all active streams to the Aborted state without
waiting for wire messages (see §10).

---

## 5. Protocol Flow

### 5.1 Happy path (TCP_STREAM, single chunk)

```text
  Sender                              Receiver
    |                                     |
    |--- OFFER(stream_id, len, TCP) ----->|
    |                                     |  allocate BulkToken, reserve credit slot
    |<-- ACCEPT(token, max_chunk) --------|
    |                                     |
    |--- CREDIT(stream_id, token,         |
    |    chunk_seq=0, len) -------------->|
    |                                     |  allocate receive buffer at offset
    |<-- CREDIT_GRANT(offset) ------------|
    |                                     |
    |=== TCP stream data on stream_id ===>|
    |                                     |
    |--- DONE(stream_id, token,           |
    |    total_transferred, csum) ------->|
    |                                     |  (no explicit ACK for DONE)
```

### 5.2 Happy path (RDMA_WRITE, single chunk)

```text
  Sender                              Receiver
    |                                     |
    |--- OFFER(stream_id, len,             |
    |    RDMA_WRITE) ------------------->|
    |<-- ACCEPT(token, max_chunk) --------|
    |                                     |
    |--- CREDIT(stream_id, token,         |
    |    chunk_seq=0, len) -------------->|
    |                                     |  pin memory, obtain rkey+addr
    |<-- CREDIT_GRANT(offset,              |
    |    rkey, addr) ---------------------|
    |                                     |
    |=== RDMA_WRITE direct to addr ======>|  (no receiver CPU involvement)
    |                                     |
    |--- DONE(stream_id, token,           |
    |    total_transferred, csum) ------->|
```

### 5.3 Multi-chunk transfer

For transfers larger than `max_chunk`, the sender pipelines multiple
CREDIT→CREDIT_GRANT→data cycles:

```text
  Sender                              Receiver
    |--- OFFER(len=1MB) ---------------->|
    |<-- ACCEPT(token, max_chunk=256K) --|
    |                                     |
    |--- CREDIT(seq=0, len=256K) ------->|
    |<-- GRANT(offset=0) ----------------|
    |=== data chunk 0 (256K) ===========>|
    |                                     |
    |--- CREDIT(seq=1, len=256K) ------->|
    |<-- GRANT(offset=256K) -------------|
    |=== data chunk 1 (256K) ===========>|
    |                                     |
    |--- CREDIT(seq=2, len=256K) ------->|
    |<-- GRANT(offset=512K) -------------|
    |=== data chunk 2 (256K) ===========>|
    |                                     |
    |--- CREDIT(seq=3, len=256K) ------->|
    |<-- GRANT(offset=768K) -------------|
    |=== data chunk 3 (256K) ===========>|
    |                                     |
    |--- DONE(total=1MB, csum) --------->|
```

The sender may issue multiple CREDIT requests before previous chunk data
transfers complete (pipelining). The receiver MUST process CREDIT requests in
`chunk_seq` order.

---

## 6. BulkToken and PinnedPool

### 6.1 BulkToken

```text
BulkToken: [u8; 32]  -- opaque handle scoped to a single connection
```

The `BulkToken` is an opaque 32-byte handle. Internally, the receiver encodes:

```rust
struct BulkTokenInner {
    connection_id: u64,    // transport session identifier
    transfer_id: u64,      // locally-unique transfer counter
    nonce: u64,            // random nonce to prevent guess/forgery
    receiver_node_id: u64, // node that owns this token
}
```

The sender treats the token as opaque and echoes it back in CREDIT, DONE, and
forgery by a misbehaving sender is detected via nonce + connection binding.

### 6.2 PinnedPool

The `PinnedPool` is a fixed-size pool of pre-registered RDMA memory regions,
drawing from the `cluster_queues` budget category (#1211). It lives on the
receiver side and is per-connection (or per-NIC, depending on RDMA device
topology).

```rust
struct PinnedPool {
    /// Total pinned bytes allocated from daemon memory budget
    max_pinned_bytes: u64,
    /// Currently pinned bytes (sum of all active credit grants)
    pinned_bytes: AtomicU64,
    /// Free region descriptors available for new credits
    free_regions: Mutex<VecDeque<PinnedRegion>>,
    /// Active grants: (stream_id, offset, len) -> region
    active_grants: Mutex<HashMap<(u32, u64), PinnedRegion>>,
}

struct PinnedRegion {
    /// Start of the pre-registered memory region
    base_addr: u64,
    /// Total size of this region
    region_len: u64,
    /// RDMA remote key for this region
    rkey: u32,
}
```

### 6.3 Credit lifecycle

The credit lifecycle flows through the PinnedPool:

```text
  ACCEPT:
    reserve_slot() -> Ok  // does NOT consume buffer bytes yet
    return BulkToken

  CREDIT (request):
    pin_bytes(stream_id, len) -> Result<(offset, rkey, addr), Error>
      - Check pinned_bytes + len <= max_pinned_bytes
      - If RDMA: carve sub-region from free_regions, return rkey+addr
      - If TCP: allocate receive buffer at offset in stream buffer pool
      - Update pinned_bytes atomically

  DONE:
    unpin_all(stream_id)
      - Return regions to free_regions
      - Subtract from pinned_bytes
      - Release credit slot

  ABORT:
    unpin_all(stream_id)  // same path as DONE
```

**Slot reservation vs. byte pinning**: The ACCEPT phase reserves a slot
(counts against `max_inflight_bulk_tokens`) but does not consume pinned bytes.
Bytes are pinned only when CREDIT is granted. This allows the pool to
overcommit slots while guaranteeing that granted credits never exceed
`max_pinned_bytes`.

---

## 7. Credit Scheduling

### 7.1 Scheduling objectives

The credit scheduler must satisfy three constraints simultaneously:

1. **Fairness**: No single stream starves others of credit
2. **Backpressure**: When the pinned pool is exhausted, new OFFERs are rejected
   with `NO_CREDITS` rather than queueing indefinitely
3. **Priority**: CONTROL > METADATA > BULK > BACKGROUND, enforced at OFFER
   acceptance and CREDIT grant time

### 7.2 Boundedness constants

| Constant | Source | Default | Purpose |
|----------|--------|---------|---------|
| `max_inflight_bulk_tokens` | #1210 | 64 | Hard cap on active BulkTokens per connection |
| `max_pinned_bytes` | #1211 | 16 MiB | Total pinned RDMA/TCP buffer memory per connection |
| `max_chunk` | per-OFFER (receiver-advertised) | 256 KiB | Maximum bytes per single CREDIT grant |
| `max_pending_credits_per_stream` | this issue | 4 | Maximum outstanding (unfulfilled) CREDIT requests per stream |

### 7.3 Fairness algorithm

The receiver maintains a per-stream credit window. For each stream:

```rust
struct StreamCreditState {
    stream_id: u32,
    priority: BulkPriority,
    total_len: u64,
    bytes_granted: u64,
    pending_credits: u32,  // outstanding CREDIT requests not yet granted
    last_grant: Instant,
}
```

**Credit grant decision**: When a CREDIT request arrives:

1. If `pending_credits >= max_pending_credits_per_stream`: return `WAIT`
2. If `pinned_bytes + request.len > max_pinned_bytes`: return `WAIT`
3. If a higher-priority stream also has pending credits and this stream has
   received >= its fair-share of recent grants: defer (return `WAIT`)
4. Otherwise: grant credit, update `pinned_bytes`, increment `pending_credits`

**Fair-share computation**: Within each priority class, grants are
round-robin across active streams. Across priority classes, CONTROL always
wins over METADATA, METADATA over BULK, BULK over BACKGROUND. Within the same
priority, each stream gets at most `max_chunk` bytes before the scheduler
moves to the next stream.

### 7.4 Backpressure propagation

```text
  PinnedPool exhausted
        │
        ▼
  New OFFERs → NO_CREDITS
  Active streams → CREDIT requests return WAIT
        │
        ▼
  Senders back off, retry CREDIT with exponential delay
        │
        ▼
  Higher-level service (VFS_RPC/COMMIT_GROUP/BLOCK_EXPORT)
  sees stalled BulkToken → applies its own backpressure
  (e.g., VFS_RPC slows WRITE acceptance)
```

Backpressure is **sender-driven** (pull model). The receiver never pushes
"slow down" signals. When credits are tight, senders discover this via
`WAIT`/`NO_CREDITS` responses and throttle themselves.

---

## 8. TCP Baseline (mode=TCP_STREAM)

### 8.1 Framing

TCP bulk data is framed within the transport session using a lightweight chunk
header:

```text
BulkChunkHeader:
  stream_id: u32
  chunk_seq: u32
  offset: u64          -- byte offset within the transfer
  payload_len: u32
  checksum32: u32      -- CRC32C of payload
```

The receiver uses `stream_id` + `chunk_seq` to demultiplex concurrent bulk
transfers on the same TCP connection. The transport lane demux routes bulk
data on the Background lane unless the transfer priority is CONTROL or
METADATA.

### 8.2 Chunking strategy

Chunking is optional but recommended for transfers > `max_chunk`:

- **Single-chunk**: For transfers ≤ `max_chunk`, the sender issues one CREDIT
  for the full transfer size and sends one data chunk.
- **Pipelined**: For transfers > `max_chunk`, the sender pipelines up to
  `max_pending_credits_per_stream` chunks. The receiver processes them in
  order.

### 8.3 Receiver assembly

The receiver maintains a per-stream reassembly buffer:

```rust
struct TcpStreamBuffer {
    stream_id: u32,
    total_len: u64,
    received: u64,
    buffer: Vec<u8>,            // pre-allocated to total_len on ACCEPT
    chunks_received: BitSet,     // track which chunks have arrived
}
```

Chunks may arrive out of order (due to TCP retransmission or lane
multiplexing). The receiver writes each chunk at its `offset` and sets the
corresponding bit in `chunks_received`. When all bits are set, the transfer is

---

## 9. RDMA Modes

### 9.1 RDMA_WRITE

The sender writes directly into receiver-pinned memory:

1. Receiver pins a region from `PinnedPool`, returns `rkey` + `addr` in
   CREDIT_GRANT.
2. Sender issues `ibv_post_send(RDMA_WRITE)` targeting `(rkey, addr + offset)`.
3. Sender waits for RDMA completion (polling CQ or waiting for completion
   notification).
4. Sender sends DONE message over the control path.

**Memory ordering**: The DONE message acts as a memory barrier. The receiver
MUST NOT read the RDMA-written data until DONE arrives. On RDMA networks
with relaxed ordering, the sender MUST use an RDMA READ of a flag byte or
an atomic operation to ensure the receiver sees the final state.

### 9.2 RDMA_READ

The receiver pulls data from sender-pinned memory:

1. Sender offers `total_len` with `mode=RDMA_READ`.
2. Receiver accepts, allocates `BulkToken`.
3. Sender pins its own send buffer, returns `rkey` + `addr` in CREDIT_GRANT
   (semantics inverted: the grant provides the sender's rkey to the receiver).
4. Receiver issues `ibv_post_send(RDMA_READ)` from sender's memory.
5. Receiver sends DONE when all reads complete.

Note: RDMA_READ inverts the usual "sender pays" assumption. The receiver
initiates data movement, which may be desirable when the receiver has more
available CPU/PCIe bandwidth than the sender.

### 9.3 RDMA admission gates

RDMA modes are disabled by default. A live BULK service MUST NOT advertise or
ACCEPT RDMA_WRITE or RDMA_READ until all of these gates have executable
evidence on the selected connection:

- transport peer security binds the authenticated peer identity to the transport
  session and rejects untrusted peers before any rkey/addr is shared;
- pinned-memory accounting charges every registered byte to the daemon budget
  and refuses new grants before `max_pinned_bytes` can be exceeded;
- rkey/addr credits are single-transfer, single-connection grants that are
  invalidated on DONE, ABORT, timeout, or connection teardown;
- ABORT cleanup drains or revokes all outstanding RDMA work requests and unpins
  memory before a token can be retired or a stream_id can be reused;
- hardware or software-RDMA runtime validation covers successful transfer,
  refused fallback, abort cleanup, and connection-loss cleanup.

RDMA_WRITE requires the sender to have RDMA_WRITE permission on the receiver's
memory region. RDMA_READ requires the sender to have RDMA_READ permission and
the receiver to trust the sender's memory registration. On untrusted networks,
strict security mode, missing pin accounting, missing cleanup evidence, or
missing runtime validation, the only admissible live BULK mode is TCP_STREAM.
If a higher layer requested RDMA, refusing RDMA or explicitly starting a new
TCP_STREAM transfer is TCP evidence, not RDMA readiness.

---

## 10. Failure Handling

### 10.1 Connection drop

When a transport session closes (graceful or abrupt), the BULK service:

1. Iterates all active `BulkTransfer` state entries for the dead session.
2. Transitions each to `Aborted` with reason `CONNECTION_LOST`.
3. Unpins all RDMA memory for those transfers.
4. Releases all credit slots.
5. Does NOT send ABORT wire messages (the connection is gone).

Higher-level services detect the abort via their `BulkToken` handle becoming
invalid.

### 10.2 Partial writes

If the receiver detects a transfer length mismatch (`total_transferred` in
DONE ≠ `total_len` in OFFER):

1. Receiver sends ABORT with reason `PROTOCOL_ERROR`.
2. Receiver discards all received data for that transfer.
3. Receiver unpins all memory.

### 10.3 Timeouts

The BULK layer does not impose its own timeouts. Timeouts are the
responsibility of higher-level services:

- VFS_RPC imposes an RPC timeout; if the BULK transfer is not complete by the
  timeout, VFS_RPC sends ABORT and retries the entire RPC.
- COMMIT_GROUP replication has its own epoch-based timeout; stalled bulk transfers
  cause commit_group sync delay, not data corruption.

### 10.4 Retry semantics

The BULK plane is a **dumb pipe**:

- No implicit retry at the BULK layer.
- If a transfer fails, higher-level services retry by issuing a new OFFER with
  a fresh `stream_id` (and, at their own layer, the same or new `op_id` per
  their idempotency rules).
- Partial data from a failed transfer is never reused; it is discarded on
  ABORT.

### 10.5 Duplicate detection

Duplicate OFFER detection is handled by the transport dedup window (#1210),
not by the BULK layer. The BULK service trusts that the transport delivers at
most once (or that higher layers handle idempotency).

---

## 11. State Machine

### 11.1 Transfer states

```text
                    ┌──────────┐
           OFFER ──>│ Offered  │
                    └────┬─────┘
                         │
              ┌──────────┼──────────┐
              │ ACCEPT   │          │ REJECT/NO_CREDITS
              ▼          │          ▼
        ┌──────────┐    │    ┌──────────┐
        │ Accepted │    │    │ Rejected │ (terminal)
        └────┬─────┘    │    └──────────┘
             │          │
    ┌────────┼──────────┼──────────┐
    │ CREDIT │          │ ABORT    │
    ▼        │          ▼          │
┌─────────┐  │    ┌──────────┐    │
│Chunking │  │    │ Aborted  │    │
└────┬────┘  │    └──────────┘    │
     │       │    (terminal)      │
     │ DONE  │                    │
     ▼       │                    │
┌─────────┐  │                    │
│  Done   │  │                    │
└─────────┘  │                    │
(terminal)   │                    │
              └────────────────────┘
```

### 11.2 State transitions

| From       | Event           | To       | Action |
|------------|-----------------|----------|--------|
| (start)    | OFFER received  | Offered  | Reserve credit slot |
| Offered    | ACCEPT sent     | Accepted | Allocate BulkToken, set max_chunk |
| Offered    | ACCEPT (reject) | Rejected | Release credit slot |
| Accepted   | CREDIT granted  | Chunking | Pin bytes, return offset/rkey |
| Accepted   | ABORT received  | Aborted  | Release slot, unpin (if any) |
| Chunking   | CREDIT granted  | Chunking | Continue pinning for next chunk |
| Chunking   | ABORT received  | Aborted  | Unpin all, release slot |
| Chunking   | Connection lost | Aborted  | Unpin all, release slot (implicit) |

### 11.3 Per-connection invariants

1. `active_transfers.len() <= max_inflight_bulk_tokens` (enforced at OFFER)
2. `pinned_bytes <= max_pinned_bytes` (enforced at CREDIT grant)
3. For each stream: `pending_credits <= max_pending_credits_per_stream`
5. At most one transfer per `stream_id` is active at any time

---

## 12. Integration with Higher-Level Services

### 12.1 VFS_RPC (#1213)

VFS_RPC uses `InlineOrBulkV1` to decide whether payload data travels inline
(within the VFS_RPC frame) or via BULK:

The `BulkToken` from VFS_RPC's `InlineOrBulkV1` is connection-scoped. The
VFS_RPC frame and every BULK frame that mentions the token MUST use the same
authenticated transport connection and peer identity. A token from another
connection, a previous connection incarnation, or a completed/aborted transfer
is invalid. VFS_RPC MUST NOT treat `kind=BULK` as live unless the local BULK
service can look up the token in that same connection's transfer table.

Current source status for the #1523 evidence pass:

- `crates/tidefs-vfs-rpc/src/lib.rs` defines `InlineOrBulk::Bulk { token, len }`
  plus `REQ_FLAG_BULK_PENDING` and `RESP_FLAG_BULK`.
- `crates/tidefs-bulk-service/` provides the BULK-owned `service_id = 0x07`
  `BulkService`/`BulkToken`/`BulkOffer` API, connection-scoped transfer table,
  TCP_STREAM credit/data/DONE/ABORT state machine, CRC32C DONE verification,
  and failed-transfer discard behavior. The crate is a service surface for a
  future transport dispatcher; it is not a multi-node product-readiness claim.
- `apps/tidefs-storage-node/src/protocol.rs` is still an object-store tag
  protocol, not a cluster service_id `0x07` BULK dispatcher.
- `crates/tidefs-transport/src/boundedness.rs` exposes generic bulk-token
  limits and a default bulk deadline for transport boundedness, and the BULK
  service consumes those bounds for TCP_STREAM transfer admission.

Until transport dispatch and the VFS_RPC handoff adapter consume that service
surface, VFS_RPC endpoints may reject BULK descriptors as unsupported. They
must not silently downgrade RDMA-capable BULK offers to TCP, claim RDMA
readiness, or treat moved bytes as storage semantics authority.

The remaining implementation blocker is therefore transport/VFS_RPC integration
that can dispatch service_id `0x07` frames to the BULK service, bind the
transport-authenticated peer identity to the same connection that carries the
VFS_RPC frame, and report timeout or ABORT completion to the waiting VFS_RPC
operation before any VFS Engine call observes failed-transfer bytes.

#### 12.1.1 WRITE with BULK

The minimal live WRITE handoff is:

1. The client chooses the VFS_RPC `op_id` for the logical WRITE. Retries of the
   same logical WRITE reuse this `op_id`.
2. On the same transport connection, the client sends a BULK OFFER in
   TCP_STREAM mode with metadata naming VFS_RPC, method WRITE, `op_id`, transfer
   direction `write_upload`, and the intended byte length.
3. The writer ACCEPTs the OFFER, reserves a connection-scoped transfer slot, and
   returns a fresh `BulkToken`.
4. The client sends the VFS_RPC WRITE request with
   `InlineOrBulkV1 { kind: BULK, bulk_token, bulk_len }` and
   `REQ_FLAG_BULK_PENDING`.
5. The client drives CREDIT/data chunks and then DONE for the accepted token.
   The writer does not call the VFS Engine and does not populate the VFS_RPC
   dedup cache until DONE verifies the expected length and checksum.
6. After DONE verifies, the writer processes the WRITE exactly once and caches
   the VFS_RPC response under `(peer_identity, op_id)`.

If OFFER, CREDIT, data transfer, or DONE fails, either side may send ABORT. The
writer discards every buffered byte for that token, releases credits, and
returns `ETIMEDOUT` if a VFS_RPC request is already waiting. Connection loss is
an implicit ABORT. Failed-transfer bytes never reach the VFS Engine and never
produce a success response in the dedup cache.

If the VFS_RPC request deadline or the transport's configured bulk deadline
fires before DONE verifies the token, the waiting side sends or records ABORT
with reason `TIMEOUT`, retires the token, and treats the operation as failed.

A retry after ABORT or timeout uses the same VFS_RPC `op_id` and a fresh
`stream_id`/`BulkToken`. If the original WRITE already completed and the
response is in the dedup cache, the writer replays the cached response and
sends ABORT for any still-active extra transfer token for that duplicate
`op_id`.

#### 12.1.2 READ with BULK

The minimal live READ handoff is:

1. The client sends the VFS_RPC READ request with its `op_id`.
2. If the writer's response exceeds the inline threshold, the writer sends a
   BULK OFFER in TCP_STREAM mode on the same transport connection with metadata
   naming VFS_RPC, method READ, `op_id`, transfer direction `read_download`, and
   the response length.
3. The client ACCEPTs the OFFER and returns a fresh `BulkToken`.
4. The writer sends the VFS_RPC response with
   `InlineOrBulkV1 { kind: BULK, bulk_token, bulk_len }` and `RESP_FLAG_BULK`.
   The response is a pending descriptor; the client does not expose read bytes
   until the matching BULK transfer reaches DONE.
5. The writer drives CREDIT/data chunks and then DONE. The client verifies the
   expected length and checksum before completing the READ to its caller.

If the transfer aborts or times out, the client discards partial bytes and
retries the READ operation under the same VFS_RPC `op_id`. A replayed READ
response MUST NOT reuse an old completed `BulkToken`; the writer either sends
inline data or creates a fresh BULK transfer for the retry.

### 12.2 COMMIT_GROUP replication

COMMIT_GROUP sync (#1241) replicates transaction group data between nodes. COMMIT_GROUP uses
BULK for the data payload, speaking its own control protocol for ordering:

- COMMIT_GROUP assigns an epoch number and includes it in the OFFER metadata blob.
- The receiver uses the epoch to fence stale transfers.
- BULK is unaware of COMMIT_GROUP semantics; it only moves bytes.

### 12.3 BLOCK_EXPORT (ublk, #1216)

The ublk block device adapter uses BULK for READ_AT/WRITE_AT payloads:

- `WRITE_AT(offset, len, data)`: ublk sends OFFER with `metadata` containing
  the block offset. BULK delivers payload bytes.
- `READ_AT(offset, len)`: ublk receives BULK transfer initiated by the storage
  node.

---

## 13. Implementation Notes

### 13.1 Crate layout

The BULK service should live in a new crate:

```text
crates/tidefs-bulk-service/
  src/
    lib.rs           -- public API: BulkService, BulkToken, BulkOffer
    protocol.rs      -- wire message types (OfferV1, AcceptV1, etc.)
    state_machine.rs -- per-transfer state machine
    pinned_pool.rs   -- PinnedPool for RDMA/TCP buffer management
    scheduler.rs     -- credit scheduling and fairness
    tcp_stream.rs    -- TCP_STREAM mode implementation
```

### 13.2 Dependencies

- `tidefs-transport` — session, lane demux, envelope
- `tidefs-types-transport-session` — transport identifiers
- `tidefs-clock-timing` — HLC timestamps for timeout-free operation

### 13.3 Feature flags

```toml
[features]
default = ["tcp"]
tcp = []
```

### 13.4 Testing strategy

1. **Unit tests**: State machine transitions, credit scheduler fairness,
   PinnedPool allocation/deallocation
2. **Integration tests**: TCP_STREAM end-to-end with chunked transfers between
   two in-process pipes
3. **Simnet tests**: Multi-node BULK transfers under the cluster simnet (#1175)
4. **Property tests**: Randomized transfer sizes, chunk sizes, credit
   exhaustion scenarios

---

## 14. Acceptance Criteria

1. OFFER/ACCEPT/CREDIT/DONE/ABORT state machine implemented and testable
2. TCP_STREAM mode works end-to-end with chunked transfers
3. PinnedPool enforces `max_pinned_bytes` from budget
4. Credit scheduling is fair across streams
5. Connection drop cleanly aborts all active BULK transfers

---

## 15. References

- [#1210](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1210) — Transport boundedness
- [#1211](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1211) — Daemon memory budget
- [#1213](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1213) — VFS Engine API contract
- [#1216](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1216) — ublk block device
- [#1227](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1227) — Security model
- [#1228](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1228) — Security model
- [#1175](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1175) — Cluster simnet
- [#1234](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1234) — TFS_RPC wire protocol
- [#1241](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1241) — COMMIT_GROUP sync scheduling

---

*Design derived from tidefs v0.262 notes §17.6.4 and the transport boundedness
contract (#1210). This is a design specification; implementation is tracked in
a separate issue.*
