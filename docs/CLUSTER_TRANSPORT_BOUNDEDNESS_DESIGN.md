# Cluster Transport Boundedness Design

Maturity: **design-spec** for provably bounded cluster transport: per-connection
frame/dedup/bulk limits, per-tick delivery budgets with lane priority ordering,
frame-level budget accounting, and integration with the unified resource
governor's `cluster_queues` budget category.

This document closes Forgejo issue #1210.

## 1. Motivation

Without per-connection bounds, a single misbehaving peer or bursty workload can
exhaust daemon RAM through:

- Cluster queues growing without bound as messages pile up
- Large frames consuming disproportionate memory per message
- Unbounded dedup windows retaining stale `(peer_node_id, op_id)` pairs
- Bulk transfers starving control-plane messages of delivery bandwidth

Neither ZFS (no native cluster transport) nor Ceph (no per-connection boundedness;
OSD op queue cut-off is a blunt throttle, not a budget model) provides a clean
solution.

tidefs must guarantee that every transport connection is **provably bounded** in
memory, CPU (per-tick delivery budget), and fairness (lane priority ordering).
The cluster transport must consume memory from the `cluster_queues` budget
category subject to the same unified resource governor (#1237) that governs
all daemon-side memory.

## 2. Design Overview

The transport boundedness design introduces four layers of enforcement:

| Layer | Mechanism | Enforces |
|-------|-----------|----------|
| Connection admission | `cluster_queues` budget category (#1237) | Total transport memory cannot exceed governor allocation |
| Per-connection limits | `ConnectionBounds` struct | Frame size, inflight count, bulk tokens, dedup window per connection |
| Per-tick delivery | `DeliveryBudget` + lane priority | Bounded CPU per scheduler tick; fair lane ordering |
| Frame-level accounting | `FrameHeaderV1` explicit length | Receivers budget before processing; no unbounded decode |

These layers compose: the governor caps total transport memory; per-connection
limits cap per-peer usage; per-tick budgets prevent CPU starvation; frame-level
accounting prevents decode-time surprise allocation.

## 3. Connection Admission

### 3.1 cluster_queues Budget Category

The transport layer consumes memory from the `cluster_queues` budget category
in the unified resource governor (#1237). Before admitting any new connection,
inbound frame, or bulk transfer token, the transport layer checks with the
governor:

```rust
impl TransportAdmissionControl {
    pub fn can_admit_frame(&self, governor: &ResourceGovernor,
                           size: u64) -> AdmissionResult {
        governor.admit(BudgetCategory::ClusterQueues, size,
                       AdmissionPriority::Normal)
    }

    pub fn can_admit_bulk_transfer(&self, governor: &ResourceGovernor,
                                   token: &BulkToken) -> AdmissionResult {
        // Bulk transfers use Normal priority under normal conditions,
        // downgrade to Low under backpressure
        let prio = if governor.backpressure_level() >= BackpressureLevel::Mild {
            AdmissionPriority::Low
        } else {
            AdmissionPriority::Normal
        };
        governor.admit(BudgetCategory::ClusterQueues,
                       token.bytes_remaining, prio)
    }
}
```

### 3.2 Backpressure Integration

When `cluster_queues` reaches the `REJECT` watermark (95% utilization), the
governor escalates to backpressure. The transport layer responds by:

| Backpressure Level | Transport Action |
|--------------------|-----------------|
| `None` | Normal admission |
| `Mild` | Shrink inflight frame cap by 50% per connection; reject new bulk tokens |
| `Moderate` | Stop accepting new `Offer` messages; drain inflight bulk transfers |
| `Severe` | Close all non-control connections; only CONTROL lane frames admitted |

This integrates with the governor's backpressure ladder (§6 of #1237) and the
BULK protocol's admission window (#1229).

## 4. Per-Connection Limits

### 4.1 ConnectionBounds

Every transport connection maintains a `ConnectionBounds` struct enforced at
both the sender and receiver:

```rust
pub struct ConnectionBounds {
    /// Maximum serialized frame size (header + payload).
    /// Frames exceeding this are rejected before decode.
    pub max_frame_bytes: u32,

    /// Maximum number of unacknowledged frames inflight.
    /// Sender blocks when this count is reached.
    pub max_inflight_frames: u16,

    /// Maximum number of concurrent bulk transfer tokens.
    pub max_inflight_bulk_tokens: u8,

    /// Size of the deduplication sliding window (ops).
    pub dedup_window_ops: u16,
}
```

### 4.2 Per-Limit Detail

#### max_frame_bytes

Frames are the transport unit. The frame header carries an explicit `payload_len`

- Sender: frames exceeding `max_frame_bytes` are rejected at serialization time
- Receiver: if `payload_len > max_frame_bytes`, the frame is dropped and the
  connection is marked as violating bounds
- Default: 1 MiB (large enough for bulk data, small enough for bounded memory)
- Overridable per-connection via HELLO negotiation

#### max_inflight_frames

Senders track unacknowledged frames. When `inflight_count >= max_inflight_frames`,
the sender blocks (does not send more frames) until an ACK arrives.

- ACKs are cumulative: acknowledging sequence `N` acknowledges all frames <= N
- Default: 64 frames per connection
- CONTROL lane frames bypass this limit (must always be deliverable)

#### max_inflight_bulk_tokens

Bulk transfers (#1229) consume tokens that reserve a portion of the connection's
capacity. Tokens are granted per-transfer and released on completion or abort.

- Default: 4 concurrent bulk transfers per connection
- A bulk transfer that cannot obtain a token is queued (deferred to next tick)
- CONTROL lane messages are never blocked by bulk token exhaustion

#### dedup_window_ops

The transport layer deduplicates messages by `(peer_node_id, op_id)` to prevent
retry storms from creating duplicate work. The dedup window is a sliding window
over the most recent `dedup_window_ops` operations per peer.

- Window overflow: oldest entries are evicted (LRU); duplicate detection is
  best-effort after overflow
- Default: 1024 ops per connection
- Dedup state is bounded by `dedup_window_ops * sizeof(DedupEntry)` bytes

### 4.3 Connection Bounds Negotiation

During the HELLO phase, peers negotiate bounds:

```
Client -> Server: HELLO {
    proposed_bounds: ConnectionBounds,
    capabilities: u64,
}
Server -> Client: HELLO_ACK {
    accepted_bounds: ConnectionBounds,  // min(client.max, server.max) per field
    server_capabilities: u64,
}
```

The accepted bounds are the per-field minimums. This prevents a high-capacity
peer from overwhelming a constrained peer.

## 5. Per-Tick Delivery Budgets

### 5.1 DeliveryBudget

The transport layer processes messages in bounded ticks, integrated with the
background service framework (#1179):

```rust
pub struct DeliveryBudget {
    /// Maximum messages delivered across all lanes in this tick.
    pub max_deliveries: u32,

    /// Maximum bytes delivered across all lanes in this tick.
    pub max_bytes: u64,

    /// Per-lane delivery caps.
    pub lane_caps: LaneDeliveryCaps,
}

pub struct LaneDeliveryCaps {
    pub control_max: u32,       // default: unlimited (must deliver)
    pub metadata_max: u32,      // default: 256
    pub bulk_max: u32,          // default: 64
    pub background_max: u32,    // default: 32
}
```

### 5.2 Lane Priority Model

Messages are delivered in strict lane priority order. The transport drains
higher-priority lanes completely before lower-priority lanes:

| Lane | Priority | Description | Example Messages |
|------|----------|-------------|-----------------|
| `CONTROL` | 0 (highest) | Cluster-critical control messages, never deferred | JOIN, HEARTBEAT, LEADER_REDIRECT, lease requests |
| `BULK` | 2 | Bulk data transfers, large but throughput-oriented | Extent replication, erasure-coded shard rebuild |

### 5.3 Delivery Algorithm

```
function deliver_tick(queues, budget):
    for lane in [CONTROL, METADATA, BULK, BACKGROUND]:
        lane_budget = budget.lane_caps[lane]
        delivered = 0

        while delivered < lane_budget and !queues[lane].is_empty():
            msg = queues[lane].peek()

            if total_bytes + msg.size > budget.max_bytes:
                break  // global byte budget exhausted

            if total_delivered >= budget.max_deliveries:
                break  // global message budget exhausted

            dispatch(msg)
            queues[lane].pop()
            delivered += 1
            total_delivered += 1
            total_bytes += msg.size

        if lane != CONTROL and total_delivered >= budget.max_deliveries:
            break
```

Key properties:
- CONTROL lane is never subject to per-lane caps (must deliver all control messages)
- Lower lanes are starved if higher lanes consume the budget — this is intentional
- Remaining messages are deferred to the next tick (head-of-line blocking only within a lane)

### 5.4 Tick Integration

The transport delivery tick runs as part of the daemon's event loop, interleaved
with FUSE request processing and background service ticks:

```rust
// In the daemon event loop:
loop {
    // 1. Process FUSE requests (bounded by governor backpressure)
    process_fuse_requests(fuse_session, governor);

    // 2. Deliver a bounded transport tick
    transport.deliver_tick(&delivery_budget);

    // 3. Run background services (#1179)
    background_scheduler.run_cycle(&cycle_budget);

    // 4. Send pending transport frames (bounded by per-connection limits)
    transport.flush_pending_frames(governor);
}
```

## 6. Frame Format and Accounting

### 6.1 FrameHeaderV1

Every transport frame carries an explicit header so receivers can budget before
processing:

```rust
pub struct FrameHeaderV1 {
    /// Magic: 0x54494445 ("TIDE" in ASCII).
    pub magic: u32,

    /// Frame format version.
    pub version: u16,

    /// Message type: (service_id << 8) | method_id.
    /// service_id = 0x00-0xFF, method_id = 0x00-0xFF.
    pub msg_type: u16,

    /// Monotonically increasing frame sequence number per connection.
    pub sequence: u64,

    /// Acknowledgement: cumulative sequence number of last received frame.
    pub ack_sequence: u64,

    /// Lane classification.
    pub lane: TransportLane,

    /// Length of payload following the header (0 = no payload).
    pub payload_len: u32,

    /// CRC32C of the payload (0 if payload_len == 0).
    pub payload_checksum: u32,

    /// CRC32C of the header itself (computed with this field zeroed).
    pub header_checksum: u32,
}
// Total header size: 40 bytes
```

### 6.2 Budget Accounting Per Frame


```rust
                         governor: &ResourceGovernor) -> Result<(), TransportError> {
    // 1. Size bound
    if frame.payload_len > bounds.max_frame_bytes {
        return Err(TransportError::FrameTooLarge {
            got: frame.payload_len,
            max: bounds.max_frame_bytes,
        });
    }

    // 2. Budget check: header + payload
    let total_size = FRAME_HEADER_SIZE + frame.payload_len as u64;
    match governor.admit(BudgetCategory::ClusterQueues, total_size,
                         AdmissionPriority::Normal) {
        AdmissionResult::Granted => Ok(()),
        AdmissionResult::Rejected(reason) => Err(TransportError::BudgetExhausted {
            category: BudgetCategory::ClusterQueues,
            reason,
        }),
        _ => Ok(()),  // Deferred: admit anyway but log pressure
    }
}
```

### 6.3 Release on ACK

When a frame is acknowledged, the sender releases its budget allocation:

```rust
fn on_ack(connection: &mut Connection, ack_sequence: u64,
          governor: &ResourceGovernor) {
    let mut released_bytes = 0;
    connection.inflight_frames.retain(|frame| {
        if frame.sequence <= ack_sequence {
            released_bytes += frame.total_size;
            false  // remove from inflight
        } else {
            true   // keep waiting for ack
        }
    });
    governor.release(BudgetCategory::ClusterQueues, released_bytes);
}
```

## 7. Bulk Transfer Boundedness

### 7.1 BulkToken Lifecycle

Bulk transfers (#1229) are the largest consumers of transport memory. They
must be explicitly bounded:

```rust
pub struct BulkToken {
    /// Unique token identifier (assigned by receiver).
    pub token_id: u64,

    /// Total bytes to transfer.
    pub total_bytes: u64,

    /// Remaining bytes not yet transferred.
    pub bytes_remaining: u64,

    /// Maximum bytes per chunk.
    pub chunk_size: u32,

    /// The connection this token is bound to.
    pub connection_id: ConnectionId,

    /// Deadline for transfer completion (wall clock).
    pub deadline_ns: u64,
}
```

Bulk tokens are bounded by:
- `max_inflight_bulk_tokens` per connection (token count)
- `max_frame_bytes` per chunk (chunk size)
- Governor's `cluster_queues` budget (memory consumption)

### 7.2 Bulk Flow Control

The BULK protocol's Offer/Accept/Credit/Done/Abort state machine (#1229) is
gated by the transport boundedness layer:

- `Offer`: check `inflight_bulk_tokens < max_inflight_bulk_tokens`; if at
  capacity, reject with `BULK_TOKEN_EXHAUSTED`
- `Accept`: allocate bulk token; admit first chunk against governor budget
- `Credit`: sender checks `inflight_frames < max_inflight_frames` before
  sending next chunk
- `Done`/`Abort`: release bulk token; release all remaining budget

### 7.3 Bulk Backpressure

When the governor is at `Mild` backpressure or higher:
- No new `Offer` messages are accepted
- In-progress bulk transfers are throttled: chunk rate is halved
- At `Severe`, all in-progress bulk transfers are aborted

## 8. Deduplication Window

### 8.1 DedupEntry

```rust
pub struct DedupEntry {
    /// Peer node that sent the original message.
    pub peer_node_id: u64,

    /// Operation identifier (monotonically increasing per peer).
    pub op_id: u64,

    /// When this entry was created (for eviction ordering).
    pub received_at_ns: u64,

    /// The response that was delivered (so retries get the same response).
    pub cached_response: Option<Vec<u8>>,
}
```

### 8.2 Deduplication Algorithm

```
function check_dedup(peer_node_id, op_id, window):
    entry = window.get((peer_node_id, op_id))
    if entry is not None:
        if entry.cached_response is not None:
            return Duplicate // resend cached response
        else:
            return Inflight  // drop; original is still being processed
    else:
        if window.size >= dedup_window_ops:
            window.evict_oldest()
        window.insert(DedupEntry{peer_node_id, op_id, now, None})
        return NewMessage
```

When a response is ready, the dedup entry is updated with `cached_response`.
Retries arriving after the response is cached get the cached response
immediately without re-processing.

## 9. Integration Contracts

### 9.1 Integration with #1237 (Resource Governor)

The transport boundedness layer is the primary consumer of the `cluster_queues`
budget category. Every byte of transport memory (frames, dedup entries, bulk
tokens, receive buffers) is accounted through the governor. When `cluster_queues`
reaches the `REJECT` watermark, the transport layer applies backpressure as
described in §3.2.

### 9.2 Integration with #1179 (Background Services)

Transport delivery ticks are interleaved with background service ticks in the
daemon event loop. The `DeliveryBudget` ensures transport delivery does not
starve background services (and vice versa).

### 9.3 Integration with #1229 (BULK Protocol)

The BULK protocol's Offer/Accept/Credit/Done/Abort state machine is gated by
the boundedness layer. Bulk token exhaustion, frame cap, and governor
backpressure are all enforced before BULK operations execute.

### 9.4 Integration with #1209 (MEMBERSHIP Service)

The MEMBERSHIP service's `CLUSTER_VIEW` pushes are transported over the
CONTROL lane, ensuring they are never deferred or starved by bulk traffic.
Node failure detection triggers transport cleanup: inflight frames and bulk
tokens for the dead node are released immediately.

### 9.5 Integration with #1287 (Checksum Architecture)

The `FrameHeaderV1` includes `payload_checksum` (CRC32C) for per-frame
integrity. This complements the two-tier checksum architecture (#1287) by
providing transport-level corruption detection before payload decode.

## 10. ZFS and Ceph Comparison

| Dimension | ZFS | Ceph | tidefs Transport Boundedness |
|-----------|-----|------|------------------------------|
| **Transport memory model** | No cluster transport. Intra-host only (ZIO pipeline in kernel). No transport memory budget concept. | `async_msgr` with configurable throttle bytes (`ms_dispatch_throttle_bytes`). Throttle is system-wide, not per-connection. No budget category integration. | Per-connection `ConnectionBounds` + governor `cluster_queues` budget category. Every transport byte is tagged and tracked through the unified resource governor. |
| **Per-connection bounds** | N/A (no multi-node transport). | No per-connection bounds. `ms_dispatch_throttle_bytes` is a global dispatch throttle, not a per-peer budget. A single misbehaving OSD can consume the global throttle. | Explicit `ConnectionBounds` per connection: `max_frame_bytes`, `max_inflight_frames`, `max_inflight_bulk_tokens`, `dedup_window_ops`. Enforced at both sender and receiver. Negotiated at HELLO. |
| **Per-tick delivery budgets** | N/A. ZIO pipeline dispatch is unbounded per cycle. | No per-tick delivery model. `ms_async_op_threads` processes messages continuously with no per-cycle caps. Can starve other daemon work under load. | `DeliveryBudget` with `max_deliveries`, `max_bytes`, and per-lane caps. Transport delivery is one bounded tick in the daemon event loop, interleaved with FUSE processing and background services. |
| **Lane priority model** | N/A. ZIO priority classes (ZIO_PRIORITY_*) exist but are within a single host, not across a cluster transport. | `ms_async_op_threads` processes messages FIFO. No lane priority ordering. Bulk recovery traffic can starve client I/O. | 4-lane priority model: CONTROL (always delivered), METADATA, BULK, BACKGROUND. Higher lanes drain completely before lower lanes. CONTROL never deferred. |
| **Deduplication** | N/A. | `async_msgr` has `keepalive` and `ack` deduplication for control messages. No general-purpose `(peer, op_id)` dedup window. | Per-connection `dedup_window_ops` sliding window (default 1024). Retried messages produce cached responses without re-processing. LRU eviction on overflow. |
| **Bulk transfer boundedness** | N/A. | `osd_op_queue_cut_off` rejects new ops when queue exceeds threshold. No per-bulk-transfer token model. Bulk recovery can consume all available op slots. | `BulkToken` with `max_inflight_bulk_tokens` per connection, `chunk_size` bounded by `max_frame_bytes`, governor backpressure integration. Abortable at any backpressure level. |
| **Backpressure integration** | ZFS write throttle delays commit_group sync. No transport-layer backpressure. | `osd_op_queue_cut_off` + `mds_throttle`. No governor integration. Throttle is operation-count-based, not memory-based. | Multi-level backpressure (§3.2): Mild→Moderate→Severe with escalating transport restrictions. Integrated with unified resource governor (#1237) backpressure ladder. |

### 10.1 Where tidefs Improves on ZFS

ZFS has no cluster transport, so all transport boundedness concepts are novel:
per-connection bounds, per-tick delivery budgets, lane priority, dedup windows,
bulk token boundedness — none of these exist in ZFS.

### 10.2 Where tidefs Improves on Ceph

- **Per-connection bounds**: Ceph's `ms_dispatch_throttle_bytes` is global.
  tidefs enforces per-connection `ConnectionBounds` negotiated at HELLO,
  preventing one misbehaving peer from exhausting transport memory.
- **Per-tick delivery budgets**: Ceph has no per-cycle delivery model.
  tidefs integrates transport delivery as bounded ticks in the daemon event
  loop, interleaved with FUSE and background services.
- **Lane priority**: Ceph processes messages FIFO. tidefs has 4-lane priority
  with CONTROL always delivered first, preventing bulk traffic from starving
  control messages.
- **Governor integration**: Ceph throttle is standalone. tidefs transports
  memory is tracked through the unified resource governor, participating in
  the same eviction/backpressure ladder as cache and data-plane memory.

### 10.3 Where tidefs Matches

- **Frame checksums**: Both Ceph (`ceph_msg_header` with data CRCs in payload)
  and tidefs (`FrameHeaderV1` with header+payload CRC32C) provide per-frame
- **Flow control**: Both use inflight caps (Ceph's inflight ops limit, tidefs's
  `max_inflight_frames`) to prevent sender overflow.
- **ACK-based release**: Both use cumulative ACKs to release inflight resources.

## 11. Implementation Plan

### Phase 1: Core Types and Constants
Implement `ConnectionBounds`, `DeliveryBudget`, `LaneDeliveryCaps`, `TransportLane`,
`BulkToken`, `DedupEntry`, `FrameHeaderV1`, and all constants in
`crates/tidefs-transport-boundedness-types/` (new crate). Binary encode/decode
with CRC32C for `FrameHeaderV1`. Gate: `tidefs-xtask check-transport-boundedness-types`.

### Phase 2: Per-Connection Bounds Enforcement
enforcement, bulk token cap, dedup window insertion/eviction/cache. Unit tests
for each bound. Gate: `tidefs-xtask check-transport-connection-bounds`.

### Phase 3: Per-Tick Delivery Scheduler
Implement `deliver_tick()` with lane priority ordering, per-lane caps, global
message/byte budgets. Tests for lane starvation behavior and budget exhaustion.
Gate: `tidefs-xtask check-transport-delivery`.

### Phase 4: Governor Integration
Wire transport admission into `ResourceGovernor` (#1237) `cluster_queues`
category. Implement `TransportAdmissionControl`, backpressure response at each
level. Tests for backpressure level transitions. Gate: `tidefs-xtask check-transport-governor`.

### Phase 5: Dedup Window
Implement `DedupWindow` with `check_dedup()`, cached response delivery, LRU
eviction on overflow. Tests for duplicate detection, inflight dedup, cache hit
on retry. Gate: `tidefs-xtask check-transport-dedup`.

### Phase 6: Bulk Token Management
Implement `BulkToken` lifecycle: allocate, credit, throttle, abort. Integrate
with BULK protocol (#1229) Offer/Accept/Credit/Done/Abort flow. Gate: `tidefs-xtask check-transport-bulk`.

### Phase 7: HELLO Negotiation
Implement HELLO/HELLO_ACK with `ConnectionBounds` negotiation (per-field min).
Gate: `tidefs-xtask check-transport-hello`.

### Phase 8: Frame Encode/Decode
Implement `FrameHeaderV1` serialization with CRC32C header and payload checksums.
corrupt frame detection and budget-exhaustion handling.
Gate: `tidefs-xtask check-transport-frame`.

### Phase 9: Daemon Event Loop Integration
Wire transport tick into the daemon event loop: interleave with FUSE processing
and background services. Integrate with MEMBERSHIP service (#1209) for CONTROL
lane delivery. Golden trace tests.
Gate: `tidefs-xtask check-transport-event-loop`.

### Phase 10: Observability and Hardening
Implement per-connection counters (frames sent/received/dropped, bulk tokens
active/completed/aborted, dedup hits/misses/evictions), per-lane delivery
counters, governor budget utilization gauges. `tidefsctl transport` command.
Production runbook for transport tuning.
Gate: `tidefs-xtask check-transport-boundedness`.

## 12. Deterministic Constraint Knobs

| Constant | Default | Meaning |
|----------|---------|---------|
| `MAX_FRAME_BYTES` | 1 MiB | Default maximum frame size per connection |
| `MAX_INFLIGHT_FRAMES` | 64 | Default maximum unacknowledged frames per connection |
| `MAX_INFLIGHT_BULK_TOKENS` | 4 | Default maximum concurrent bulk transfers per connection |
| `DEDUP_WINDOW_OPS` | 1024 | Default dedup sliding window size per connection |
| `DEDUP_ENTRY_MAX_BYTES` | 256 | Maximum cached response size in dedup entry |
| `FRAME_HEADER_SIZE` | 40 | Size of `FrameHeaderV1` in bytes |
| `CONTROL_LANE_CAP` | u32::MAX | CONTROL lane delivery cap per tick (unlimited) |
| `METADATA_LANE_CAP` | 256 | METADATA lane delivery cap per tick |
| `BULK_LANE_CAP` | 64 | BULK lane delivery cap per tick |
| `BACKGROUND_LANE_CAP` | 32 | BACKGROUND lane delivery cap per tick |
| `GLOBAL_MAX_DELIVERIES_PER_TICK` | 512 | Maximum total deliveries per transport tick |
| `GLOBAL_MAX_BYTES_PER_TICK` | 16 MiB | Maximum total bytes per transport tick |
| `TRANSPORT_TICK_INTERVAL_MS` | 10 | Minimum interval between transport ticks |
| `HELLO_TIMEOUT_MS` | 5000 | Timeout for HELLO/HELLO_ACK handshake |
| `BULK_DEADLINE_DEFAULT_MS` | 30000 | Default bulk transfer deadline |
| `BULK_CHUNK_SIZE_DEFAULT` | 256 KiB | Default chunk size for bulk transfers |

## 13. Error Hierarchy

The transport crate defines five error enums in `crates/tidefs-transport/src/error.rs`
rather than a single monolithic `TransportBoundednessError`:

### 13.1 TransportError (`error.rs`)

Top-level transport errors: `BindFailed`, `ConnectFailed`, `AcceptFailed`,
`SessionNotFound`, `SessionInWrongState`, `HandshakeFailed`, `MaxSessionsReached`,
`PeerNotFound`, `IdentityMismatch`, `Io`, `RdmaNotAvailable`,
`RdmaRegistrationFailed`, `RdmaConnectionFailed`, `RdmaDegraded`,
`Generic(String)`, `WouldBlock(String)`.

### 13.2 SessionError (`error.rs`)

Session-level errors: `AlreadyClosed`, `NotEstablished`, `InvalidTransition`,
`ReconnectionExhausted`, `VersionMismatch`, `RdmaRegistrationFailed`,
`RdmaDegraded`, `RdmaCarrierLost`, `RdmaFallbackFailed`, `ReconnectGateRefused`.

### 13.3 EnvelopeError (`envelope.rs`)


### 13.4 ChunkError and ChunkTransferError (`chunk_shipper.rs`)

`ChunkError`: `TransferNotFound`, `TransferInWrongState`,
`ChecksumMismatch`, `MaxConcurrentReached`, `TransferFailed`, `Refused`, `Io`.

`ChunkTransferError`: `ConnectionLost { at_offset }`, `Timeout { at_offset }`,
`NoSpace { needed, available }`, `FenceViolated { peer_version, our_version }`,
`Io { at_offset, source: IoErrorWrapper }`.

### 13.5 Boundedness enforcement in practice

Bounds violations are checked at multiple layers:
  and returns an `Err(String)` — no dedicated enum variant needed.
- `DeliveryBudget::reserve()` returns `false` on lane/global budget exhaustion;
  the caller translates this to the appropriate session/transport error.
- Governor budget rejection surfaces through backpressure escalation described in §3.2.


## 14. Open Questions

1. **CONTROL lane dedicated connection** — Resolved: single multiplexed
   connection for v1. All 5 lane classes share one TCP connection via
   `LaneDemux`. A future `MultiPathTransport` extension may add a dedicated
   CONTROL connection.

2. **Per-connection dedup** — Resolved: per-connection dedup with
   `dedup_window_ops` (default 1024). Cross-connection dedup is deferred.

3. **Dynamic delivery budgets** — Resolved: static per-tick budgets
   (`GLOBAL_MAX_DELIVERIES_PER_TICK = 512`, `GLOBAL_MAX_BYTES_PER_TICK = 16 MiB`).
   `LaneClass::Control` has unlimited cap (`u32::MAX`); `Metadata` = 256,
   `Demand` (BULK) = 64, `Speculative`/`Background` (BACKGROUND) = 32.

4. **Jumbo frames for shard rebuild** — Resolved: jumbo frames deferred to
   HELLO-time negotiation. Default `max_frame_bytes = 1 MiB`. Erasure-coded
   shard rebuild (#1249) can negotiate larger frames per-connection.

5. **RDMA carrier support** — The `TransportBackend` abstraction (§16)
   supports TCP (default), TLS, and RDMA (`TransportBackendKind::Rdma`).
   RDMA sessions degrade to TCP on carrier loss with `SessionError::RdmaCarrierLost`
   and `TransportError::RdmaDegraded`. Full RDMA data path is gated behind
   OW-308.

## 15. References

- [#1210] This design spec
- [#1237] Unified resource governor — `cluster_queues` budget category
- [#1179] Background service framework — transport tick scheduling
- [#1229] BULK protocol — Offer/Accept/Credit/Done/Abort state machine
- [#1209] MEMBERSHIP service — CONTROL lane delivery
- [#1287] Checksum architecture — two-tier checksums (CRC32C + BLAKE3)
- [#1268] Workload-signature materialization economy — future dynamic budget adaptation
- [#1847] RDMA-specific TransportError/SessionError variants
- [#1861] API documentation for transport layer public items
- [#1889] Transport endpoint lifecycle and invariants documentation
- [#1910] RDMA-specific SessionCloseReason, degraded→TCP fallback, ReconnectState
- [P8-01] `docs/TRANSPORT_SESSION_COHORT_GRAPH_P8-01.md` — transport/session/cohort graph law
- `docs/ERASURE_CODING_PLACEMENT_DESIGN.md` — shard rebuild transport requirements
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`
- `crates/tidefs-transport/src/envelope.rs` — `TransportEnvelope` wire format, `MessageFamily`, `VisibilityClass`, `SequenceTracker`
- `crates/tidefs-transport/src/lane_demux.rs` — 5-lane priority multiplexer with per-lane backpressure
- Python v0.262 reference: `cluster_tuning.py`, `simnet.py`
