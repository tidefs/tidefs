# tidefs-transport

Transport/session layer for the TideFS distributed runtime.

## Capabilities

- TCP transport backend with configurable session lifecycle
- Session cohort graph for multi-node topology
- 5-lane multiplexing with per-lane budget control
- Chunk shipping with BLAKE3-verified integrity
- Reconnection with exponential backoff and jitter
- Transport-layer connection keepalive with deadline-based failure detection and health-score integration
- RDMA carrier support (TCP fallback)
- Deterministic carrier selection from membership peer capability advertisements with RDMA preference and TCP fallback (module )
- TLS session encryption
- Session handshake with mutual attestation
- Receive-side flow control with credit-based windowing for inbound frame backpressure
- TDMA gate for time-division multiplexing
- Send coalescing with session-and-priority-aware batching for reduced per-frame overhead
- Cross-session send scheduling with weighted fair queueing for fair outbound bandwidth sharing across active peer sessions
## Configuration

Unified transport configuration via `TransportConfigBuilder` (module
`tidefs_transport::config`, source [config.rs](src/config.rs)).  All fields
are validated at build time; invalid combinations are refused with a
`ConfigError`.

### Builder API

```rust
use std::net::SocketAddr;
use tidefs_transport::config::{TransportConfigBuilder, TransportEndpoint};

let addr: SocketAddr = "192.168.1.10:9090".parse().unwrap();
let config = TransportConfigBuilder::default()
    .endpoint(TransportEndpoint::Tcp(addr))
    .connect_timeout_secs(10)
    .send_buffer_size(128 * 1024)
    .max_concurrent_streams(512)
    .build()
    .expect("valid config");
```

### Default values

| Field | Default | Notes |
|---|---|---|
| Endpoint | TCP 127.0.0.1:9090 | Placeholder until #5787 lands |
| `connect_timeout` | 30 s | TCP handshake ceiling |
| `idle_timeout` | 300 s | Connection idle before keepalive probing |
| `read_timeout` | 30 s | Per-read operation ceiling |
| `write_timeout` | 30 s | Per-write operation ceiling |
| `send_buffer_size` | 64 KiB | SO_SNDBUF |
| `recv_buffer_size` | 64 KiB | SO_RCVBUF |
| `max_concurrent_streams` | 256 | Multiplexed stream ceiling |
| `per_stream_buffer` | 64 KiB | Per-stream buffer capacity |
| Keepalive `interval` | 30 s | Probe interval when idle (ping-pong cycle) |
| Keepalive `timeout` | 5 s | Response wait before probe counted as missed |
| Keepalive `probe_count` | 3 | Consecutive missed probes before peer declared dead |

### Validation rules

- Every timeout must be non-zero.
- Every buffer size and stream count must be non-zero.
- `read_timeout` and `write_timeout` must not exceed `idle_timeout`.
- Keepalive `timeout` must not exceed keepalive `interval`.
- Keepalive `probe_count` must be at least 1; zero is rejected at config build.
- `probe_count` must be at least 1.

### Follow-on

Wire `TransportConfig` into the connection lifecycle state machine (#5788)
and replace the local `TransportEndpoint` placeholder with the canonical
`TransportAddr` from #5787.


## TransportAddr — Unified Endpoint Address

`TransportAddr` is a single address enum in `tidefs-transport` that represents
all three transport carriers — TCP, RDMA, and Unix domain sockets — so the
send path, receive path, and peer admission code never branch on carrier type.

### Variants

| Variant | Fields | Example URI |
|---|---|---|
| `Tcp(SocketAddr)` | IPv4/IPv6 socket address | `tcp://10.0.0.1:9100` |
| `Rdma { gid, qpn, service_id }` | 16-byte GID, queue-pair number, service ID | `rdma://fe80:0000:0000:0000:0000:0000:0000:0001:42:1` |
| `Unix(PathBuf)` | Absolute or relative filesystem path | `unix:///run/tidefs/transport.sock` |

### URI parsing

`TransportAddr` implements `FromStr` for round-trip parse/display:

- `TransportAddr::from_str("tcp://0.0.0.0:9100")` → `TransportAddr::Tcp(0.0.0.0:9100)`
- `TransportAddr::from_str("rdma://fe80::1:42:1")` → `TransportAddr::Rdma { gid: [0xfe, 0x80, ...], qpn: 42, service_id: 1 }`
- `TransportAddr::from_str("unix:///run/tidefs/transport.sock")` → `TransportAddr::Unix("/run/tidefs/transport.sock")`

Malformed URIs (missing scheme, invalid IP, empty Unix path, bad GID) return
`AddrParseError` with a descriptive message.

### Carrier dispatch

`TransportAddr::carrier()` returns a `TransportCarrier` enum (`Tcp`, `Rdma`,
`Unix`) so that backends can extract their native address:

```rust
fn bind(&mut self, addr: TransportAddr) -> Result<(), TransportError> {
    let sock_addr = match addr {
        TransportAddr::Tcp(sa) => sa,
        ref other => return Err(TransportError::UnsupportedCarrier {
            carrier: other.carrier().to_string(),
        }),
    };
    // ... bind to sock_addr
}
```

### Integration

- `NodeInfo` stores `Vec<TransportAddr>` instead of `Vec<SocketAddr>`, so a
  node can advertise multiple carrier addresses.
- `TransportBackend::bind()`, `connect()`, `local_addr()`, and `accept()` all
  use `TransportAddr`, eliminating carrier branching in upper layers.
- The send path (#5778), receive path (#5780), and peer admission (#5785)
  consume `TransportAddr` for carrier-agnostic connection setup.


## Flow Control

Credit-based flow control prevents a fast sender from overwhelming a slow
receiver by bounding the number of in-flight bytes per transport stream
through a BLAKE3-verified credit-grant protocol.

### Credit window model

Each stream has a configurable maximum receive window (`max_window_bytes`)
and a low-watermark threshold. The receiver consumes credits as data
arrives; when the available credits drop below the low-watermark, the
receiver automatically sends a `CreditGrant` to refill the window. The
sender must not exceed the granted credits or the stream is in violation.

Default settings:
- Max window: 1 MiB
- Low watermark: 256 KiB (25% of max window)

### BLAKE3 domain separation

Credit grant and credit request frames use separate schema type IDs within
the `FC` (0x4643) domain family, preventing cross-type replay. The wire
format is a fixed 53-byte frame:

```
[magic:4][frame_type:1][stream_id:8 LE][value:8 LE][BLAKE3-256:32]
```

The BLAKE3 digest covers the 21-byte prefix with domain-separated hashing
via `blake3_domain_digest`. Magic bytes are `VFCT`.

### Backpressure integration

The `FlowController` per-stream state machine decrements credits on
receive, issues `CreditGrant` frames when the window drains below the
low-watermark, and validates incoming credit frames with BLAKE3 integrity
checks and stale-sequence rejection. The controller connects to the
send-stream dispatch path so that chunk transmission checks credit
availability before framing.

### API overview

- `CreditWindow` — bounded receive window with configurable max and
  low-watermark
- `FlowControlFrame` — `CreditGrant` and `CreditRequest` variants
- `FlowController` — per-stream state machine with consume/grant/receive
  operations
- `FlowControlError` — `WindowExhausted`, `InvalidCreditFrame`,
  `StaleCreditSequence`, `StreamNotFound`, `UnknownFrameType`
- `encode_flow_control_frame` / `decode_flow_control_frame` — wire format
  encode/decode with BLAKE3 verification

### Follow-on

Wire flow control into the ublk block-volume data path for backpressured
RDMA transfer.

### Per-peer flow control

Token-bucket flow control at the peer level adapts send windows based on
membership health state, preventing buffer bloat to degraded peers and
enabling clean drain on departure.

`SendWindow` implements a per-peer token bucket: tokens represent bytes the
sender is allowed to transmit, refilling at a configurable rate. The
`PeerFlowController` registry manages windows keyed by `MemberId` and
consumes membership state transitions:

| State     | Window action                                      |
|-----------|----------------------------------------------------|
| Alive     | Open, normal refill                                |
| Suspected | Shrink capacity by `suspected_shrink_factor` (0.5) |
| Failed    | Drain remaining tokens (timeout: 30s), then close  |
| Left      | Close window immediately                           |

When a window cannot satisfy an acquire, the controller emits a
`BackpressureSignal` (`WindowExhausted`, `WindowClosed`, or `PeerDrained`).
BLAKE3-256 domain-separated digests (domain
`tidefs-transport-flow-control-v1`) verify window state integrity.

## Message Batching

## Receive Batching

The `RecvBatchDecoder` provides receive-side batch message decoding for
vectored-socket-read dispatch. It scans raw socket-read buffers for complete
length-delimited frames using the canonical 5-byte codec header format
([`crate::codec`]), decodes each frame into a `(MessageFamily, Vec<u8>)` pair
in a single pass, and returns the accumulated batch. Incomplete trailing bytes
are retained in an internal prefix buffer for the next read cycle, avoiding
per-message copy overhead.

### RecvBatchConfig

| Parameter | Default | Description |
|---|---|---|
| `max_batch_size` | 128 | Maximum decoded messages per `feed()` call |
| `min_batch_bytes` | 0 | Minimum raw bytes before processing (0 = always) |

### API

- `RecvBatchDecoder::new(config, codec)` -- create a decoder.
- `RecvBatchDecoder::feed(&[u8])` -- feed raw bytes; returns `Vec<(MessageFamily, Vec<u8>)>`.
- `RecvBatchDecoder::diagnostics()` -- snapshot of `total_bytes_fed`, `frames_emitted`, `malformed_skipped`, `buffered_bytes`.
- `RecvBatchDecoder::reset()` -- discard prefix buffer and reset counters.

### Integration

Attach a `RecvBatchDecoder` to the `ConnectionReceiver` via
`ConnectionReceiver::with_recv_batch(decoder)`. When set, the receive loop
feeds raw socket bytes to the batch decoder instead of the default
`FramingDecoder`. Decoded batches are dispatched to per-channel receive queues
via `MessageDispatch::dispatch_or_warn`.

### Tuning guidance

| Workload | `max_batch_size` | `min_batch_bytes` | Rationale |
|---|---|---|---|
| High-throughput metadata | 256 | 4096 | Aggressive batching; amortize syscalls |
| Latency-sensitive control | 1 | 0 | Single-message; minimal buffering |
| Default (general-purpose) | 128 | 0 | Balanced |


## Send Batching

The `SendBatcher` provides byte-level batching without wire-format framing or
inner hashing. It accumulates raw message payloads for the same peer into
a single `Vec<u8>`, flushing when byte or time thresholds are reached. The
accumulated buffer is then enqueued into the per-peer FIFO send queue
(`PeerSendQueue`) as one unit, reducing per-enqueue syscall overhead.

### BatchConfig

| Parameter | Default | Description |
|---|---|---|
| `max_batch_bytes` | 65536 (64 KiB) | Maximum accumulated bytes before forcing a flush |
| `max_flush_interval` | 200 µs | Maximum time to hold a batch open since its first enqueue |

### API

- `SendBatcher::new(config)` -- create a batcher with the given config.
- `SendBatcher::enqueue(peer, payload)` -- enqueue a message; returns
  `BatchResult::Queued` or `BatchResult::Flushed{peer, bytes}`.
- `SendBatcher::flush_peer(peer)` -- drain a specific peer immediately.
- `SendBatcher::flush_all()` -- drain all peers (deterministic BTreeMap order).
- `SendBatcher::flush_expired()` -- drain only peers whose deadline elapsed.
- `SendBatcher::active_peers()` and `is_empty()` for inspection.

### Flush semantics

A batch is flushed when:
1. The next enqueue would exceed `max_batch_bytes`.
2. `max_flush_interval` has elapsed since the first enqueue for that peer.
3. The caller explicitly invokes `flush_peer()`, `flush_all()`, or
   `flush_expired()`.
4. A single payload exceeds `max_batch_bytes` -- it is flushed immediately
   without accumulation.

### Tuning guidance

| Workload | `max_batch_bytes` | `max_flush_interval` | Rationale |
|---|---|---|---|
| High-throughput metadata | 128 KiB | 1 ms | Aggressive coalescing; latency-tolerant |
| Latency-sensitive control | 4 KiB | 100 µs | Minimal buffering; near-real-time |
| Default (general-purpose) | 64 KiB | 200 µs | Balanced |

The batcher is safe to share across threads (internal `Mutex`). Per-peer
state is kept separate -- enqueuing for peer A never delays or flushes peer B.

## Send Coalescing

The `SendCoalescer` provides session-and-priority-aware message coalescing
in the outbound send pipeline. It accumulates framed messages (with binary-schema
envelope headers) per `(SessionId, SendPriority)` key and flushes them as a
single concatenated byte buffer when byte, count, or deadline thresholds are
reached. The receive-side framing decoder natively handles back-to-back frames,
so the wire protocol is unchanged.

Batching is disabled by default (`CoalesceConfig::enabled = false`), preserving
existing individual-frame send behaviour. Enable by setting `enabled = true` and
configuring thresholds.

### CoalesceConfig

| Parameter | Default | Description |
|---|---|---|
| `max_batch_bytes` | 65536 (64 KiB) | Maximum accumulated framed bytes before flush |
| `max_batch_messages` | 64 | Maximum messages per batch before flush |
| `batch_window` | 200 µs | Maximum time to hold a batch open |
| `enabled` | false | Whether coalescing is active |

### API

- `SendCoalescer::new(config)` -- create a coalescer.
- `SendCoalescer::enqueue(key, frame)` -- enqueue a framed message; returns
  `Some(CoalesceFlush)` on trigger, `None` when queued.
- `SendCoalescer::flush_key(key)` -- flush a specific session/priority batch.
- `SendCoalescer::flush_all()` -- drain all batches.
- `SendCoalescer::flush_expired()` -- drain only expired batches.
- `SendCoalescer::active_batches()` / `is_empty()` / `total_queued()` for inspection.

### Flush triggers

A batch is flushed when:
1. The next enqueue would exceed `max_batch_bytes`.
2. The batch has accumulated `max_batch_messages` messages.
3. `batch_window` has elapsed since the first enqueue for that key.
4. The caller explicitly invokes `flush_key()`, `flush_all()`, or `flush_expired()`.

### Integration

Attach to a `SendPipelineHandle` via `with_send_coalescer()`:

```rust
use tidefs_transport::send_coalesce::{CoalesceConfig, SendCoalescer};

let coalescer = SendCoalescer::new(CoalesceConfig::new(
    65536, 64, Duration::from_micros(200),
));
let handle = SendPipelineHandle::new(state, tx, 256)
    .with_session_id(session_id)
    .with_send_coalescer(coalescer);
```

When attached, `try_send` and `send` methods route frames through the
coalescer automatically. Message deadlines are not coalesced; deadline-aware
send methods bypass the coalescer.

## Send Buffer

Bounded per-peer send buffer management with memory accounting and backpressure
propagation completes the transport resource-management picture for
deterministic multi-node operation.

### PeerSendBuffer

Each peer gets a bounded `VecDeque<Bytes>` with configurable `max_memory`
(default 4 MiB, min 4 KiB, max 64 MiB). When a peer's buffer is full,
`try_enqueue` returns `Backpressure::PeerFull` so the producing subsystem can
slow down or drop rather than growing memory unboundedly.

### Backpressure contract

| Variant    | Meaning                                              |
|------------|------------------------------------------------------|
| `Ok`       | Frame accepted into the buffer.                      |
| `PeerFull` | Buffer at capacity; caller should slow down or drop. |
| `Shutdown` | Buffer has been shut down (peer departed/closed).    |

`PeerFull` is a soft-backpressure signal — distinct from circuit-breaker
open, which is a hard-failure signal.

### Memory accounting

Memory tracking uses plain atomic counters (`AtomicU64`):
- `enqueued` — frames accepted
- `dropped` — frames discarded on drain
- `rejected` — frames rejected due to full buffer
- `rejected_shutdown` — frames rejected due to shutdown

### API overview

- `SendBufferConfig` — configuration with validated `max_memory`
- `PeerSendBuffer` — bounded FIFO queue with `try_enqueue`, `dequeue`,
  `drain`, and `shutdown`
- `Backpressure` — `Ok`, `PeerFull`, `Shutdown` outcomes
- `PeerBufferStats` — lock-free atomic counters with `snapshot()`
- `BufferStatsSnapshot` — point-in-time stat values

Message batch aggregation coalesces multiple small outbound messages destined
for the same peer into a single transport frame, reducing per-frame header
overhead, syscall count, and encryption operations for bursty multi-subsystem
workloads.

### MessageBatch wire format

```
[sequence:8 LE][peer:8 LE][msg_count:4 LE]
[sizes:msg_count*4 LE][payloads:concat][BLAKE3-256:32]
```

The BLAKE3-256 integrity hash is domain-separated with
`tidefs-transport-message-batch-v1` and covers all preceding bytes.

### BatchConfig

- `max_batch_bytes` (default 65536) — maximum bytes of concatenated payloads
  in a single batch.
- `max_batch_messages` (default 64) — maximum number of messages per batch.
- `max_wait` (default 500us) — deadline-driven flush: if a peer has at least
  one queued message and `max_wait` has elapsed since the first enqueue, the
  batch is emitted on the next `drain_ready()` call.
- `enabled` — when `false`, every enqueue immediately returns a single-message
  batch; `BatchConfig::disabled()` provides this preset.

### MessageBatcher API

- `enqueue(peer, payload) -> Option<MessageBatch>` — enqueue a message;
  returns a batch if a flush was triggered (byte or count threshold).
- `drain_batch(peer) -> Option<MessageBatch>` — force-drain the queue for
  a specific peer.
- `drain_ready() -> Vec<(peer, MessageBatch)>` — drain all peers whose
  deadline has expired or whose batch is full.
- `flush_all() -> Vec<(peer, MessageBatch)>` — force-drain every peer with
  queued messages.
- `total_queued() -> usize` — number of messages queued across all peers.
- `active_peers() -> usize` — number of peers with at least one queued message.
- `is_empty() -> bool` — whether all queues are empty.

### Receiver-side reassembly

`MessageBatch::decompose()` splits a decoded batch back into individual
message payloads in enqueue order for dispatch through the existing
`MessageDispatcher`. `MessageBatch::verify()` performs integrity check
without full decode, and `MessageBatch::decode()` verifies and decodes
in one step.

### BLAKE3 domain

Domain string: `tidefs-transport-message-batch-v1`


## Send Barrier

Connection-level send-barrier providing a one-shot flush point that callers
insert into the outbound send pipeline. When the barrier marker is processed
by the send drainer — after all messages enqueued before the barrier have been
dequeued and written to the I/O path — the barrier's completion signal fires.

### Purpose

Subsystems (epoch-commit notifications, membership state updates, lease grants)
can use `request_barrier()` to know when an entire batch of messages has been
delivered before taking the next coordination step, without building ad-hoc
completion tracking per subsystem.

### Ordering guarantee

The barrier completes after all messages that were enqueued before it are
dequeued from the priority scheduler and handed to the I/O path.
The barrier uses only oneshot channels for coordination. Completion
signals are fired when ahead-of-barrier items are dequeued from the
priority scheduler and handed to the I/O path. The existing transport
session security boundary provides message integrity.

### API overview

- **`SendPipelineHandle::request_barrier(priority) -> Result<SendBarrier, SendPipelineError>`** —
  enqueues a barrier marker and returns a handle.
- **`SendBarrier::wait() -> Result<(), BarrierError>`** — async wait for
  completion. Returns `Ok(())` when the barrier fires, or
  `Err(BarrierError::Cancelled)` if the pipeline shuts down first.
- **`SendBarrier::try_wait() -> Option<Result<(), BarrierError>>`** —
  non-blocking poll.
- **`SendBarrier::ahead_count() -> usize`** — informational snapshot of the
  number of items ahead of the barrier at creation time.
- **`OutboundItem`** — enum (`Frame | Barrier`) traveling through the
  pipeline's scheduler with FIFO ordering.

### Integration

The barrier integrates with the send-priority scheduler (`SendScheduler`)
and the outbound send pipeline (`SendPipeline`). The `QueueEntry` internal
enum distinguishes framed data from barrier completion signals so that the
scheduler preserves ordering while carrying barriers through priority-class
sub-queues.

## Delivery Confirmation

Per-message delivery confirmation with per-peer sequence acknowledgment
and send-completion notification. This provides the generic reliability
primitive that intent-log replication, membership proposals, lease operations,
and chunk transfers use to know when their messages are safely delivered.

### Wire format

Acknowledgment frames are 76-byte fixed-size frames:

```
[0..4)    magic       u32 LE ("VDAC" = 0x43414456)
[4..36)   peer_id     [u8; 32]  sender peer identity (BLAKE3 node hash)
[36..44)  ack_seq     u64 LE    acknowledged delivery sequence number
[44..76)  digest      [u8; 32]  BLAKE3-256 domain-separated hash
```

The BLAKE3-256 integrity digest covers the 44-byte plaintext prefix
(magic + peer_id + ack_seq) with domain `tidefs-transport-delivery-ack-v1`
and family `VDAC` (0x56444143), preventing cross-type replay and tampering.

### Send side

Callers opt in by requesting a delivery confirmation channel from a
per-peer `DeliveryTracker`. The returned `DeliverySequence` (monotonic u64)
is embedded in the message envelope flags to signal the receiver that an
acknowledgment is expected.

`DeliveryOutcome` has three variants:

- `Delivered` — the peer acknowledged receipt
- `TimedOut` — the acknowledgment did not arrive within the configured timeout
- `Cancelled` — the delivery tracker was dropped before resolution

### Receive side

After message dispatch completes, `DeliveryConfirmationEngine` constructs
an `AcknowledgmentFrame` and sends it back to the originating peer. Inbound
ack frames are routed through `process_inbound_ack()`, which resolves the
corresponding `DeliveryTracker` entry to `Delivered`.

### API overview

- `DeliverySequence` — monotonic per-peer sequence number (u64)
- `AcknowledgmentFrame` — wire type with encode/decode/verify_full
- `DeliveryTracker` — per-peer `HashMap<DeliverySequence, oneshot::Sender>`;
  supports `register()`, `record_ack()`, `timeout_pending()`, `cancel_all()`,
  and concurrent registrations from multiple sender threads
- `DeliveryConfirmationEngine` — wires send/receive paths together;
  `build_ack_frame()`, `process_inbound_ack()`, `remove_peer()`,
  and `get_or_create_tracker()`

### Timeout and cleanup

`DeliveryTracker::timeout_pending(Duration)` garbage-collects entries older
than the given age, resolving them to `TimedOut`. On session close or peer
departure, `DeliveryConfirmationEngine::remove_peer()` cancels all pending
entries for the departing peer.

### BLAKE3 domain

Domain string: `tidefs-transport-delivery-ack-v1`

## Send Priority Scheduling

Five-class weighted round-robin send-priority scheduler (`SendScheduler`) with
per-class sub-queues, starvation prevention via guard counters, and integration
into the outbound send pipeline. Higher-priority Control and Membership messages
are transmitted before Data and Bulk under backpressure, preventing spurious
peer-failure detection during saturated data channels.

### Priority classes

| Class      | Priority | Weight (default) | Max burst (default) | Use cases                                  |
|------------|----------|-------------------|---------------------|--------------------------------------------|
| Control    | highest  | 10                | 16                  | Membership liveness, epoch transitions     |
| Membership | high     | 6                 | 8                   | Roster changes, peer admission             |
| IntentLog  | medium   | 3                 | 4                   | Intent-log commits, durability barriers    |
| Data       | normal   | 2                 | 4                   | Data transfer, control-plane messages      |
| Bulk       | low      | 1                 | 2                   | Scrub, rebuild, backfill                   |

### Scheduling algorithm

1. **Starvation check** — any message older than `starvation_threshold_ms`
   (default 1000 ms) is dequeued immediately regardless of class, ensuring
   no message stays queued indefinitely.
2. **Weighted round-robin** — each class receives a burst budget proportional
   to its configured weight. The scheduler cycles through classes in priority
   order (Control → Membership → IntentLog → Data → Bulk), dequeuing up to
   `max_burst` messages per turn before advancing.
3. **Empty-queue skip** — classes with empty queues are skipped, and the
   round-robin pointer advances to the next non-empty class with remaining
   budget.
4. **Budget refill** — when all per-class burst budgets are exhausted, the
   scheduler refills all budgets and starts a new round.

### Pipeline integration

The `SendScheduler` lives inside `SendPipeline::run()`. Each loop iteration
drains available messages from the internal mpsc channel into the scheduler,
then dequeues the highest-priority message(s) for transmission. This means
when backpressure eases and the pipeline can send again, higher-priority
messages always go first. The scheduler preserves writev batching by
gathering consecutive scheduler dequeues into a single vectored write.

### Caller guidance

When `SendPipelineHandle::with_session_class()` is called, the default
`send()` and `send_tagged()` methods derive `SendPriority` from the bound
`SessionClass` via `session_class_to_send_priority()`. When no session class
is bound, the fallback is `SendPriority::Data`.

`SessionClass` to `SendPriority` mapping:

| SessionClass           | SendPriority  |
|------------------------|---------------|
| `Bootstrap`, `Control` | `Control`     |
| `ReplicationMeta`, `TransitionOrchestration` | `Membership` |
| `TransferBulk`, `ShadowValidation` | `Bulk`  |

| Subsystem            | Recommended priority |
|----------------------|----------------------|
| Membership heartbeat | Control              |
| Epoch transitions    | Control              |
| Roster changes       | Membership           |
| Peer admission       | Membership           |
| Intent-log commits   | IntentLog            |
| Durability barriers  | IntentLog            |
| Normal file I/O      | Data                 |
| Control-plane RPC    | Data                 |
| Scrub / rebuild      | Bulk                 |
| Backfill             | Bulk                 |

### Configuration

```rust
use tidefs_transport::send_scheduler::{SendScheduler, SendSchedulerConfig};

let config = SendSchedulerConfig {
    control_weight: 10,
    membership_weight: 6,
    intent_log_weight: 3,
    data_weight: 2,
    bulk_weight: 1,
    control_max_burst: 16,
    membership_max_burst: 8,
    intent_log_max_burst: 4,
    data_max_burst: 4,
    bulk_max_burst: 2,
    starvation_threshold_ms: 1000,
};
config.validate().expect("invalid scheduler config");
let mut scheduler = SendScheduler::<Vec<u8>>::new(config);

## Cross-Session Send Scheduling

Cross-session weighted fair queueing scheduler (`CrossSessionScheduler`) that
sits above per-session send pipelines and fairly interleaves send
opportunities across active peer sessions using deficit round-robin.
Without cross-session coordination, a bulk data transfer to one peer can
saturate the local outbound path and starve membership-control or
replication traffic to other peers.

### Weighted Fair Queueing

Each registered session is assigned a configurable weight. The scheduler
tracks a per-session deficit counter, refills deficits each round in
proportion to weight, and picks the session with the largest positive
deficit. Sessions with higher weight receive proportionally more send
opportunities.

### Registration Lifecycle

Sessions register on creation via `CrossSessionScheduler::register(session_id, peer_addr, weight)`
and deregister on teardown via `CrossSessionScheduler::deregister(session_id)`.
The scheduler is held as `Arc<CrossSessionScheduler>` by the transport
runtime. A background scheduling loop calls `schedule_next()` to pick
the next eligible session, then dispatches framed messages from that
session's outbound queue.

### Configuration

```rust
use tidefs_transport::cross_session_scheduler::{CrossSessionScheduler, CrossSessionSchedulerConfig};
use std::collections::HashMap;
use std::net::SocketAddr;

let mut peer_weights = HashMap::new();
peer_weights.insert("192.168.1.10:9090".parse::<SocketAddr>().unwrap(), 4);

let config = CrossSessionSchedulerConfig {
    default_weight: 1,
    max_burst: 8,
    peer_weights,
};
config.validate().expect("invalid cross-session scheduler config");
let scheduler = CrossSessionScheduler::new(config);
```

### Per-peer weight map

The `peer_weights` map enables asymmetric bandwidth allocation:
replication sources can be given higher weight, while backfill targets
receive lower weight to avoid competing with client I/O.

### Interaction with per-session priority scheduling

The cross-session scheduler decides **which session** sends next. Within
a session, the per-session `SendScheduler` decides **which priority class**
goes first. Together they provide two-level hierarchical scheduling:
cross-session WFQ for fairness across peers, then per-session weighted
round-robin for priority within a single session.

## Message Prioritization

Per-session message prioritization (`message_priority` module) provides
head-of-line bypass for control-plane messages within a single session.
Two priority classes are defined:

| Class   | Priority | Use cases                                                |
|---------|----------|----------------------------------------------------------|
| Control | high     | Membership state, leases, epoch transitions, keepalive   |
| Data    | normal   | Object replication, chunk transfer, background scrub     |

### Design

Each session holds a `MessagePriorityQueue<Vec<u8>>` with two independent
FIFO sub-queues. Dequeue drains the Control queue before the Data queue,
with optional starvation prevention (see below). When a `Control`-priority
message is enqueued while `Data` messages are pending, the Control message
skips ahead and is written to the connection first.

### Bounded Control queue

The Control queue has a configurable maximum depth (default 16 messages).
Enqueue beyond this limit returns `MessagePriorityError::ControlQueueFull`
so no single caller can starve the Data queue by flooding Control messages.
The Data queue is unbounded.

### Starvation prevention

When enabled via `MessagePriorityConfig::starvation_prevention_threshold`
(default 0 = disabled), after N consecutive Control dequeues the scheduler
yields one Data message (if available) to prevent indefinite Data starvation
under sustained control traffic. The consecutive-Control counter resets
whenever a Data message is dequeued (either by starvation yield or by
natural fall-through after the Control queue empties).

| Config field                          | Default | Description                                        |
|---------------------------------------|---------|----------------------------------------------------|
| `starvation_prevention_threshold`     | 0       | Consecutive Control dequeues before yielding Data  |

When set to 0 (default, backward-compatible), behavior is unchanged:
Control drains strictly before Data, as in prior releases. Callers that
expect heavy concurrent control and data traffic should set a threshold
(e.g. 8 or 16) to guarantee forward progress for Data.

### API overview

- `Transport::send_message(session_id, payload)` — enqueues at Data priority
  (backward-compatible with existing callers).
- `Transport::send_priority(session_id, payload, priority)` — enqueues with
  explicit `MessagePriority::Control` or `MessagePriority::Data`.
- `MessagePriorityQueue::enqueue(message, priority)` — direct queue access
  for subsystem authors.
- `MessagePriorityQueue::dequeue()` — drains Control-first, then Data.

Both `send_message` and `send_priority` automatically flush the priority
queue after enqueue, writing all pending Control messages before any Data
messages through the standard epoch-barrier, fragmentation, and encryption
pipeline.

### No wire-format changes

Prioritization is a send-side ordering decision only. Receivers process
messages in wire-arrival order as before. No new frame headers, flags,
or protocol negotiation is required.

### Caller guidance

| Message type                      | Recommended priority |
|-----------------------------------|----------------------|
| Membership join/leave/roster      | Control              |
| Lease renewals and epoch fencing  | Control              |
| Keepalive / heartbeat messages    | Control              |
| Coordinator promotion / failover  | Control              |
| Object replication                | Data                 |
| Chunk transfer                    | Data                 |
| Background scrub / rebuild        | Data                 |
| State transfer                    | Data                 |

When in doubt, use `Data` priority. Reserve `Control` for messages whose
delay would cause false failure detection, lease expiry, or membership
timeouts.



## Message Batching

Per-session message batching (`message_batcher` module) coalesces multiple
small outbound messages destined for the same peer into a single wire frame
(a `MessageBatch`), reducing per-frame header overhead, syscall count, and
encryption operations for bursty multi-subsystem workloads.

### Design

Each session can be configured with a `BatchConfig` specifying:

| Field              | Default        | Description                                           |
|--------------------|----------------|-------------------------------------------------------|
| `max_batch_bytes`  | 65536 (64 KiB) | Payload byte threshold before automatic flush         |
| `max_batch_messages` | 64           | Message count threshold before automatic flush        |
| `max_wait`         | 500 us         | Maximum time to wait after first enqueue before flush |
| `enabled`          | false          | When false, every send writes immediately             |

When batching is enabled, `batched_send` enqueues messages into the
session's priority queue (preserving Control/Data ordering) but does
**not** flush immediately. Flushes occur on:

1. **Byte threshold** — next enqueue would push accumulated bytes past
   `max_batch_bytes`.
2. **Count threshold** — batch reaches `max_batch_messages` messages.
3. **Deadline** — `max_wait` elapsed since first enqueue.
4. **Explicit flush** — `flush_batches()` called by the caller (e.g., from a
   background tick or before session teardown).

Each batch is encoded with a BLAKE3 integrity hash and sent as a single
wire frame. The receiver decomposes the batch back into individual message
payloads for dispatch.

### API overview

- `Transport::batched_send(session_id, payload, priority)` — enqueues for
  batching; falls through to `send_priority` when batching is disabled.
- `Transport::flush_batches(session_id)` — drains priority queue through
  the batcher and writes all ready batches.
- `Transport::set_batch_config(session_id, config)` — enable or reconfigure
  batching for an existing session.
- `Session::configure_batching(config)` — session-level configuration (also
  called by `set_batch_config`).
- `MessageBatcher::stats()` — returns `BatchStats` with `messages_batched`,
  `batches_flushed`, and `bytes_batched` counters.

### BatchConfig presets

- `BatchConfig::default()` — 64 KiB / 64 messages / 500 us, enabled.
- `BatchConfig::disabled()` — batching off; every send writes immediately.
- `BatchConfig::new(max_bytes, max_msgs, max_wait)` — custom configuration.

### Caller guidance

| Workload                                      | Recommendation                          |
|-----------------------------------------------|-----------------------------------------|
| Multi-node membership heartbeat / lease renew | Enable with default config              |
| Bursty control-plane message exchange         | Enable with tighter `max_wait`          |
| Latency-sensitive single-message workloads    | Disable (default)                       |
| Bulk data transfer / chunk shipping           | Disable — batching adds framing overhead|

When in doubt, leave batching disabled (the default). Enable it when
profiling shows measurable per-message overhead from many small sends
to the same peer.


## Per-Session Compression

Per-session message compression (`compression` module) reduces wire bandwidth for
multi-node data-plane and control-plane traffic. Compression is applied on the
outbound send path before framing and reversed on the inbound receive path after
opening. The compression layer uses CRC32C-verified frames with a stable wire
format.

### Wire format

```text
[algorithm:1][uncomp_len:4 LE][comp_len:4 LE][payload:n][CRC32C:4 LE]
```

Minimum frame size: 9 header bytes + 4 byte CRC32C = 13 bytes. The CRC32C
checksum covers the algorithm tag, both length fields, and the compressed
payload. CRC32C is hardware-accelerated and sufficient for framing error
detection; the transport MAC provides cryptographic integrity for the transport
payload.

### Supported algorithms

| Algorithm | Wire tag | Description                                |
|-----------|----------|--------------------------------------------|
| None      | 0        | Passthrough (uniform frame format)         |
| Lz4       | 1        | Fast compression via `lz4_flex`            |
| Zstd      | 2        | High-ratio compression via `zstd`          |

Unknown algorithm tags on receive are rejected with `CompressionError`, keeping
the decode path forward-compatible.

### CompressionConfig

`CompressionConfig` governs per-session compression behavior:

-   `algorithm` — the negotiated `CompressionAlgorithm` (default `None`).
-   `threshold` — payloads smaller than this byte count skip compression
    entirely (default 256 bytes).

`CompressionConfig::disabled()` creates a config with `algorithm: None` and
`threshold: 0`.

### CompressionState

`CompressionState` tracks per-session compression statistics:

-   `frames_compressed` / `frames_decompressed` — per-direction frame counters.
-   `total_uncompressed_bytes` / `total_compressed_bytes` — byte counters.
-   `compression_ratio()` — returns `compressed / uncompressed` (1.0 when no
data processed).
-   `reset_counters()` — zeroes all counters while preserving config.

### Session integration

Compression is optional per-session:

-   `Session::set_compression(config)` — enables compression.
-   `Session::disable_compression()` — disables compression.
-   `Session::has_compression()` — queries whether compression is active.
-   `Session::compress_outbound(payload)` — compresses an outbound payload.
-   `Session::decompress_inbound(data)` — decompresses an inbound frame.

When compression is disabled, `compress_outbound` returns the original payload
as-is and `decompress_inbound` returns the input unchanged.

### Transport integration

Compression sits between message dispatch and the epoch-barrier/fragmentation/
encryption pipeline. On the send path (`write_payload_to_session`), outbound
payloads are compressed before epoch-barrier stamping. On the receive path
(`read_payload_from_session` and fragment reassembly), decompression runs after
epoch-barrier unwrapping. This ordering ensures all downstream transforms
operate on compressed bytes, maximizing wire-bandwidth savings.

### Interaction with batching

Compression and batching (`send_batcher`, `message_batcher`) compose correctly:
individual messages are compressed before batched framing. A batch may contain
a mix of compressed and uncompressed frames. The receiver decompresses each
frame independently after batch extraction.

## Send Concurrency Limiting



Per-connection send-concurrency limiting caps the number of in-flight

(sent but unacknowledged) messages per connection, releasing permits on

send-completion acknowledgement. This prevents unbounded per-message

tracking state (completion handles, sequence numbers, buffer slots) when

a burst of sends arrives before any acknowledgement.



### Relationship to queue backpressure and receive-window



- **Queue backpressure** (#5971) bounds the outbound queue depth per

  connection, preventing unbounded queuing.

- **Receive-window** (#5978) bounds receiver-side buffer capacity through

  credit-grant flow control.

- **Send concurrency** bounds the number of messages concurrently in-flight,

  gating entry to the send queue before queue-insertion. Together, these

  three mechanisms bound memory use across all stages of the send pipeline.



### Architecture



```text

Caller

  |

  +-- try_acquire_send_permit() / acquire_send_permit()

       |

       +-- check connection state gate

       +-- acquire semaphore permit (non-blocking or async)

       +-- update high-watermark metric

       +-- return SendPermit (releases on drop or explicit release)

             |

             v

        SendPermit is held during send lifecycle

             |

             +-- Drop (or release()) releases permit back to semaphore

```



### Configuration



`max_inflight` defaults to 256 and is configurable per connection via

`ConnectionManagerConfig::max_inflight`:



```rust

use tidefs_transport::connection::ConnectionManagerConfig;



let config = ConnectionManagerConfig {

    max_inflight: 512,

    ..Default::default()

};

```



### Metrics



| Metric | Description |

|---|---|

| `in_flight_current` | Number of currently held permits (in-flight sends). |

| `in_flight_high_watermark` | Peak in-flight count observed. |

| `permit_wait_count` | Number of times an async acquire waited. |



Access metrics via `ConnectionHandle::send_concurrency_limiter()`.



### API overview



- **`SendConcurrencyLimiter`** — per-connection semaphore-based limiter with

  `try_acquire()`, `acquire()`, and metric accessors.

- **`SendPermit`** — RAII guard that releases the permit on drop or via

  explicit `release()`.

- **`SendConcurrencyError`** — error type covering `LimitExceeded`,

  `ConnectionNotSendable`, and `Shutdown`.

- **`ConnectionHandle::try_acquire_send_permit()`** — non-blocking permit

  acquisition.

- **`ConnectionHandle::acquire_send_permit()`** — async permit acquisition

  with wait-count tracking.




```

## Request Concurrency Limiting

Per-session request concurrency limiting caps the number of in-flight
tracked requests (see [Request-Response Correlation](#request-response-correlation))
within a single session. When the limit is reached, `send_tracked_request`
returns a `TransportError` wrapping a `RequestLimitExceeded` error, providing
caller backpressure without dropping messages or opening the circuit breaker.

### Configuration

The limit is configured through `ResponseTrackerConfig.max_pending`:

- `Some(n)`: at most `n` tracked requests may be in-flight concurrently.
  `n` must be positive; zero is rejected at config-build time.
- `None`: unlimited in-flight requests (subject only to available memory).
  This is useful for low-throughput or single-node setups where backpressure
  is not needed.

Default: `Some(1024)`

### Runtime reconfiguration

- `Transport::set_max_in_flight_requests(session_id, max)` — sets the
  limit for an already-established session.  Already-in-flight requests are
  unaffected; only future `register_request` calls observe the new limit.
- `RequestResponseHandle::set_max_in_flight(max)` — lower-level API for
  callers that hold a handle directly.

### API Overview

- `RequestConcurrencyGuard` — RAII guard that atomically tracks one
  in-flight slot; released on drop (response arrival, timeout expiry,
  or `fail_all`).
- `RequestLimitExceeded` — error type carrying the current count and
  configured limit.
- `RequestResponseHandle::in_flight_count()` — atomic read of current
  in-flight count.
- `RequestResponseHandle::max_in_flight()` — returns the configured limit.


## Connection Admission

The admission controller validates every inbound transport connection against
the membership roster before the peer manager or any message-processing
subsystem sees the connection. This closes the pre-admission gap between
transport accept and peer manager lifecycle.

### Admission flow

1. Transport accept loop receives a new TCP connection.
2. Handshake extracts the peer's claimed identity and epoch.
3. `AdmissionController::admit(peer_id, peer_epoch, &roster)` checks the peer
   against the current roster snapshot.
4. On `Accepted`: the connection proceeds to session setup and peer manager
   integration.
5. On `Rejected`: a `RejectionFrame` with a BLAKE3-attested reason is sent to
   the peer before closing the connection.

### Decision variants

| Decision | Condition |
|---|---|
| `Accepted` | Peer is in roster with state `Alive` and epoch matches |
| `Rejected(NotInRoster)` | Peer identity not found in the roster |
| `Rejected(PeerSuspected)` | Peer is `Suspected` (unreachable, ping timeout) |
| `Rejected(PeerDrained)` | Peer is `Failed` or `Drained` |
| `Rejected(EpochMismatch)` | Peer claims an epoch ahead of the roster |

### Rejection

Admission rejection carries the rejection reason through the authenticated
session context established during handshake. The `ConnectionAdmission`
wrapper emits rejection events to registered subscribers for audit
and operator visibility.

### Rejection frame wire format

```
[ 0.. 4)  magic        "VADM" (4 bytes, ASCII)
[ 4..12)  peer_id      u64 LE
[12..13)  reason       u8 discriminant
```

The rejection reason is carried through the authenticated session context.
No standalone attestation field is needed; integrity is provided by the
transport session security boundary.

### API overview

- `RosterEntry` — simplified roster entry (peer_id, state, epoch)
- `RosterPeerState` — Alive, Suspected, Failed, Drained
- `AdmissionController` — holds state digest, exposes `update_roster()` and
  `admit()`
- `AdmissionDecision` — Accepted or Rejected(reason, attestation)
- `AdmissionRejection` — NotInRoster, PeerSuspected, PeerDrained, EpochMismatch
- `RejectionFrame` — wire-format frame with encode/decode/verify

### ConnectionAdmission gate

The `ConnectionAdmission` struct wraps `AdmissionController` with a cached
roster snapshot and a subscriber dispatch mechanism for rejected-connection
audit events.

- `ConnectionAdmission::new()` / `with_roster()` / `Default` — construction
- `admit(peer_id, peer_epoch) -> Result<(), AdmissionRejection>` — check a
  connecting peer against the cached roster
- `admit_with_frame(peer_id, peer_epoch) -> Result<(), RejectionFrame>` —
  check and produce a wire-format rejection frame on failure
- `update_roster(&[RosterEntry])` / `set_roster(Vec<RosterEntry>)` — update
  the cached roster from membership-layer event subscribers
- `subscribe(Box<dyn ConnectionAdmissionSubscriber>)` — register an audit
  subscriber notified on every rejection

#### Admission rejection events

`ConnectionAdmissionEvent` carries `peer_id`, `claimed_epoch`, and `reason`
for operator audit of unauthorized connection attempts. Subscribers implement
`ConnectionAdmissionSubscriber::on_admission_rejected(&self, &event)` and are
called synchronously on each rejection. Subscribers should be non-blocking;
spawn asynchronous work for long-running audit actions.

#### Transport error variant

`TransportError::AdmissionRejected { peer_id, reason }` enables the transport
accept loop to translate admission rejections into structured errors for
upstream callers.

#### Integration pattern

```text
// In the membership event subscriber (membership-live):
admission_gate.update_roster(&new_roster);

// In the transport accept loop:
match admission_gate.admit(peer_id, peer_epoch) {
    Ok(()) => { /* proceed to session setup */ }
    Err(rejection) => {
        // Subscribers are notified automatically
        return Err(TransportError::AdmissionRejected {
            peer_id,
            reason: format!("{}", rejection.discriminant()),
        });
    }
}
```


## Peer Admission Control

The peer admission gate (`peer_admission.rs`) consults the real membership
epoch member set during transport connection establishment, rejecting
connections from peers not present in the current epoch or in non-active
member states (Draining, Drained, Failed).

### Admission flow

1. The transport accept loop captures an `EpochStamp` representing the
   current epoch.
2. The join handshake (#5782) establishes the peer identity.
3. `AdmissionGate::admit_with_stamp(peer_id, &stamp)` checks the peer
   against the current member set and validates the epoch stamp.
4. On success: an `AdmittedPeer` is returned, carrying the peer identity
   and admission epoch for downstream routing and message dispatch.
5. On failure: an `AdmissionError` identifies the rejection reason.

### Error variants

| Error | Condition |
|---|---|
| `NotAMember` | Peer not present in the current epoch member set |
| `Draining` | Peer is in Draining state and not accepting new connections |
| `Drained` | Peer has been fully drained from the cluster |
| `Failed` | Peer has been confirmed failed |
| `EpochAdvanced { stamped_epoch, current_epoch }` | Epoch advanced past the stamp during handshake; retryable |

### Epoch-generation stamp race

A connection attempt may begin under epoch N but complete under epoch N+1.
If the peer was evicted by epoch N+1, admitting it under epoch N rules is
incorrect. The `EpochStamp` mechanism captures the epoch at connection
initiation; `admit_with_stamp` rejects connections whose stamp is behind
the current epoch with `AdmissionError::EpochAdvanced`, which is retryable.

### Integration with membership layer

`AdmissionGate` bridges directly to `tidefs_membership_epoch::EpochMemberSet`
for member-set lookups, and holds separate `BTreeSet<u64>` collections for
Draining, Drained, and Failed peer IDs. On every epoch transition, the
membership layer calls `AdmissionGate::update_epoch()` to replace the member
set and non-active peer sets.

### API overview

- `EpochStamp` — captured at connection initiation, validated after handshake
- `AdmissionError` — NotAMember, Draining, Drained, Failed, EpochAdvanced
- `AdmittedPeer` — tagged admission result (peer_id, admitted_epoch)
- `AdmissionGate` — holds epoch member set and non-active peer sets;
  exposes `admit()`, `admit_with_stamp()`, `update_epoch()`, and incremental
  `set_draining()`, `set_drained()`, `set_failed()`, `clear_non_active()`
- `EpochStamp::validate()` — checks if the stamp matches the current epoch
## Connection Registry

The connection registry (`connection_registry.rs`) is the central in-memory
bookkeeping structure that tracks every active transport connection by peer
ID and connection ID. It provides lookup for send/receive dispatch, mirrors
lifecycle state transitions, and supports iteration and coordinated
graceful drain.

### Data model

- `ConnectionRegistry` — `HashMap<PeerId, ConnectionEntry>` plus a secondary
  `HashMap<ConnectionId, PeerId>` for reverse lookup, protected by `RwLock`
  for concurrent read-heavy access.
- `ConnectionEntry` — holds the peer ID, connection ID, lifecycle state,
  admitted epoch, and creation timestamp.
- `ConnectionState` — `Connecting`, `Accepted`, `Connected`, `Draining`,
  `Drained`, `Closed`; mirrors the transport connection lifecycle state
  machine (`#5788`).
- `ConnectionId` — unique `u64` identifier per connection.

### Lookup patterns

| Operation | Input | Output |
|---|---|---|
| `get` | peer ID | `Option<ConnectionEntry>` |
| `get_by_conn` | connection ID | `Option<PeerId>` |
| `list_active` | — | `Vec<PeerId>` (Accepted or Connected only) |
| `drain_all` | — | `Vec<ConnectionEntry>` (empties registry) |

### Integration with admission

After `AdmissionGate::admit()` returns `AdmittedPeer`, the caller inserts
the admitted peer into the registry via `ConnectionRegistry::insert()`.
Duplicate peer insertions are rejected with `RegistryError::DuplicatePeer`.

### API overview

- `ConnectionRegistry::new()` — create empty registry
- `insert(&AdmittedPeer, ConnectionId) -> Result<(), RegistryError>` —
  register a newly admitted connection
- `remove(peer_id) -> Result<ConnectionEntry, RegistryError>` — remove and
  return the entry
- `get(peer_id) -> Option<ConnectionEntry>` — look up by peer ID
- `get_by_conn(ConnectionId) -> Option<u64>` — reverse lookup
- `list_active() -> Vec<u64>` — peers in active (Accepted, Connected) state
- `drain_all() -> Vec<ConnectionEntry>` — return all entries, empty registry
- `set_state(peer_id, ConnectionState) -> Result<ConnectionState, RegistryError>` —
  transition lifecycle state
- `len()` / `is_empty()` — inspection

## Connection Lifecycle

The connection lifecycle module (`connection.rs`) provides the connection
substrate for send (#5778) and receive (#5780) paths. It manages TCP and
Unix socket connection establishment, state tracking, graceful drain, and
disconnect operations.

### State machine

Each connection progresses through a forward-only state machine:
`Disconnected → Connecting → Connected → Draining → Disconnected`.

- **Disconnected** — initial and terminal state; no connection exists.
- **Connecting** — outbound connect or inbound accept in progress; transitions
  to Connected on success, Disconnected on failure.
- **Connected** — connection established; can send and receive frames.
- **Draining** — graceful drain in progress; new sends rejected, existing
  in-flight work completes before closing.

Invalid transitions (`Connected → Connecting`, `Draining → Connected`, etc.)
are rejected with `ConnectionError::InvalidStateTransition` carrying both
the from/to states and the peer address when available.

### ConnectionManager

`ConnectionManager<E>` manages a set of connections keyed by `SocketAddr`:

- `connect(peer_addr)` — outbound TCP connect with configurable timeout and
  retry with configurable exponential backoff via the `connection_retry` module.
- `bind(addr)` — bind a TCP listener for inbound connections.
- `accept_one()` — accept a single inbound connection.
- `accept_loop(on_accept)` — accept loop calling `on_accept` per connection.
- `disconnect(peer_addr)` — force-close a connection immediately.
- `drain(peer_addr)` — graceful drain with inflight completion tracking and
  configurable drain timeout.
- `SessionDrainHandle` (session_drain.rs) provides per-session token-based drain
with in-flight completion tracking for membership-eviction session teardown.
- `inflight_inc` / `inflight_dec` — in-flight operation tracking for
  send/receive integration.
- `handle(peer_addr)` — returns a `ConnectionHandle` for state-checked access.


## Connection Retry

The connection retry module (`connection_retry.rs`) provides configurable
exponential-backoff retry for outbound TCP connection establishment with
per-peer attempt coalescing.

### RetryConfig

`RetryConfig` controls retry behaviour:
- `max_attempts` (default 5) — total connection attempts including the first.
- `initial_backoff` (default 100 ms) — first backoff before the second attempt.
- `max_backoff` (default 30 s) — hard cap on computed backoff.
- `backoff_multiplier` (default 2.0) — per-attempt multiplier.
- `connect_timeout` (default 5 s) — per-attempt connect deadline.

The backoff for attempt n (0-indexed) is:
`backoff_n = min(initial_backoff × multiplier^n, max_backoff)`.
The first attempt (n=0) uses zero backoff.

### Error classification

Errors are classified as retryable (ECONNREFUSED, ECONNRESET, ETIMEDOUT,
EHOSTUNREACH, ENETUNREACH, EADDRINUSE, EAGAIN) or terminal (everything else).
Retryable errors trigger backoff and retry; terminal errors abort immediately.

### PeerConnectGate

The `PeerConnectGate` provides per-peer attempt deduplication. When multiple
callers concurrently attempt to connect to the same `SocketAddr`, only one
TCP `connect()` call is in-flight. Waiting callers:
- On success — perform a single `TcpStream::connect()` (no retry needed).
- On failure — receive the shared terminal `RetryError`.

This prevents thundering-herd connection storms after network partitions.

### Integration

`ConnectionManager::connect()` delegates to `connect_with_retry()` using the
`retry_config` field in `ConnectionManagerConfig`. A `PeerConnectGate` is
stored in `ConnectionManagerInner` and shared across all calls.

Configuration is via `ConnectionManagerConfig` with defaults: max 1024
connections, 5s connect timeout, 3 retries, 30s read timeout, 10s drain
timeout.



## Peer Send Queue

The peer send queue (`peer_send_queue.rs`) provides a bounded FIFO send
queue per connected peer, giving upper-layer protocols (membership, leases,
filesystem data) ordered delivery with configurable backpressure.

### Architecture

`PeerSendQueue<M>` manages a registry of queues keyed by `PeerId`. Each
queue consists of a cloneable `PeerQueueSender<M>` (for upper-layer
producers) and a single-consumer `PeerQueueReceiver<M>` (for the transport
send path). The queue is backed by a `VecDeque<M>` under a Tokio async
mutex with notification-based wakeup.

### Backpressure policies

Three policies control behaviour when a peer's queue is at capacity:

| Policy | Behaviour |
|---|---|
| `Block` | Sender waits asynchronously until capacity frees up |
| `DropOldest` | Evicts the oldest message to make room for the new one |
| `Error` | Returns `SendError::Full` immediately |

The default capacity is 256 messages per peer, configurable via
`PeerSendQueue::new(capacity, policy)`.

### API overview

- `PeerSendQueue::sender(peer_id)` -- get or create a cloneable sender handle
- `PeerSendQueue::take_receiver(peer_id)` -- take the single-consumer receiver
- `PeerSendQueue::remove_peer(peer_id)` -- close and remove a peer's queue
- `PeerSendQueue::stats(peer_id)` -- snapshot queue statistics
- `PeerQueueSender::send(msg)` -- enqueue a message (async, policy-aware)
- `PeerQueueSender::try_send(msg)` -- enqueue without blocking
- `PeerQueueReceiver::recv()` -- dequeue the next message
- `PeerQueueReceiver::close()` -- mark the queue closed

### Queue statistics

`QueueStats` tracks `depth` (current queue length), `total_enqueued`, and
`total_dropped` (under `DropOldest` policy). Statistics are available via
`PeerQueueSender::stats()` and `PeerSendQueue::stats(peer_id)`.

### Integration

The peer send queue sits between upper-layer protocol handlers and the
transport send path (#5778). Protocol handlers obtain a sender and call
`send(msg).await`. The transport send path drains each peer's receiver
in a select loop, forwarding messages to frame encoding.

## Send Dispatch

The send dispatch layer (`send_dispatch.rs`) provides per-connection outbound
send dispatch with ordered delivery and backpressure flow control. It fills
the queuing-and-backpressure gap between the send batching layer (upstream)
and the TCP I/O write path (downstream).

### Architecture

```
MessageFamily + payload
       |
       v
SendDispatcher::enqueue(conn_id, msg)
       |
       +-- lookup conn_id -> SendQueue
       +-- enqueue into bounded FIFO queue
       |   (max messages + max bytes guards)
       +-- return Ok or SendError::Backpressure
             |
             v
        SendDrainer per connection
             |
             +-- pull from SendQueue
             +-- feed serialized bytes to TCP I/O write half
             +-- notify blocked producers on capacity free
```

### SendQueue

A bounded FIFO queue per remote connection with configurable limits on both
message count and total byte occupancy. Enqueue returns `Ok(())` or
`SendError::Backpressure` when either threshold is exceeded.

**Configuration** via `SendQueueConfig`:
- `max_messages` (default 256): maximum messages the queue will hold
- `max_bytes` (default 4 MiB): maximum total bytes of payload across all messages

### SendDispatcher

Owns a map of connection ID (`PeerId`) to `SendQueue`. Routes outbound
`OutboundMessage` entries (carrying `MessageFamily` + serialized payload)
to the correct per-connection queue. Queues are created automatically on
first enqueue to a connection. Exposes:

- `enqueue(conn_id, msg)` -- route a message to the correct connection queue
- `remove_connection(conn_id)` -- shut down and remove a connection's queue
- `shutdown_all()` -- shut down all connection queues
- `depth_snapshot()` -- get per-connection queue depths
- `queue(conn_id)` -- borrow a specific connection's queue

### Backpressure signal

`SendError::Backpressure` carries the connection ID, current queue depth
(message count), and current byte depth. This is a non-fatal signal --
callers can inspect the depths and decide whether to delay, drop, or shed
load without tearing down the connection.

| Variant | Meaning |
|---|---|
| `Ok` | Message accepted into the queue |
| `Backpressure { conn_id, depth, byte_depth }` | Queue at capacity; caller should react |
| `NoConnection { conn_id }` | No queue exists for the connection |
| `Shutdown { conn_id }` | Queue has been shut down |

### SendDrainer

A per-connection background task that drains messages from a `SendQueue`
in FIFO order, batches them into `DrainedBatch` entries, and feeds them to
the TCP I/O write half via an mpsc channel. The drainer exits when the queue
is shut down and empty, or when the drain channel closes.

### Integration with send batching and TCP I/O

1. `SendBatcher` (#5803) coalesces small outbound messages into batched
   byte buffers.
2. Batched output is enqueued into `SendDispatcher` per destination connection.
3. `SendDispatcher` routes to the correct per-connection `SendQueue`, applying
   message-count and byte-count backpressure.
4. `SendDrainer` pulls batches from the queue and feeds them to the TCP I/O
   write half (#5822) for wire transmission.

### WritevBatcher

The `WritevBatcher` (introduced in #6005) reduces per-frame `write(2)` syscall
overhead on the transport outbound hot path by coalescing consecutive dequeued
frames into `write_vectored` calls.

#### Design

- Frames destined for the same connection are accumulated into a pending batch.
- When the batch reaches `max_iovec` frames (default 128), it is flushed in a
  single vectored I/O write via `tokio::io::AsyncWriteExt::write_vectored`.
- Barrier markers force a flush before subsequent frames are accumulated.
- Frame ordering is preserved — the batcher never reorders.

#### Configuration

`WritevBatcherConfig { max_iovec: 128 }` controls the maximum iovec count per
`writev` call. Tune `max_iovec` based on replication micro-benchmark validation
once #5995 (replication write-path) lands.

#### Integration

`SendDrainer::run_with_writev` uses the batcher between `SendQueue::dequeue()`
and socket write. This is an alternative dispatch path to `run()` (which uses
mpsc) — choose writev mode for direct-socket low-overhead dispatch, or mpsc
mode when a separate I/O task is desired.


### SendQueueDepth Governance



`send_queue_depth.rs` enforces per-session-class (LaneClass) send-queue depth

caps to prevent unbounded outbound memory growth when a peer connection stalls

or a receiver drains slowly. It closes the depth-governance gap between the

send-concurrency limiter (#5998, bounds in-flight sends) and per-connection

queue backpressure (#5803, bounds per-connection queue depth).



#### Design



- One `SendQueueDepth` is shared across all managed connections (via `Arc`).

- Five independent atomic counters track current queued depth per `LaneClass`

  (Control, Metadata, Demand, Speculative, Background).

- `try_reserve(lane)` atomically checks the configured `max_depth` for that

  lane and increments the counter on success, or returns `SendQueueDepthError`.

- `release(lane)` decrements the counter when a message is drained from the

  queue by `SendDrainer`.

- Ungoverned lanes (`max_depth == 0`) always succeed without tracking.



#### Configuration



`SendQueueDepthConfig` sets per-lane-class `max_depth` bounds:



| Lane        | Default | Rationale                          |

|-------------|---------|------------------------------------|

| Control     | 64      | Command traffic is light           |

| Metadata    | 128     | Publication/log metadata is bounded|

| Demand      | 512     | Foreground fetches, urgent I/O     |

| Speculative | 256     | Shadow compare, warmup             |

| Background  | 1024    | Bulk rebuild, relocation           |



Use `SendQueueDepthConfig::with_lanes()` for selective governance (e.g.

only Control and Demand lanes).



#### Integration



- **Enqueue path**: `SendDispatcher::enqueue()` calls `try_reserve()` before

  enqueueing into the per-connection `SendQueue`. On enqueue failure

  (backpressure/shutdown), the reservation is released immediately.

- **Dequeue path**: `SendDrainer::run()` and `SendDrainer::drain_sync()` call

  `release()` for each dequeued message, decrementing the lane-class counter.

- **Enable**: `SendDispatcher::with_queue_depth(config)` arms governance.

  `SendDispatcher::queue_depth()` returns the `Arc<SendQueueDepth>` for

  passing to `SendDrainer::new()`.



#### Backpressure contract



`SendError::SendQueueFull { lane, depth, max_depth }` is returned when a

lane class is at capacity. This is a non-fatal signal — callers can inspect

the lane and current depth to make load-shedding decisions.


## Session Rekeying

The session rekey engine (`session_rekey.rs`) rotates per-session encryption
keys when membership roster changes occur (peer join, drain, or fail) and on
a configurable periodic interval.

### Trigger types

- `MemberJoin` — a new peer joined the membership roster
- `MemberDrain` — a peer is being gracefully drained from the roster
- `MemberFail` — a peer failed and was removed from the roster
- `PeriodicRotation` — periodic timer fired (no membership change)

### Protocol

1. Initiator sends `RekeyPropose { new_key_hash }` to the peer
2. Responder validates and replies with `RekeyAccept { ack_hash }`
3. Initiator sends `RekeyAcknowledge { confirm }` and activates the new key
4. Old keys remain valid for a configurable drain window (default 5s) to
   allow in-flight messages to complete
5. After drain timeout expires, old keys are retired

### Configuration

| Parameter | Default | Description |
|---|---|---|
| `drain_timeout` | 5s | How long old keys remain valid after rotation |
| `periodic_interval` | 3600s (Some) | Interval for periodic rekey; None disables |
| `max_concurrent_rotations` | 16 | Max simultaneous rekey handshakes |

### BLAKE3 domain

`tidefs-transport-session-rekey-v1`

### API overview

- `SessionRekeyEngine` — per-peer state machine with BLAKE3-256 state digest
- `RekeyConfig` — configuration with validated defaults
- `TransportEpochSubscriber` — canonical trait (from `epoch_bridge`) for receiving epoch transition events
- `RekeyTrigger` — enum identifying what triggered a rekey
- `trigger_rekey(peer, trigger)` — enqueue a rekey for a specific peer
- `on_rekey_accept(peer, key)` / `on_rekey_acknowledge(peer, old_key)` —
  protocol state transitions
- `retire_expired(now)` — retire old keys past the drain window
- `timeout_proposals(timeout, now)` — time out stale proposals
- `check_periodic(now)` — fire periodic rekey if due
- `compute_state_digest()` — BLAKE3-256 digest of entire engine state

## Message Routing

BLAKE3-verified routing table resolves next-hop peers for any destination
node from the membership roster adjacency graph, enabling multi-node message
delivery through intermediate relays.

### RoutingTable

`RoutingTable` computes shortest-path routes via breadth-first search over
the undirected peer adjacency graph.  `self_id` excludes routes to the local
node.  Routes are fully recomputed on every `update()` call.

### RouteEntry

Each route entry carries:
- `next_hop` — the immediate peer to forward messages through
- `path_length` — hop count (1 = direct, >= 2 = relay)
- `digest` — BLAKE3-256 domain-separated digest (domain
  `tidefs-transport-routing-v1`) covering `(destination, next_hop, path_length)`

### API

- `RoutingTable::new()` — create empty table
- `set_self(node)` — set the local node identifier
- `update(active_members, adjacencies)` — recompute routes from fresh
  membership and adjacency data
- `resolve_route(destination) -> Option<&RouteEntry>` — resolve next-hop
- `table_digest() -> [u8; 32]` — BLAKE3-256 digest of full routing state
- `len()` / `is_empty()` / `iter()` — inspection

### Integration

The routing table consumes `MembershipRoster` snapshots (active members) and
peer-manager connection state (adjacencies).  The resolved `next_hop` feeds
into peer-manager session routing for connection-level forwarding of relayed
messages.

### BLAKE3 domain

Domain string: `tidefs-transport-routing-v1`

## Message Deduplication

Per-peer deduplication filter that guarantees exactly-once message delivery at
the transport receiver via a sequence-number sliding window. When a sender
retries a message after a lost ACK, the receiver drops the retry instead of
double-processing state mutations.

### Key types

| Type | Purpose |
|---|---|
| `DedupFilter` | Per-peer deduplication filter keyed by peer ID, with independent sliding windows |
| `DedupFilterConfig` | Configuration: window size (default 1024, clamped \[1, 65535\]), strict vs. lenient mode |
| `DeliveryVerdict` | Outcome enum: `Deliver`, `Duplicate`, or `Stale` |
| `DedupFilterStats` | Aggregate statistics snapshot (delivered, duplicates, stales) |

### Window semantics

Each peer tracks seen sequence numbers in a bitmap-backed sliding window of
configurable size (default 1024). The window covers `[floor, floor + window_size)`:
- Sequence in range and unseen -> `Deliver` and recorded.
- Sequence in range and already seen -> `Duplicate` (drop).
- Sequence below `floor` -> `Stale` (reject in strict mode; deliver-with-warning in lenient mode).
- Sequence at or beyond the window end -> slide window forward, evicting oldest entries.

### Integration guidance for subsystem authors

Call `DedupFilter::check_and_record(peer_id, delivery_seq)` on the receive path
before dispatching to subsystem handlers:

```ignore
match filter.check_and_record(peer_id, msg.header.sequence) {
    DeliveryVerdict::Deliver => dispatch_to_subsystem(msg),
    DeliveryVerdict::Duplicate => trace!("dropping duplicate seq {}", msg.header.sequence),
    DeliveryVerdict::Stale => warn!("stale seq {} below floor", msg.header.sequence),
}
```

Higher layers (intent-log replication, membership broadcast, lease operations)
get exactly-once delivery without per-subsystem sequence tracking.

### BLAKE3 domain separation

State digests use domain `tidefs-transport-dedup-v1` for deterministic
filter-state verification. `DedupFilter::state_digest()` covers
`(peer_count, [(peer_id, floor, bits)])` sorted by peer_id.

## Epoch Event Bridge

Membership-to-transport dispatch bridge (`EpochEventBridge`) that fans out
epoch completion events to all registered transport subsystem subscribers,
keeping per-peer state consistent with the current membership roster after
every epoch transition.

### Architecture

The bridge decouples membership epoch advancement from individual transport
subsystem updates. Instead of each subsystem (send buffer, send scheduler,
delivery confirmation, routing table, connection admission, flow control)
independently polling the membership layer, they implement
`TransportEpochSubscriber` and register with the bridge once.

On each epoch completion:
1. The membership layer calls `EpochEventBridge::on_epoch_completed` with
   the new epoch number, sorted roster, and per-peer deltas.
2. The bridge validates ordering (rejects stale/duplicate epochs, queues
   future epochs for in-order application).
3. Every registered subscriber's `on_epoch_transition` is called with the
   epoch, full roster, and delta list.

### `TransportEpochSubscriber` trait

```rust
pub trait TransportEpochSubscriber: Send + Sync {
    fn on_epoch_transition(
        &self,
        new_epoch: u64,
        roster: &[u64],
        deltas: &[PeerStateDelta],
    );
}
```

Each subscriber receives the complete sorted roster and the per-peer change
list. Four delta variants cover all peer-state transitions:

- `Joined { node_id }` — allocate per-peer resources (routing entry, send
  buffer, flow-control window, delivery tracker).
- `Drained { node_id }` — tear down after draining in-flight work.
- `Failed { node_id }` — immediate cancel, release resources, trigger
  backfill/rebuild.
- `StateChanged { node_id }` — re-validate connections, adjust windows.

### Out-of-order handling

If epoch N+2 arrives before N+1, the bridge inserts N+2 into a sorted pending
queue. When N+1 later arrives, both N+1 and N+2 are dispatched in order.
Rapid epoch churn (up to hundreds of epochs queued) is handled without
dropped notifications.

### BLAKE3 state digest

After each dispatched epoch, the bridge recomputes a BLAKE3-256
domain-separated digest covering `(last_applied_epoch, roster_hash,
subscriber_count)` under domain `tidefs-transport-epoch-bridge-v1`.
This provides deterministic validation of correct bridge operation.

---


## Membership Session Guard

The `membership_guard` module implements a `TransportEpochSubscriber` that
proactively tears down transport sessions to departed peers when the
membership roster changes. It complements `EpochFence` (which marks
connections `Draining` in the `ConnectionRegistry`) by driving actual teardown
through `ConnectionManager`, closing TCP streams and freeing OS resources
without waiting for idle-timeout expiry.

### Architecture

- `MembershipSessionGuard`: a `TransportEpochSubscriber` registered with the
  `EpochEventBridge`. On each epoch transition, the guard updates its
  current-roster snapshot and enqueues teardown requests for peers marked
  `Drained` or `Failed` in the delta list.
- `MembershipSessionGuardRuntime`: a background tokio task that receives
  teardown requests via an mpsc channel, resolves the departed peer's
  transport addresses through `PeerAddressRegistry`, and calls
  `ConnectionManager::drain` (graceful) or `ConnectionManager::disconnect`
  (forced) for each address, avoiding blocking the subscriber dispatch path.

### Lifecycle

1. Create a (`MembershipSessionGuard`, `MembershipSessionGuardRuntime`) pair
   via `MembershipSessionGuard::new(cm, addr_registry)`.
2. Register the guard with the `EpochEventBridge` via
   `bridge.register(Box::new(guard))`.
3. Spawn the runtime as a tokio task via `tokio::spawn(runtime.run())`.
4. On each `Drained` or `Failed` delta from the bridge, the runtime tears
   down sessions to the departed peer.

### Roster gating

The guard maintains a sorted snapshot of the current roster, available via
`MembershipSessionGuard::current_roster()`, `is_member(node_id)`, and
`member_count()`. Call `MembershipSessionGuard::as_roster_verifier()` to
obtain a `GuardRosterVerifier` that implements `MembershipRosterVerifier`,
enabling integration with `SessionEstablishment` for roster-gated connection
admission without a separate membership query.

### PeerDeparted error notification

When a session is torn down due to peer departure, callers with pending
response futures receive `CorrelationError::PeerDeparted` so they can retry
or route around the departed peer immediately instead of waiting for a timeout.

### Relationship to EpochFence

| Component | Layer | Action |
|---|---|---|
| `EpochFence` | Connection registry | Transitions entries to `Draining` |
| `MembershipSessionGuard` | Connection manager | Closes TCP streams / frees OS resources |

## Membership Roster Change to Transport Session Bridge

The `tidefs-membership-live` crate bridges committed membership roster changes
to transport session lifecycle operations through the
`MembershipTransportBridge` + `TransportSessionManager` trait pair. When the
epoch coordinator commits a new epoch view with a changed member set, the
bridge diffs the previous and new rosters and dispatches:

- **Additions**: `register_peer(peer_id, addresses)` calls the transport's
  `connect()` + `perform_handshake()` to proactively establish outbound
  sessions so the new peer is immediately reachable for multi-node message
  delivery. Addresses are resolved from a shared `PeerAddressRegistry` that
  membership populates from join handshakes or configuration.

- **Removals**: `close_peer_sessions(peer_id)` drains in-flight messages with
  a bounded grace period and calls `close_session(sid, PeerRemoved)` for each
  tracked session, complementing the `MembershipSessionGuard` (which acts on
  `ConnectionManager` entries).

### Architecture

| Component | Crate | Role |
|---|---|---|
| `MembershipTransportBridge` | `tidefs-membership-live` | Subscribes to `EpochAdvanceCoordinator`, diffs member sets, dispatches to `TransportSessionManager` |
| `TransportSessionManager` (trait) | `tidefs-membership-live` | Trait with `register_peer` / `close_peer_sessions`; defined in membership, implemented by transport |
| `TransportBridgeManager` | `tidefs-membership-live` | Production `TransportSessionManager` wrapping `Arc<Mutex<Transport>>` |
| `PeerAddressRegistry` | `tidefs-transport` | Shared address registry populated by the join handshake or external config |

### Wiring

Call `MembershipRuntime::wire_membership_transport_bridge(transport, address_registry)`
once during startup after initial peers and transport are configured. The
method creates a `TransportBridgeManager`, constructs a
`MembershipTransportBridge`, seeds the initial member set, and subscribes
the bridge to the `EpochAdvanceCoordinator`. Subsequent epoch commits
automatically drive session establishment and teardown.

### Idempotency

The bridge tracks the previous member set internally. If the same roster is
committed in consecutive epochs, no calls are dispatched. Duplicate additions
or removals for the same peer in the same epoch are coalesced by the BTreeSet
diff.

### Relationship to MembershipSessionGuard

| Component | Trigger | Action |
|---|---|---|
| `MembershipSessionGuard` | `EpochEventBridge` delta | Tears down `ConnectionManager` entries |
| `MembershipTransportBridge` | `EpochAdvanceCoordinator` commit | Registers new peers for session establishment; closes sessions for removed peers |

## Membership Lease Dispatch

The `membership_lease_dispatch` module routes [`tidefs_cluster::MembershipLeaseMessage`]
values through the transport envelope layer using `MessageFamily::LeaseFenceDeadline` (m3).

### Message types carried

| Message | Direction | Purpose |
|---|---|---|
| `MembershipLeaseMessage::Acquire` | Holder → Authority | Request a membership slot lease |
| `MembershipLeaseMessage::AcquireAck` | Authority → Holder | Grant the lease slot |
| `MembershipLeaseMessage::AcquireNack` | Authority → Holder | Deny the lease request |
| `MembershipLeaseMessage::Renew` | Holder → Authority | Extend lease expiration |
| `MembershipLeaseMessage::RenewAck` | Authority → Holder | Confirm renewal |
| `MembershipLeaseMessage::RenewNack` | Authority → Holder | Deny renewal |
| `MembershipLeaseMessage::Release` | Holder → Authority | Voluntarily release the lease |
| `MembershipLeaseMessage::ReleaseAck` | Authority → Holder | Confirm release |
| `MembershipLeaseMessage::ExpireNotify` | Holder → Authority | Notify that lease expired |

### Encode/decode

```rust
use tidefs_transport::{
    encode_membership_lease_message,
    decode_membership_lease_message,
    MembershipLeaseMessageHandler,
    MEMBERSHIP_LEASE_MESSAGE_FAMILY,
};
use tidefs_cluster::MembershipLeaseMessage;

// Encode for transport
let encoded = encode_membership_lease_message(&msg)?;
// Send through transport envelope with family m3

// Decode on the receiving side
let decoded = decode_membership_lease_message(&payload)?;
```

### Wire format

Each message is self-framed: 1-byte discriminant, bincode payload, 32-byte
BLAKE3-256 digest. The transport layer carries these bytes as opaque
payloads inside transport envelopes. All hashing uses domain
`tidefs-cluster-membership-lease-protocol-v1` for cross-domain replay
prevention.

### Integration with state machine

The `MembershipLeaseMessageHandler` trait provides the session-level
dispatch hook. Implementors (typically the `ClusterLeaseRuntime`) receive
decoded messages alongside the transport session they arrived on so
responses can be sent back on the same session.

## Message Dispatch

Family-keyed message dispatch registry that routes decoded transport messages
to subsystem handlers without crate-level coupling. Module
`tidefs_transport::dispatch`, source [dispatch.rs](src/dispatch.rs).

### Purpose

After the receive path decodes transport envelopes and demultiplexes streams,
the decoded message must be routed to the correct subsystem handler
(membership, leases, placement, state transfer, etc.). The `MessageDispatch`
registry maps each `MessageFamily` variant to a boxed `MessageHandler`,
enabling the transport layer to route messages without depending on those
subsystems.

### Architecture

```text
DecodedMessage { family, payload }
  |
  v
MessageDispatch::dispatch(msg)
  |
  +-- lookup family -> Box<dyn MessageHandler>
  +-- handler.handle(msg)
```

### MessageHandler trait

Implementors receive a `DecodedMessage` (family + payload bytes) and return
`Ok(())` or `DispatchError::HandlerError`.

```rust
use tidefs_transport::dispatch::{DecodedMessage, DispatchError, MessageHandler};

struct MyHandler;

impl MessageHandler for MyHandler {
    fn handle(&self, msg: DecodedMessage) -> Result<(), DispatchError> {
        // Process msg.payload based on msg.family
        Ok(())
    }
}
```

### Registry API

`MessageDispatch` uses internal `RwLock<HashMap<MessageFamily, Box<dyn MessageHandler>>>`
and is designed for `Arc<MessageDispatch>` sharing.

```rust
use std::sync::Arc;
use tidefs_transport::{DecodedMessage, MessageDispatch};
use tidefs_transport::envelope::MessageFamily;

let dispatch = Arc::new(MessageDispatch::new());
dispatch.register(MessageFamily::StateTransfer, Box::new(MyHandler));

let msg = DecodedMessage::new(MessageFamily::StateTransfer, payload_bytes);
dispatch.dispatch(msg)?;
```

### DispatchError

| Variant | Meaning |
|---|---|
| `NoHandlerRegistered(MessageFamily)` | No handler registered for the requested family |
| `HandlerError(Box<dyn Error>)` | The registered handler returned an error |
| `StaleFence(StaleFence)` | Write rejected: this node does not hold the active write fence |


### Warning-instrumented dispatch

`MessageDispatch::dispatch_or_warn(msg)` wraps `dispatch` with `tracing::warn!`
instrumentation: unregistered families log a warning instead of returning an
error, and handler errors are logged as warnings. This provides the
no-silent-drop guarantee required by the transport receive path.

```rust
// No handler registered -> tracing::warn! logged, no panic
dispatch.dispatch_or_warn(DecodedMessage::new(
    MessageFamily::ShadowValidation,
    payload,
));
```

### Write-gate integration

`MessageDispatch` optionally carries a `WriteGate` for receive-side single-writer
fencing. When configured, messages arriving on write-gated families
(`ReplicaTransferVerify`, `StateTransfer`) are rejected with
`DispatchError::StaleFence` if the local node does not hold an active write
fence. Construct via `MessageDispatch::new().with_write_gate(gate)`.

### Test builder helpers

Two `#[cfg(test)]` builder methods simplify handler injection in test code:

```rust
use tidefs_transport::dispatch::MessageHandler;

let dispatch = MessageDispatch::new()
    .with_test_handler(MessageFamily::StateTransfer, Box::new(my_handler))
    .with_test_handlers(vec![
        (MessageFamily::HelloClose, Box::new(hello_handler)),
        (MessageFamily::HeartbeatAck, Box::new(hb_handler)),
    ]);
```

Both methods return `Self` for chaining.

### Follow-on

Refactor the receive path demux output to use `MessageDispatch` for typed
handler routing instead of inline match.
## Message Codec

The `codec` module bridges typed [`MessageFamily`] discriminants and opaque
payloads to length-delimited wire byte frames, providing the encode/decode
surface between transport message types and byte-level send/receive framing.

### Wire Format

Every frame is a contiguous byte sequence:

| Offset | Size | Field | Description |
|---|---|---|---|
| 0 | 4 | `payload_len` | u32 little-endian, length of payload only |
| 4 | 1 | `family` | u8 [`MessageFamily`] discriminant (0–9) |
| 5 | N | `payload` | opaque payload bytes |

Total frame size = 5 + payload_len. The codec ignores trailing bytes beyond
the declared payload length on decode, enabling extraction from a stream that
may include subsequent frames.

### Discriminant Assignment

| Discriminant | Variant |
|---|---|
| 0 | `HelloClose` |
| 1 | `HeartbeatAck` |
| 2 | `ElectionControl` |
| 3 | `LeaseFenceDeadline` |
| 4 | `PublicationProgress` |
| 5 | `LogSyncMetadata` |
| 6 | `StateTransfer` |
| 7 | `ReplicaTransferVerify` |
| 8 | `ShadowValidation` |
| 9 | `TransitionHoldResume` |

Discriminants match the `#[repr(u8)]` values of [`MessageFamily`]. Unknown
discriminants (>9) are rejected with [`CodecError::InvalidDiscriminant`].

### Usage

```rust
use tidefs_transport::codec::MessageCodec;
use tidefs_transport::envelope::MessageFamily;

let codec = MessageCodec::default();

// Encode a message
let frame = codec.encode(MessageFamily::StateTransfer, b"chunk-data").unwrap();

// Decode a received frame
let (family, payload) = codec.decode(&frame).unwrap();
assert_eq!(family, MessageFamily::StateTransfer);
assert_eq!(payload, b"chunk-data");
```

### Configuration

`MessageCodec` exposes a configurable `max_frame_size` (default 16 MiB).
Payloads exceeding this limit are rejected at encode time with
[`CodecError::PayloadTooLarge`].

```rust
let codec = MessageCodec::with_max_frame_size(64 * 1024 * 1024); // 64 MiB
```

### Error Handling

[`CodecError`] covers all wire-level failure modes:

| Variant | Condition |
|---|---|
| `PayloadTooLarge { actual, max }` | Payload exceeds configured `max_frame_size` |
| `TruncatedHeader` | Fewer than 5 bytes in receive buffer |
| `TruncatedPayload { declared, available }` | Declared payload length exceeds available bytes |
| `InvalidDiscriminant(d)` | Discriminant byte does not map to a known `MessageFamily` |

The codec is allocation-only — it has no `std`-only dependencies and is
compatible with `no_std` (with `alloc`) environments.


## Request-Response Correlation

The `request_response` module provides a shared correlation table that
tracks in-flight requests by correlation ID, resolves incoming responses
to waiting senders via oneshot channels, and expires timed-out entries.
Upper-layer protocols (membership, leases, placement, state transfer) use
a single `RequestResponseHandle` to register outgoing requests and deliver
incoming responses, eliminating duplicated correlation logic across
subsystems.

### Correlation ID scheme

Each request is assigned a monotonically incrementing `u64` correlation ID
at registration time. The caller embeds this ID in the outgoing message;
the receiver extracts it and calls `deliver_response` to wake the waiter.

### API surface

```rust
use std::time::Duration;
use tidefs_transport::request_response::{
    CorrelationError, RequestResponseTable, TimeoutConfig,
};

// Create a table with capacity 512 entries and a 30-second default timeout.
let table: RequestResponseTable<Vec<u8>> =
    RequestResponseTable::new(512, Duration::from_secs(30));
let handle = table.handle();

// Register before transmitting: gets a correlation ID and a oneshot receiver.
let (correlation_id, rx) = handle.register_request().await.unwrap();

// Deliver when a response arrives: wakes the waiter above.
handle.deliver_response(correlation_id, response_bytes).await.unwrap();

let result = rx.await.unwrap().unwrap();
```

### Timeout expiry

`RequestResponseTable::spawn_timeout_task` starts a background scanner
that periodically evicts entries whose deadline has elapsed, signalling
`CorrelationError::Timeout` to the waiting sender. The scan interval is
configurable via `TimeoutConfig`.

### Capacity

The table enforces a `max_entries` bound. If a protocol attempts to
register a request when the table is full, `register_request` returns
`CorrelationError::TableFull`, providing backpressure to the caller.


### Teardown

When a peer departs and sessions are torn down (via
`MembershipSessionGuard`), `RequestResponseHandle::fail_all(error)` drains
all pending futures with a `CorrelationError::PeerDeparted(member_id)` so
callers receive immediate failure notification instead of waiting for a
timeout.

```rust
// Tear down: complete all pending futures with PeerDeparted.
let failed_count = handle.fail_all(CorrelationError::PeerDeparted(42)).await;
```

### Session Integration

Every [] can carry an optional response tracker. The session
owner calls [] during session establishment,
which creates the correlation table, spawns a background timeout-reaping
task, and stores the handle. Once attached:

- [] registers a new in-flight request
  before the caller transmits an outbound message.
- [] delivers an inbound response payload to
  the blocked caller keyed by correlation ID.
- [] drains all pending entries on
  session drain or close so callers unblock promptly instead of waiting
  for per-request timeout expiry.
- [] stops the background reaper
  when the session transitions to a closed state.

### Configuration

Per-session response tracking is configured through
[] on []:

| Field            | Default   | Description                                       |
|-----------------|-----------|---------------------------------------------------|
| default_timeout  | 30 s     | Per-request deadline after which the caller receives `CorrelationError::Timeout`. |
| reap_interval    | 1 s      | Interval between background scans for expired entries. |
| max_pending      | 1024     | Maximum concurrently in-flight requests per session. |

Builder shorthand methods are available on []:
`response_timeout`, `response_reap_interval`, `max_pending_responses`.

### Session Drain and Close Interaction

When a session is drained ([]) or closed
([]), all pending response entries are
immediately failed with `CorrelationError::Timeout`. This prevents
callers from hanging indefinitely when a peer is evicted or the
connection is torn down.

### Graceful Session Drain

`drain_session_gracefully()` flushes the session's priority send queue
(Control then Data messages per head-of-line bypass ordering) before
closing, bounded by a configurable deadline. This bridges the gap between
immediate teardown (`close_session` with `PeerRemoved`) and
reconnection (`SessionReconnector`): controlled shutdown that lets
in-flight work finish when the caller can afford to wait.

**Configuration** (`GracefulDrainConfig`):

| Field              | Default | Description                                                |
|--------------------|---------|------------------------------------------------------------|
| `deadline`         | 5 s     | Maximum time to wait for the queue to empty.               |
| `poll_interval`    | 10 ms   | How often to check queue depth while draining.             |
| `reject_new_sends` | `true`  | When `true`, `send_message`/`send_priority` return an error while the session is draining. When `false`, new sends are enqueued and drained alongside existing messages. |

Set via `Transport::with_graceful_drain_config(cfg)`.

**Return value** (`DrainOutcome`):

| Variant                                     | Meaning                                                   |
|----------------------------------------------|-----------------------------------------------------------|
| `Completed { messages_drained }`             | Queue emptied before deadline; drain succeeded.           |
| `DeadlineExpired { messages_remaining }`     | Deadline expired with messages still queued.              |
| `AlreadyClosed`                              | Session was already in `Closed` state.                    |

**Drain state query**: `is_session_draining(session_id)` returns `true`
while a graceful drain is in progress.

**Teardown vs. drain decision guide**:

- Use **graceful drain** when a peer is departing cleanly (operator
  maintenance, planned coordinator handoff, coordinated multi-node
  state transitions).
- Use **immediate teardown** (`close_session` with `PeerRemoved`) when
  a peer is unreachable, fenced by epoch advancement, or membership
  eviction requires prompt cleanup.

### Correlation Framing

When the transport layer itself manages the request-response lifecycle,
messages are wrapped with a lightweight correlation frame header so the
receiver can automatically deliver responses without protocol-specific
parsing:



### Send-Side API

[] registers a new in-flight request in
the session's response tracker, frames the payload with a correlation
header, and transmits the framed bytes. The caller receives a
[] that resolves when the peer replies
or the request times out:



The response tracker is auto-created from
[] when a session reaches
[]. If a tracker already exists on the
session, it is reused.

### Receive-Side API

[] checks whether an
inbound message carries a correlation header with the response flag
set. When it does, the payload is delivered through the session's
response tracker to wake the blocked caller, and the method returns
`true`. When the message is not a correlation response (or is a
request), it returns `false` so the caller can dispatch the message
through the normal message-handler path:



### Auto-Creation and Configuration

The response tracker is automatically created on session establishment
using the [] stored on []. Callers
can override the config at any time via
[]; the new config applies to
sessions established after the call. Existing sessions are unaffected.

## Transfer Control Protocol

The transfer control protocol coordinates placement-driven data transfers
between a source node and a destination node. It is consumed by the
`PlacementTransferCoordinator` in `tidefs-cluster`.

### Message flow

```
Coordinator --TransferInitiate--> Source
Source --(data chunks)--> Destination
Destination --TransferChunkAck--> Coordinator
Source --TransferComplete--> Coordinator
Coordinator --TransferAbort--> Source/Destination (on failure)
```

### Types

| Type | Module | Purpose |
|---|---|---|
| `TransferInitiate` | `transfer_control` | Start a transfer from source to destination |
| `TransferChunkAck` | `transfer_control` | Progress acknowledgement from destination |
| `TransferChunk` | `transfer_control` | Data payload chunk from source to destination |
| `TransferComplete` | `transfer_control` | Source signals transfer finished |
| `TransferAbort` | `transfer_control` | Abort transfer and release resources |
| `TransferControlMessage` | `transfer_control` | Unified enum for all message variants |
| `TransferRange` | `transfer_control` | A byte range within an object to transfer |
| `TransferControlError` | `transfer_control` | Encode/decode errors |

### Wire format

```
[1-byte discriminant (0x41-0x45)][bincode payload]
```

Node-to-node authenticity and integrity are provided by the transport/session
security boundary.

### Discriminants

| Value | Name | Direction |
|---|---|---|
| 0x41 | `Initiate` | Coordinator -> Source |
| 0x42 | `ChunkAck` | Destination -> Coordinator |
| 0x43 | `Complete` | Source -> Coordinator |
| 0x44 | `Abort` | Bidirectional |
| 0x45 | `Chunk` | Source -> Destination |

### API

- `TransferInitiate::encode_wire()` / `TransferChunkAck::encode_wire()` /
  `TransferChunk::encode_wire()` / `TransferComplete::encode_wire()` /
  `TransferAbort::encode_wire()` — encode to wire format.
- `decode_transfer_control_message(wire: &[u8])` — unified decoder that
  reads the discriminant and deserializes the appropriate variant.

## Epoch Fence

The `epoch_fence` module bridges membership epoch transitions to transport
connection lifecycle by re-evaluating all active connections against the new
member set after every epoch advance. Connections belonging to peers absent
from the new member set are transitioned to `Draining`.

### Relationship to AdmissionGate

`AdmissionGate` (module `peer_admission`) gates new connection establishments
against the current member set at establishment time. `EpochFence` complements
this by re-evaluating already-active connections when the epoch advances,
catching peers that departed after their connections were already established.

### Architecture

- `EpochTransition`: immutable event carrying the new epoch number, member
  set, and wall-clock timestamp. Published by the membership layer when the
  epoch advances.
- `EpochFence`: holds a `tokio::sync::broadcast` channel and a reference to
  `ConnectionRegistry`. Provides `sender()` for publishing transitions and
  `subscribe()` for consuming them.
- `EpochFenceRuntime`: a tokio task spawned to await transitions on the
  broadcast receiver. On each transition it computes departed peers (active
  in the registry, absent from the new member set) and transitions their
  connection state to `Draining` via `ConnectionRegistry::set_state`.
- `FenceOutcome`: per-peer result enum (`Drained`, `AlreadyDraining`,
  `NoConnection`, `DrainFailed`) for observability.
- `FenceSummary`: aggregate counts by outcome category, suitable for
  operator monitoring.

### Broadcast channel integration

The membership layer clones a `Sender<EpochTransition>` from
`EpochFence::sender()` and calls `send()` whenever the epoch advances.
`EpochFenceRuntime::run()` is spawned as a tokio task that receives
transitions and fences departed peers, returning accumulated outcomes
when the channel closes.

### Graceful error handling

- Peers with no active connection produce `NoConnection`.
- Peers already in `Draining`, `Drained`, or `Closed` produce
  `AlreadyDraining`.
- Registry lookup races (peer removed between lookup and state update)
  produce `DrainFailed`.
- Broadcast channel lag is noted but does not halt the runtime; the
  next received transition is applied normally.

### Review Debt

Wiring `tidefs_cluster::ClusterLeaseRuntime` to publish `EpochTransition`
events into the `EpochFence` broadcast channel when the membership epoch
advances is Review debt TFR-017.

## Epoch Gate

The `epoch_gate` module provides lightweight, per-connection stale-epoch
message rejection. It complements `EpochBarrier` (which provides
fine-grained epoch-stamped wire-format fencing with future-epoch
queuing) by offering a simpler gate that checks incoming message epoch
against a monotonically increasing connection-level barrier.

### Relationship to EpochBarrier and EpochFence

- **EpochBarrier** wraps outbound messages with a full wire format (magic,
  epoch, seq, plen, digest), enforces ordering on receive, and queues
  future-epoch messages for delivery when the barrier advances.
- **EpochFence** transitions departed-peer connections to Draining when the
  membership epoch advances.
- **EpochGate** sits in the receive dispatch hot path and drops stale-epoch
  messages before they reach the message handler. It is connection-scoped
  and does not alter the wire format -- the epoch is read from the envelope
  header's `schema_fingerprint_low` field (bytes 48..56, u64 LE).

### API

- `EpochGate::new(initial_epoch)` -- create a gate starting at a given epoch.
- `EpochGate::at_zero()` -- create a gate starting at epoch 0.
- `current_epoch() -> u64` -- return the current gate epoch.
- `set_epoch(new_epoch)` -- advance the gate (panics on non-monotonic update).
- `check(message_epoch) -> Result<(), EpochRejected>` -- validate an inbound
  message epoch. Returns `Err(EpochRejected { current_epoch, received_epoch })`
  when the message epoch is behind the gate. The per-gate `stale_epoch_rejected`
  `AtomicU64` counter is incremented on each rejection.
- `rejected_count() -> u64` -- return the total stale-epoch rejections.

### Integration

`EpochGate` is attached to `ConnectionReceiver` via `with_epoch_gate(gate)`.
In `dispatch_frames`, after the message family is decoded, the envelope
header's epoch field is checked: stale messages are dropped with a warning
log and counted as `ProtocolViolation` telemetry errors. The membership
subscriber bridge calls `set_epoch` on epoch-commit events to advance the
gate.

## Connection Keepalive

**Default-off policy**: Keepalive is disabled by default (`TransportConfig::keepalive` is `None`). Single-node FUSE/ublk mounts must not run keepalive. Multi-node cluster deployments require explicit opt-in via `TransportConfig::with_keepalive()` or `ConnectionRegistry::enable_keepalive()`. As of 2026-05-28 no production path enables keepalive; cluster membership dead-peer detection does not yet consume live transport keepalive signals.

Transport-layer connection keepalive with heartbeat failure detection
prevents silent TCP connection failures (firewall timeouts, NIC hangs,
virtualized network partitions) from going undetected without relying on
membership gossip timeouts. The implementation provides two complementary
engines and a session-scoped integration wrapper.

### Dual-engine design

The keepalive module provides two independent liveness-detection engines
that serve different operational needs:

- **HeartbeatTracker** -- BLAKE3-verified ping/pong heartbeat with a
  Healthy/Suspect/Dead/Reconnecting state machine. Sends pings on every
  configured interval regardless of data-plane activity. Suitable for
  dedicated keepalive channels where continuous liveness proof is required.

- **KeepaliveEngine** -- Idle-timeout-driven probing that only sends probes
  when the connection has been idle (no received data) for
  `idle_timeout`. This avoids wasting bandwidth on connections that are
  actively transporting data -- the data itself proves liveness.

### HeartbeatTracker state machine

```
Healthy --(miss)--> Suspect(n) --(miss threshold)--> Dead
   ^                      |                              |
   |                      +--(ack received)--------------+
   |                                                      |
   +-----------(reconnect success)-- Reconnecting <-------+
```

| State | Meaning |
|---|---|
| `Healthy` | No missed heartbeats; connection is alive. |
| `Suspect(n)` | `n` consecutive missed heartbeats (n < miss_threshold). Receiving a valid pong returns to Healthy. |
| `Dead` | `miss_threshold` consecutive misses reached. Connection is lost; reconnection must be initiated. |
| `Reconnecting` | Reconnection in progress. On success returns to Healthy with reset counters. |

### KeepaliveEngine state machine

```
Idle --(idle_timeout elapsed)--> Probing --(probe ack'd)--> Idle
                                     |
                                     +--(max_missed_probes exceeded)--> Failed
```

| State | Meaning |
|---|---|
| `Idle` | Connection is active; no probing in progress. Receiving data resets the idle timer. |
| `Probing { missed }` | Probing in progress; `missed` consecutive probes unanswered. Data receipt returns to Idle. |
| `Failed` | Peer is considered dead after exceeding `max_missed_probes`. |

### Configuration

**HeartbeatConfig** -- BLAKE3-verified ping/pong heartbeat:

| Field | Type | Default | Description |
|---|---|---|---|
| `interval` | `Duration` | 1 s | Interval between heartbeat pings |
| `miss_threshold` | `u32` | 5 | Consecutive missed pongs before declaring Dead |

**KeepaliveEngineConfig** -- idle-timeout-based keepalive:

| Field | Type | Default | Description |
|---|---|---|---|
| `idle_timeout` | `Duration` | 30 s | Inactivity duration before first probe |
| `probe_interval` | `Duration` | 5 s | Interval between successive probes |
| `max_missed_probes` | `u8` | 3 | Max unanswered probes before declaring Failed |

Both configs validate at construction: zero durations and zero counts are
rejected. `KeepaliveEngineConfig::new()` returns `Option<Self>` (None on invalid
input); `validate()` returns `Result<(), &'static str>`.

### Wire format

Heartbeat ping/pong frames are 44-byte fixed-size frames:

```
[0..4)   magic        "VKPL" (4 bytes, ASCII)
[4..12)  seq          u64 LE (monotonic sequence number)
[12..44) digest       BLAKE3-256 of magic || seq with domain separation
```

Ping and pong use different domain-separated BLAKE3 hashes (family `KP`,
type 1 for ping, type 2 for pong), preventing ping-to-pong replay.

Keepalive probe/response frames are 40-byte frames (no magic prefix):

```
[0..8)   seq          u64 LE (monotonic sequence number)
[8..40)  digest       BLAKE3-256 of seq with domain separation
```

Probes and responses use family `KQ` (0x4B51), types 1 and 2 respectively,
with domain `tidefs-transport-keepalive-probe-v1`.

Sequence numbers are monotonic u64 values that persist across resets and
reconnections so the remote peer always sees strictly increasing numbers.

### SessionKeepalive integration

`SessionKeepalive` wraps `HeartbeatTracker` for per-session keepalive
management. It maps the internal `HeartbeatState` to a `KeepaliveHealth`
classification:

| Health | HeartbeatState mapping |
|---|---|
| `Alive` | `Healthy` or newly activated (no pings sent yet) |
| `Degraded` | `Suspect(n)` -- missed some heartbeats, still recoverable |
| `Dead` | `Dead` -- exceeded miss threshold |

The session calls `on_ping_sent()` before each outbound heartbeat and
`on_pong_received()` on each valid inbound pong. `activate()` resets the
tracker and records the activation timestamp; `deactivate()` clears
active state on teardown.

### ReconnectOrchestrator

`ReconnectOrchestrator` wraps the existing `ReconnectState` from
`crate::reconnect` and adds keepalive-aware scheduling: exponential
backoff with jitter, configurable max retries, and a backoff cap. It
integrates with `HeartbeatTracker::start_reconnect()` and
`reconnect_success()` to drive the Dead to Reconnecting to Healthy transition.

### BLAKE3 domain separation

All keepalive frames use domain-separated BLAKE3-256 hashing:

| Component | Family | Type | Domain |
|---|---|---|---|
| Heartbeat ping | `KP` (0x4B50) | 1 | `SectionBody` |
| Heartbeat pong | `KP` (0x4B50) | 2 | `SectionBody` |
| Keepalive probe | `KQ` (0x4B51) | 1 | `SectionBody` |
| Keepalive response | `KQ` (0x4B51) | 2 | `SectionBody` |

### API overview

- `HeartbeatConfig` -- heartbeat interval and miss threshold configuration
- `HeartbeatState` -- Healthy / Suspect(n) / Dead / Reconnecting state enum
- `HeartbeatTracker` -- per-connection runtime tracker with `record_ping_sent()`,
  `record_pong()`, `record_miss()`, `start_reconnect()`, `reconnect_success()`,
  `should_ping()`, `has_ping_timed_out()`
- `KeepaliveEngineConfig` -- idle-timeout-based configuration with validated
  construction
- `KeepaliveState` -- Idle / Probing { missed } / Failed state enum
- `KeepaliveEngine` -- idle-timeout-driven engine with `record_activity()`,
  `should_send_probe()`, `send_probe()`, `record_missed_probe()`,
  `record_response()`, `is_peer_dead()`, `reset()`
- `KeepaliveHealth` -- Alive / Degraded / Dead classification
- `SessionKeepalive` -- per-session wrapper with `activate()`, `deactivate()`,
  `health()`, `on_ping_sent()`, `on_pong_received()`, `is_active()`,
  `should_ping()`
- `ReconnectOrchestrator` -- keepalive-aware reconnect with `next_backoff()`,
  `is_exhausted()`, `reset()`, `attempt()`
- `encode_ping()` / `encode_pong()` / `decode_ping()` / `decode_pong()` --
  BLAKE3-verified wire encode/decode for heartbeat frames
- `build_probe()` / `build_response()` / `validate_pong()` / `detect_failure()` --
  probe/response wire format and failure detection
- `KEEPALIVE_MAGIC` / `KEEPALIVE_FRAME_SIZE` / `KEEPALIVE_PROBE_SIZE` --
  wire format constants

### Integration with connection lifecycle

The keepalive engine integrates with the connection lifecycle state machine
(#5788) through `ConnectionManagerConfig`, `ConnectionEntry`, and
`ConnectionRegistry`:

- `ConnectionManagerConfig::keepalive_config` accepts an
  `Option<config::KeepaliveConfig>`. When `Some`, a per-connection
  `KeepaliveLifecycle` is created (via `From` conversion) and armed on
  connection establishment for both outbound (`connect()`) and inbound
  (`accept_one()` / `accept_loop()`).
- `ConnectionEntry.keepalive` stores `Option<KeepaliveLifecycle>`.
- `ConnectionRegistry::enable_keepalive()` arms the registry for per-peer
  keepalive tracking. `record_activity()` and `on_keepalive_pong()` are
  called by the I/O runtime read path on every successfully decoded frame
  and HeartbeatAck pong, respectively.
- `read_task()` checks the local keepalive engine state before
  auto-responding: when the engine is Idle (not expecting a pong), the
  inbound frame is treated as a ping and a pong is sent back; when the
  engine is Probing (expecting a pong), the inbound frame is a response
  and no auto-reply is needed, preventing an infinite ping-pong loop.
- `ConnectionManager::spawn_keepalive_tick_loop()` spawns a tokio
  background task that periodically calls `tick_keepalive()` (default every
  1 s), sends pending ping frames through each connection's stream, and drains
  connections whose keepalive has declared the peer dead. Returns `None` when
  keepalive is not configured.
- `ConnectionRegistry::spawn_keepalive_tick_loop()` provides the same
  background tick for the `ConnectionRegistry` path.
- On dead-peer detection (`KeepaliveState::Failed`), the connection
  lifecycle transitions to `Draining` via the `tick_keepalive()` path.
- When keepalive is not configured (`keepalive_config = None`), no
  `KeepaliveLifecycle` is created and `tick_keepalive()` skips the
  connection — no-op overhead for single-node mounts.

## Transport Validation Validation

Two-node deterministic round-trip validation (issue #5819) exercises the
transport dispatch path end-to-end through the `TwoNodeHarness`:

- **8 scenarios**, 8 PASS, 0 FAIL
- Validation tier: multi-process distributed
- Covers: single-message roundtrip, ordered multi-message dispatch,
  bidirectional interleaved dispatch, drain-and-reconnect continuity,
  send-queue backpressure, large payload fidelity (up to 16kB),
  unknown-family graceful skip, and deterministic replay.

**Reproduce**:
```sh
cargo test -p tidefs-validation -- \
  scenario_01_single_message_roundtrip \
  scenario_02_ordered_multi_message \
  scenario_03_bidirectional_dispatch \
  scenario_04_drain_reconnect_continuity \
  scenario_05_backpressure_bounded_capacity \
  scenario_06_large_payload_roundtrip \
  scenario_07_unknown_family_handling \
  scenario_08_deterministic_replay
```

**Validation output**:
`crates/tidefs-validation/validation/transport-two-node-roundtrip.md`

## Async I/O Runtime

The async I/O runtime (`io_runtime.rs`) bridges the transport connection
lifecycle, peer send queues, and message dispatch registry to actual TCP
socket I/O, enabling the transport crate to accept connections, read framed
messages from peers, and write queued outbound messages to peer sockets.

### Architecture

```
TcpListener ──(accept)──▶ TcpStream
                             │
             ┌───────────────┴───────────────┐
             ▼                               ▼
        read_task()                    write_task()
             │                               │
    decode frame ────▶ dispatch         dequeue from PeerSendQueue
        via MessageDispatch                 encode frame
                                              write to TcpStream
```

### Wire format

Each frame on the wire is a 5-byte header followed by a variable-length
payload:

```
[0]       family    u8   MessageFamily discriminant
[1..5]    len       u32  big-endian payload length
[5..]     payload   [u8] variable-length payload
```

Maximum frame payload size is 16 MiB (`MAX_FRAME_PAYLOAD`).

### IoRuntime lifecycle

1. Create an `IoRuntime` with a `TransportConfig`.
2. Call `bind(addr: &TransportAddr)` to obtain a `TcpListener`.
3. Call `accept_loop(listener, registry, dispatch, send_queues, encode)`
   to accept connections and spawn both per-connection read and write tasks.
   The `send_queues` parameter is an `Arc<Mutex<PeerSendQueue<Vec<u8>>>>`
   that provides a `PeerQueueReceiver` for each peer's write task.
   Upper-layer protocols obtain `PeerQueueSender` handles from the same
   `PeerSendQueue` to enqueue outbound messages.

The read task decodes framed messages and routes them through
`MessageDispatch`.  The write task drains the peer's `PeerSendQueue`
and writes framed messages to the socket using the `encode` function
supplied to `accept_loop`.

### API overview

- `IoRuntime::new(config)` — create a new I/O runtime
- `IoRuntime::bind(addr)` — bind a TCP listener
- `IoRuntime::accept_loop(listener, registry, dispatch, send_queues, encode)` —
  accept loop that spawns both read and write tasks per connection
- `IoRuntime::spawn_write_task(write_half, peer_id, receiver, encode)` —
  spawn a standalone peer write task (for external stream management)
- `IoRuntime::spawn_write_task_from_stream(stream, peer_id, receiver, encode)` —
  convenience wrapper that splits a full `TcpStream`
- `IoRuntime::connect(addr, registry, dispatch, send_queues, encode)` —
  establish an outbound TCP connection, returning a [`ConnectionHandle`]
- `encode_frame(family, payload)` / `decode_frame(data)` — frame encode/decode
- `read_frame(stream)` / `write_frame(stream, family, payload)` — async
  frame I/O over `TcpStream`

### Error types

`IoError` covers bind, accept, read, write, frame-size, unknown message
family, dispatch, unsupported carrier, connect, and registry errors.  `IoError`
implements `From<DispatchError>` and `From<RegistryError>` for ergonomic
error propagation.

### Integration

- Accept loop registers connections in `ConnectionRegistry` with synthetic
  `AdmittedPeer` entries; upper-layer admission gates (#5785) filter.
- Read tasks dispatch decoded messages through `MessageDispatch`.
- Write tasks are spawned automatically by accept_loop once a
  `PeerQueueReceiver` is obtained from the shared `PeerSendQueue`.
- Graceful drain: when `PeerQueueReceiver::recv()` returns `None` (queue
  closed), the write task performs `shutdown()` and exits.
- The read task transitions the connection to `Drained` state in the
  registry on clean EOF or read error.

## Connection Accept

The `TransportListener` provides the server-side accept path for multi-node
transport. It binds a TCP socket from a `TransportAddr` and blocks on
`accept()` until a new connection arrives, returning a `TransportConnection`
that supports the same frame-oriented read/write as outbound connections.

### TransportListener API

- `TransportListener::bind(addr: TransportAddr) -> Result<TransportListener>`
  Binds a TCP socket to the given address. Only the `Tcp` variant is
  supported; RDMA and Unix addresses return `UnsupportedCarrier`.

- `TransportListener::accept(&mut self) -> Result<TransportConnection>`
  Blocking accept that returns an established connection wrapped as a
  `TransportConnection`.

- `TransportListener::local_addr(&self) -> TransportAddr`
  Returns the bound address for discovery.

- `TransportListener::set_nonblocking(&self, nonblocking: bool)`
  Enables non-blocking accept mode.

### TransportConnection

`TransportConnection` wraps a `std::net::TcpStream` and implements
`ConnectionLike`, making it compatible with the epoch fence, keepalive
engine, and message codec machinery. It exposes:

- `peer_addr() -> SocketAddr` — the remote peer's address
- `read_frame() -> Result<Vec<u8>>` — read a length-delimited frame
- `write_frame(data: &[u8]) -> Result<()>` — write a length-delimited frame
- `close()` — shutdown the connection

### Integration

Accepted connections feed into the same connection lifecycle as outbound
connections established via `TcpTransport::connect()`. After acceptance,
`TransportConnection` can be wrapped in a `Box<dyn ConnectionLike>` and
passed to the epoch fence, keepalive, and codec layers without special
handling.

For async/tokio-based connection management, see `ConnectionManager` in the
[`connection`] module.
## Channel Multiplexing

`channel.rs` provides per-connection channel-ID multiplexing at the transport
message layer. Multiple logical channels can share a single transport
connection without head-of-line blocking, so bulk-data state transfer and
control messages (membership, leases, heartbeat) operate independently.

### ChannelId

A unique per-connection identifier. `ChannelAllocator` hands out sequential
`ChannelId` values starting at 1. ID 0 is reserved (no channel). All 65535
IDs are available; exhaustion returns `ChannelError::AllocatorExhausted`.

```rust
let mut table = ChannelTable::new();
let bulk_ch    = table.open()?;   // ChannelId(1), state: Opening
let ctrl_ch    = table.open()?;   // ChannelId(2), state: Opening
table.activate(bulk_ch)?;        // bulk_ch now Active
```

### Lifecycle state machine

Each channel moves through four states:

| State   | Can send | Can receive | Meaning |
|---------|----------|-------------|---------|
| Opening | no       | no          | Allocated; peer ack pending |
| Active  | yes      | yes         | Usable for send/receive |
| Closing | no       | yes         | Graceful close in progress |
| Closed  | no       | no          | Terminal state |

State transitions:

```
open() --> Opening --activate()--> Active --close()--> Closing --finalize_close()--> Closed
                \                                                              /
                 \---- reset() -----------------------------------------------/
                                    Active --reset()--> Closed
```

### Per-channel byte counters

`ChannelEntry` tracks `bytes_sent` and `bytes_received` (saturating u64).
`ConnectionHandle::channel_send()` validates the channel is Active and records
the byte count atomically. `channel_record_recv()` records received bytes.

### Integration with DecodedMessage

`DecodedMessage` now carries an `Option<ChannelId>` field. When a message
arrives on a multiplexed channel, the receive path sets `channel_id` so
subsystem handlers can distinguish bulk data from control traffic on the
same connection.

```rust
let msg = DecodedMessage::with_channel_id(
    MessageFamily::StateTransfer,
    payload,
    bulk_ch,
);
```

### ChannelEnvelope: tagging outbound messages



`ChannelEnvelope` wraps a raw payload with an optional `ChannelId` for

the send path. Upper-layer protocols create envelopes via

`ChannelEnvelope::on_channel()` to tag messages for a specific channel,

or `ChannelEnvelope::new()` for connection-wide (untagged) messages.

Envelopes flow through the per-peer send queue and the receive side

extracts the channel ID to build a `DecodedMessage::with_channel_id()`.



```rust

let env = ChannelEnvelope::on_channel(bulk_ch, payload);

send_queue.try_send(env)?;

```


### Shared access

`ChannelTable` is wrapped as `SharedChannelTable` (`Arc<RwLock<ChannelTable>>`)
for concurrent access from multiple `ConnectionHandle` clones. Attach via
`ConnectionHandle::with_channel_table()`.

```rust
let table = new_shared_channel_table();
let handle = ConnectionHandle::new(peer_addr, manager)
    .with_channel_table(table.clone());
```

### Relationship to stream_mux

`stream_mux.rs` handles wire-level framing (magic bytes, per-stream sequence
numbers, backpressure signaling). `channel.rs` operates one layer above at
the transport message level: it tags `DecodedMessage` with channel IDs so
that the message dispatch and subsystem handlers can route independently
without duplicating the wire framing.

### ChannelMultiplexer: lifecycle-gated send bridge

`ChannelMultiplexer<S>` bridges channel lifecycle management with the
per-peer send queue. It enforces that only channels in `Active` state
can send, records `bytes_sent` atomically, and wraps payloads in
`ChannelEnvelope` for transport delivery.

```rust
let table = new_shared_channel_table();
let mux = ChannelMultiplexer::new(table.clone(), send_queue_sender);

// Open and activate channels
let bulk_ch = mux.open_channel()?;
let ctrl_ch = mux.open_channel()?;
mux.activate_channel(bulk_ch)?;
mux.activate_channel(ctrl_ch)?;

// Send on specific channels
mux.try_send_on_channel(bulk_ch, bulk_payload)?;
mux.try_send_on_channel(ctrl_ch, ctrl_payload)?;

// Untagged messages (connection-wide)
mux.try_send_untagged(global_payload)?;
```

The multiplexer is generic over the sender type via the
`ChannelEnvelopeSender` trait. `PeerQueueSender<ChannelEnvelope>`
implements this trait, as does any mock sender for testing.

```rust
let handle = ConnectionHandle::new(peer_addr, manager);
let mux = handle.build_channel_multiplexer(send_sender)
    .expect("channel table auto-created");
let ch = mux.open_channel()?;
mux.activate_channel(ch)?;
mux.try_send_on_channel(ch, payload)?;
```

#### Receive-side bridge

On the receive path, use `envelope_to_decoded_message()` to convert
drained `ChannelEnvelope` items into `DecodedMessage` instances with
the channel ID set for dispatch:

```rust
while let Some(env) = recv_queue.recv().await {
    let decoded = envelope_to_decoded_message(env, family);
    dispatch.dispatch(decoded)?;
}
```

### Active Connection Initiation

`IoRuntime::connect` establishes an outbound TCP connection to a peer.
It resolves a `TransportAddr` to a `SocketAddr`, calls
`TcpStream::connect`, registers the peer in the `ConnectionRegistry`
and `PeerSendQueue`, and spawns the same per-connection read and write
tasks that `accept_loop` uses for inbound connections.  It returns a
`ConnectionHandle` carrying the `peer_id` and `ConnectionId` for
lifecycle tracking.

#### Signature

```rust
pub async fn connect<F>(
    &self,
    addr: &TransportAddr,
    registry: Arc<ConnectionRegistry>,
    dispatch: Arc<MessageDispatch>,
    send_queues: Arc<Mutex<PeerSendQueue<Vec<u8>>>>,
    encode: Arc<F>,
) -> Result<ConnectionHandle, IoError>
where
    F: Fn(&[u8]) -> (MessageFamily, Vec<u8>) + Send + Sync + 'static + ?Sized;
```

#### Parameters

| Parameter | Role |
|---|---|
| `addr` | Peer address to connect to (`TransportAddr::Tcp` only). |
| `registry` | Shared connection registry for lifecycle tracking. |
| `dispatch` | Message dispatch for decoded inbound frames. |
| `send_queues` | Shared peer send-queue registry; the caller obtains a `PeerQueueSender` from this after `connect` returns for outbound messages. |
| `encode` | Function mapping a `&[u8]` payload to `(MessageFamily, Vec<u8>)` for wire framing. |

#### Returns

`ConnectionHandle` with:

- `peer_id: u64` — derived from the remote `SocketAddr` (same hash as
  `accept_loop` uses).
- `connection_id: ConnectionId` — registry-local connection identifier.

#### Errors

- `IoError::UnsupportedCarrier` — the `TransportAddr` is not a `Tcp`
  variant.
- `IoError::Connect` — the TCP `connect` syscall failed (refused, timeout,
  unreachable).
- `IoError::Registry` — the connection registry rejected the insertion
  (duplicate peer, internal error).

#### Relationship to accept_loop

`connect` and `accept_loop` are symmetric:

- `accept_loop` binds a `TcpListener` and accepts inbound connections.
- `connect` initiates an outbound connection via `TcpStream::connect`.

Both paths register the peer identically in the registry and send-queue
map, and both spawn the same `read_task` and `write_task_impl` per
connection.  Upper-layer code treats accepted and initiated connections
uniformly — the transport does not distinguish between passive and
active open after the connection is established.

#### Usage example

```rust
let rt = IoRuntime::new(config);
let addr = TransportAddr::Tcp("192.168.1.42:9100".parse().unwrap());
let handle = rt.connect(
    &addr,
    Arc::clone(&registry),
    Arc::clone(&dispatch),
    Arc::clone(&send_queues),
    Arc::clone(&encode_fn),
).await?;

// Enqueue a message to the connected peer.
let mut sq = send_queues.lock().await;
let sender = sq.sender(handle.peer_id).unwrap();
sender.send(b"hello".to_vec()).await.unwrap();
```


## Backpressure Enforcement

Per-channel send-queue depth tracking and backpressure enforcement prevent
unbounded memory growth under receiver slowdown. Each channel independently
tracks in-flight message depth, with configurable per-channel limits and a
stall threshold that feeds the connection health score (#5885).

### Acquire/Release Protocol

Before enqueuing a message for send, callers acquire a `SendSlot` via
`BackpressureController::try_acquire_send_slot(channel)`. On success, the slot
represents reserved capacity in the channel send queue. Callers must release
the slot via `release_send_slot` after the send pipeline completes (success or
failure) so the depth counter is decremented.

```rust
use tidefs_transport::backpressure::{
    BackpressureController, ChannelBackpressureConfig,
};
use tidefs_transport::channel::ChannelId;

let config = ChannelBackpressureConfig {
    max_depth: 128,
    stall_threshold_fraction: 0.75,
    byte_budget: None,
};
let mut ctrl = BackpressureController::new(config);
let ch = ChannelId::new(1);

let slot = ctrl.try_acquire_send_slot(ch)
    .expect("send slot available");
// ... enqueue message for send ...
ctrl.release_send_slot(slot);
```

When the channel is at capacity, `try_acquire_send_slot` returns
`Err(BackpressureRejected { channel, current_depth, limit })`. The caller
should back off or propagate the error, which maps to
`TransportErrorKind::BackpressureStall` in the error classification taxonomy.

### Configuration

| Field | Type | Default | Description |
|---|---|---|---|
| `max_depth` | `usize` | 256 | Maximum in-flight messages per channel |
| `stall_threshold_fraction` | `f64` | 0.75 | Fraction of `max_depth` at which the channel is flagged stalled |
| `byte_budget` | `Option<usize>` | `None` | Optional per-channel byte budget for size-aware gating |

The stall threshold determines when a channel is considered stalled for
health-score purposes. It is clamped to [0.0, 1.0] with a minimum stall depth
of 1 (unless `max_depth` is 0).

### Byte Budget

When `byte_budget` is `Some(n)`, acquires also consume from a per-channel
byte counter. Use `try_acquire_send_slot_with_hint(channel, byte_hint)` to
deduct a payload-size estimate. This enables gating large payloads
independently of the message-count limit.

### Backpressure Snapshot

`BackpressureController::backpressure_snapshot()` returns a read-only
`BackpressureSnapshot` with per-channel `ChannelSnapshot` entries (depth,
high_watermark, stalled, byte_usage), total depth, and stalled-channel count.
This snapshot is consumed by the connection health score aggregator (#5885)
to incorporate backpressure depth as a multi-signal input.


### Connection-Level Outbound Backpressure

`OutboundBackpressure` wraps `BackpressureController` with connection-level
high-watermark tracking, callback dispatch, and mode enforcement.

**Configuration** via `OutboundBackpressureConfig`:

| Field | Type | Default | Description |
|---|---|---|---|
| `high_watermark` | `usize` | 1024 | Total queue depth across all channels that triggers backpressure |
| `mode` | `BackpressureMode` | `Notify` | Enforcement: `Notify`, `Block`, or `DropTail` |

**Enforcement modes**:
- `Notify`: Sends always accepted; `BackpressureCallback` fires on threshold
  crossing and queue drain. Poll via `backpressure_status()`.
- `Block`: `try_acquire` returns `Err(WouldBlock)` above high-watermark.
- `DropTail`: `try_acquire` returns `Err(WouldBlock)` above high-watermark;
  caller sheds oldest message. `dropped_count()` tracks total drops.

**ConnectionHandle API**:
- `backpressure_status() -> Option<BackpressureStatus>` — poll depth, hwm, under-pressure flag
- `register_backpressure_callback(cb)` — register for transition notifications
- `try_acquire_send_slot(ch, hint) -> Result<SendSlot, WouldBlock>` — acquire slot under backpressure
- `release_send_slot(slot)` — release slot

**SendPipelineHandle API**:
- `with_backpressure(bp)` — attach shared backpressure manager
- `backpressure_status() -> Option<BackpressureStatus>` — poll from send handle
- `try_send_backpressure()` / `try_send_backpressure_with_priority()` —
  non-blocking send returning `SendPipelineError::WouldBlock` under backpressure

Integrates with send-completion (#5923), send-barrier (#5967), and peer
liveness (#5958) for full transport flow control.

### Per-Connection Lifecycle

One `BackpressureController` is instantiated per transport connection during
setup and torn down (via `reset()`) on disconnect. Every send submission
consults the controller before the message enters the send pipeline (#5880).


## Send-Side Backpressure

Send-side backpressure propagates per-priority queue-depth signals from the
send pipeline drain loop to upstream callers so they can asynchronously await
capacity instead of busy-polling or dropping messages under transient
congestion.

### SendWatermarkConfig

Each [`SendPriority`] class (Control, Membership, IntentLog, Data, Bulk) gets
independent high/low watermarks expressed as queue-depth counts. When a priority
queue depth reaches or exceeds its high watermark, the capacity signal flips to
*full*. When it drains to or below the low watermark after being full, the
signal flips back to *available*. A high watermark of 0 disables backpressure
for that class.

Default watermarks:
- Control: 48 high / 16 low
- Membership: 96 high / 32 low
- IntentLog: 128 high / 48 low
- Data: 192 high / 64 low
- Bulk: 192 high / 64 low

### SendCapacitySet and SendCapacity

[`SendCapacitySet`] owns five `tokio::sync::watch` channels — one per priority
class — and transitions them based on queue depth observed after each dequeue
in the send pipeline drain loop.

[`SendCapacity`] is a per-priority handle obtained via
`SendCapacitySet::capacity(pri)`. It provides:
- `is_available() -> bool` — synchronous poll without waiting.
- `wait_for_capacity()` — async, resolves when the queue drains below the low
  watermark or immediately if already available.

Watermark transitions are checked in [`SendPipeline::run`] after each primary
and batched dequeue from the priority scheduler (`SendScheduler`). The current
queue depth for the dequeue priority class is fed to
`check_after_dequeue(pri, depth)`.

### Handle Integration

[`SendPipelineHandle`] exposes:
- `with_capacity_set(cs)` — attach a custom [`SendCapacitySet`].
- `send_capacity(pri)` — obtain a [`SendCapacity`] handle for the given
  priority class.
- `try_send_with_backpressure(family, pri, payload, deadline)` — enqueues
  immediately if capacity permits; otherwise awaits `wait_for_capacity()` then
  enqueues, respecting the message send deadline.

A default [`SendCapacitySet`] is created automatically when a [`SendPipeline`]
is constructed, so all transport sessions get backpressure signals without
explicit configuration.


## Connection Initialization Handshake

After a raw TCP connection is established (accept or connect) but before the
message dispatch pipeline runs, peers negotiate protocol compatibility and
exchange node identity via a two-message Hello/HelloAck handshake.

### Exchange

```
Initiator (connect side)          Responder (accept side)
     │                                    │
     │──── Hello(v=1, my_node_id) ──────▶ │
     │                                    │ validate version, record peer
     │ ◀── HelloAck(v=1, peer_node_id,    │
     │           accepted=true) ───────── │
     │                                    │
     ▼                                    ▼
   Active                               Active
```

### Messages

```rust
pub enum HandshakeMessage {
    Hello {
        protocol_version: u32,
        node_id: u64,
    },
    HelloAck {
        protocol_version: u32,
        node_id: u64,
        accepted: bool,
    },
}
```

### Protocol version

The handshake uses a single protocol version constant (`HANDSHAKE_PROTOCOL_VERSION = 1`).
Both sides must agree on the exact version. A mismatch results in a refused
handshake (`accepted = false`) and connection close.

### Wire format

Handshake messages are serialized with bincode and wrapped in the existing
`MessageCodec` wire format using `MessageFamily::HelloClose` as the family
discriminant. Total overhead per handshake message: 5 bytes codec header +
bincode payload.

### State machines

`HandshakeInitiator` drives the connecting (client) side: builds a `Hello`,
waits for `HelloAck`, validates version and `accepted` flag.

`HandshakeResponder` drives the listening (server) side: waits for `Hello`,
validates version, replies with `HelloAck` (accepting or rejecting).

Both track per-connection lifecycle through `ConnectionInitState`:
`Pending` → `Handshaking` → (`Active` | `Failed`).

### Error handling

On handshake failure (version mismatch, peer rejection, timeout, or wire
error), the connection transitions to `Failed` and the caller should close
the TCP stream. Errors are surfaced as `ConnectionInitError` variants.

## Error Classification and Recovery

Systematic classification of connection-level errors (TCP resets, timeouts,
protocol violations, backpressure stalls) into a typed taxonomy with
per-error-type recovery action dispatch. Replaces ad-hoc error handling
across the I/O runtime, send dispatch, and keepalive modules.

### TransportErrorKind — Error Taxonomy (10 variants)

| Variant              | Cause                                               |
|----------------------|-----------------------------------------------------|
| `ConnectionReset`    | TCP RST from peer (`ECONNRESET`, `EPIPE`)          |
| `ConnectionRefused`  | No listener on peer port (`ECONNREFUSED`)           |
| `ConnectionTimeout`  | Connection timed out (`ETIMEDOUT`)                  |
| `ProtocolViolation`  | Bad magic, version mismatch, unexpected sequence    |
| `ChannelClosed`      | Multiplexed channel closed by remote peer           |
| `BackpressureStall`  | Outbound send queue at capacity (soft signal)       |
| `KeepaliveTimeout`   | Heartbeat timeout; peer unreachable                 |
| `MessageTooLarge`    | Frame exceeds `MAX_FRAME_PAYLOAD` (16 MiB)         |
| `UnknownMessageFamily` | Unrecognized `MessageFamily` discriminant on wire |
| `InternalError`      | Assertion, allocation, or logic failure (fallback)  |

### RecoveryAction — Recovery Dispatch (5 actions)

| Action               | Behavior                                           |
|----------------------|----------------------------------------------------|
| `CloseConnection`    | Immediately close the connection                   |
| `DrainAndClose`      | Drain pending writes gracefully, then close        |
| `Retry { backoff }`  | Retry operation after the given backoff duration   |
| `ReportToMembership` | Report error to membership for peer-liveness       |
| `Ignore`             | Transient error, no action needed                  |

### Default Error-Kind-to-Action Mapping

| Kind                    | Default Action         |
|-------------------------|------------------------|
| `ConnectionReset`       | `CloseConnection`      |
| `ConnectionRefused`     | `CloseConnection`      |
| `ConnectionTimeout`     | `ReportToMembership`   |
| `ProtocolViolation`     | `CloseConnection`      |
| `ChannelClosed`         | `Ignore`               |
| `BackpressureStall`     | `Retry { backoff: 10ms }` |
| `KeepaliveTimeout`      | `DrainAndClose`        |
| `MessageTooLarge`       | `CloseConnection`      |
| `UnknownMessageFamily`  | `CloseConnection`      |
| `InternalError`         | `CloseConnection`      |

### Observer Integration

The `ErrorObserver` trait provides a pluggable callback notified on every
classified error with its dispatched recovery action. Implementations can
log, increment counters, feed membership liveness trackers, or emit
structured telemetry. A default `TracingErrorObserver` logs via
`tracing::warn!`.

```ignore
use tidefs_transport::error_classification::{
    ErrorClassifier, RecoveryDispatcher, TracingErrorObserver,
};
use std::sync::Arc;

let classifier = ErrorClassifier::new();
let observer = Arc::new(TracingErrorObserver::default());

// In an I/O task:
let transport_err = classifier.classify(io_error, conn_id);
let action = DefaultRecoveryDispatcher.dispatch(&transport_err);
observer.on_error(&transport_err, action);
```

### I/O Runtime Wiring

The `IoRuntime` carries an `ErrorClassifier` and `Arc<dyn ErrorObserver>`.
Both the `read_task` and `write_task_impl` per-connection tasks classify
errors on their error paths, dispatch recovery actions, notify the
observer, and apply connection state changes (`CloseConnection` →
`ConnectionState::Closed`, `DrainAndClose` → `ConnectionState::Drained`).

`SendDispatcher::enqueue` maps send errors (`SendError`) through the
classifier: `Backpressure` maps to `BackpressureStall`, `NoConnection` maps
to `InternalError`, `Shutdown` maps to `InternalError`.

## Receive Loop

The per-connection async receive loop bridges raw TCP socket reads to typed
message dispatch. It runs after the connection initialization handshake (#5840)
completes and feeds decoded messages into the inbound router (#5834).

### Architecture

```
TcpStream (read half)
  |
  v
ConnectionReceiver::recv_loop()
  |
  +-- tokio::io::read -- framing buffer
  |                         |
  |                         v
  |              FramingDecoder::feed()
  |                         |
  |                         v
  |                  Vec<FramedMessage>
  |                         |
  |     +-------------------+-------------------+
  |     v                                       v
  |  family_id -> MessageFamily            type_id -> ChannelId
  |     |                                       |
  |     +-------------------+-------------------+
  |                         v
  |                  DecodedMessage
  |                         |
  |                         v
  |              MessageDispatch::dispatch_or_warn()
```

### Frame format

Each frame on the wire uses the canonical binary-schema envelope header (64
bytes) followed by the payload body. The framing is provided by
`tidefs-binary_schema-framing`, which handles length-delimited frame
extraction, partial-read accumulation, multi-frame coalescing, and corruption
resynchronization.

| Field | Bytes | Description |
|---|---|---|
| magic | 0..4 | u32 LE "VBFS" (0x5346_4256) |
| family_id | 4..12 | u64 LE: TRANSPORT_FAMILY_ID_BASE + MessageFamily discriminant |
| type_id | 12..20 | u64 LE: channel stream-ID (lower 16 bits = ChannelId; 0 = untagged) |
| version | 20..24 | u16 major (1), u16 minor (0) |
| flags | 24..28 | u32 LE: reserved (0) |
| section_count | 28..30 | u16 LE: reserved (0) |
| total_body_bytes | 32..40 | u64 LE: payload length |
| header_crc32c | 60..64 | u32 LE: CRC32C of bytes [0..60) |
| payload | 64.. | variable-length message payload |

### Integration points

- **Upstream**: The receive loop is spawned after connection handshake (#5840)
  completes and runs until connection teardown (#5854).
- **Downstream**: Decoded messages are dispatched through
  `MessageDispatch::dispatch_or_warn()` (#5834).
- **Channel demux**: The channel stream-ID is extracted from the envelope
  `type_id` field and attached to `DecodedMessage::channel_id` for per-channel
  delivery (#5827).

### Graceful shutdown

On TCP EOF (peer closed write half), the receive loop drains any remaining
complete frames from the decoder buffer and dispatches them before returning.
Partial frames (incomplete header or body) are silently discarded. On
unrecoverable I/O errors, the loop logs a warning and returns the error.

### Error handling

Unknown message family IDs in the envelope header are dropped with a
`tracing::warn!` log and do not terminate the loop. Only I/O errors cause
the loop to exit.

## Peer Health Scoring

The `peer_health` module fuses keepalive round-trip latency, error-
classification event rate, channel backpressure depth, and queue drain
velocity into a single weighted health score in [0.0, 1.0]. The score
drives smarter connection-lifecycle decisions and enriches the membership
heartbeat protocol with a continuous health signal instead of binary
alive/dead detection.

### HealthSignal — Multi-signal inputs (5 variants)

| Signal | Source | Meaning |
|---|---|---|
| `KeepaliveRtt(Duration)` | `keepalive.rs` | Round-trip latency of last ping-pong cycle. Lower is better. |
| `ErrorRate(f64)` | `error_classification.rs` | Classified error events per second. Lower is better. |
| `BackpressureDepth(usize)` | `send_dispatch.rs` | Outbound queue depth in messages. Lower is better. |
| `DrainVelocity(f64)` | `receive_loop.rs` | Messages drained per second. Higher is better. |
| `ConnectionUptime(Duration)` | connection start | Time since connection establishment. Higher is better. |

### SignalWeight — Per-signal configuration

Each signal has a weight (0.0–1.0, default sum = 1.0) and an EMA decay
half-life. The half-life controls how quickly old measurements lose
influence: α = 1 − 2^(−Δt / half_life).

Default weights:

| Signal | Weight | Half-life |
|---|---|---|
| Keepalive RTT | 0.30 | 30 s |
| Error rate | 0.25 | 60 s |
| Backpressure depth | 0.20 | 15 s |
| Drain velocity | 0.15 | 30 s |
| Connection uptime | 0.10 | 300 s |

### HealthTier — Discrete classification

| Tier | Range | Meaning |
|---|---|---|
| Healthy | [0.7, 1.0] | Normal operation; membership heartbeat interval nominal. |
| Degraded | [0.3, 0.7) | Stressed but usable; membership heartbeat interval halved. |
| Unhealthy | [0.0, 0.3) | Connection should be drained or replaced. |

Tier transitions require the new tier to be sustained for a configurable
duration (default 5 s) before a `ConnectionHealthEvent::TierTransition` is
emitted, preventing flapping from transient signal spikes.

### HealthScoreConfig — Builder configuration

```rust
let cfg = HealthScoreConfig::new()
    .with_keepalive_rtt(0.30, Duration::from_secs(30))
    .with_error_rate(0.25, Duration::from_secs(60))
    .with_backpressure_depth(0.20, Duration::from_secs(15))
    .with_drain_velocity(0.15, Duration::from_secs(30))
    .with_connection_uptime(0.10, Duration::from_secs(300))
    .with_thresholds(0.7, 0.3)
    .with_sustain_duration(Duration::from_secs(5));
```

### HealthScoreRegistry — Per-connection tracking

`HealthScoreRegistry` maps `ConnectionId` → `PeerHealthAggregator` and
exposes:

- `ingest(conn_id, signal) → Option<f64>` — auto-registers on first use.
- `get(conn_id) → Option<&PeerHealthAggregator>` — read-only lookup.
- `poll_all() → Vec<ConnectionHealthEvent>` — poll all connections for tier
  transitions after sustain duration.
- `register(conn_id)` / `remove(conn_id)` — lifecycle management.

### Integration hooks

Each signal source provides a feed method that accepts a `&mut dyn
HealthSignalSink`:

- **keepalive**: `HeartbeatTracker::feed_health_rtt(sink, conn_id)` emits
  `KeepaliveRtt` from the most recent ping-pong cycle.
- **error_classification**: `ErrorRateTracker` tracks a sliding window of
  error timestamps; `feed_health_rate(sink, conn_id)` emits the current
  error rate as `ErrorRate`.
- **send_dispatch**: `SendDispatcher::feed_health_backpressure(peer_id, sink)`
  emits the current per-connection queue depth as `BackpressureDepth`.
- **receive_loop**: `DrainVelocityTracker` samples diagnostic counters
  periodically; `feed_health_drain(sink, conn_id)` emits the EMA-smoothed
  drain velocity as `DrainVelocity`.
- **backpressure** (#5891): `BackpressureController::backpressure_snapshot()`
  provides per-channel depth snapshots consumable by the health scoring
  system.

### Lifecycle integration

`PeerHealthLifecycleSubscriber` implements `LifecycleSubscriber` to
auto-register/remove connections in the `HealthScoreRegistry`:

- On `LifecycleEvent::Active`: calls `registry.register(conn_id)`.
- On `LifecycleEvent::Closed` / `DrainComplete`: calls `registry.remove(conn_id)`.

Instantiate one subscriber per connection and register it with the
connection's `LifecycleBus`.

```rust
use tidefs_transport::peer_health::{
    new_shared_registry, PeerHealthLifecycleSubscriber, HealthScoreConfig,
};

let registry = new_shared_registry(HealthScoreConfig::default());
let sub = PeerHealthLifecycleSubscriber::new(conn_id, registry.clone());
lifecycle_bus.subscribe(Box::new(sub));
```

### Connection lifecycle and membership

- **connection state machine** (#5869): reacts to
  `ConnectionHealthEvent::TierTransition` for drain/reconnect decisions via
  `HealthScoreRegistry::poll_all()`.
- **membership heartbeat** (#5875): uses the continuous health score to
  adjust heartbeat deadlines instead of binary alive/dead detection.



## Connection Lifecycle

The connection state machine provides authoritative lifecycle governance
for transport connections, enforcing valid transitions and emitting structured
events for downstream subsystems (error recovery, membership bridging, receive
loop).

### State Graph

```
Disconnected ──► Connecting ──► Handshaking ──► Active
     ▲               │                │              │
     │               ▼                ▼              ▼
     ◄──────── Disconnected ◄──────────┘          Draining
                                                       │
                                                       ▼
                                                    Closed
```

### ConnectionState — Six canonical states

| State          | Description                                         |
|----------------|-----------------------------------------------------|
| `Disconnected` | No connection exists; starting state.               |
| `Connecting`   | TCP connect in progress; awaiting completion.       |
| `Handshaking`  | Connection established; Hello/HelloAck in progress. |
| `Active`       | Fully established; normal message flow permitted.   |
| `Draining`     | Graceful drain in progress; no new sends.           |
| `Closed`       | Connection closed; terminal state.                  |

### Valid Transitions

| From           | To             | Notes                              |
|----------------|----------------|------------------------------------|
| `Disconnected` | `Connecting`   | Connection initiation.             |
| `Connecting`   | `Handshaking`  | TCP connect succeeded.             |
| `Connecting`   | `Disconnected` | Connect failed or refused.         |
| `Handshaking`  | `Active`       | Handshake completed successfully.  |
| `Handshaking`  | `Disconnected` | Handshake failed or rejected.      |
| `Active`       | `Draining`     | Graceful shutdown initiated.       |
| `Active`       | `Disconnected` | Connection reset or forced close.  |
| `Draining`     | `Closed`       | Drain complete; all writes acked.  |

All other transitions return `InvalidTransition`. `Closed` is terminal; no
outbound transitions are permitted.

### Lifecycle Events

`ConnectionLifecycle::transition_to()` emits a `LifecycleEvent` carrying a
monotonic generation number:

| Event               | Emitted on                                   |
|---------------------|----------------------------------------------|
| `ConnectStarted`    | Any transition into `Connecting`/`Handshaking` |
| `Active`            | Transition into `Active`                     |
| `DrainStarted`      | `Active` → `Draining`                        |
| `DrainComplete`     | `Draining` → `Closed`                        |
| `Closed`            | Any other transition into `Closed` or `Disconnected` |
| `HandshakeComplete` | Available for handshake-complete signaling.  |

### Query Methods

- `is_active()` — true when state is `Active`.
- `can_send()` — true in `Active` | `Draining`.
- `can_receive()` — true in `Handshaking` | `Active` | `Draining`.
- `generation()` — current monotonic generation counter.

### Subscriber Integration

`LifecycleBus` fans out lifecycle events to registered `LifecycleSubscriber`
implementations. Subscribers are called synchronously in registration order
on each `broadcast()` call.

```ignore
use tidefs_transport::connection_state::{
    ConnectionLifecycle, ConnectionState, LifecycleBus, LifecycleSubscriber,
};

let mut lifecycle = ConnectionLifecycle::new();
let mut bus = LifecycleBus::new();
bus.subscribe(Box::new(my_error_recovery_subscriber));
bus.subscribe(Box::new(my_membership_bridge_subscriber));

match lifecycle.transition_to(ConnectionState::Active) {
    Ok(event) => bus.broadcast(&event),
    Err(e) => tracing::warn!("Invalid transition: {}", e),
}
```

Subscribers can be removed by concrete type (`unsubscribe_by_type::<T>()`)
or by index (`unsubscribe_by_index(idx)`).

### Integration Points

- **Error recovery** (#5860): Consumes `Closed`, `DrainStarted` events to
  drive `RecoveryAction::CloseConnection` and `DrainAndClose` dispatch.
- **Membership bridging** (#5854, #5867): Consumes lifecycle events to
  teardown/establish transport connections on epoch peer transitions.
- **Receive loop** (#5861): Queries `can_receive()` to decide whether to
  continue the read loop; watches for `DrainStarted` to drain remaining
  frames before shutdown.

## Outbound Send Pipeline

The outbound send pipeline (`outbound_send` module) provides the data-plane
path from message submission through length-delimited framing to raw TCP
socket writes, complementing the inbound [`Receive Loop`](#receive-loop).

### Architecture

```text
MessageFamily + payload
       |
       v
SendPipelineHandle::send(family, payload)
       |
       +-- check connection state gate (Accepted/Connected/Draining ok)
       +-- frame via SendFramer (binary-schema envelope + payload)
       +-- push framed bytes into mpsc channel
             |
             v
        SendPipeline::run()
             |
             +-- drain mpsc receiver, batch frames
             +-- writev gather-output to TcpStream (write half)
             +-- loop until channel closed
```

### Frame format

Frames use the canonical binary-schema envelope header (64 bytes) followed
by the payload body, matching the format decoded by the receive loop's
`FramingDecoder`. The header carries `total_body_bytes` (u64 LE at offset
32) which the decoder uses to delimit frames.

### Connection state gating

Sends are gated by the connection lifecycle state via
`SendPipelineHandle::send()`:

| State      | Send allowed? |
|------------|---------------|
| Connecting | No            |
| Accepted   | Yes           |
| Connected  | Yes           |
| Draining   | Yes           |
| Drained    | No            |
| Closed     | No            |

### writev batching

When multiple frames are queued in the mpsc channel, the pipeline drains up
to `max_batch_frames` (default 64) in one pass and writes them via vectored
I/O (`write_vectored`), reducing syscall overhead under load. A single frame
uses a plain `write_all` call.

### API overview

- **`SendFramer`** — stateless framer that encodes `MessageFamily` + payload
  into binary-schema frames via `sendFramer::frame()`.
- **`SendPipelineHandle`** — cloneable handle implementing outbound send with
  state gating (`send`, `send_tagged`, `try_send`, `can_send`).
- **`SendPipeline`** — owns the TCP write half, drains the mpsc channel, and
  writes framed bytes to the socket with writev batching. Created via
  `SendPipeline::new()` which returns `(SendPipeline, SendPipelineHandle)`.
- **`SendPipelineError`** — error type covering state refusal, backpressure,
  shutdown, and I/O errors.

### Integration

The pipeline is designed to integrate with the connection state machine
(`#5869`): `SendPipelineHandle` can be distributed to subsystem dispatchers
that target the transport outbound path. The pipeline's run loop exits when
all handles are dropped (channel close). Wired into connection state
transitions, the pipeline is spawned on `Active` entry and torn down on
`Closing`/`Closed` by dropping handles.

## Send Completion Tracking

The send completion module provides delivery-acknowledgement oneshot handles
that resolve after the framed message has been fully written to the transport
socket. This enables subsystem authors to build reliable request-response
patterns, timeout/retry logic, and backpressure-aware pacing on top of the
outbound send path. Delivery signalling uses tokio::sync::oneshot only —
node-to-node security is handled at the transport/session boundary, not inside
this module.

### SendCompletion / SendCompletionToken model

Each outbound message can carry an optional `SendCompletion` (the sender half
of a tokio oneshot channel) alongside its framed bytes. The pipeline returns a
`SendCompletionToken` (the receiver half) to the caller at send time. After
the write succeeds or fails, the pipeline resolves the completion, and the
caller's `await` on the token returns a `CompletionOutcome`:

| Outcome     | Meaning                                                    |
|-------------|------------------------------------------------------------|
| `Written`   | The framed message was fully written to the socket.        |
| `WriteError`| The write to the socket failed (connection broken, etc.).  |
| `Cancelled` | The pipeline shut down before writing the message.         |

### CompletionDispatcher

`CompletionDispatcher` collects completions for a batch of messages dequeued
from the priority scheduler. After the writev call completes, the dispatcher
atomically resolves all collected completions:

- `complete_all_written()` — socket write succeeded for all messages in batch.
- `complete_all_error()` — socket write failed for all messages in batch.
- `complete_all_cancelled()` — explicit cancellation (drop on unflushed
  dispatcher also resolves remaining completions as `Cancelled`).

### Ordering guarantee

Completions are resolved in the same order messages are dequeued from the
`SendScheduler`, which is priority-class weighted round-robin with starvation
prevention. Within a single priority class, completions respect FIFO
submission order.

### API overview

`SendPipelineHandle` gains the following completion-carrying send methods:

- `send_with_completion(family, payload)` → `Result<SendCompletionToken, SendPipelineError>`
- `send_with_priority_completion(family, priority, payload)` → `Result<SendCompletionToken, SendPipelineError>`
- `try_send_with_completion(family, payload)` → `Result<SendCompletionToken, SendPipelineError>`
- `try_send_with_priority_completion(family, priority, payload)` → `Result<SendCompletionToken, SendPipelineError>`

On backpressure (channel full), `try_send_*_completion` returns
`SendPipelineError::ChannelFull` and the completion token is not created
(the caller is signalled via the error return). On shutdown, all pending
completions resolve as `Cancelled`.

### Integration guidance

Subsystem authors building request-response patterns:

1. Call `send_with_completion()` or `send_with_priority_completion()` instead
   of `send()` to obtain a `SendCompletionToken`.
2. `await` the token to learn delivery outcome.
3. Combine with a `tokio::time::timeout` to implement retry deadlines.
4. For best-effort messages that don't need delivery acknowledgment,
   continue using the existing `send()` / `send_with_priority()` methods
   (no completion overhead).

## Connection Drain Protocol

The drain protocol (`drain_protocol` module) bridges the ConnectionState
`Draining → Closed` transition with a coordinated peer handshake. Without
a drain protocol, connection teardown is abrupt: in-flight messages may be
lost, and the remote peer cannot distinguish intentional shutdown from a
network fault.

### Protocol sequence

```text
Initiator                               Responder
    |                                       |
    |  stop new sends, wait pending -> 0    |
    |~~~~ DrainRequest(generation=N) ~~~~~~>|
    |                                       |  stop new sends, drain pending
    | <~~~~ DrainAck(generation=N) ~~~~~~~~ |
    |                                       |
    v                                       v
  Closed                                 Closed
```

### Wire format

Drain protocol messages are serialized with bincode. The framing layer
(codec, channel multiplexing) is handled by the existing transport pipeline.

| Field        | Type  | Bytes | Description                              |
|-------------|-------|-------|------------------------------------------|
| `generation` | `u64` | 8     | Connection lifecycle generation number   |

### Messages

- **`DrainRequest`** — sent by the initiator to request graceful shutdown.
  Carries the connection lifecycle generation.
- **`DrainAck`** — sent by the responder after draining its pending sends.
  Echoes the initiator's generation.

### Deadline configuration

The initiator arms a configurable deadline when the `DrainRequest` is sent
(default 5 seconds via `DEFAULT_DRAIN_DEADLINE_MS`). If the `DrainAck` does
not arrive before the deadline, the initiator force-closes the connection and
emits a `DrainTimeout` event. The responder has no deadline: it drains its
pending sends and sends the ack when ready.

### Pending send tracking

Both sides use a `PendingSendCounter` (atomic `u64`) to track in-flight
messages. The drain request is not sent until the initiator's counter reaches
zero. The responder similarly waits for its counter to reach zero before
sending the ack.

### API overview

- **`DrainRequest` / `DrainAck`** — bincode-serializable wire messages.
- **`DrainInitiator`** — the side initiating the drain: stops new sends,
  waits for pending counter, sends `DrainRequest`, waits for `DrainAck`
  with deadline, transitions to `Closed`.
- **`DrainResponder`** — the side receiving the drain: handles
  `DrainRequest`, drains pending sends, sends `DrainAck`, transitions to
  `Closed`.
- **`PendingSendCounter`** — thread-safe atomic counter for tracking
  in-flight sends on a connection.
- **`DrainProtocolError`** — error type covering connection state rejection,
  deadline exceeded, generation mismatch, and serialization errors.

### Integration

The drain protocol is designed to integrate with the connection state machine
(`#5869`): membership-driven connection teardown (`#5854`) triggers the drain
via `DrainInitiator`, and the `DrainResponder` handles inbound drain requests
from the peer. Lifecycle events (`DrainTimeout`, `DrainAcknowledged`) are
emitted for consumption by error recovery (`#5860`) and health scoring
(`#5885`) subscribers.


## Keepalive Protocol

Per-connection transport-layer keepalive detects silent connection failures
(network partitions, remote process crash without TCP RST) through periodic
ping/pong exchanges. Integrity is provided by the transport session security
boundary; keepalive frames carry only a monotonic sequence number for echo
matching.

### Wire format

Every keepalive message is an 8-byte frame:

```
[seq:u64 LE]
```

Ping and pong frames are identical on the wire. The transport
message-type discriminator (`KeepaliveMessage::Ping` / `KeepaliveMessage::Pong`)
distinguishes them in the framing layer. Keepalive messages use the
`HeartbeatAck` [`MessageFamily`].

### State machine

```
Idle --(idle timeout)--> Probing --(miss threshold)--> Failed
  ^                          |                            |
  |-----(pong received)------|                            |
  |                                                       |
  +-----(reconnect/reset)--------------------------------+
```

- **Idle**: connection is active; no probing in progress.
- **Probing**: sending probes, awaiting responses. Each unanswered probe
  increments the missed counter.
- **Failed**: maximum consecutive misses reached; the connection should
  transition to `Draining`.

### Configuration

Keepalive is **opt-in**: disabled by default for single-node mounts and local
development. Enable via [`TransportConfigBuilder::with_keepalive()`] or set
`ConnectionManagerConfig::keepalive_config` to `Some(config)`.

Two config types coordinate:

- [`config::KeepaliveConfig`] (user-facing): `interval`, `timeout`, `probe_count`
- [`keepalive::KeepaliveConfig`] (engine-facing): `idle_timeout`, `probe_interval`, `max_missed_probes`

The conversion is automatic via `From<config::KeepaliveConfig> for keepalive::KeepaliveConfig`:
`interval` maps to both `idle_timeout` and `probe_interval`; `probe_count` maps to
`max_missed_probes` (clamped to `u8::MAX`).

| Field | Type | Description |
|---|---|---|
| `idle_timeout` | `Duration` | Connection idle before probing starts |
| `probe_interval` | `Duration` | Interval between consecutive probes |
| `max_missed_probes` | `u8` | Consecutive misses before peer declared dead |

All fields must be non-zero. Config validation rejects zero values.

### API overview

| Type | Role |
|---|---|
| [`KeepaliveMessage`] | Transport frame variants: `Ping { seq }`, `Pong { seq }` |
| [`KeepaliveInitiator`] | Drives the ping side; calls drain trigger on failure |
| [`KeepaliveResponder`] | Statelessly responds to pings with pongs |
| [`KeepaliveLifecycle`] | Bridges [`ConnectionLifecycle`] and keepalive |
| [`KeepaliveSubscriber`] | Trait for keepalive event notification |
| [`KeepaliveEvent`] | Events: `PingSent`, `PongReceived { rtt }`, `KeepaliveMissed`, `KeepaliveFailed` |
| [`KeepaliveRunner`] | Tokio-driven background keepalive task |

### Connection state integration

The [`KeepaliveLifecycle`] bridge connects keepalive to the connection state
machine:

1. On `ConnectionState::Active`, call `KeepaliveLifecycle::on_active()`.
2. On each event-loop tick, call `KeepaliveLifecycle::tick()`:
   - `KeepaliveAction::SendPing(seq)` → send a keepalive frame.
   - `KeepaliveAction::Drain` → transition the connection to `Draining`.
   - `KeepaliveAction::None` → no action.
3. On any received data, call `KeepaliveLifecycle::record_activity()` (proves
   liveness).
4. On received pong, call `KeepaliveLifecycle::on_pong(seq)`.

### Health score integration

Round-trip time samples from successful ping-pong cycles feed the connection
health score aggregator via `HealthSignal::KeepaliveRtt`. The
`KeepaliveSubscriber` trait notifies subscribers of keepalive events so that
health scoring, logging, and monitoring can react without polling.

### Follow-on

  with passive activity-watch semantics.
  stale epoch identifiers.

## Idle Timeout

Passive activity-watch detection that drains or force-closes connections after
a configurable deadline without message activity.  Complements keepalive:
keepalive actively probes peers, idle timeout passively watches for activity
and acts when the connection goes silent on both sides.

### Relationship to keepalive

| Mechanism         | Detection mode          | Triggers on                   |
|-------------------|-------------------------|-------------------------------|
| Keepalive (#5906) | Active probe (ping/pong)| Missed responses              |
| Idle timeout      | Passive activity watch  | No message activity for deadline |

Keepalive catches crashed peers that stop responding to pings.  Idle timeout
catches abandoned connections where neither side sends anything -- including
keepalive probes (e.g., upper-layer bug, silent TCP drop without RST).

### Types

| Type                  | Role                                                              |
|-----------------------|-------------------------------------------------------------------|
| IdleTimeoutConfig     | Deadline, activity sources, trigger-drain toggle, optional warn   |
| IdleTracker           | Thread-safe per-connection last-activity timestamp; shared clones |
| IdleTimeoutController | Polls tracker each tick; fires DrainInitiated or ForceClosed      |
| IdleTimeoutRunner     | Tokio background task; polls controller and invokes drain/close   |
| IdleTimeoutEvent      | Warned, DrainInitiated, ForceClosed (each carries idle_duration)  |
| IdleTimeoutSubscriber | Trait for event consumers (health score, logging, monitoring)     |

### Integration

1. Create an IdleTracker per connection and share it with the receive loop
   (via ConnectionReceiver::with_idle_tracker) and send pipeline
   (via SendPipeline::with_idle_tracker).
2. Wrap the tracker in an IdleTimeoutController with the desired
   IdleTimeoutConfig.
3. Wrap the controller in an IdleTimeoutRunner and call spawn() with drain
   and force-close callbacks. The runner polls on a configurable interval.
4. When the connection enters Draining or Closed, call runner.cancel().

### Follow-on

- Wire IdleTimeoutEvent variants into the health score aggregator (#5885)
  as signal inputs.

## Connection Telemetry

Per-connection telemetry collection with lock-free atomic counters and rate-limited
emission provides operator observability into transport health without modifying
hot-path semantics.

### TelemetryAccumulator

The `TelemetryAccumulator` maintains per-connection counters:

| Counter | Type | Operation |
|---|---|---|
| `bytes_sent` | `AtomicU64` | `fetch_add(n, Relaxed)` |
| `bytes_received` | `AtomicU64` | `fetch_add(n, Relaxed)` |
| `messages_sent` | `AtomicU64` | `fetch_add(1, Relaxed)` |
| `messages_received` | `AtomicU64` | `fetch_add(1, Relaxed)` |
| `errors_by_class` | `HashMap<TransportErrorClass, AtomicU64>` | Lock-guarded (errors are rare) |
| `connection_state_transitions` | `AtomicU64` | `fetch_add(1, Relaxed)` |
| `last_active_at` | `AtomicI64` | Unix timestamp |

All hot-path operations (bytes/messages sent/received) are single `fetch_add`
with `Ordering::Relaxed`, imposing negligible overhead.

### TransportErrorClass

Five error classes mapping from `TransportErrorKind`:

| Class | Kind mapping |
|---|---|
| `Timeout` | `ConnectionTimeout`, `KeepaliveTimeout` |
| `ProtocolViolation` | `ProtocolViolation`, `UnknownMessageFamily`, `MessageTooLarge` |
| `PeerReject` | `ConnectionRefused`, `ConnectionReset`, `ChannelClosed` |
| `ResourceExhaustion` | `BackpressureStall` |
| `Internal` | `InternalError` |

### TelemetryEmitter

The emitter runs on a configurable interval (default 60 s), snapshots and resets
the accumulator atomically (snapshot-then-reset to prevent gaps), and dispatches
snapshots to registered `TelemetrySubscriber`s. The default subscriber logs at
`info` level.

```rust
use std::sync::Arc;
use tidefs_transport::connection_telemetry::{
    TelemetryAccumulator, TelemetryEmitter, TelemetrySubscriber,
};

let acc = Arc::new(TelemetryAccumulator::new(42));
let emitter = TelemetryEmitter::new(acc.clone())
    .with_interval(std::time::Duration::from_secs(30));

// Register a custom subscriber
struct MySubscriber;
impl TelemetrySubscriber for MySubscriber {
    fn on_telemetry_snapshot(&self, snap: &TelemetrySnapshot) {
        println!("conn {}: {} bytes sent", snap.connection_id, snap.bytes_sent);
    }
}
// emitter.subscribe(Arc::new(MySubscriber)).await;

// Spawn background emission
// let handle = emitter.spawn();
```

### Integration via ConnectionHandle

```rust
use tidefs_transport::connection::ConnectionHandle;
use tidefs_transport::connection_telemetry::TelemetryAccumulator;
use std::sync::Arc;

let acc = Arc::new(TelemetryAccumulator::new(42));
let handle: ConnectionHandle = /* ... */
    .with_telemetry(acc.clone());

// Hot-path recording (lock-free)
handle.record_bytes_sent(4096);
handle.record_message_sent();

// Query snapshot (e.g., for tidefsctl)
if let Some(snap) = handle.telemetry_snapshot() {
    println!("bytes sent: {}", snap.bytes_sent);
}
```

### Lifecycle integration

`TelemetryLifecycleSubscriber` implements `LifecycleSubscriber` to auto-count
connection state transitions. Register with the connection's `LifecycleBus`:

```rust
use tidefs_transport::connection_telemetry::TelemetryLifecycleSubscriber;
use tidefs_transport::connection_state::LifecycleBus;

let sub = TelemetryLifecycleSubscriber::new(acc.clone());
lifecycle_bus.subscribe(Box::new(sub));
```

### Serialization

`TelemetrySnapshot` derives `Serialize` and `Deserialize` for `tidefsctl`
JSON output and `tidefs-observe-core` integration. Error class keys
are serialized as their variant names (`"Timeout"`, `"ProtocolViolation"`, etc.).

### Follow-on

Wire telemetry snapshots into `tidefs-observe-core` for centralized
cluster-wide transport monitoring.

### Receive-Window Advertisement (Connection-Level)

Connection-level receive-window advertisement provides the receive-side
half of transport flow control, complementing outbound backpressure.
Each connection tracks available buffer capacity via `ReceiveWindow` and
periodically advertises it to the sending peer so the sender can avoid
overrunning the receiver's buffers.

**How it works**:
- `ReceiveWindow` tracks available bytes per connection.
- On inbound message receipt, the receive loop consumes bytes from the
  window. After the application dispatches the message, bytes are released
  back to the window.
- When available bytes drop below the configured low-watermark, a
  `WindowAdvertisement` frame (8-byte LE u64) is sent to the peer.
- The `WindowAdvertiser` runs as a background task, polling the window
  at the configured batch interval and sending advertisements when needed.
- A minimum batch interval prevents advertisement flooding under rapid
  consume/release cycles.
- Inbound window advertisements from the peer are decoded in the receive
  loop and stored as `peer_window_bytes`; the outbound send path consults
  this value to throttle sends.

**Configuration** (`ReceiveWindowConfig`):
- `capacity`: maximum receive buffer capacity in bytes (default: 1 MiB)
- `low_watermark_ratio`: fraction of capacity that triggers advertisement
  (default: 0.25, range: (0.0, 1.0])
- `advertise_batch_interval`: minimum interval between advertisements
  (default: 10 ms)

**API entries**:
- `ReceiveWindowConfig` — configuration struct with `validate()`
- `ReceiveWindow` — per-connection window tracking consume/release/advertise
- `WindowAdvertisement` — 8-byte LE u64 wire-format advertisement message
- `WindowAdvertiser` — background task driving periodic advertisements
- `spawn_window_advertisement_task` — tokio task spawn wrapper
- TransportConfig `receive_window` field and builder methods
- `ConnectionHandle` receive-window methods: `receive_window_consume`,
  `receive_window_release`, `receive_window_needs_advertisement`,
  `receive_window_mark_advertised`, `receive_window_available`,
  `set_peer_window`, `peer_window_bytes`
- `ConnectionReceiver::with_connection_handle` — attaches a connection
  handle to the receive loop for automatic window accounting


## Session Statistics

The `session::stats` module provides per-session operational statistics
with atomic counters for bytes, messages, errors, and queue depths.
Module `tidefs_transport::session::stats`, source
[session/stats.rs](src/session/stats.rs).

### Purpose

Operators and integration tests use session statistics to observe
transport health during multi-node operation without packet capture or
ad-hoc logging. Every session tracks sent/received bytes, message counts
by priority, error tallies, and current queue depths.

### Counter Semantics

Monotonic counters (`bytes_sent`, `messages_sent`, `send_errors`, etc.)
only increase over the session lifetime and are reset to zero by
`SessionStats::reset()`. Queue-depth fields in `SessionStatsSnapshot`
reflect the live queue state at snapshot time; they are not monotonic.

Snapshots are point-in-time consistent: all atomic counters are loaded
under the session lock so no counter advances between reads.

### Types

| Type                     | Role                                                     |
|--------------------------|----------------------------------------------------------|
| `SessionStats`           | Atomic per-session counters (bytes, messages, errors)    |
| `SessionStatsSnapshot`   | Point-in-time read-only snapshot with queue depths       |
| `TransportStats`         | Aggregate stats across all sessions keyed by `SessionId` |

### SessionStats fields

| Counter                       | Type       | Semantics                          |
|-------------------------------|------------|------------------------------------|
| `bytes_sent`                  | AtomicU64  | Total bytes written to wire        |
| `bytes_received`              | AtomicU64  | Total bytes read from wire         |
| `messages_sent`               | AtomicU64  | Total outbound messages            |
| `messages_received`           | AtomicU64  | Total inbound messages             |
| `messages_sent_control`       | AtomicU64  | Outbound Control-priority messages |
| `messages_sent_data`          | AtomicU64  | Outbound Data-priority messages    |
| `messages_received_control`   | AtomicU64  | Inbound Control-priority (best-effort) |
| `messages_received_data`      | AtomicU64  | Inbound Data-priority (best-effort)    |
| `send_errors`                 | AtomicU64  | Send-side transport errors         |
| `receive_errors`              | AtomicU64  | Receive-side transport errors      |
| `reconnections`               | AtomicU64  | Reconnection attempt count         |
| `chunks_shipped`              | AtomicU64  | Chunks sent (chunk shipper)        |
| `chunks_received`             | AtomicU64  | Chunks received (chunk shipper)    |

### API

- `Session::stats()` returns a `SessionStatsSnapshot` with live queue depths.
- `Session::reset_stats()` zeros all counters and clears timestamps.
- `Session::stats_ref()` returns a shared `&SessionStats` for direct
  instrumentation from the transport layer.
- `Transport::session_stats(session_id)` returns `Option<SessionStatsSnapshot>`.
- `Transport::all_stats()` returns `TransportStats` across all sessions.
- `Transport::reset_session_stats(session_id)` resets a single session's counters.

### TransportStats

`TransportStats` provides per-session drill-down via `sessions: BTreeMap<SessionId, SessionStatsSnapshot>`
and aggregate sum methods: `total_bytes_sent()`, `total_bytes_received()`,
`total_messages_sent()`, `total_send_errors()`, `total_receive_errors()`.


## Join-State Push Message

The `join_state_push` module delivers the committed epoch roster to a
first-time joining peer during the transport join handshake. Module
`tidefs_transport::join_state_push`, source [join_state_push.rs](src/join_state_push.rs).

### Purpose

When a brand-new peer connects that is not yet in the committed roster,
the acceptor side sends a `JoinStatePushMessage` carrying the current
committed roster so the peer can participate in epoch-gate enforcement
immediately. This closes the first-time peer-join gap after initial
transport connection acceptance.

### Wire format

```
[0..8)   push_seq         u64 LE -- monotonic push sequence number
[8..16)  epoch            u64 LE -- epoch number
[16..48) roster_hash      32 bytes -- BLAKE3-256 roster hash
[48..52) member_count     u32 LE -- number of member IDs
[52..M)  member_ids       member_count x u64 LE -- sorted member node IDs
[M..M+8) joining_peer_id  u64 LE -- the peer this join push is for
```

### Types

| Type                        | Role                                                       |
|-----------------------------|------------------------------------------------------------|
| JoinStatePushMessage        | Wire-format message with encode/decode                     |
| JoinStatePushHandler        | Trait for receiving incoming join-state pushes             |
| JoinStatePushDispatcher     | Bridges transport dispatch to a registered handler         |

### Integration

1. On the acceptor side, create a `JoinStatePushMessage` with the current
   committed roster and deliver it to the joining peer over the transport
   session.
2. On the joining-peer side, register a `JoinStatePushDispatcher` with a
   `JoinStatePushHandler` to process the incoming roster state and
   initialize the local epoch-gate.


## Multi-Session Broadcast Send

The `broadcast` module provides efficient one-to-many message delivery
for control-plane fan-out (e.g., membership epoch distribution,
proposal fanout). Module `tidefs_transport::broadcast`, source
[broadcast.rs](src/broadcast.rs).

### Purpose

When a coordinator needs to distribute the same message to multiple
connected peers (e.g., a newly committed epoch view), broadcasting
avoids per-session re-encode overhead: the caller encodes the message
once and fans the bytes out to every target session. Each target
independently applies its own epoch gating, backpressure policy, and
compression — one failing session does not block delivery to others
under the default best-effort mode.

### Configuration

`BroadcastConfig` controls failure handling:

| Field           | Type                  | Default       | Description                              |
|-----------------|-----------------------|---------------|------------------------------------------|
| `failure_mode`  | `BroadcastFailureMode`| `BestEffort`  | `FailFast` aborts on first error         |
| `parallelism`   | `usize`               | `0`           | Advisory max concurrent session sends    |

### Types

| Type                     | Role                                                       |
|--------------------------|------------------------------------------------------------|
| `BroadcastConfig`        | Failure mode and parallelism configuration                 |
| `BroadcastFailureMode`   | `FailFast` or `BestEffort`                                 |
| `BroadcastOutcome`       | Per-session `Ok` or `Err(BroadcastError)`                  |
| `BroadcastError`         | `SessionNotFound`, `SessionNotEstablished`, `PeerNotInRoster`, `SendBufferFull`, `SendBufferShutdown`, `SessionDraining`, `Generic(String)` |
| `BroadcastResults`       | Collected outcomes with `succeeded()`, `failed()`, `all_ok()` helpers |

### API

```rust
use tidefs_transport::broadcast::{BroadcastConfig, BroadcastResults, BroadcastOutcome};

/// Broadcast a single message payload to multiple sessions.
let results: BroadcastResults = transport.broadcast_send(
    &target_session_ids,
    &encoded_payload,
    MessagePriority::Control,
    &BroadcastConfig::default(),
);

// Inspect results
if !results.all_ok() {
    for (sid, err) in results.failed() {
        tracing::warn!(%sid, %err, "broadcast delivery failed");
    }
}
```

### Error semantics

- `SessionNotFound`: the session ID is not in the transport session table.
- `SessionNotEstablished`: the session exists but is not in a sendable state
  (`Bound`, `CohortAttached`, `Established`, or `Degraded`).
- `PeerNotInRoster`, `SendBufferFull`, `SendBufferShutdown`, `SessionDraining`:
  mapped from the underlying `TransportError` variants returned by each
  session's send path.
- `Generic(String)`: any other transport error.

Under `BestEffort` (default), all targets receive at least one delivery
attempt. Under `FailFast`, broadcast stops at the first error and
remaining targets are left unattempted.
