# tidefs-replication

Production replication protocol: fanout writes, collect quorum ACKs,
handle partial failures, and commit through the flow commit coordinator.

## Write-Path API

The `write_path` module provides the core replication write-path: accept a
write payload, dispatch it concurrently to every configured replica peer via
the transport layer, collect per-replica acknowledgments, and signal quorum
satisfaction or shortfall to the caller.

### ReplicationWriteHandle

The primary public entry point. Construct with a transport backend
implementing `ReplicationWriteTransport` and call `submit_write`:

```ignore
use tidefs_replication::write_path::{
    QuorumMode, ReplicationWriteHandle, ReplicationWriteOutcome,
};
use tidefs_membership_epoch::MemberId;

let transport = MyTransportBackend::new();
let mut handle = ReplicationWriteHandle::new(transport);

let outcome = handle.submit_write(
    b"payload",
    &[MemberId::new(1), MemberId::new(2), MemberId::new(3)],
    QuorumMode::Majority,
);
assert!(outcome.is_quorum_reached());
```

`submit_write` blocks until quorum is reached, quorum becomes impossible,
or the aggregate deadline expires. The per-target timeout defaults to 30s;
override with `set_timeout`.

### QuorumMode

Three quorum semantics:

| Mode | Minimum ACKs | Use Case |
|------|-------------|----------|
| `All` | N of N | Critical metadata |
| `Majority` | N/2 + 1 | Content payloads |
| `Single` | 1 of N | Best-effort background data |

### ReplicationWriteOutcome

Returned by `submit_write`. Variants:

- `QuorumReached { ack_count, target_count, acked, failed }` — write is durable.
- `QuorumShortfall { ack_count, quorum_required, reason }` — quorum not met.
- `NoReplicas` — empty replica set.

### ReplicationWriteTransport

Trait abstracting the transport layer. Implement this for production use
against `tidefs_transport::Transport`:

```ignore
impl ReplicationWriteTransport for MyTransport {
    fn write_to_target(
        &self,
        target: MemberId,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<bool, String> {
        // Dispatch payload to target, return Ok(true) on ack,
        // Ok(false) on explicit rejection, or Err on transport failure.
    }
}
```

### ReplicationWriteRequest

A oneshot-based async variant. Construct a request with its payload, replica
set, quorum mode, and timeout; retain the receiver to await the outcome:

```ignore
let (request, rx) = ReplicationWriteRequest::new(
    b"payload".to_vec(),
    vec![MemberId::new(1), MemberId::new(2)],
    QuorumMode::Majority,
    Duration::from_secs(30),
);
// Send request to a worker task...
let outcome = rx.recv().unwrap();
```

### Integration Notes

- The transport security boundary (#5919, #5926) provides node-to-node
  authenticity and integrity. Replication relies on that boundary; it does
  not add per-message cryptographic layers.
- Storage-node replication wiring (#5944) consumes `ReplicationWriteHandle`
  as the transport-backed replication entry point.
- The write path is intentionally synchronous (thread-per-fanout).
  Production callers should invoke `submit_write` from a worker or I/O
  pool thread.

### Architecture

```text
submit_write(payload, replicas, quorum)
        |
        v
  ReplicationWriteHandle
        |
        v
  ReplicaSendDispatch  (concurrent fan-out, one thread per target)
        |
   +----+----+----+
   v    v         v
target_0  target_1  target_N
   |    |         |
   v    v         v
 ack/nack     ack/nack     ack/nack
   |    |         |
   +----+----+----+
        |
        v
  QuorumAcknowledgmentAggregator
        |
        v
  ReplicationWriteOutcome
```

## Other Modules

- `chunk` — BLAKE3-framed replica chunk wire format for object-data push.
- `push` — Replica chunk push engine with encode/fanout/quorum/retry.
- `retry` — Push retry policy with exponential backoff, jitter, dead-target marking.
- `runtime` — Async replication transport runtime with concurrent dispatch and cancellation.
- `dispatcher` — Replication dispatch engine consuming ReplicationIntent and fanning out to placement-resolved targets.
- `adapters` — Feature-gated adapter implementations (LocalObjectStoreTarget, StaticPlacementResolver).
