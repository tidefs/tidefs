# tidefs-transport

`tidefs-transport` contains the transport/session APIs used by TideFS
distributed runtime code. This README is only a contributor orientation for
the crate boundary; the source modules are the API contract for implemented
behavior.

## Authority Boundary

- Source files under `src/` own current behavior, invariants, and public API
  details.
- `docs/TRANSPORT_CLUSTER_AUTHORITY.md` owns the split between transport-local
  mechanics and membership/runtime authority.
- `docs/MEMBERSHIP_AUTHORITY.md` owns membership, epoch, roster, and quorum
  decisions that transport may enforce mechanically.
- `docs/security/transport-security-boundary.md` owns transport security
  boundary language.
- `validation/claims.toml` and generated claim-registry material own
  product-facing claim state.
- Live GitHub issues and pull requests own missing runtime work, validation
  work, and coordination gaps.

Do not add historical issue lineage, future-work plans, claim text, or
readiness language here. If a gap is real, record it in the owning source
contract, authority document, validation entry, or live issue instead of
keeping it as README prose.

## Public Entry Points

Most contributors start with these crate exports:

| Area | Public types | Source |
|---|---|---|
| Endpoint addresses | `TransportAddr`, `TransportCarrier`, `AddrParseError` | `src/addr.rs` |
| Configuration | `TransportConfig`, `TransportConfigBuilder`, `ConfigError` | `src/config.rs` |
| Backend boundary | `TransportBackend`, `ConnectionLike`, `TransportBackendKind` | `src/backend.rs` |
| Transport/session runtime | `Transport`, `Session`, session stats and state exports | `src/transport.rs`, `src/session/` |
| Framing and receive/send loops | frame encode/decode helpers, receiver, dispatcher, completion types | `src/io_runtime.rs`, `src/receive_loop.rs`, `src/send_dispatch.rs`, `src/send_completion.rs` |
| Flow and admission mechanics | receive credit, send admission, backpressure, scheduler, gate, drain types | `src/receive_flow.rs`, `src/send_admission.rs`, `src/send_backpressure.rs`, `src/send_scheduler.rs`, `src/send_gate.rs`, `src/session_drain.rs` |
| Chunk and transfer control | `ChunkShipper`, transfer-control messages, chunk error types | `src/chunk_shipper.rs`, `src/transfer_control.rs`, `src/error.rs` |
| Error surfaces | `TransportError`, `SessionError`, `ChunkError`, `ChunkTransferError` | `src/error.rs` |

Use `src/lib.rs` for the full export list. Prefer module rustdoc when the
README and source appear to disagree.

## Address and Carrier Types

`TransportAddr` is the crate-level endpoint address enum:

- `TransportAddr::Tcp(SocketAddr)`
- `TransportAddr::Rdma { gid, qpn, service_id }`
- `TransportAddr::Unix(PathBuf)`

`TransportAddr::carrier()` returns the corresponding `TransportCarrier`.
`FromStr` accepts `tcp://`, `rdma://`, and `unix://` URI forms and returns
`AddrParseError` for malformed input. Backend implementations are responsible
for accepting or refusing the carrier variants they can actually bind or
connect.

`TransportBackendKind` names the backend family used by a backend
implementation. Treat it as source-level carrier plumbing, not as readiness
language for any deployment path.

## Configuration Boundary

`TransportConfigBuilder` constructs a validated `TransportConfig`.
Configuration currently covers:

- endpoint address
- connect, idle, read, and write timeouts
- send and receive buffer sizes
- multiplexed stream limits
- optional keepalive configuration
- receive-window and receive-credit configuration
- send-priority scheduler configuration
- response tracking configuration

`build()` returns `ConfigError` for invalid values such as zero timeouts,
zero buffer sizes, zero stream limits, invalid receive-window thresholds, or
invalid response-tracker limits. Check `src/config.rs` for the exact defaults
and validation rules before changing callers.

## Module Map

- `addr`, `backend`, `config`, `error`, and `types` define the basic crate
  boundary.
- `transport`, `listener`, `connection_pool`, `connection_state`,
  `connection_retry`, and `connect_tracker` cover connection lifecycle
  mechanics.
- `session`, `session_concurrency`, `session_drain`, `session_rekey`,
  `transport_session_set`, and `reconnect` cover session state and session
  management.
- `codec`, `io_runtime`, `receive_loop`, `outbound_send`, `send_dispatch`,
  `send_completion`, `recv_batch`, and `frame_governance` cover framed I/O.
- `receive_flow`, `backpressure`, `send_admission`, `send_backpressure`,
  `send_scheduler`, `send_deadline`, `send_gate`, `send_batcher`, and
  `send_coalesce` cover queueing and flow mechanics.
- `chunk_shipper`, `chunk_stream`, `transfer_control`, and related service
  modules cover chunk and object movement plumbing.
- `epoch_fence`, `membership_guard`, `epoch_gate`, `epoch_barrier`, and
  `committed_roster_push` mechanically enforce authority that belongs to the
  membership and runtime layers.
- `carrier_selection`, `path_evidence`, `peer_address_registry`,
  `peer_drain_coordinator`, and `peer_health` provide typed carrier, path,
  and peer state used by adjacent distributed code.

When adding a module, keep its durable contract in rustdoc or the appropriate
authority document. Keep this map brief.

## Error Boundary

Transport-level callers should normally match on `TransportError` for
connection, session, carrier, queue, epoch, and I/O failures. Session-local
callers can use `SessionError`; chunk-transfer callers can use `ChunkError`
and `ChunkTransferError`.

Avoid converting typed errors into strings at module boundaries unless the
caller is already in a diagnostics-only path. New runtime gaps should add
typed errors or live issues, not README explanations.

## Contributor Rules

- Keep this README short and source-backed.
- Do not use this file as a status report, validation ledger, or historical
  issue index.
- Do not widen security, distributed-availability, carrier, scheduling,
  performance, or product claims here.
- Retarget missing behavior to the source module, authority document,
  validation registry, or live issue that owns the decision.
