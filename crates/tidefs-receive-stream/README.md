# tidefs-receive-stream

Developer orientation for the receive-stream crate.

This README describes crate-local APIs and invariants that are visible in the
source and tests. It does not define send/receive roadmap, snapshot shipping,
durability admission, or TideFS status decisions. Those decisions live in the
repository authority docs and claim registry.

## Crate Scope

`tidefs-receive-stream` decodes receive-stream chunk frames, verifies their
per-frame authentication tag, reassembles object chunks, and hands assembled
objects to a caller-provided dispatch implementation. The crate also contains
receive persistence and session admission helpers used by higher-level receive
paths.

## Modules

- `decoder` (`ChunkDecoder`, `FramedChunk`, `ChunkDecodeError`): parses frames
  with a fixed 64-byte header, 32-byte authentication tag, and payload. The
  decoder validates frame magic, header CRC, payload length, and the BLAKE3
  domain tag before yielding a `FramedChunk`.
- `assembler` (`ObjectAssembler`, `AssembledObject`, `AssemblerError`):
  buffers chunks by object, orders them by chunk index, and yields an
  `AssembledObject` after all chunks for an object are present.
- `dispatch` (`ReceiveDispatch`, `NoOpDispatch`, `receive_object`): abstracts
  object storage behind `store_object` and `flush`. `receive_object` wires
  decode, assembly, and dispatch for callers that already have frame bytes.
- `receive_persistence` (`ReceiveContract`, `BaseRootPinLookup`,
  `ReceivePersistenceBridge`): checks base-root pins, lineage, and generation
  constraints before handing accepted receive output to persistence.
- `session`: tracks receiver authority, admission, checkpoint, and refusal
  state for receive sessions.

## Local API Example

```rust
use tidefs_receive_stream::dispatch::{receive_object, NoOpDispatch};
use tidefs_receive_stream::decoder::ChunkDecoder;

let mut dispatch = NoOpDispatch::new();
let mut decoder = ChunkDecoder::new(1024 * 1024);
let wire: &[u8] = &[/* frame bytes from a caller-owned source */];

let (n_objects, _n_bytes) = receive_object(&mut decoder, wire, &mut dispatch)?;
assert_eq!(dispatch.objects_received.len(), n_objects);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Test Scope

At this snapshot, the crate source and tests contain 85 receive-stream tests:

- 64 unit tests across decoder, assembler, dispatch, receive persistence, and
  session behavior.
- 21 integration tests covering send-stream round trips and receive
  persistence integration.

Treat this count as a source snapshot, not an authority claim. Recount the
tests before updating it.

## Authority Pointers

Use these repository-level authorities for broader send/receive, snapshot,
distributed shipping, transform, and claim-gate decisions:

- `docs/SEND_RECEIVE_VERSION_AUTHORITY.md`
- `docs/SNAPSHOT_CLONE_DEADLIST_AUTHORITY.md`
- `docs/design/distributed-snapshot-shipping.md`
- `docs/TRANSFORM_PIPELINE_AUTHORITY.md`
- `validation/claims.toml`
- `docs/CLAIM_REGISTRY.md`
