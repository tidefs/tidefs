# tidefs-receive-stream

Receive-stream chunk decoding with BLAKE3 verification and object reassembly
for multi-node state transfer.

This crate completes the send/receive transport pair: it decodes wire-format
chunk frames produced by `tidefs-send-stream::framer::ChunkFramer`, verifies
BLAKE3-256 domain-separated authentication tags under the `TransferStream`
domain, reassembles ordered chunks into complete objects, and dispatches
received objects to local storage through the `ReceiveDispatch` trait.

## Architecture

```
Wire bytes --> ChunkDecoder --> FramedChunk (verified)
                                    |
                                    v
                              ObjectAssembler
                                    |
                                    v
                             ReceiveDispatch
                                    |
                                    v
                             Local storage
```

## Modules

- **`decoder`** (`ChunkDecoder`, `FramedChunk`, `ChunkDecodeError`):
  Parses wire-format chunk frames (64-byte header with magic, object_id,
  offset, chunk_index, total_chunks, payload_len, chunk_flags, and CRC32C
  header integrity), extracts the payload and 32-byte BLAKE3-256 auth tag,
  and verifies the tag against the `TransferStream` domain.

- **`assembler`** (`ObjectAssembler`, `AssembledObject`, `AssemblerError`):
  Buffers and reassembles ordered chunks into complete objects, handling
  out-of-order arrival via sequence-number ordering. Tracks per-object
  progress and yields a complete `AssembledObject` when all chunks arrive.

- **`dispatch`** (`ReceiveDispatch` trait, `NoOpDispatch`, `receive_object`):
  The `ReceiveDispatch` trait abstracts storage backends behind
  `store_object` and `flush`. A `NoOpDispatch` collects objects into a
  `Vec` for testing. The top-level `receive_object()` entry point runs
  the full pipeline: decode, assemble, dispatch.

## Usage

```rust
use tidefs_receive_stream::dispatch::{receive_object, NoOpDispatch};
use tidefs_receive_stream::decoder::ChunkDecoder;

let mut dispatch = NoOpDispatch::new();
let mut decoder = ChunkDecoder::new(1024 * 1024); // max payload 1 MiB

// Wire bytes from send-stream ChunkFramer:
let wire: &[u8] = &[...];

let (n_objects, n_bytes) = receive_object(&mut decoder, wire, &mut dispatch)
    .expect("receive pipeline succeeded");

assert_eq!(dispatch.objects_received.len(), n_objects);
```

## Wire Format

Each chunk frame on the wire (little-endian):

| Offset | Size | Field            |
|--------|------|------------------|
| 0      | 4    | magic (0x5653_4352 = "VSCR") |
| 4      | 32   | object_id        |
| 36     | 8    | offset (u64)     |
| 44     | 4    | chunk_index (u32)|
| 48     | 4    | total_chunks (u32)|
| 52     | 4    | payload_len (u32)|
| 56     | 4    | chunk_flags (bit 0 = is_last)|
| 60     | 4    | header_crc32c (of bytes 0..60)|
| 64     | 32   | auth_tag (BLAKE3-256, TransferStream domain)|
| 96     | N    | payload          |

## Testing

```sh
cargo test -p tidefs-receive-stream
```

44 tests: 34 unit (decoder, assembler, dispatch) + 10 cross-crate round-trip
integration tests with `tidefs-send-stream`.
