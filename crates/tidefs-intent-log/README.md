# tidefs-intent-log

BLAKE3-authenticated intent-log records, replay helpers, and no_std append/scan
primitives for TideFS mutation intent records.

## Record Types

`IntentLogRecord` covers 21 filesystem mutation variants: Write, Truncate,
Setattr, Create, Unlink, Rename, Symlink, HardLink, Mkdir, Rmdir, Mknod,
XattrSet, XattrRemove, Flush, Fallocate, BufferedWrite, WriteIntentAck,
Tmpfile, Lseek, Fsync, CleanupQueue, and CopyFileRange.

## Replay Architecture

`IntentReplayEngine` provides deterministic dispatch of unapplied intent-log
records. The engine iterates intent-log segments, filters records by the
applied-transaction-group watermark, and dispatches each record through a
trait-based `IntentReplayHandler`.

### Design

- **Segment iteration**: the engine reads BLAKE3-verified intent-log segments
  via `IntentLogReader`, handling both fully committed segments and truncated
  segments.
- **LSN filtering**: records with LSN <= the committed root's transaction group
  are skipped — the filesystem state already reflects those mutations.
- **Record-type dispatch**: each replayable record variant is dispatched through
  `IntentReplayHandler::handle_record()`. Implementations bridge records back to
  filesystem operations (e.g., VfsEngine dispatch).
- **BLAKE3 checkpoint**: after replay completes, `compute_checkpoint()` produces
  a domain-separated digest (`tidefs-intent-replay-v1`) over the replay state.

### Idempotency

Replay is naturally idempotent:
- Records at or below the applied watermark are skipped.
- Non-replayable record types (Flush, Fsync, WriteIntentAck, Lseek, CleanupQueue)
  are counted as skipped — they are acknowledgment markers, not mutations.
- Handlers treat already-applied operations as success (e.g., EEXIST for
  namespace creates means the entry already exists).

### Partial-Record Handling

Truncated segments with no valid footer are replayed up to the last valid
record checksum. Corrupt segments are reported as skipped by this helper.

### Record-Type Dispatch Table

| Record Type        | Replayable | Dispatch Strategy                  |
|--------------------|-----------|------------------------------------|
| Write              | No        | Hash-only record; no inline data   |
| BufferedWrite      | Yes       | Open file, write inline data       |
| Truncate           | Yes       | setattr with FATTR_SIZE            |
| Setattr            | Yes       | setattr with decoded attr blob     |
| Create             | Yes       | create(), idempotent via EEXIST    |
| Unlink             | Yes       | unlink(), idempotent via ENOENT    |
| Rename             | Yes       | rename(), idempotent via ENOENT    |
| Symlink            | Yes       | symlink(), idempotent via EEXIST   |
| HardLink           | Yes       | link(), idempotent via EEXIST      |
| Mkdir              | Yes       | mkdir(), idempotent via EEXIST     |
| Rmdir              | Yes       | rmdir(), idempotent via ENOENT     |
| Mknod              | Yes       | mknod(), idempotent via EEXIST     |
| Tmpfile            | Yes       | tmpfile(), idempotent via EEXIST   |
| XattrSet/Remove    | No        | Key/value not available in record  |
| Fallocate          | No        | Requires open file handle          |
| CopyFileRange      | No        | Requires open file handles         |
| Flush              | No        | Acknowledgment marker              |
| Fsync              | No        | Barrier marker                     |
| WriteIntentAck     | No        | Completion marker                  |
| Lseek              | No        | Read-path metadata marker          |
| CleanupQueue       | No        | GC ledger state marker             |

## Replay Consumers

- Consumers can wire `IntentReplayEngine` with `VfsReplayHandler`.
- `tidefs-local-filesystem`: can invoke replay after committed-root selection.

## KernelStorageIo Append API

The `kernel-io` feature exposes no_std append and scan APIs over
`KernelStorageIo`:

- `IntentLogKernelWriter` writes real `IntentLogFrame` bytes through
  `KernelStorageIo`.
- Each append assigns the next monotonic record sequence, pads only the final
  physical sector, checks for short writes, and optionally calls
  `KernelStorageIo::flush()` when the caller selects the flush policy.
- The frame checksum is the existing BLAKE3 `IntentLogFrame` checksum. There is
  no zero checksum placeholder, fake digest, or compatibility shim in this
  path.
- `IntentLogKernelScanner` reads sector-aligned frames back through the same
  `KernelStorageIo`, validates length and checksum fields before yielding a
  `KernelScannedRecord`, and can drive redo through a caller-owned
  `RedoCallback`.
- Corrupt frames advance the scan cursor before returning
  `KernelScanError::CorruptedRecord`; `scan_and_replay()` skips them and keeps
  moving, while fatal storage or callback errors abort replay.

These primitives provide record append and scan helpers only; higher-level
replay validation belongs to their consuming layers.
