# tidefs-intent-log

BLAKE3-authenticated intent-log for TideFS crash-consistent mutation recording.

## Record Types

`IntentLogRecord` covers 21 filesystem mutation variants: Write, Truncate,
Setattr, Create, Unlink, Rename, Symlink, HardLink, Mkdir, Rmdir, Mknod,
XattrSet, XattrRemove, Flush, Fallocate, BufferedWrite, WriteIntentAck,
Tmpfile, Lseek, Fsync, CleanupQueue, and CopyFileRange.

## Replay Architecture

`IntentReplayEngine` provides deterministic intent-log replay for mount-time
crash recovery. The engine iterates intent-log segments, filters records by
the applied-transaction-group watermark, and dispatches each record through a
trait-based `IntentReplayHandler`.

### Design

- **Segment iteration**: the engine reads BLAKE3-verified intent-log segments
  via `IntentLogReader`, handling both fully committed segments and truncated
  segments (crashed mid-write).
- **LSN filtering**: records with LSN <= the committed root's transaction group
  are skipped — the filesystem state already reflects those mutations.
- **Record-type dispatch**: each replayable record variant is dispatched through
  `IntentReplayHandler::handle_record()`. Implementations bridge records back to
  filesystem operations (e.g., VfsEngine dispatch).
- **BLAKE3 checkpoint**: after replay completes, `compute_checkpoint()` produces
  a domain-separated digest (`tidefs-intent-replay-v1`) over the replay state,
  enabling deterministic verification of recovery consistency.

### Idempotency

Replay is naturally idempotent:
- Records at or below the applied watermark are skipped.
- Non-replayable record types (Flush, Fsync, WriteIntentAck, Lseek, CleanupQueue)
  are counted as skipped — they are acknowledgment markers, not mutations.
- Handlers treat already-applied operations as success (e.g., EEXIST for
  namespace creates means the entry already exists).

### Partial-Record Handling

Truncated segments (crashed mid-write, no valid footer) are replayed up to the
last valid record checksum. Corrupt segments are skipped with a warning but do
not abort recovery — the filesystem is still consistent up to the previous
segment.

### No-fsck Recovery Contract

Recovery is automatic through committed roots and intent replay. No fsck-style
scanning or repair is required. On mount, the system:
1. Selects the newest valid committed root.
2. Replays any unapplied intent-log records through `IntentReplayEngine`.
3. The filesystem reaches a consistent state without manual intervention.

### Record-Type Dispatch Table

| Record Type        | Replayable | Dispatch Strategy                  |
|--------------------|-----------|------------------------------------|
| Write              | No        | Data lost in crash                 |
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
| Fsync              | No        | Durability barrier marker          |
| WriteIntentAck     | No        | Durable-commit acknowledgment      |
| Lseek              | No        | Read-path metadata marker          |
| CleanupQueue       | No        | GC ledger state marker             |

## Integrations

- `tidefs-recovery-loop`: wires `IntentReplayEngine` with `VfsReplayHandler`
  for mount-time crash recovery replay through VfsEngine.
- `tidefs-local-filesystem`: invokes replay during mount after committed-root
  selection and before marking the filesystem clean.

## KernelStorageIo Append Path

The `kernel-io` feature exposes no_std append and scan surfaces for mounted
kernel code:

- `IntentLogKernelWriter` writes real `IntentLogFrame` bytes through
  `KernelStorageIo`.
- Each append assigns the next monotonic record sequence, pads only the final
  physical sector, checks for short writes, and optionally calls
  `KernelStorageIo::flush()` for commit-barrier durability.
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

These primitives are consumed by the mounted `KernelPoolCore` path. They do not
by themselves replace the current kernel bring-up table or close mounted
object/extent replay.

## Retired Validation Report

The old `tests/intent_log_replay_validation.rs` validation report was retired.
It mixed source-model and single-process PASS rows into a release-facing
validation shape. Intent-log replay closure now belongs to mounted recovery
validation that exercises committed-root selection and replay through the
product storage path, or to ordinary focused unit tests that do not claim
release readiness.
