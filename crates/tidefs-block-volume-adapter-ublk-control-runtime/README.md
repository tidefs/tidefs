# tidefs-block-volume-adapter-ublk-control-runtime

Control-plane bridge between Linux ublk block devices and TideFS block-volume
semantics. Owns `/dev/ublk-control`, issues `UBLK_CMD_ADD_DEV`/`DEL_DEV`/
`SET_PARAMS`/`START_DEV`/`STOP_DEV` through io_uring, and maintains the
in-memory device registry.

## Queue Lifecycle

The [`QueueLifecycle`] state machine governs the attach, drain, and teardown
of ublk device queues, enforcing drain-before-removal sequencing:

```
Unattached ──attach()──▶ Attached ──drain()──▶ Draining
     ▲                      │                      │
     │                 remove_idempotent()    remove()
     │                      │                      │
     │                      ▼                      ▼
     └─────────────── Removed ◀──confirm_removed()── Removing
           re-attach via attach()
```

### States

- **Unattached** — no device is present; initial state and state after a
  successful removal cycle.
- **Attached** — device is live and accepting block I/O through ublk
  data-queue rings.
- **Draining** — drain has been initiated; in-flight I/O is completing.
  No new I/O requests are accepted.
- **Removing** — device removal is in progress; `UBLK_CMD_DEL_DEV` has been
  issued, and resource cleanup (fd close, buffer release, queue
  unregistration) is pending.
- **Removed** — device is fully removed and all resources freed. The lifecycle
  can be restarted by calling `attach()` again.

### Transitions

| Transition | Method | Precondition | Postcondition |
|---|---|---|---|
| Attach | `attach()` | `Unattached` or `Removed` | `Attached` |
| Drain | `drain()` | `Attached` | `Draining` |
| Remove | `remove()` | `Draining` | `Removing` |
| Confirm | `confirm_removed()` | `Removing` | `Removed` |
| Force remove | `remove_idempotent()` | Any state | `Removed` |

### Drain semantics

The drain-before-removal contract requires that the caller:

1. Call `drain()` to stop accepting new I/O.
2. Wait for all in-flight I/O to complete (tracked by the daemon's
   io_uring completion polling).
3. Call `remove()` to enter the `Removing` state.
4. Issue `UBLK_CMD_DEL_DEV` and close resources.
5. Call `confirm_removed()` to finalize the lifecycle.

`remove_idempotent()` bypasses all steps and transitions directly to
`Removed`. It is intended for error-recovery paths (e.g. daemon restart
when the kernel device state is unknown).

### Re-attach contract

After reaching `Removed`, calling `attach()` with a new (or the same)
device ID transitions back to `Attached`. This supports the repeated
attach/remove cycles required by validation harnesses. The caller is
responsible for re-acquiring kernel resources (device fd, io_uring ring,
mmap) before re-attaching.


## I/O Dispatch



The [`dispatch_io`] function classifies ublk I/O descriptors by opcode and

routes them to typed backend methods via the [`UblkIoBackend`] trait:



| Opcode | Method | Sector-range extraction | Completion reporting |

|--------|--------|------------------------|----------------------|

| `UBLK_IO_OP_READ` | `read(byte_offset, buf)` | `start_sector * 512`, `sector_count * 512` | `Completed { byte_count }` |

| `UBLK_IO_OP_WRITE` | `write(byte_offset, data)` | `start_sector * 512`, `sector_count * 512` | `Completed { byte_count }` |

| `UBLK_IO_OP_FLUSH` | `flush()` | none | `Completed { byte_count: 0 }` |

| `UBLK_IO_OP_DISCARD` | `discard(byte_offset, byte_len)` | `start_sector * 512`, `sector_count * 512` | `Completed { byte_count: 0 }` |

| `UBLK_IO_OP_WRITE_ZEROES` | `write_zeroes(byte_offset, byte_len)` | `start_sector * 512`, `sector_count * 512` | `Completed { byte_count: 0 }` |

| `UBLK_IO_OP_WRITE_SAME` | unsupported | - | `UnsupportedOperation` |



### Discard dispatch



`dispatch_discard()` extracts the sector range from the descriptor,

converts to byte range (`start_sector * 512`, `sector_count * 512`),

and calls `backend.discard(byte_offset, byte_len)`. On success it

returns `UblkIoDispatchResult::Completed { byte_count: 0 }`; on

backend error it maps the OS error to `UblkIoHandlerError::BackendIoError`.



The `FUA` flag on write descriptors is validated before dispatch

(FUA-only-for-write check). Unknown opcodes return

`UnsupportedOperation(error)`. Flush descriptors must not carry

range information.



[`dispatch_io`]: crate::ublk_io::dispatch_io

[`UblkIoBackend`]: crate::ublk_io::UblkIoBackend
### Integration

The `UblkControlRuntime` uses `QueueLifecycle` internally to validate
state transitions in `remove_device()` and `mark_attached()`. Daemon-side
code can use `QueueLifecycleHandle` for queue-level lifecycle tracking
with device-ID association.

[`QueueLifecycle`]: crate::queue_lifecycle::QueueLifecycle


## CQ Overflow Handling

The completion queue (CQ) reap path in [`poll_completed_fetch_reqs`] implements
bounded retry overflow handling to prevent silent I/O completion loss under
sustained load.

### Feature Detection

At data-queue runtime creation (`open_data_queue_runtime`), the kernel's
`IORING_FEAT_NODROP` capability is probed via `ring.params().is_feature_nodrop()`
and stored in `UblkDataQueueRuntime::nodrop_enabled`. When NODROP is supported
(Linux 5.5+), the kernel buffers overflowed CQEs internally instead of dropping
them. Without NODROP, overflowed events are permanently lost but the overflow
counter still provides observability.

### Overflow Detection and Recovery

After draining all visible CQEs from the ring, [`poll_completed_fetch_reqs`]
checks `CompletionQueue::overflow()` to detect whether the kernel has recorded
overflow events. On overflow:

1. The `cq_overflow_count` counter on `UblkDataQueueRuntime` is incremented for
   observability.
2. `ring.submit()` is called to flush kernel-buffered overflow CQEs. The
   `io-uring` crate internally calls `io_uring_enter(2)` with the
   `IORING_ENTER_GETEVENTS` flag when `IORING_SQ_CQ_OVERFLOW` is set and
   `IORING_FEAT_NODROP` is enabled, making buffered events visible in the CQ
   ring.
3. A bounded retry loop (maximum 5 iterations) drains newly visible CQEs and
   repeats the overflow check, preventing infinite spinning under pathological
   load.

### Observability

- `UblkDataQueueRuntime::nodrop_enabled()` — reports whether the kernel supports
  NODROP buffering.
- `UblkDataQueueRuntime::cq_overflow_count()` — cumulative count of overflow
  cycles detected since runtime creation.

[`poll_completed_fetch_reqs`]: crate::ublk_io::poll_completed_fetch_reqs

## Integrity Validation Validation

The [`integrity_validation`] module produces tier-classified ublk block-volume
sector-pattern data integrity validation exercising deterministic write/read-back
verification across the full ublk I/O path with committed-root consistency
checks. This closes the normal-operation data-correctness gap between
crash-consistency (#5844) and discard durability (#5857).

### Sector Patterns

Four deterministic sector-fill patterns keyed by LBA (logical block address):

- **LbaIndexed** — fills each 512-byte sector with the 8-byte LBA repeated 64
  times. Detects misdirected I/O and off-by-one addressing errors.
- **AllZeros** — fills each sector with 0x00. Detects stale data / uninitialized
  read paths.
- **AllOnes** — fills each sector with 0xFF. Detects bit-stuck-low errors.
- **CounterFill** — fills each sector with a repeating 8-byte counter starting
  at `LBA * 7 + 1` and incrementing per chunk. Detects intra-sector byte-order
  errors.

### Validation Tiers

| Tier | Level | Description | Min Sectors |
|---|---|---|---|
| `SingleSectorRoundTrip` | 1 | Write one sector, read back, verify byte-identical | 1 |
| `MultiSectorSequential` | 2 | Write contiguous range, read back, verify each sector | 8 |
| `StaggeredOffsetOverlapped` | 3 | Write at staggered offsets; verify no cross-contamination | 16 |
| `FullVolumeSweep` | 4 | Write and read every sector in the device volume | device-dependent |

### Validation Report

[`IntegrityValidationReport::canonical`] produces a 24-row validation report:

- 16 core rows (4 patterns × 4 tiers) with canonical sector ranges
- 8 edge-case rows: LBA 0 round-trip, last-sector round-trip, boundary-crossing
  verify, unaligned-start staggered, zero-length refusal, intentional miscompare
  diagnostic, past-end refusal, and overflow refusal

Each row records the pattern, tier, start LBA, sector count, outcome (Pass /
Fail / Refusal), and a diagnostic message.

### QEMU Harness

The Nix QEMU test harness at `nix/vm/ublk-integrity-validation.nix` exercises
all four I/O patterns through the ublk device with deterministic sector-level
write/read-back verification, mounting and re-mounting across committed-root
checkpoints. Every sector read must match its written pattern byte-for-byte.

```sh
nix build -f nix/vm/ublk-integrity-validation.nix
```

### Outcome Classification

- **Pass** — all sectors matched expected pattern byte-for-byte
- **Fail** — one or more sectors miscompared (first-byte offset reported)
- **Refusal** — test could not execute (no /dev/kvm, no ublk support, device unavailable)

[`integrity_validation`]: crate::integrity_validation
[`IntegrityValidationReport::canonical`]: crate::integrity_validation::IntegrityValidationReport::canonical

## Integrity Validation Validation

The [`integrity_validation`] module produces tier-classified ublk block-volume
sector-pattern data integrity validation exercising deterministic write/read-back
verification across the full ublk I/O path with committed-root consistency
checks. This closes the normal-operation data-correctness gap between
crash-consistency (#5844) and discard durability (#5857).

### Sector Patterns

Four deterministic sector-fill patterns keyed by LBA (logical block address):

- **LbaIndexed** — fills each 512-byte sector with the 8-byte LBA repeated 64
  times. Detects misdirected I/O and off-by-one addressing errors.
- **AllZeros** — fills each sector with 0x00. Detects stale data / uninitialized
  read paths.
- **AllOnes** — fills each sector with 0xFF. Detects bit-stuck-low errors.
- **CounterFill** — fills each sector with a repeating 8-byte counter starting
  at `LBA * 7 + 1` and incrementing per chunk. Detects intra-sector byte-order
  errors.

### Validation Tiers

| Tier | Level | Description | Min Sectors |
|---|---|---|---|
| `SingleSectorRoundTrip` | 1 | Write one sector, read back, verify byte-identical | 1 |
| `MultiSectorSequential` | 2 | Write contiguous range, read back, verify each sector | 8 |
| `StaggeredOffsetOverlapped` | 3 | Write at staggered offsets; verify no cross-contamination | 16 |
| `FullVolumeSweep` | 4 | Write and read every sector in the device volume | device-dependent |

### Validation Report

[`IntegrityValidationReport::canonical`] produces a 24-row validation report:

- 16 core rows (4 patterns × 4 tiers) with canonical sector ranges
- 8 edge-case rows: LBA 0 round-trip, last-sector round-trip, boundary-crossing
  verify, unaligned-start staggered, zero-length refusal, intentional miscompare
  diagnostic, past-end refusal, and overflow refusal

Each row records the pattern, tier, start LBA, sector count, outcome (Pass /
Fail / Refusal), and a diagnostic message.

### QEMU Harness

The Nix QEMU test harness at `nix/vm/ublk-integrity-validation.nix` exercises
all four I/O patterns through the ublk device with deterministic sector-level
write/read-back verification, mounting and re-mounting across committed-root
checkpoints. Every sector read must match its written pattern byte-for-byte.

```sh
nix build -f nix/vm/ublk-integrity-validation.nix
```

### Outcome Classification

- **Pass** — all sectors matched expected pattern byte-for-byte
- **Fail** — one or more sectors miscompared (first-byte offset reported)
- **Refusal** — test could not execute (no /dev/kvm, no ublk support, device unavailable)

[`integrity_validation`]: crate::integrity_validation
[`IntegrityValidationReport::canonical`]: crate::integrity_validation::IntegrityValidationReport::canonical
