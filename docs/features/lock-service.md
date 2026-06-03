# POSIX Advisory Lock Service

## Overview

The TideFS lock service provides POSIX 1003.1-compliant advisory byte-range
locking (fcntl F_SETLK / F_SETLKW / F_GETLK) with deadlock detection and
BLAKE3-verified intent-log crash safety. It operates locally per-filesystem
instance and is the backend for FUSE lock dispatch handlers.

## Lock Model

- **Per-inode lock table**: each inode maintains an ordered list of granted
  locks sorted by start byte.
- **Lock types**: Read (shared), Write (exclusive). Multiple Read locks on an
  overlapping range are compatible; Write conflicts with any lock.
- **Lock ranges**: start (inclusive) and len in bytes. A len of 0 follows
  POSIX semantics meaning "lock to end of file" (EOF, internally
  `u64::MAX`).
- **Owners**: locks are owned by a PID (process identifier). Same-PID
  overlapping locks replace each other; different PID overlapping locks
  conflict.
- **Blocking waits (F_SETLKW)**: conflicting non-blocking requests return
  `WouldBlock` (EAGAIN). Blocking requests are parked in FIFO order and
  re-evaluated when conflicting locks are released.

## Deadlock Detection

Before parking a blocking (F_SETLKW) request, the lock manager constructs a
**wait-for graph** across all inodes:

1. **Nodes**: process PIDs (LockOwnerPid).
2. **Edges**: each parked waiter → each lock holder it conflicts with
   (different PID, overlapping range, incompatible types).
3. **Proposed edge**: the new waiter → each current conflicting holder.

A **DFS cycle detector** runs on the graph. If adding the proposed waiter
would create a directed cycle reachable from the waiter's PID, the request
is rejected with `PosixLockError::Deadlock` (POSIX EDEADLK).

The algorithm is O(N + E) per deadlock check where N = number of distinct
PIDs and E = number of waiter → holder edges.

## Crash Recovery

Lock operations are recorded as `LockIntent` records in the intent log:

| Variant        | Encodes                                        | Body size |
| -------------- | ---------------------------------------------- | --------- |
| `Acquire`      | discriminant + ino(8) + range(16) + type(1) + pid(4) | 30 bytes |
| `Release`      | discriminant + ino(8) + range(16) + pid(4)      | 29 bytes |
| `ReleaseOwner` | discriminant + pid(4)                           | 5 bytes  |

Each record is BLAKE3-256 hashed with a domain-separated key
(`"TideFS LockIntent v1"`) for tamper detection. Full records are
`body || blake3::Hash` (body + 32 bytes).

On crash recovery, intent-log records are replayed in order:

- `Acquire` → re-inserted non-blocking (idempotent; silently skips if lock
  already exists).
- `Release` → best-effort release (silently skips if lock not found).
- `ReleaseOwner` → bulk release of all locks for a PID.

Parked waiters are NOT persisted; on crash the filesystem is re-mounted and
applications must re-issue their lock requests. This is consistent with
POSIX advisory locking semantics where locks are process-local and do not
survive process termination.

## Crate Structure

| File             | Purpose                                        |
| ---------------- | ---------------------------------------------- |
| `posix_lock.rs`  | LockRange, LockEntry, PosixLockTable, deadlock  |
| `lock_intent.rs` | LockIntent types, encode/decode, bridge, replay |
| `lib.rs`         | Cluster-level LOCK service protocol             |

## Test Coverage

86 tests cover: lock range semantics, acquire/release, overlapping conflict,
adjacent merge, blocking wait/wake, deadlock detection (2-process inversion,
cross-inode), release-all, EOF semantics, intent encode/decode with
BLAKE3 verification, tamper detection, domain separation, idempotent
replay, and full crash-recovery scenarios.
