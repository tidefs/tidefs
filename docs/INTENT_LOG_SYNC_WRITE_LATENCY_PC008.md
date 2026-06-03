# Intent-log sync write latency model (PC-008)

Maturity: **implemented-source** specification for publishing checklist item
`PC-008`.

This document binds the current PC-008 closeout to source without claiming a
production persistent WAL, kernel block path, ublk path, or measured latency
SLO pass.

## Source binding

The authoritative source markers are in
`crates/tidefs-local-filesystem/src/lib.rs`:

- `INTENT_LOG_SYNC_WRITE_LATENCY_SPEC`
- `INTENT_LOG_SYNC_WRITE_LATENCY_POLICY_VERSION`
- `IntentLogLatencyClass`
- `IntentLogReplyState`
- `IntentLogSyncWriteLatencyCase`
- `INTENT_LOG_SYNC_WRITE_LATENCY_CASES`
- `intent_log_sync_write_latency_cases()`

The implementation-tracked non-release cases define how a future intent-log analogue is allowed to
bound sync write latency:

- `sync-write-range`
- `odsync-data-range`
- `fsync-dirty-drain`
- `shared-mmap-msync-sync`
- `namespace-sync-intent`
- `pressure-fallback`
- `crash-replay-reconcile`

## Rules

1. A bounded sync write reply must be backed by a durable replayable intent or
   by the full normal commit path.
2. A replayable data intent must carry the target root anchor, affected range,
   chunk or extent identity, payload digest, and the metadata deltas needed to
   make replay exact.
3. `O_DSYNC` may omit unrelated metadata from the fast path, but it may not
   omit file-size-affecting metadata or range identity.
4. `fsync` drains all sealed intents and dirty windows for the target file into
   the normal root-slot publication boundary before reporting durable
   completion.
5. `MS_SYNC` for shared writable mappings consumes the same replayable range
   intent law as buffered sync writes; clean page-cache state alone is not a
   durability receipt.
6. Namespace intents must name parent directories, affected inode ids,
   link-count deltas, and conflict guards.
7. If intent reserve, dirty-window reserve, or latency budget is unavailable,
   the fast path must be refused or fall back to a full commit before success.
8. Crash replay may either complete each durable intent exactly once into a
   normal committed root or reject it as an explicit integrity/media error.
   Partial mounted truth is forbidden.

## Relationship to PC-007 and OW-204

PC-008 does not replace the transaction model. It constrains the fast path that
may exist before the full root-slot publication boundary is reached.
`PC-007` defines commit groups, dirty buffers, `fsync`, and `O_DSYNC`
semantics. PC-008 says which subset of those operations may use a bounded
intent-log analogue before normal publication finishes.

`OW-204` already binds page-cache/writeback/mmap state as non-authoritative.
The PC-008 `shared-mmap-msync-sync` case consumes that law: shared mmap dirty
completion can be reported.

## Non-claims

This closeout does not implement:

- a production persistent WAL or journal execution path;
- kernelspace, ublk, or block-volume sync write handling;
- a recovery daemon that mutates mounted truth.

