# tidefs-cleanup-queue-core

This crate owns the source-level cleanup queue records used to persist deferred
cleanup work. Cleanup roots point at a sealed commit-group page containing the
serialized queue entries.

`CleanupQueueReplayReceipt` verifies that a cleanup queue root and sealed page
agree on the root magic/version, page digest, entry count, and zeroed reserved
fields before queue entries are replayed from that page.

The receipt is a cleanup queue consistency check only. It does not define
background scheduler dispatch, allocator publication, mounted capacity
accounting, reclaim behavior, or filesystem recovery guarantees.
