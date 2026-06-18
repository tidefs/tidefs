# tidefs-cleanup-queue-core

This crate owns the source-level cleanup queue records used to persist deferred
cleanup work. Cleanup roots point at a sealed commit-group page containing the
serialized queue entries.

`CleanupQueueReplayReceipt` verifies that a cleanup queue root and sealed page
agree on the root magic/version, page digest, entry count, and zeroed reserved
fields before the page is treated as durable replay evidence.

The receipt is cleanup queue replay evidence only. It is not, by itself, a full
filesystem crash-recovery proof and does not change background scheduler
dispatch policy or reclaim behavior.
