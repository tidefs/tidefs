# tidefs-cleanup-engine

`tidefs-cleanup-engine` drains deferred cleanup queue entries through the
cleanup job executors and records per-entry decisions.

## Cleanup Decision Receipts

Cleanup decision receipts are local engine records. A receipt
records:

- cleanup queue entry id;
- work kind;
- work-item generation, currently the enqueue commit group;
- decision: executed, skipped, deferred, or rejected;
- required evidence for the decision;
- decision reason;
- validation tier represented by that evidence;
- optional external artifact digest.

The receipt format is deterministic and machine-readable, and it is scoped to
why this engine accepted, skipped, deferred, or rejected an observed cleanup
entry. It does not define the cleanup queue root format, background scheduling
policy, allocator publication, mounted capacity accounting, or reclaim behavior.

Product-level cleanup, reclaim, capacity, snapshot/deadlist, and compaction
boundaries live in the authority documents and validation claims. For this
crate, the useful invariant is narrower: a receipt must describe one engine
decision without promoting that local decision into filesystem recovery,
capacity, or release-readiness evidence.
