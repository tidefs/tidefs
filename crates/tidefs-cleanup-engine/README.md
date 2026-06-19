# tidefs-cleanup-engine

`tidefs-cleanup-engine` drains deferred cleanup queue entries through the
cleanup job executors and records progress for resume.

## Replay Decision Receipts

Cleanup replay decision receipts are per-entry engine evidence. A receipt
records:

- cleanup queue entry id;
- work kind;
- work-item generation, currently the enqueue commit group;
- decision: executed, skipped, deferred, or rejected;
- required evidence for the decision;
- decision reason;
- validation tier represented by that evidence;
- optional external artifact digest.

The receipt format is deterministic and machine-readable, but it is scoped to
engine decisions only. It does not change the cleanup queue root format,
background scheduling policy, or reclaim runtime behavior.

Before TideFS can strengthen cleanup/reclaim product claims, the remaining
evidence must still show cleanup queue root replay across crash/remount,
runtime reclaim side effects against the allocator and namespace state, and
mounted workload recovery that proves reclaimed space remains correct after
interruption. These receipts explain why the cleanup engine accepted, skipped,
deferred, or rejected an observed entry; they do not by themselves prove
end-to-end reclaim crash safety.
