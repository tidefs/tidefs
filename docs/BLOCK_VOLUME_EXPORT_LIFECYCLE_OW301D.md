# Block Volume Export Lifecycle OW-301D

## Source Boundary

OW-301D executable block-volume export lifecycle slice is implemented in
`tidefs-block-volume-adapter-core`.

This slice extends the OW-301A image model, OW-301B queue/admission model, and
OW-301C dispatch execution model without creating a userspace daemon. It models
the export runtime phases that a later block-volume adapter must preserve:

- bootstrap;
- export admission;
- queues-live data admission;
- quiesce transition for resize/revoke/failover-style boundaries;
- fenced after drain;
- resumed under a fresh fence epoch;
- stopped with data admission refused.

The quiesce transition closes data-plane ingress and classifies existing
submission contexts before the export can move to fenced. Read contexts are
classified as commit-ok, mutating write/discard/write-zeroes contexts are
classified as replay-required, and uncompleted flush contexts are classified as
abort-required. Fence completion is refused until the queue runtime has drained
its inflight submission contexts.


The implementation-tracked non-release tests cover:

- bootstrap refusal before queue-live admission;
- export admission and queues-live transition;
- stopped exports refusing new data admission;
- quiesce transition closing ingress while retaining inflight classifications;
- drain-incomplete refusal before fenced completion;
- successful fenced completion after explicit queue drain;
- resume reopening data admission under a fresh fence epoch;
- invalid lifecycle transitions recorded without state mutation.


```text
tidefs-xtask check-block-volume-export-lifecycle
```

## Relationship To Parent Gates

This is a prerequisite for #30 / OW-301. It gives the block-volume model an
explicit export lifecycle and quiesce boundary after queue admission and
dispatch execution, before any Linux `ublk` surface is admitted.

OW-301E extends this lifecycle model with cache coherency and barrier records so
export transitions can remain subordinate to dirty-range drains, FUA barriers,

OW-301F extends this lifecycle model with resize/fence capacity transitions.
Resize prepare and commit require the export to reach the fenced phase after a
resize quiesce and drain boundary; queues-live and bootstrap states can publish
refusal records but cannot mutate geometry.

## Non-Claims

This is not a ublk daemon, not a Linux block device, not a `/dev/ublk-control`
