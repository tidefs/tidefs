# Block Volume Queue Admission OW-301B

> TFR-019 authority classification: Current spec (scoped). See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

## Source Boundary

OW-301B executable block-volume queue admission slice is implemented in
`tidefs-block-volume-adapter-core`.

This slice extends the OW-301A core model with the queue/runtime mirrors that a
later userspace `ublk` daemon must preserve before it can expose a Linux block
device:

- queue classes for reads, ordered mutations, barriers, and zero/discard work;
- queue sets and queue shards over deterministic block-range partitions;
- submission context mirrors that bind request class, range, exactness,
  durability, and shard refs;
- backpressure refusal when inflight request or byte limits are exceeded;
- export fence refusal before resize/failover/revoke work is admitted;
- flush epoch records that seal mutating submission contexts;
- completion commit mirrors that release queue state and render Linux-visible
  status codes.


The implementation-tracked non-release tests cover:

- read/write/flush classification into queue classes;
- overlapping mutation ranges sharing at least one queue shard for
  serialization;
- backpressure refusal without inflight-state mutation;
- export fence refusal without queue-state mutation;
- flush epoch sealing for mutating submission contexts;
- completion commit release of backpressure and Linux status rendering.


```text
tidefs-xtask check-block-volume-queue-admission
```

OW-301C extends this queue/admission model with dispatch execution in the same
`tidefs-block-volume-adapter-core` package. OW-301B remains the admission and
queue-state boundary; OW-301C executes only admitted contexts against the
deterministic image model and records dispatch/completion mirrors without
claiming a live `ublk` export.

## Relationship To Parent Gates

This is a prerequisite for OW-301. It provides queue/admission records and
deterministic refusal behavior before any Linux export surface is admitted.

## Non-Claims

This is not a ublk daemon, not a Linux block device, not a `/dev/ublk-control`
