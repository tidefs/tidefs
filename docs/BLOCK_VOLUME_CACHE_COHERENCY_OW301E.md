# Block Volume Cache Coherency OW-301E

> TFR-019 authority classification: Current spec (scoped). See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

## Source Boundary

OW-301E executable block-volume cache coherency slice is implemented in
`tidefs-block-volume-adapter-core`.

This slice extends the block-volume core, queue, dispatch, and lifecycle models
with source records for clean read-cache windows, dirty range epochs, flush/FUA barriers,
and cache-loss behavior. Cached bytes are never authority: losing a clean cache
barriers, or authoritative storage records.

The model records clean read-cache windows, dirty range epochs, flush/FUA barriers,

The concrete records include:

- clean hot and prefetch read-cache windows with anchor snapshots;
- flush barriers over unsealed dirty epochs;
- FUA completion tickets for FUA-required barriers;
- direct-overlap guards that block until overlapping dirty epochs are sealed;
- cache-loss transitions that drop clean windows without erasing dirty records.


The implementation-tracked non-release tests cover:

- flush barrier coverage and FUA ticket creation;
- direct-overlap guard blockage until dirty drain;
- clean cache loss without removing dirty authority records.


```text
tidefs-xtask check-block-volume-cache-coherency
```

## Relationship To Parent Gates

This is a prerequisite for #30 / OW-301 and follows the P6-02 cache/flush/FUA
law. It gives the block-volume model explicit cache coherency and barrier
records before any Linux `ublk` surface is admitted.

OW-301F consumes these cache coherency records as resize drain blockers. A shrink
transition refuses while an unsealed dirty epoch or direct-overlap guard covers
present.

## Non-Claims

This is not a ublk daemon, not a Linux block device, not a `/dev/ublk-control`
