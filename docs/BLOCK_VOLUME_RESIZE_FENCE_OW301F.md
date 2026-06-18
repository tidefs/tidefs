# Block Volume Resize Fence OW-301F

> TFR-019 authority classification: Current spec (scoped). See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

## Source Boundary

OW-301F executable block-volume resize/fence transition slice is implemented in
`tidefs-block-volume-adapter-core`.

This slice extends the OW-301D export lifecycle and OW-301E cache coherency
models with explicit resize transition records. Resizes are not inferred from
ordinary writes. A resize must publish a capacity target, identify the affected
tail range, prove the export is fenced after quiesce, and refuse when authority

The concrete records cover:

- capacity target publication for prepared and committed transitions;
- affected tail range calculation for grow and shrink;
- zero-visible grow range semantics for newly exposed blocks;
- drain-incomplete refusal when dirty, inflight, or guarded ranges overlap the
  shrink tail;
- no-authority resize refusal when the caller lacks the export authority
  anchor;
- post-resize geometry publication into the queue runtime after commit;
- ordinary writes past current end stay refused and do not imply resize.


The implementation-tracked non-release tests cover:

- grow prepare/commit publishing new geometry and zero-visible tail range;
- shrink refusal while an unsealed dirty epoch overlaps the removed tail;
- resize refusal when the export is not fenced;
- no-authority resize refusal;
- write-past-end refusal without implicit geometry mutation.


```text
tidefs-xtask check-block-volume-resize-fence
```

## Relationship To Parent Gates

This is a prerequisite for #30 / OW-301. It binds resize/fence policy to source
records after the lifecycle and cache gates, before any Linux `ublk` surface is
admitted.

OW-301D provides the quiesce/fence boundary that a resize must pass before
commit. OW-301E provides cache dirty epochs and direct-overlap guards that act
as resize drain blockers for removed tail ranges.

The old OW-301G model-backed app smoke command has been retired. This
resize/fence model remains source-level design context only; live block-volume
artifacts.

## Non-Claims

This is not a ublk daemon, not a Linux block device, not a `/dev/ublk-control`
