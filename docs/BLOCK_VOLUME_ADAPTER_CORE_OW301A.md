# Block Volume Adapter Core OW-301A

> TFR-019 authority classification: Current spec (scoped). See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

## Source Boundary

OW-301A executable block-volume adapter core slice is implemented in
`tidefs-block-volume-adapter-core`.

The core model is deliberately smaller than a userspace export daemon. It binds
the block-volume laws that a later userspace `ublk` adapter must preserve:

- geometry bounds over a fixed block size and block count;
- read/write exactness over a bounded byte image;
- dirty-range epoch records for mutating writes;
- flush barrier records that cover unsealed dirty epochs;
  dirty epochs;
- explicit out-of-bounds, misaligned-range, and unsupported-discard refusals.


The implementation-tracked non-release tests cover:

- exact block read/write round trip;
- flush barrier creation and dirty epoch sealing;
- misaligned write refusal without mutation;
- out-of-bounds read refusal;
- discard alignment refusal.


```text
tidefs-xtask check-block-volume-adapter-core
```

OW-301B extends this crate with a queue/admission model in the same
`tidefs-block-volume-adapter-core` package. The OW-301A boundary remains the
byte/geometry/dirty-range model; OW-301B adds queue classes, queue shards,
backpressure, export-fence, flush-epoch, and completion-commit mirrors without
claiming a live `ublk` export.

## Relationship To Parent Gates

This is a prerequisite for #30 / OW-301. It gives the repository an executable
block-volume adapter family member before any Linux export surface is admitted.

## Non-Claims

durability claim. It does not close #30, #50, or #57.
