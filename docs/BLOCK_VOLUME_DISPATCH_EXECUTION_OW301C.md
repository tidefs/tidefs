# Block Volume Dispatch Execution OW-301C

> TFR-019 authority classification: Current spec (scoped). See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

## Source Boundary

OW-301C executable block-volume dispatch execution slice is implemented in
`tidefs-block-volume-adapter-core`.

This slice connects the OW-301A image model and the OW-301B queue/admission
model without creating a userspace daemon. It executes only admitted submission
contexts. The admitted submission contexts record dispatch/completion mirrors
for:

- read dispatch returning exact payload bytes from the block image;
- write dispatch mutating exact byte ranges and releasing queue backpressure;
- flush dispatch sealing dirty image epochs and recording queue flush epochs;
- discard and write-zeroes dispatch making zeroes visible through the image;
- unadmitted context refusal without a completion commit;
- payload-mismatch refusal that releases the admitted queue context without
  mutating image bytes.


The implementation-tracked non-release tests cover:

- admitted read dispatch with returned payload and completion commit;
- admitted write dispatch with exact byte mutation and queue release;
- flush dispatch with dirty epoch sealing and completion recording;
- discard/write-zeroes dispatch over visible zeroed ranges;
- unadmitted dispatch refusal without completion commit;
- payload-mismatch refusal without mutation and with queue release.


```text
tidefs-xtask check-block-volume-dispatch-execution
```

## Relationship To Parent Gates

This is a prerequisite for #30 / OW-301. It gives the block-volume model a
deterministic execution step after queue admission and before any Linux `ublk`
surface is admitted.

OW-301D extends this dispatch model with export lifecycle and quiesce phases so
dispatch remains subordinate to explicit queue-live, fenced, resumed, and stopped
state.

## Non-Claims

This is not a ublk daemon, not a Linux block device, not a `/dev/ublk-control`
