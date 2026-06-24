# Block Volume File Backing OW-301N

> TFR-019 authority classification: Current spec (scoped). See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

## Source Boundary

OW-301N executable block-volume file-backed image surface is implemented in
`crates/tidefs-block-volume-adapter-core` and surfaced through
`tidefs-block-volume-adapter-daemon backing-file-smoke`.

The source surface adds `BlockVolumeFileImage` beside the existing in-memory
`BlockVolumeImage`. It binds the same block geometry, request plan, dirty
epoch, flush barrier, discard intent, and refusal records to a real userspace
backing file:

- create zeroed backing files with `std::fs::File` and exact geometry-derived
  length;
- reopen existing backing files only when length matches the requested block
  geometry;
- read and write block ranges through Unix `FileExt` offset I/O;
- flush through `sync_all`;
- make discard and write-zeroes ranges zero-visible by writing zeroes to the
  backing file;
- refuse invalid geometry, out-of-bounds ranges, unsupported discard, and
  misaligned payloads without claiming a live block device.

This command does not open `/dev/ublk-control`. It does not create
`/dev/ublkcN` or `/dev/ublkbN`, process io_uring queues, issue ublk fetch or
commit commands, run fio, run mkfs/mount, or prove guest-filesystem behavior.


The implementation-tracked non-release tests and commands cover:

- `BlockVolumeFileImage::create_zeroed` and `BlockVolumeFileImage::reopen_existing`;
- exact file-backed read/write round trip after flush and reopen;
- real `sync_all` flush execution before flush barrier publication;
- discard/write-zeroes zero visibility through the backing file;
- invalid range and misaligned payload refusal without backing mutation;
- backing length mismatch refusal;
- `tidefs-block-volume-adapter-daemon backing-file-smoke`;
- `tidefs-xtask check-block-volume-file-backing`;


```text
tidefs-block-volume-adapter-daemon backing-file-smoke
tidefs-xtask check-block-volume-file-backing
```

## Relationship To Parent Gates

This follows OW-301M. OW-301M binds ublk descriptor intake, queue
admission, dispatch, and completion rendering against the existing in-memory
source image; OW-301N adds a durable userspace backing-file image surface that
future live ublk work can use without changing the request semantics.

This remains below OW-301 and PC-012. It is not a kernel ublk runtime and does not claim block-device readiness.

## Non-Claims

This is not a ublk daemon, not a Linux block device, not a `/dev/ublk-control`
runtime, not `/dev/ublkcN` command execution, not io_uring queue execution.
