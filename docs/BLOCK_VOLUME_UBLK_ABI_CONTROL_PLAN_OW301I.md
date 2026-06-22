# Block Volume ublk ABI Control Plan OW-301I

> TFR-019 authority classification: Current spec (scoped). See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

## Source Boundary

OW-301I executable block-volume ublk ABI control-plan surface is implemented in
`crates/tidefs-ublk-abi` and surfaced through
`apps/tidefs-block-volume-adapter-daemon ublk-abi-plan`.

The crate mirrors the Linux userspace `ublk` header boundary from
`/usr/include/linux/ublk_cmd.h` into typed Rust constants and records:

- control command numbers for `GET_FEATURES`, `ADD_DEV`, `SET_PARAMS`,
  `START_DEV`, `GET_DEV_INFO2`, `QUIESCE_DEV`, `UPDATE_SIZE`, `STOP_DEV`, and
  `DEL_DEV`;
- ioctl request encoding and decoding for the Linux `_IOR` / `_IOWR` command
  shape;
- `repr(C)` control command, device-info, I/O command, I/O descriptor, and
  parameter records;
- feature flags for command ioctl encoding, user copy, recovery, resize, and
  quiesce support;
- queue, tag, request-buffer, and auto-buffer-registration packing helpers.

The app command prints a parseable dry-run plan. It does not open
`/dev/ublk-control`, issue ioctl, load modules, create `/dev/ublkcN`, create
`/dev/ublkbN`, run fio, run mkfs/mount, or attach/list/detach a live export.


The implementation-tracked non-release tests and commands cover:

- `tidefs-block-volume-adapter-daemon ublk-abi-plan`;
- struct-size checks for the mirrored `ublksrv_*` and `ublk_params` layouts;
- ioctl direction/type/number/size decoding for read-only and mutating control
  commands;
- feature-mask composition for the future TideFS control plan;
- queue/tag/buffer address packing boundary checks;
- dry-run command ordering for
  `GET_FEATURES -> ADD_DEV -> SET_PARAMS -> START_DEV -> GET_DEV_INFO2`;
- explicit mutating/non-mutating classification for quiesce, resize, stop, and
  delete boundaries;
- `tidefs-xtask check-block-volume-ublk-abi`;


```text
tidefs-block-volume-adapter-daemon ublk-abi-plan
tidefs-xtask check-block-volume-ublk-abi
```

## Relationship To Parent Gates

This is a prerequisite for OW-301. It is below the PC-012 Linux block-device acceptance gates: it defines and tests the typed ABI
and does not create `/dev/ublkbN`.

OW-301H decides whether a host can admit live `ublk` work. OW-301I defines the
control command and record layout the future live path must use after host
admission succeeds.

OW-301J follows this ABI control plan by projecting TideFS block geometry and
queue policy into the concrete `ublk_params` payload for the future
`UBLK_CMD_SET_PARAMS` step.

## Non-Claims

This is not a ublk daemon, not a Linux block device, not a `/dev/ublk-control`
