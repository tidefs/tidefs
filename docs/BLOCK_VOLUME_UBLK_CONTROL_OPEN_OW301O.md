# Block Volume ublk Control Open OW-301O

> TFR-019 authority classification: Current spec (scoped). See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

## Source Boundary

OW-301O executable ublk control-device open boundary is implemented in
`apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open.rs` and surfaced
through `tidefs-block-volume-adapter-daemon ublk-control-open`.

The command is the first runtime boundary after the typed `ublk` plan and the
file-backed image surface. It performs host admission in order:

- classify the real host kernel release through the observe host-probe receipt;
- require the Linux 7.0-or-newer baseline already used by the host preflight;
- require `/dev/ublk-control` to exist and be a character device;
- attempt `OpenOptions::new().read(true).write(true)` only after those gates
  pass;
- bind the report to the typed `tidefs-ublk-abi` control-plan request values.

not admitted, the command refuses before opening the control device and records
the exact refusal class. On a suitable host, it opens the real control device and
immediately drops the handle after recording admission.

This command does not issue read-only probe ioctls, does not issue mutating ublk control ioctls, and does not create `/dev/ublkbN`. It also does not create `/dev/ublkcN`, process io_uring queues, run fio, or run mkfs/mount.


The implementation-tracked non-release tests and commands cover:

- old-kernel refusal without an attempted control-device open;
- missing `/dev/ublk-control` refusal without an attempted open;
- non-character `/dev/ublk-control` refusal without an attempted open;
- admitted host open result after the kernel and control-device gates pass;
- open failure recording without issuing read-only or mutating ioctls;
- typed `ublk` control-plan request printing for the boundary report;
- `tidefs-block-volume-adapter-daemon ublk-control-open`;
- `tidefs-xtask check-block-volume-ublk-control-open`;


```text
tidefs-block-volume-adapter-daemon ublk-control-open
tidefs-xtask check-block-volume-ublk-control-open
```

## Relationship To Parent Gates

This follows #95 / OW-301N. OW-301N proves that block-volume semantics can run
against a durable userspace backing file; OW-301O adds the real control-device
admission/open boundary that a future live ublk runtime must pass before it can
attempt attach/list/detach behavior.

This remains below #30 / OW-301, #50 / PC-005, and #57 / PC-012. It is not
harness.

## Non-Claims

This is not a ublk daemon, not a Linux block device, not `UBLK_CMD_ADD_DEV` or
`UBLK_CMD_START_DEV` execution, not read-only `UBLK_CMD_GET_FEATURES` execution,
