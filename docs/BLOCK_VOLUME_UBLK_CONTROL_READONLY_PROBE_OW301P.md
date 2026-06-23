# Block Volume ublk Control uring_cmd Probe OW-301P

> TFR-019 authority classification: Current spec (scoped). See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

## Source Boundary

OW-301P executable read-only ublk control uring_cmd probe boundary is implemented in
`crates/tidefs-block-volume-adapter-ublk-control-runtime` and surfaced through
`tidefs-block-volume-adapter-daemon ublk-control-readonly-probe`.

The runtime crate owns the only unsafe system-call wrapper for this slice. It
submits a real Linux `UBLK_U_CMD_GET_FEATURES` `IORING_OP_URING_CMD` request:

- `UBLK_U_CMD_GET_FEATURES` request number `0x13`;
- `_IOR('u', 0x13, struct ublksrv_ctrl_cmd)` command-op encoding;
- an SQE128 `io_uring` control command, matching the kernel ublk control file operation;
- `cmd.len == UBLK_FEATURES_LEN`;
- `cmd.addr` points at an 8-byte userspace feature buffer;
- no mutating ublk control command is exposed by the read-only probe builder.

The daemon command keeps the OW-301O host admission order before it can call the
runtime boundary:

- classify the real host kernel release through the observe host-probe receipt;
- require the Linux 7.0-or-newer baseline already used by the host preflight;
- require `/dev/ublk-control` to exist and be a character device;
- require a successful `OpenOptions::new().read(true).write(true)` open;
- submit only the read-only `GET_FEATURES` uring_cmd after those gates pass.

If the host is not admitted, the command refuses before opening the control device and records
`probe.uring_cmd_attempted=false`. On a suitable host, it can submit `GET_FEATURES`
and map the returned feature mask into the typed `tidefs-ublk-abi` feature
flags.

This command does not issue mutating ublk control commands and does not create `/dev/ublkbN`. It also does not create `/dev/ublkcN`, process io_uring data queues, run fio, or run mkfs/mount.


The implementation-tracked non-release tests and commands cover:

- old-kernel refusal without an attempted open or uring_cmd;
- missing `/dev/ublk-control` refusal without an attempted open or uring_cmd;
- control open failure without an attempted uring_cmd;
- real `GET_FEATURES` uring_cmd shape and 8-byte feature buffer binding;
- successful feature-mask mapping;
- CQE errno mapping for ublk command failure;
- mutating-command rejection at the read-only builder;
- `tidefs-block-volume-adapter-daemon ublk-control-readonly-probe`;
- `tidefs-xtask check-block-volume-ublk-control-readonly-probe`;


```text
tidefs-block-volume-adapter-daemon ublk-control-readonly-probe
tidefs-xtask check-block-volume-ublk-control-readonly-probe
```

## Relationship To Parent Gates

This follows OW-301O. OW-301O proves the real control-device open
admission boundary; OW-301P adds the first admitted read-only ublk control
uring_cmd boundary without creating or starting a device.

This remains below OW-301 and PC-012. It is not a block-device acceptance harness.

## Non-Claims

This is not a ublk daemon, not a Linux block device, not `UBLK_CMD_ADD_DEV` or
`UBLK_CMD_START_DEV` execution, not io_uring data-queue execution, not fio.
