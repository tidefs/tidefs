# Block Volume ublk ADD_DEV Boundary OW-301Q

> TFR-019 authority classification: Current spec (scoped). See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

## Source Boundary

OW-301Q executable ublk ADD_DEV control uring_cmd boundary is implemented in
`crates/tidefs-block-volume-adapter-ublk-control-runtime` and surfaced through
`tidefs-block-volume-adapter-daemon ublk-control-add-dev`.

This is the first mutating ublk control boundary in the Block Volume Adapter
path. It is intentionally narrow: the daemon must pass the OW-301O real-host
open gate and the OW-301P read-only feature probe before it can issue
`UBLK_U_CMD_ADD_DEV`.

The runtime crate owns the unsafe system-call boundary for this slice. It
submits a real Linux `UBLK_U_CMD_ADD_DEV` `IORING_OP_URING_CMD` request:

- `_IOWR('u', 0x04, struct ublksrv_ctrl_cmd)` command-op encoding;
- an SQE128 `io_uring` control command, matching the kernel ublk control file
  operation;
- `cmd.len == sizeof(struct ublksrv_ctrl_dev_info)`;
- `cmd.addr` points at a mutable `ublksrv_ctrl_dev_info`;
- `queue_id == u16::MAX`, because ADD_DEV is a global control command rather
  than a per-queue command;
- `ublksrv_ctrl_dev_info.dev_id == u32::MAX`, matching the kernel selftest
  convention for automatic device-id allocation;
- conservative TideFS geometry: one hardware queue, queue depth 64, and 1 MiB
  maximum I/O buffer size;
- required feature flags: `UBLK_F_CMD_IOCTL_ENCODE | UBLK_F_USER_COPY`.

The daemon command keeps the admission order explicit:

1. classify the real host kernel release through the observe host-probe receipt;
2. require the Linux 7.0-or-newer baseline already used by the host preflight;
3. require `/dev/ublk-control` to exist and be a character device;
4. require a successful read/write open;
5. submit `UBLK_U_CMD_GET_FEATURES`;
6. require `UBLK_F_CMD_IOCTL_ENCODE | UBLK_F_USER_COPY`;
7. submit `UBLK_U_CMD_ADD_DEV`.

not admitted, the command refuses before opening the control device and records
`add_dev.uring_cmd_attempted=false`. On an admitted host, a successful ADD_DEV
can create the kernel ublk device pair and returns the kernel-mutated
`ublksrv_ctrl_dev_info`, including the allocated device id and owner uid/gid.

This command does not issue `UBLK_U_CMD_SET_PARAMS`, does not issue `UBLK_U_CMD_START_DEV`, does not process ublk data queues, and does not start `/dev/ublkbN`. It does not run fio, mkfs, mount, or guest-filesystem acceptance.


The implementation-tracked non-release tests and commands cover:

- old-kernel refusal without an attempted open, feature probe, or ADD_DEV;
- missing `/dev/ublk-control` refusal without an attempted open, feature probe,
  or ADD_DEV;
- feature-probe failure refusal before ADD_DEV;
- required feature-mask refusal before ADD_DEV;
- real ADD_DEV command shape, SQE128 use, global queue id, and mutable
  `ublksrv_ctrl_dev_info` binding;
- automatic device-id request through `ublksrv_ctrl_dev_info.dev_id`;
- conservative queue geometry and max I/O buffer size;
- CQE errno mapping for ADD_DEV failure;
- successful ADD_DEV outcome recording of the kernel-returned device info;
- `tidefs-block-volume-adapter-daemon ublk-control-add-dev`;
- `tidefs-xtask check-block-volume-ublk-add-dev-boundary`;


```text
tidefs-block-volume-adapter-daemon ublk-control-add-dev
tidefs-xtask check-block-volume-ublk-add-dev-boundary
```

## Relationship To Parent Gates

This follows OW-301P. OW-301P proves the admitted read-only
`GET_FEATURES` uring_cmd boundary; OW-301Q adds the first guarded mutating
control command boundary and records whether the kernel accepted ADD_DEV.

This remains below OW-301 and PC-012. It is not a
block-device acceptance harness.

## Non-Claims

This is not a ublk daemon, not a started Linux block-device export, not
`UBLK_U_CMD_SET_PARAMS` execution, not `UBLK_U_CMD_START_DEV` execution.
