# Block Volume ublk DEL_DEV Cleanup Boundary OW-301R

> TFR-019 authority classification: Current spec (scoped). See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

## Source Boundary

OW-301R executable ublk DEL_DEV cleanup uring_cmd boundary is implemented in
`crates/tidefs-block-volume-adapter-ublk-control-runtime` and surfaced through
`tidefs-block-volume-adapter-daemon ublk-control-add-del-dev`.

This follows OW-301Q. The command keeps the same admission sequence as the
guarded ADD_DEV boundary: the daemon must pass the OW-301O real-host open gate
and the OW-301P read-only `GET_FEATURES` probe before it can issue
`UBLK_U_CMD_ADD_DEV`. It then submits `UBLK_U_CMD_DEL_DEV` only after successful
ADD_DEV returns a concrete kernel device id.

The runtime crate owns the system-call boundary for this slice. It submits a
real Linux `UBLK_U_CMD_DEL_DEV` `IORING_OP_URING_CMD` request:

- `_IOWR('u', 0x05, struct ublksrv_ctrl_cmd)` command-op encoding;
- an SQE128 `io_uring` control command;
- `cmd.dev_id` set to the returned ADD_DEV device id;
- `queue_id == u16::MAX`, because DEL_DEV is a global control command rather
  than a per-queue command;
- `cmd.len == 0`;
- `cmd.addr == 0`;
- no userspace control buffer.

The daemon command keeps cleanup ordering explicit:

1. classify the real host kernel release through the observe host-probe receipt;
2. require the Linux 7.0-or-newer baseline already used by the host preflight;
3. require `/dev/ublk-control` to exist and be a character device;
4. require a successful read/write open;
5. submit `UBLK_U_CMD_GET_FEATURES`;
6. require `UBLK_F_CMD_IOCTL_ENCODE | UBLK_F_USER_COPY`;
7. submit `UBLK_U_CMD_ADD_DEV`;
8. submit `UBLK_U_CMD_DEL_DEV` for the returned device id.

not admitted, the command refuses before mutation and records
`add_dev.uring_cmd_attempted=false` and `del_dev.uring_cmd_attempted=false`. On
an admitted host where ADD_DEV succeeds, DEL_DEV cleanup is attempted and any
cleanup failure is reported explicitly as `control.cleanup_failed_after_add_dev`.

This command does not issue `UBLK_U_CMD_SET_PARAMS`, does not issue `UBLK_U_CMD_START_DEV`, does not process ublk data queues, and does not start
`/dev/ublkbN`. It does not run fio, mkfs, mount, or guest-filesystem acceptance.


The implementation-tracked non-release tests and commands cover:

- old-kernel refusal without an attempted open, feature probe, ADD_DEV, or
  DEL_DEV;
- ADD_DEV failure without a DEL_DEV attempt;
- real DEL_DEV command shape, SQE128 use, global queue id, zero-length command
  buffer, and zero command address;
- rejection of the automatic ADD_DEV device-id sentinel as a DEL_DEV target;
- successful ADD_DEV followed by successful DEL_DEV cleanup;
- CQE errno mapping for DEL_DEV cleanup failure after ADD_DEV;
- `tidefs-block-volume-adapter-daemon ublk-control-add-del-dev`;
- `tidefs-xtask check-block-volume-ublk-del-dev-cleanup-boundary`;


```text
tidefs-block-volume-adapter-daemon ublk-control-add-del-dev
tidefs-xtask check-block-volume-ublk-del-dev-cleanup-boundary
```

## Relationship To Parent Gates

This follows #98 / OW-301Q. OW-301Q proves the first guarded ADD_DEV mutating
control boundary; OW-301R adds the paired guarded cleanup boundary so successful
ADD_DEV execution does not leave an unmanaged ublk device pair.

This remains below #30 / OW-301, #50 / PC-005, and #57 / PC-012. It is not a
block-device acceptance harness.

## Non-Claims

This is not a ublk daemon, not a started Linux block-device export, not
`UBLK_U_CMD_SET_PARAMS` execution, not `UBLK_U_CMD_START_DEV` execution, not
#57.
