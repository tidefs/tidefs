# Block Volume ublk SET_PARAMS Boundary OW-301S

> TFR-019 authority classification: Current spec (scoped). See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

## Source Boundary

OW-301S executable ublk SET_PARAMS control uring_cmd boundary is implemented in
`crates/tidefs-block-volume-adapter-ublk-control-runtime` and surfaced through
`tidefs-block-volume-adapter-daemon ublk-control-set-params`.

This follows OW-301R. The command keeps the same admission sequence as the
guarded ADD_DEV/DEL_DEV boundary: the daemon must pass the OW-301O real-host
open gate and the OW-301P read-only `GET_FEATURES` probe before it can issue
`UBLK_U_CMD_ADD_DEV`. It then projects the existing OW-301J TideFS
basic/discard/segment `ublk_params` record and submits `UBLK_U_CMD_SET_PARAMS`
only for the concrete device id returned by ADD_DEV.

The runtime crate owns the system-call boundary for this slice. It submits a
real Linux `UBLK_U_CMD_SET_PARAMS` `IORING_OP_URING_CMD` request:

- `_IOWR('u', 0x04, struct ublksrv_ctrl_cmd)` command-op encoding;
- an SQE128 `io_uring` control command;
- `cmd.dev_id` set to the returned ADD_DEV device id;
- `queue_id == u16::MAX`, because SET_PARAMS is a global control command;
- `cmd.len == sizeof(struct ublk_params)`;
- `cmd.addr` pointing at a live userspace `ublk_params` buffer;
- required `UBLK_PARAM_TYPE_BASIC | UBLK_PARAM_TYPE_DISCARD | UBLK_PARAM_TYPE_SEGMENT` parameter bits.

The daemon command keeps cleanup ordering explicit:

1. classify the real host kernel release through the observe host-probe receipt;
2. require the Linux 7.0-or-newer baseline already used by the host preflight;
3. require `/dev/ublk-control` to exist and be a character device;
4. require a successful read/write open;
5. submit `UBLK_U_CMD_GET_FEATURES`;
6. require `UBLK_F_CMD_IOCTL_ENCODE | UBLK_F_USER_COPY`;
7. submit `UBLK_U_CMD_ADD_DEV`;
8. project TideFS geometry and queue policy into `ublk_params`;
9. submit `UBLK_U_CMD_SET_PARAMS`;
10. submit `UBLK_U_CMD_DEL_DEV` for the returned device id, including when
    SET_PARAMS fails after ADD_DEV.

If the host is not admitted, the command refuses before mutation and records
`set_params.uring_cmd_attempted=false` and `del_dev.uring_cmd_attempted=false`.
On an admitted host where ADD_DEV succeeds, DEL_DEV cleanup is attempted and any
cleanup failure is reported explicitly as `control.cleanup_failed_after_add_dev`.

This command does not issue `UBLK_U_CMD_START_DEV`, does not process ublk data
queues, and does not start `/dev/ublkbN`. It does not run fio, mkfs, mount, or
guest-filesystem acceptance.


The implementation-tracked non-release tests and commands cover:

- old-kernel refusal without an attempted open, feature probe, ADD_DEV,
  SET_PARAMS, or DEL_DEV;
- feature-mask refusal without SET_PARAMS or DEL_DEV;
- ADD_DEV failure without SET_PARAMS or DEL_DEV;
- real SET_PARAMS command shape, SQE128 use, global queue id, full
  `ublk_params` buffer length, and live `cmd.addr`;
- rejection of the automatic ADD_DEV device-id sentinel as a SET_PARAMS target;
- required basic/discard/segment parameter fields;
- successful ADD_DEV followed by SET_PARAMS and DEL_DEV cleanup;
- CQE errno mapping for SET_PARAMS while still attempting DEL_DEV cleanup;
- CQE errno mapping for DEL_DEV cleanup failure after SET_PARAMS;
- `tidefs-block-volume-adapter-daemon ublk-control-set-params`;
- `tidefs-xtask check-block-volume-ublk-set-params-boundary`;


```text
tidefs-block-volume-adapter-daemon ublk-control-set-params
tidefs-xtask check-block-volume-ublk-set-params-boundary
```

## Relationship To Parent Gates

This follows OW-301R. OW-301R proves guarded ADD_DEV cleanup; OW-301S
adds the first guarded parameter-setting control command using the existing
TideFS geometry parameters and preserves cleanup after successful ADD_DEV.

This remains below OW-301 and PC-012. It is not a
block-device acceptance harness.

## Non-Claims

This is not a ublk daemon, not a started Linux block-device export, not
`UBLK_U_CMD_START_DEV` execution, not io_uring data-queue execution, not fio.
