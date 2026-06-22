# Block Volume ublk START_DEV Boundary OW-301T

> TFR-019 authority classification: Current spec (scoped). See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

## Source Boundary

OW-301T guarded ublk START_DEV control boundary is implemented in
`crates/tidefs-block-volume-adapter-ublk-control-runtime` and surfaced through
`tidefs-block-volume-adapter-daemon ublk-control-start-dev`.

This follows OW-301S. The runtime now owns the real Linux
`UBLK_U_CMD_START_DEV` command shape for `IORING_OP_URING_CMD`:

- `_IOWR('u', 0x06, struct ublksrv_ctrl_cmd)` command-op encoding;
- an SQE128 control command;
- `cmd.dev_id` set to the concrete device id returned by ADD_DEV;
- `queue_id == u16::MAX`, because START_DEV is a global control command;
- `cmd.len == 0` and `cmd.addr == 0`;
- `cmd.data[0]` set to the daemon pid, matching the Linux ublk driver and
  selftest contract;
- explicit rejection of the automatic ADD_DEV device-id sentinel and invalid
  daemon pids before SQE submission.

The daemon command preserves the existing guarded sequence:

1. classify the real host kernel release through the observe host-probe receipt;
2. require the Linux 7.0-or-newer baseline already used by the host preflight;
3. require `/dev/ublk-control` to exist and be a character device;
4. require a successful read/write open;
5. submit `UBLK_U_CMD_GET_FEATURES`;
6. require `UBLK_F_CMD_IOCTL_ENCODE | UBLK_F_USER_COPY`;
7. submit `UBLK_U_CMD_ADD_DEV`;
8. project TideFS geometry and queue policy into `ublk_params`;
9. submit `UBLK_U_CMD_SET_PARAMS`;
10. require data queue FETCH_REQ readiness before START_DEV;
11. submit `UBLK_U_CMD_DEL_DEV` for the returned device id after ADD_DEV.

The Linux ublk driver waits inside START_DEV until every queue/tag slot has an
in-flight `UBLK_U_IO_FETCH_REQ`. A control-only START_DEV would therefore be an
unsafe hang, not a valid boundary. OW-301T records that prerequisite directly:
`tidefs-block-volume-adapter-daemon ublk-control-start-dev` reports
`start_dev.failure_class=data_queue_fetches_not_ready` and does not submit
START_DEV without ready data queues. OW-301U strengthens the same guard with
`start_dev.data_queue_runtime_live`, so submitted counts alone cannot satisfy
START_DEV after data-queue runtime ownership has been dropped.

In short, the daemon does not submit START_DEV without ready data queues.

not admitted, the command refuses before mutation and records
`start_dev.uring_cmd_attempted=false`. On an admitted host where ADD_DEV and
SET_PARAMS succeed but data queues are not ready, DEL_DEV cleanup is still
attempted after ADD_DEV.

This command does not process ublk data queues, does not submit START_DEV
without ready data queues, and does not start `/dev/ublkbN`. It does not run
fio, mkfs, mount, or guest-filesystem acceptance.


The implementation-tracked non-release tests and commands cover:

- real START_DEV command shape, SQE128 use, global queue id, zero control
  buffer, and inline daemon pid in `cmd.data[0]`;
- rejection of the automatic ADD_DEV device-id sentinel and invalid daemon pids;
- SET_PARAMS failure without START_DEV submission while preserving DEL_DEV
  cleanup;
- successful ADD_DEV and SET_PARAMS followed by an explicit
  `data_queue_fetches_not_ready` START_DEV refusal;
- simulated ready-queue START_DEV success and errno mapping in evaluation;
- cleanup outcome reporting after the START_DEV boundary;
- `tidefs-block-volume-adapter-daemon ublk-control-start-dev`;
- `tidefs-xtask check-block-volume-ublk-start-dev-boundary`;


```text
tidefs-block-volume-adapter-daemon ublk-control-start-dev
tidefs-xtask check-block-volume-ublk-start-dev-boundary
```

## Relationship To Parent Gates

This follows OW-301S. OW-301S proves guarded SET_PARAMS with cleanup;
OW-301T adds the real START_DEV command shape and prevents unsafe START_DEV
submission until the real ublk data-queue FETCH_REQ prerequisite exists.

This remains below OW-301 and PC-012. It is not a
block-device acceptance harness.

## Non-Claims

This is not a complete ublk daemon, not a started Linux block-device export, not
