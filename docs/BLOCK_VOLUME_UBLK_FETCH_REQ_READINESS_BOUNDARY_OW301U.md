# Block Volume ublk FETCH_REQ Readiness Boundary OW-301U

> TFR-019 authority classification: Current spec (scoped). See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

## Source Boundary

OW-301U guarded ublk data-queue FETCH_REQ readiness boundary is implemented in
`crates/tidefs-block-volume-adapter-ublk-control-runtime` and surfaced through
`tidefs-block-volume-adapter-daemon ublk-data-queue-fetch-req`.

This follows OW-301T. The runtime now owns the real Linux
`UBLK_U_IO_FETCH_REQ` command shape for data-queue `IORING_OP_URING_CMD` use:

- `_IOWR('u', UBLK_IO_FETCH_REQ, struct ublksrv_io_cmd)` command-op encoding;
- an SQE128 data-queue command for `/dev/ublkcN`;
- `cmd.q_id` bound to the data queue id;
- `cmd.tag` bound to the queue tag slot;
- `cmd.result == 0`, because FETCH_REQ does not commit a prior request result;
- `cmd.addr == 0` for the TideFS `UBLK_F_USER_COPY` boundary;
- `user_data` bound to tag, command number, and queue id;
- submission through a caller-owned io_uring without waiting for a CQE.

The no-wait submission rule is intentional. Linux keeps a FETCH_REQ in flight
until a block request is fetched. Therefore the caller must keep the data-queue
ring and `/dev/ublkcN` fd live, and the command must remain in flight before a
future START_DEV boundary can be considered ready.

The daemon command reports the implementation-tracked non-release command, queue geometry, user-data
encoding, and readiness calculation without opening `/dev/ublkcN` and without
submitting FETCH_REQ. Readiness is not a count-only flag: it requires both all
queue/tag FETCH_REQ submissions and `data_queue_runtime_live=true`. The
OW-301T START_DEV guard now consumes the same readiness bit, so a detached or
dropped data-queue runtime cannot satisfy START_DEV admission.

This command does not submit FETCH_REQ without a live data-queue runtime, does
not issue START_DEV, and does not start `/dev/ublkbN`. It does not run fio,
mkfs, mount, or guest-filesystem acceptance.


The implementation-tracked non-release tests and commands cover:

- real FETCH_REQ command shape, SQE128 use, data queue id, tag, zero result,
  and zero USER_COPY address;
- encoding of `ublksrv_io_cmd` into the `uring_cmd80` payload;
- rejection of invalid queue geometry, queue ids, tags, and nonzero USER_COPY
  addresses;
- `user_data` binding for tag, `UBLK_IO_FETCH_REQ`, and queue id;
- readiness requiring a live data-queue runtime as well as submitted counts;
- START_DEV readiness inheriting `data_queue_runtime_live`;
- `tidefs-block-volume-adapter-daemon ublk-data-queue-fetch-req`;
- `tidefs-xtask check-block-volume-ublk-fetch-req-readiness-boundary`;


```text
tidefs-block-volume-adapter-daemon ublk-data-queue-fetch-req
tidefs-xtask check-block-volume-ublk-fetch-req-readiness-boundary
```

## Relationship To Parent Gates

This follows #101 / OW-301T. OW-301T source-binds START_DEV and refuses it
until data queue readiness exists; OW-301U source-binds the first data-queue
FETCH_REQ readiness primitive and makes runtime liveness part of that readiness.

This remains below #30 / OW-301, #50 / PC-005, and #57 / PC-012. It is not a
block-device acceptance harness.

## Non-Claims

This is not a complete ublk daemon, not a started Linux block-device export, not
