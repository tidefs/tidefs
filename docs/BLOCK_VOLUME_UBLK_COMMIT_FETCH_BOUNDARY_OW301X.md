# Block Volume ublk COMMIT_AND_FETCH_REQ Boundary OW-301X

> TFR-019 authority classification: Current spec (scoped). See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

## Source Boundary

OW-301X guarded ublk COMMIT_AND_FETCH_REQ boundary is implemented in
`crates/tidefs-block-volume-adapter-ublk-control-runtime` and surfaced through
`tidefs-block-volume-adapter-daemon ublk-data-queue-commit-and-fetch`

This follows OW-301W. After FETCH_REQ commands are submitted and a fetched block
request has been completed by the caller, the runtime now owns the first guarded
COMMIT_AND_FETCH_REQ submission boundary:

- it requires live data-queue runtime ownership (the `/dev/ublkcN` fd and io_uring
  must be live);
- it requires a fetched request to be available and completed;
- it requires a completion result to be ready (zero, positive byte count, or
  negative errno);
- it encodes the `UBLK_U_IO_COMMIT_AND_FETCH_REQ` `IORING_OP_URING_CMD` with
  SQE128 geometry, queue id, tag, completion result, and user data bound to
  tag/command number/queue id;
- it submits the command without waiting for a CQE, preserving the
  `commits_result=true` and `fetches_next_request=true` semantics so the driver
  can recycle the tag for the next block request;
- it refuses `UBLK_IO_RES_NEED_GET_DATA` and non-zero zone-append LBA values.
  Positive byte counts are admitted because Linux ublk treats a zero read
  completion as I/O error and expects read/write completions to report bytes
  completed.

The boundary does not wait for the COMMIT_AND_FETCH_REQ CQE. The daemon must keep
the data-queue fd and io_uring live while the command is in flight for the next
request cycle. This boundary therefore does not complete a full I/O loop,
claim `/dev/ublkbN` readiness, or process further block I/O.


The implementation-tracked non-release tests and commands cover:

- COMMIT_AND_FETCH_REQ spec encoding with SQE128, `ReadWrite` direction, and
  `size_of::<UblkSrvIoCmd>()` payload;
- command encoding for queue id, tag, result, and zero LBA;
- input rejection for bad geometry, out-of-range queue/tag, and unsupported
  special result values, plus positive byte-count completion admission;
- user-data binding to tag, command number, and queue id;
- readiness guards requiring live runtime, fetched request availability, and
  completion result readiness;
- outcome encoding preserving queue, tag, result, and user data;
- `tidefs-block-volume-adapter-daemon ublk-data-queue-commit-and-fetch`;
- `tidefs-xtask check-block-volume-ublk-commit-fetch-boundary`;


```text
tidefs-block-volume-adapter-daemon ublk-data-queue-commit-and-fetch
tidefs-xtask check-block-volume-ublk-commit-fetch-boundary
```

## Relationship To Parent Gates

This follows #107 / OW-301W. OW-301W submits the FETCH_REQ set against a live
data-queue runtime; OW-301X uses that same live runtime plus a fetched and
completed request to submit a guarded COMMIT_AND_FETCH_REQ that commits the
result and fetches the next request.

This remains below #30 / OW-301, #50 / PC-005, and #57 / PC-012. It is not a
acceptance harness.

## Non-Claims

This is not a complete ublk daemon, not a started Linux block-device export, not
START_DEV completion, not a full read/write I/O loop through io_uring, not fio
#30, #50, or #57.
