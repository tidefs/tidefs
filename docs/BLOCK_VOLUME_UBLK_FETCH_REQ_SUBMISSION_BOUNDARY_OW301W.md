# Block Volume ublk FETCH_REQ Submission Boundary OW-301W

> TFR-019 authority classification: Current spec (scoped). See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

## Source Boundary

OW-301W guarded ublk FETCH_REQ submission boundary is implemented in
`crates/tidefs-block-volume-adapter-ublk-control-runtime` and surfaced through
`tidefs-block-volume-adapter-daemon ublk-data-queue-fetch-req-submit`.

This follows OW-301V. The runtime now owns the first guarded submission boundary
for required data-queue `UBLK_U_IO_FETCH_REQ` commands:

- it requires host admission before opening `/dev/ublk-control`;
- it requires successful read-only `GET_FEATURES`;
- it requires the ADD_DEV feature mask used by the existing ADD_DEV boundary;
- it requires successful ADD_DEV returning a concrete kernel device id;
- it requires live data-queue runtime ownership for the matching `/dev/ublkcN`;
- it submits one no-wait `FETCH_REQ` command for each tag in the first queue;
- it records the first submitted tag, last submitted tag, submitted count, and
  partial-submit error class when submission stops early.

The boundary deliberately does not wait for FETCH_REQ CQEs. Linux keeps these
commands in flight until block requests are fetched, so the daemon must keep the
data-queue fd and io_uring live while the commands are outstanding. The report
therefore treats submitted FETCH_REQ count plus live runtime ownership as the
readiness input for a future START_DEV boundary.

This boundary requires live data-queue runtime ownership, but it does not submit START_DEV.
It does not start `/dev/ublkbN`, process block I/O, run fio, run mkfs/mount, or
claim guest-filesystem acceptance.


The implementation-tracked non-release tests and commands cover:

- FETCH_REQ submission specs derived from live data-queue runtime outcomes;
- queue tag coverage from tag `0` through the configured queue depth;
- no-wait submission accounting without waiting for CQEs;
- START_DEV readiness only after all required FETCH_REQ submissions and live
  data-queue runtime ownership are present;
- partial submission error reporting with failed tag, submitted count, errno,
  and DEL_DEV cleanup accounting;
- refusal to attempt FETCH_REQ submission when data-queue open fails;
- `tidefs-block-volume-adapter-daemon ublk-data-queue-fetch-req-submit`;
- `tidefs-xtask check-block-volume-ublk-fetch-req-submit-boundary`;


```text
tidefs-block-volume-adapter-daemon ublk-data-queue-fetch-req-submit
tidefs-xtask check-block-volume-ublk-fetch-req-submit-boundary
```

## Relationship To Parent Gates

This follows #103 / OW-301V. OW-301V opens and owns the concrete `/dev/ublkcN`
runtime after ADD_DEV; OW-301W uses that live runtime as the guard for submitting
the required FETCH_REQ commands that a future START_DEV completion path needs.

This remains below #30 / OW-301, #50 / PC-005, and #57 / PC-012. It is not a
block-device acceptance harness.

## Non-Claims

This is not a complete ublk daemon, not a started Linux block-device export, not
START_DEV submission, not START_DEV completion, not io_uring data-queue request
production resize/failover runtime, and not production block-volume durability
