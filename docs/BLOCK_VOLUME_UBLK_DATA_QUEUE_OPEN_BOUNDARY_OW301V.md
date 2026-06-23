# Block Volume ublk Data Queue Open Boundary OW-301V

> TFR-019 authority classification: Current spec (scoped). See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

## Source Boundary

OW-301V guarded ublk data-queue runtime-open boundary is implemented in
`crates/tidefs-block-volume-adapter-ublk-control-runtime` and surfaced through
`tidefs-block-volume-adapter-daemon ublk-data-queue-open`.

This follows OW-301Q through OW-301U. The runtime now owns the first live
data-queue resource boundary before any FETCH_REQ submission:

- it requires successful ADD_DEV and a concrete kernel-returned device id;
- it derives the Linux data-queue path from that id as `/dev/ublkcN`;
- it rejects the automatic ADD_DEV device-id sentinel before runtime open;
  existing ublk geometry limits;
- it requires the requested path to match the derived `/dev/ublkcN` path;
- it requires the target to exist and be a character device;
- it opens the data queue read/write;
- it creates an SQE128 io_uring with the same ring entry count used by the
  FETCH_REQ readiness boundary.

The daemon command uses the normal guarded control sequence: host admission,
`/dev/ublk-control` read/write open, `GET_FEATURES`, required feature admission,
`ADD_DEV`, guarded data-queue open, and `DEL_DEV` cleanup after ADD_DEV. The
data-queue runtime is kept live until cleanup is attempted.

This boundary does not submit FETCH_REQ. It feeds OW-301U readiness with
`data_queue_runtime_live=true` only when the runtime is actually open, but the
submitted FETCH_REQ count remains `0`, so START_DEV readiness remains false.
It also does not submit START_DEV and does not start `/dev/ublkbN`.


The implementation-tracked non-release tests and commands cover:

- data-queue open specs for concrete dev ids, queue ids, `/dev/ublkcN`, ring
  entries, SQE128 use, and read/write open mode;
- rejection of automatic device ids and invalid queue geometry;
- path mismatch, missing path, non-character-device, open errno, and io_uring
  setup errno classification;
- daemon sequencing that refuses data-queue open before ADD_DEV completion;
- daemon reporting that successful runtime-open feeds FETCH_REQ liveness while
  still leaving submitted FETCH_REQ count at zero;
- DEL_DEV cleanup accounting after ADD_DEV;
- `tidefs-block-volume-adapter-daemon ublk-data-queue-open`;
- `tidefs-xtask check-block-volume-ublk-data-queue-open-boundary`;


```text
tidefs-block-volume-adapter-daemon ublk-data-queue-open
tidefs-xtask check-block-volume-ublk-data-queue-open-boundary
```

## Relationship To Parent Gates

This follows OW-301U. OW-301U source-binds FETCH_REQ readiness but
requires live data-queue runtime ownership. OW-301V provides the guarded runtime
open boundary that can satisfy that liveness input without submitting FETCH_REQ.

This remains below OW-301 and PC-012. It is not a
block-device acceptance harness.

## Non-Claims

This is not a complete ublk daemon, not a started Linux block-device export, not
FETCH_REQ submission, not START_DEV submission, not io_uring data-queue request
production resize/failover runtime, and not production block-volume durability.
