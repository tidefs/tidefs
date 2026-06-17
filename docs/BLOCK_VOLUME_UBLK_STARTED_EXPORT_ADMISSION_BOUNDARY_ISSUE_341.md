# Block Volume ublk Started Export Admission Boundary Issue 341

## Source Boundary

Issue 341 binds the existing ublk control and data-queue pieces into one
bounded started-export admission artifact. The daemon path is implemented in
`apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/data_queue_io_loop.rs`
with artifact formatting and fail-closed verification in
`apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/started_export_admission.rs`.

When `TIDEFS_UBLK_STARTED_EXPORT_ARTIFACT` is set, the daemon writes a JSON
artifact after the live data-queue loop reaches shutdown or a refusal path. The
artifact records:

- host preflight, `/dev/ublk-control` open, `GET_FEATURES`, and required
  feature admission;
- `ADD_DEV` device id and `SET_PARAMS` geometry;
- `/dev/ublkcN` data-queue runtime open and configured queue geometry;
- complete `FETCH_REQ` queue/tag coverage for the configured queue count and
  queue depth;
- `START_DEV` attempted, refused, or succeeded state;
- daemon-owned service-loop observation, including either first request service
  or a bounded no-request observation;
- `STOP_DEV`, `DEL_DEV`, drain, final flush, and cleanup outcome.

`START_DEV` is a fail-closed boundary. The daemon verifier rejects an artifact
that attempts `START_DEV` without live data-queue runtime ownership and exact
configured queue/tag `FETCH_REQ` coverage. A successful `START_DEV` must also
bind to a daemon-owned service loop and record either a serviced request cycle
through `COMMIT_AND_FETCH_REQ` or a bounded no-request observation.

The artifact consumes the existing qid/tag completion authority instead of
creating a second completion model. A runtime row that wants started-export
evidence should set both `TIDEFS_UBLK_COMPLETION_ARTIFACT` and
`TIDEFS_UBLK_STARTED_EXPORT_ARTIFACT`, then validate the first with
`tidefs-xtask validate-ublk-completion-artifact` and the second with
`tidefs-xtask validate-ublk-started-export-admission-artifact`.

Cleanup failures stay visible. If `DEL_DEV` was required but did not succeed,
the artifact verifier records `claim_state=cleanup_failed` rather than hiding
cleanup failure behind a successful runtime observation.

## Relationship To Parent Gates

This follows the source boundaries documented by:

- `docs/BLOCK_VOLUME_UBLK_START_DEV_BOUNDARY_OW301T.md`
- `docs/BLOCK_VOLUME_UBLK_FETCH_REQ_READINESS_BOUNDARY_OW301U.md`
- `docs/BLOCK_VOLUME_UBLK_DATA_QUEUE_OPEN_BOUNDARY_OW301V.md`
- `docs/BLOCK_VOLUME_UBLK_FETCH_REQ_SUBMISSION_BOUNDARY_OW301W.md`
- `docs/BLOCK_VOLUME_UBLK_COMMIT_FETCH_BOUNDARY_OW301X.md`

The focused QEMU runner remains the smallest supported runtime row for this
artifact. It extracts both the qid/tag completion artifact and the
started-export admission artifact before reporting the row as passed.

## Non-Claims

This is not fio workload breadth, mkfs/mount acceptance, online resize
acceptance, crash durability, product block-device readiness, distributed
placement, kernel VFS residency, or an OpenZFS/Ceph-class behavior claim. It is
only bounded evidence that a started ublk export was admitted through a live
daemon-owned data-queue service loop and paired with the existing qid/tag
completion verifier.
