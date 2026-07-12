# Snapshot Pruner Live Scheduling Decision

Status: design decision for GitHub issue #1549.

This document decides the live scheduling boundary for
`crates/tidefs-snapshot-pruner`. It is not a product-readiness claim and does
not implement a daemon, mounted filesystem behavior, snapshot deletion
semantics, deadlist derivation, reclaim execution, operator UAPI, or runtime
validation.

## Decision

Live automated snapshot-pruner scheduling belongs to the background-service
and incremental-job boundary. The live daemon should admit `JobKind::SnapshotPruner`
work through the shared background scheduler, using the dataset catalog,
dataset lifecycle state, and dataset properties as admission inputs. The
snapshot-pruner crate remains the retention, integrity, pin-evidence, and
destroy-planning authority; it must not grow its own daemon loop.

Dataset-level cadence is a dataset policy input, not a CLI-only switch. The
existing `snapshot.retention` property is the policy anchor; a follow-up source
issue must add the missing live cadence and execution-mode admission data before
any automatic destructive run is enabled.

Operator commands remain explicit control and visibility surfaces. The existing
`tidefsctl snapshot prune` command is a manual local-only operation, while
future live scheduling must report job state, dry-run plans, destructive
outcomes, and refusal reasons through the operator-visible job/status path.

The selected boundary is therefore:

1. Dataset property/catalog/lifecycle state decides whether a dataset has an
   admitted prune policy and whether it is eligible to run now.
2. The background scheduler decides when due datasets receive bounded
   `SnapshotPruner` work and owns retry/backoff/checkpoint behavior.
3. The pruner builds a current plan and refuses candidates without fresh
   evidence.
4. The selected snapshot deletion path remains the only place that mutates
   snapshot state and hands off deadlist/reclaim work.
5. Operator surfaces show plan and result evidence; they do not secretly act as
   the background scheduler.

## Evidence Reviewed

- `docs/workspace-package-classification.md` classifies
  `tidefs-snapshot-pruner` as current product-code authority, with live daemon
  integration and dataset-level automated scheduling still open before this
  decision.
- `docs/REVIEW_TODO_REGISTER.md` keeps TFR-013/TFR-016 stage-residue cleanup
  open broadly; this decision and its follow-up map own only the
  snapshot-pruner live-scheduling boundary after closed #834 established the
  crate authority.
- Closed #834 established the authority claim for retention planning,
  integrity-gated prune, clone/origin protection, deadlist evidence management,
  explicit destroy, and validation evidence. It left live scheduling as a
  follow-up.
- `crates/tidefs-snapshot-pruner/src/lib.rs` documents retention policies,
  BLAKE3 integrity gating, fail-closed pin evidence, and explicit snapshot
  deletion.
- `crates/tidefs-snapshot-pruner/src/pruner.rs` exposes
  `plan_dataset_prune`, `prune_dataset`, `record_snapshot_pin_evidence`,
  `PruneResult`, and per-candidate block reasons for missing/corrupt evidence,
  clone/origin protection, deadlist pins, checksum failures, and store errors.
- `docs/SNAPSHOT_CLONE_DEADLIST_AUTHORITY.md` keeps snapshot deletion as an
  authority mutation first and maps deadlist derivation and reclaim handoff to
  separate follow-ups.
- `docs/SNAPSHOT_CLONE_DEADLIST_AUTHORITY.md` keeps destructive snapshot
  pruning behind current snapshot authority and per-candidate pin evidence.
- `crates/tidefs-background-scheduler` already maps `JobKind::SnapshotPruner`
  into the scheduler priority model.
- `crates/tidefs-incremental-job-core` defines the crash-resumable,
  budget-respecting `IncrementalJob` contract that background work must use.
- `crates/tidefs-dataset-properties` already defines a `snapshot.retention`
  dataset property, but not live cadence or destructive-mode admission.
- `crates/tidefs-dataset-catalog` records published snapshot lineage evidence
  useful to later snapshot-pruner and send-stream checks, while still warning
  that mounted snapshot authority currently lives in local-filesystem state
  until pool-level persistence is wired.
- `crates/tidefs-dataset-lifecycle` exposes active/destroying/tombstone state,
  poison state, and background-service root pinning, making it the eligibility
  gate rather than the scheduler loop.
- `apps/tidefsctl/src/commands/snapshot.rs` has a manual `snapshot prune`
  command routed through live-owner or offline input, but it is not recurring
  daemon scheduling.
- Live overlap check on 2026-06-30 found open PR #1491 editing
  `crates/tidefs-local-filesystem/src/snapshot.rs` for deadlist enqueue
  implementation. That work is related but non-overlapping with this docs-only
  decision.

## Admission And Refusal

A live scheduled prune job may run only after all of these admission checks pass:

- The dataset has an explicit retention policy and cadence, and the cadence is
  due. No automatic destructive run is admitted from default policy alone.
- The dataset is in an active lifecycle state, not destroying, tombstoned,
  poisoned, or otherwise fenced from snapshot mutation.
- The dataset catalog identity and snapshot lineage evidence are current for
  the dataset being pruned. If mounted authority still lives in a local
  filesystem state map, the implementation must route through that authority
  rather than invent a second snapshot catalog.
- No same-dataset snapshot destroy, dataset destroy, receive-delete, or prune
  job is already running in a way that can mutate the same snapshot set.
- The job can produce a dry-run plan. Destructive execution requires an
  explicit destructive mode admitted by dataset policy or a privileged operator
  action.

Per-candidate deletion evidence remains fail-closed:

- The pruner must read current snapshot catalog entries and current clone/origin
  indexes before planning.
- Persisted pin evidence is usable only when its snapshot root matches the
  current catalog entry and it contains explicit clone-origin and deadlist-pin
  fields. Missing fields, missing entries, stale roots, corrupt payloads, live
  clone/origin pins, or deadlist pins block the candidate.
- The BLAKE3 snapshot checksum gate must pass before a candidate can enter the
  delete set.
- A destructive run must execute from the current plan. A stale cached dry-run
  plan is report-only and cannot be replayed as deletion authority.

If the implementation cannot prove freshness across the catalog, lifecycle,
pin-evidence, and checksum inputs, it must refuse the candidate and report the
specific block reason instead of deleting.

## Alternatives

### Background Scheduler Owns Recurrence

Chosen. It matches the existing `JobKind::SnapshotPruner` type, the
background-scheduler priority model, and the `IncrementalJob` contract for
bounded work, checkpointing, and operator-visible job state.

### Dataset Lifecycle Or Catalog Owns Recurrence

Rejected. The lifecycle and catalog paths are eligibility and identity
authorities, not periodic worker loops. Putting timers and retry behavior there
would mix state authority with execution policy and would make it harder to
share fairness, budget, and job visibility with other background work.

### Explicit Operator Command Only

Rejected as the live automated boundary. `tidefsctl snapshot prune` remains
useful for manual action and future dry-run/destructive controls, but a command
invocation cannot satisfy dataset-level recurring cadence or daemon-owned
backoff/checkpoint behavior.

### Deliberately No Live Daemon Boundary

Rejected for this decision. The repo already has a background scheduler,
`JobKind::SnapshotPruner`, dataset snapshot policy input, and pruner planning
evidence. Keeping the boundary deferred would preserve the documented gap
without giving later implementation issues a non-overlapping map.

### Snapshot-Pruner Crate Starts Its Own Daemon

Rejected. The pruner crate is the retention and evidence authority. A private
daemon loop inside the crate would duplicate the background-service scheduler,
hide admission decisions from dataset lifecycle/catalog state, and fragment
operator job reporting.

## Deadlist And Reclaim Interaction

Automated pruning must not introduce a new deadlist or reclaim model.

- #1259 owns receive-side snapshot-deletion trigger wiring.
- #1265 owns local snapshot-delete deadlist derivation enqueue wiring.
- Closed #1266 records the reclaim drain cadence, admission limits, operator
  reporting, and capacity/accounting policy.
- Open PR #1491 is implementing local-filesystem deadlist enqueue work in
  `crates/tidefs-local-filesystem/src/snapshot.rs`.

A future scheduler implementation calls the selected snapshot deletion path
only after the pruner has produced a current delete set. It does not derive
deadlists, enqueue reclaim candidates, free segments, or report physically
reclaimed space on its own. It may report that a snapshot-prune delete request
was handed to the delete path and then surface the deadlist/reclaim debt
reported by the existing reclaim authorities.

## Follow-Up Issue Map

Managed issue creation was disabled for issue #1549, so the implementation
splits are recorded here for planner admission.

| Follow-up | Expected write set | Boundary and validation |
| --- | --- | --- |
| Dataset prune policy admission | `crates/tidefs-dataset-properties/`, `crates/tidefs-dataset-catalog/`, `crates/tidefs-dataset-lifecycle/` | Add explicit live cadence, dry-run/destructive mode, and lifecycle/catalog refusal evidence for snapshot-pruner admission. Do not implement the scheduler loop or operator commands. Validate with focused unit tests and `git diff --check`. |
| Snapshot-pruner scheduler job | `crates/tidefs-background-scheduler/`, `crates/tidefs-incremental-job-core/`, `crates/tidefs-types-incremental-job-core/`, and `crates/tidefs-snapshot-pruner/` only if a narrow adapter/checkpoint API is needed | Implement bounded `JobKind::SnapshotPruner` scheduling, due-dataset enumeration, checkpoint/result persistence, dry-run planning, destructive admission handoff, and refusal reporting. Do not edit operator UAPI, deadlist derivation, reclaim drain, or runtime validation in this slice. Validate with focused scheduler/job tests, pruner planning tests if touched, and `git diff --check`. |
| Operator visibility and controls | `apps/tidefsctl/`, `docs/PREVIEW_UAPI_ABI_BOUNDARY_OW202.md`, `docs/OPERATOR_UAPI_AUTHORITY.md`, `docs/security/operator-authz-boundary.md`, `docs/CLAIMS_GATE_POLICY.md` | Expose scheduled prune policy, dry-run plans, destructive enable/disable, job status, refusal reasons, and result summaries through existing operator authority. Do not implement scheduling or deadlist/reclaim internals. Validate command classification/admission tests, focused CLI tests, and `git diff --check`. |
| Mounted or daemon runtime evidence | `apps/tidefs-posix-filesystem-adapter-daemon/tests/`, `apps/tidefs-storage-node/tests/`, `validation/claims.toml`, `docs/GITHUB_CI.md` | After scheduler and operator slices land, collect the smallest mounted/live-daemon evidence needed to claim automated prune scheduling works through the live owner. Do not add product-readiness claims before the evidence exists. Use focused GitHub Actions validation, not broad release-candidate rows. |
