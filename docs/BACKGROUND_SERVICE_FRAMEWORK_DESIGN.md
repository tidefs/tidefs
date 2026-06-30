# Background Service Framework

This file is the single surviving documentation surface for the background
service scheduler after the TFR-019 / GitHub issue #1590 duplicate-family
collapse. The deleted background-service design variants were Forgejo-era
lineage and phase-tracking material; git history and issue history preserve
that record.

## Current Source Boundary

The current source-backed scheduler boundary is:

- `crates/tidefs-background-scheduler/src/lib.rs`: `BackgroundService`,
  `BackgroundScheduler`, `ServicePriority`, `ServiceBudget`, and
  `IncrementalJobAdapter`.
- `crates/tidefs-incremental-job-core/src/lib.rs`: object-safe
  `IncrementalJob` trait and checkpoint codec boundary.
- `crates/tidefs-types-incremental-job-core/src/lib.rs`: `WorkBudget`,
  `JobKind`, `JobId`, `Checkpoint`, `StepResult`, and progress/error types.
- `xtask/tidefs-xtask/src/bg_framework.rs`: focused source-marker validation
  for the background-service framework.

This document does not supersede source. If source and this summary disagree,
source plus the focused xtask check wins and this file must be corrected.

## Authority Limits

This file is not release-readiness evidence and does not prove every background
maintenance subsystem is wired into mounted runtime behavior. It also does not
prove scrub, resilver, rebake, compaction, reclamation, snapshot, distributed
repair, or product-comparison claims. Those behaviors require their own current
source evidence, validation, and claim IDs where they become publishing-facing
claims.

The current guarantee is narrow: TideFS has a shared scheduler/job contract in
the crates named above, and that contract is validated by the focused
background-framework xtask check.
