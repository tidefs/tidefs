# tidefs-recovery-loop

Continuous failure recovery loop: detect, scope, plan, execute, verify.

The recovery loop is the central crash-recovery coordinator for TideFS. It validates
committed roots via BLAKE3 chain verification, replays intent-log records through a
replay target, restores consistency, and health-gates rebuild decisions. No fsck —
recovery is automatic through committed roots and intent replay.

## Crate modules

- **`recovery_loop`** — Committed-root-validated crash recovery state machine
  (`RecoveryLoop`, `RecoveryPhase`, `RecoveryLoopConfig`, `RecoveryError`,
  `RecoveryOutcome`, `HealthGateDecision`, `ReplayTarget` trait with `NoOpReplayTarget`).
- **`replay`** — VfsEngine-aware intent-log replay engine (`ReplayEngine`,
  `ReplayState`, `ReplayOutcome`, `VfsReplayHandler`).
- **Top-level** — `RecoveryPolicy`, `CrashRecoveryLoop`, `RecoveryPlan`,
  `RecoveryAction`, `RecoveryThrottle`, `CascadingFailureGuard`,
  `RecoveryProgressReceipt`, and related types.

## Retired Validation Report

The old `tests/recovery_loop_validation.rs` validation report was retired. It
made source-model and single-process recovery rows look like release validation.
Recovery-loop closure now requires mounted committed-root/replay artifacts
from the product path, or focused unit tests that do not publish validation-tier
PASS rows.
