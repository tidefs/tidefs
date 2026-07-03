# tidefs-recovery-loop

Source orientation for recovery-loop planning and state-machine code.

This crate contains APIs for sequencing committed-root inspection, intent-log
replay hooks, recovery planning, throttling, and health-gate decisions. These
types are crate-local building blocks; they are not product proof for mounted
crash recovery, automatic repair, or release readiness.

## Crate modules

- **`recovery_loop`** — Committed-root inspection and replay-hook state machine
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
