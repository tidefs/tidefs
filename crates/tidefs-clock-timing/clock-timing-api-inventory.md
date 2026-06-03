# tidefs-clock-timing API Inventory

**Generated**: 2026-05-08 | **Worker**: s9 | **Issue**: #3559

## Crate Structure

8 source files, 3248 total lines, 0 external deps beyond std+serde (HlcValue only).

| File | Lines | Purpose |
|------|-------|---------|
| `lib.rs` | 98 | Module declarations, re-exports, doc example |
| `types.rs` | 839 | Canonical enums, structs, record types (P8-04 §§2-6) |
| `hlc.rs` | 297 | HybridLogicalClock implementation (P8-04 §5.2) |
| `health.rs` | 413 | ClockSampler + TimeHealthMonitor (P8-04 §§4-5.1) |
| `drift.rs` | 359 | DriftEstimator + DriftSample (P8-04 §§3, 7.1) |
| `deadline.rs` | 395 | LeaseDeadline + FenceDeadline trackers (P8-04 §§5.3-5.4) |
| `escalation.rs` | 313 | TimeoutEscalator — miss→action policy (P8-04 §4) |
| `fence.rs` | 534 | Freshness fence eval + epoch attestation + drift safety (P8-04 §§4-7) |

## Public API Surface

### Types & Enums (types.rs)
- `ClockClass` — 7 variants (MonoRawLocal through LeaseDeadline)
- `DriftClass` — 5 variants (TrustedLocal through UntrustedTime)
- `TimeHealth` — 5 variants (Healthy through Untrusted)
- `HlcState` — 4 variants (Idle through PersistedForReceipt)
- `LeaseDeadlineState` — 6 variants (Open through FailoverStaged)
- `FenceDeadlineState` — 6 variants (Issued through Escalated)
- `DriftSuspicionState` — 5 variants (Nominal through Recovered)
- `EscalationAction` — 5 variants (None through Stop)
- `FindingSeverity` — 4 variants (Info through Emergency)
- `FenceClass` — 3 variants (Strict, Bounded, Soft)
- `FreshnessVerdict` — 4 variants (WithinBound, StaleSource, DegradedAdmission, Expired)

### Value Types & Records (types.rs)
- `HlcValue` — (physical_ns, logical) with Ord, Serialize, Deserialize
- `DerivedDeadline` — base + drift slack deadline with has_passed/remaining_ns
- `ClockSourceSample` — 4-clock snapshot (mono_raw, mono_service, boottime, realtime)
- `LeaseDeadlineRecord` — full lease lifecycle record
- `FenceDeadlineRecord` — full fence lifecycle record
- `HeartbeatEpochRecord` — heartbeat epoch with suspicion tracking
- `DeadlineEscalationReceipt` — canonical escalation validation
- `TimeHealthFinding` — health finding with severity
- `FenceFrontier` — (epoch, wall_ns) barrier
- `FenceTiming` — issue_time + max_drift_window
- `FreshnessFenceRecord` — complete freshness fence
- `EpochTimingAttestation` — epoch transition timing proof
- `SourceQuorum` — confirmed/total source count
- `ClockResynchronizationReceipt` — drift recovery validation

### Stateful Components
- `HybridLogicalClock` — advance_local, merge_remote, persist_for_receipt (hlc.rs)
- `ClockSampler` — sample(), last_sample(), sample_count() (health.rs)
- `TimeHealthMonitor` — classify(), health(), findings() (health.rs)
- `DriftEstimator` — observe(), drift_class(), estimated_skew_ns() (drift.rs)
- `LeaseDeadline` — open(), evaluate(), renew(), stage_failover() (deadline.rs)
- `FenceDeadline` — issue(), acks_inflight(), evaluate() (deadline.rs)
- `TimeoutEscalator` — classify_miss(), classify_lease_expiry(), classify_fence_escalation() (escalation.rs)

### Pure Functions (fence.rs)
- `evaluate_freshness_against_fence()`
- `evaluate_transfer_ticket_freshness()`
- `attest_epoch_timing_and_bind_to_config_epoch()`
- `detect_drift_exceeded_and_trigger_safety_actions()`

## Test-Controlled Time Injection

**No external time source trait or mock is needed.** Every API that uses time accepts explicit `u64` nanosecond values. The design is inherently testable:

- `ClockSampler::sample()` takes 4 explicit `u64` args instead of calling clock_gettime
- `TimeHealthMonitor::classify()` takes a `&ClockSourceSample` with explicit values
- `DriftEstimator::observe()` takes a `DriftSample` with explicit timestamps
- `HybridLogicalClock::advance_local()` takes explicit `physical_ns: u64`
- `LeaseDeadline::open()` and `evaluate()` take explicit nanosecond values
- `FenceDeadline::issue()` and `evaluate()` take explicit nanosecond values
- `TimeoutEscalator::classify_miss()` takes explicit `current_ns: u64`
- All fence functions take explicit `current_ns: u64`

**Result**: All 81 existing tests are deterministic and time-independent. `cargo test` passes identically under faketime, in containers, and offline. No `Instant::now()` or `clock_gettime` calls exist in the production code paths.

## Test Coverage Summary

| Module | Tests | Coverage Notes |
|--------|-------|----------------|
| types.rs | 34 | ClockClass, DriftClass, TimeHealth, LeaseDeadlineState, DerivedDeadline (+edge cases), HlcValue (+serde round-trip), HeartbeatEpochRecord, ClockResynchronizationReceipt, EpochTimingAttestation, SourceQuorum, ClockSourceSample, FenceFrontier, FenceTiming, FreshnessFenceRecord expiry, DeadlineEscalationReceipt, TimeHealthFinding |
| hlc.rs | 12 | Full HLC lifecycle: advance, merge, persist, causal ordering, merge chains |
| health.rs | 10 | ClockSampler, TimeHealthMonitor: jump/jitter/suspend detection, recovery |
| drift.rs | 11 | DriftEstimator: classification thresholds, recovery, sliding window, estimates |
| deadline.rs | 18 | LeaseDeadline lifecycle (+zero periods, no-regress), renew_deadline(), FenceDeadline lifecycle (+no-regress), ack_deadline(), acks_inflight guard |
| escalation.rs | 21 | TimeoutEscalator: per-drift-class actions (+12 threshold-boundary tests), lease expiry, fence escalation, receipt chain |
| fence.rs | 19 | Fence freshness eval (all 4 verdicts), bounded drift slack, transfer holds, attestation validity, drift safety actions, recovery receipts |

## Changes (this chunk, #3559 chunk 3)

Added 46 tests across 3 files, bringing total from 81 to 129:

- **types.rs** (+23): HeartbeatEpochRecord (2), ClockResynchronizationReceipt (5), SourceQuorum (1), EpochTimingAttestation (4), HlcValue serde (3), DerivedDeadline edge cases (5), ClockSourceSample (2), FenceFrontier (2), FreshnessFenceRecord expiry (2), DeadlineEscalationReceipt (1), TimeHealthFinding (1)
- **deadline.rs** (+7): renew_deadline() (1), ack_deadline() (1), zero periods (1), lease no-regress (1), fence no-regress (1), acks_inflight guard (1)
- **escalation.rs** (+12): threshold-boundary tests for TrustedLocal (4), NominalCluster (3), ElevatedCluster (3), SevereCluster (2)
- **Cargo.toml**: Added `serde_json` dev-dependency for HlcValue serde round-trip tests

## Changes (chunk 4)

- **Bugfix**: Removed duplicate recovery counter block in `DriftEstimator::observe()` (drift.rs). The second copy of the recovery tracking code caused each nominal sample to double-increment the counter, making recovery fire at half the configured `recovery_samples` threshold. The redundant block was dead code when recovery triggered in the first block, and a correctness bug when it didn't — it silently doubled the effective increment.
- **Regression tests**: Added `recovery_counter_increments_by_one` (verifies recovery fires at exactly 2 samples with recovery_samples=2) and `non_nominal_resets_recovery_counter` (verifies a non-nominal sample resets the counter and recovery requires the full count again).
- **Total**: 129 tests (81 existing + 46 in chunk 3 + 2 in chunk 4)

## Remaining Gaps

1. COMMIT_GROUP window boundaries — no COMMIT_GROUP module exists yet in this crate (future work: #3469 will consume COMMIT_GROUP abstractions)
2. Timer-wheel ordering — no timer-wheel exists in this crate (ordered deadline collection is in scheduling layer)
3. Wall-clock ↔ monotonic conversion — not an API this crate provides
