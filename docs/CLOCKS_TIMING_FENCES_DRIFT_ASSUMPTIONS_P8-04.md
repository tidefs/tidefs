# clocks / timing / fences / drift assumptions (v0.325)

> TFR-019 authority classification: Historical input. See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

This document is the source-of-truth for production item **P8-04**.

It settles the live timing law for tidefs across:
- Rust userspace services (`policy_authority`, `posix_filesystem_adapter`, `block_volume_adapter`, `control_plane`, `explanation_query`)
- future Rust-for-Linux kernel modules
- Linux 7.0 as the baseline host/runtime model

It is subordinate to design rule and the production blueprint, and it must not reintroduce wall-clock folklore as hidden authority.

See also:
- `docs/END_TO_END_PRODUCTION_BLUEPRINT.md`
- `docs/REPLICATION_REBUILD_RELOCATION_DATA_FLOWS_P8-03.md`
- `docs/CANONICAL_BINARY_ENCODE_DECODE_ENDIAN_CHECKSUM_LAW_P2-03.md`
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`

## 1. Design objective

Tidefs needs one production-grade answer to all of these questions:

- which clocks are legal for authority ordering,
- which clocks are legal only for local scheduling,
- how lease expiry and failover suspicion behave under drift,
- how freshness fences and ack deadlines work without pretending the cluster is globally coherent,
- how suspend, NTP step, leap smearing, CPU pause, and VM steal time are handled,
- and how userspace and future kernel implementations share one timing law.

The answer is:

**authority ordering is receipt/epoch/anchor-based; time only gates waiting, liveness, escalation, and narrative rendering.**

## 2. Canonical clock classes

Tidefs now distinguishes **7 canonical clock classes**.

| Clock class | Purpose | Linux 7.0 baseline |
|---|---|---|
| `time_clock_0.mono_raw_local` | local elapsed-time measurement with no wall-clock semantics | `CLOCK_MONOTONIC_RAW` in userspace; monotonic raw-ish local cycle source in kernel |
| `time_clock_1.mono_service_local` | local service deadlines, queue wait, short worker budgets | `CLOCK_MONOTONIC` |
| `time_clock_2.boottime_local` | suspend-aware lease / heartbeat / cutover deadlines | `CLOCK_BOOTTIME` |
| `time_clock_3.realtime_narrative` | human/operator timestamps only | `CLOCK_REALTIME` |
| `time_clock_4.hlc_cluster` | hybrid logical time for cross-node narrative ordering and tie-breaking metadata | HLC layered over receipt exchange |
| `time_clock_5.fence_deadline` | explicit freshness/transition deadline class derived from local clock + drift slack | derived, never sampled directly |
| `time_clock_6.lease_deadline` | explicit lease / quorum / failover deadline class derived from local clock + drift slack | derived, never sampled directly |

Rules:
- `time_clock_3.realtime_narrative` is **never** authoritative ordering.
- `time_clock_5` and `time_clock_6` are policy/runtime deadline classes, not storage types pretending to be physical clocks.

## 3. Drift and trust classes

Tidefs now distinguishes **5 canonical drift / trust classes**.

| Class | Meaning |
|---|---|
| `drift_time_0.trusted_local` | local monotonic source healthy; no sign of step regression or suspend anomaly |
| `drift_time_1.nominal_cluster` | cluster skew within ordinary slack budget |
| `drift_time_2.elevated_cluster` | drift larger than target budget; deadlines widened; product freshness may degrade |
| `drift_time_3.severe_cluster` | drift / pause / scheduler stall large enough to hold or downgrade failover-sensitive actions |
| `drift_time_4.untrusted_time` | time source unhealthy enough that authority movement must freeze until a stronger path (quorum/receipt) re-establishes legality |

Rules:
- drift class is about **admission and escalation law**, not narrative blame.
- the system must function safely in `drift_time_3` and `drift_time_4`, though with degraded concurrency, slower cutovers, or stricter holds.

## 4. Runtime components

The timing subsystem now distinguishes **9 runtime components**.

| Component | Responsibility |
|---|---|
| `type_map.clock_sampler` | sample local monotonic/raw/boottime/realtime sources and detect anomalies |
| `time_manager_2.deadline_wheel` | local timer-wheel / heap for short service deadlines |
| `time_manager_3.lease_timer` | lease renewal, expiry, and baton-handoff deadline tracking |
| `time_manager_4.fence_deadline_coordinator` | freshness fence ack deadlines and escalation |
| `time_manager_5.heartbeat_scheduler` | node/session heartbeats and liveness sampling |
| `time_manager_7.time_health_monitor` | classify local clock source health, step regressions, suspend/resume anomalies |
| `time_manager_8.timeout_escalator` | convert deadline misses into hold / degrade / failover / stop actions under policy |

No component is allowed to create authority truth. They only classify health, issue deadlines, and emit receipts/findings.

## 5. Canonical state machines

### 5.1 Local time health state
`time_health_0.healthy -> time_health_1.jittered -> time_health_2.suspend_or_pause_suspect -> time_health_3.step_regressed -> time_health_4.untrusted`

### 5.2 HLC state
`hlc0.idle -> hlc1.local_advanced -> hlc2.remote_merged -> hlc3.persisted_for_receipt`

### 5.3 Lease deadline state
`lease_state_0.open -> lease_state_1.renewing -> lease_state_2.warning -> lease_state_3.grace -> lease_state_4.expired -> lease_state_5.failover_staged`

### 5.4 Fence deadline state
`failure_domain_0.issued -> failure_domain_1.acks_inflight -> failure_domain_2.partial_lag -> failure_domain_3.grace_extension -> failure_domain_4.degraded_visibility -> failure_domain_5.escalated`

### 5.5 Drift suspicion state
`drift_state_0.nominal -> drift_state_1.elevated -> drift_state_2.severe -> drift_state_3.hold_sensitive_actions -> drift_state_4.recovered`

### 5.6 Replay / narrative render state
`network_route_0.pending -> network_route_1.receipt_linked -> network_route_2.wallclock_rendered -> network_route_3.archived`

## 6. Canonical schema families

The design now introduces **10 canonical schema families**.

| Record | Key fields | Role |
|---|---|---|
| `ClockSourceHealthRecord` | `source_id`, `node_ref`, `clock_class`, `health_state`, `last_sample_raw`, `last_sample_mono`, `last_sample_boot`, `last_step_delta_ns`, `jitter_summary`, `issuance_receipt_ref` | authoritative runtime mirror of clock health |
| `DriftEstimateRecord` | `estimate_id`, `node_ref`, `peer_or_cohort_ref`, `drift_class`, `estimated_skew_ns`, `estimated_jitter_ns`, `sample_window_ref`, `confidence_class`, `issuance_receipt_ref` | authoritative runtime mirror of drift classification |
| `LeaseDeadlineRecord` | `lease_deadline_id`, `lease_ref`, `clock_class`, `opened_at_ns`, `renew_deadline_ns`, `expiry_deadline_ns`, `grace_deadline_ns`, `drift_slack_class`, `deadline_state` | authoritative deadline mirror |
| `FenceDeadlineRecord` | `fence_deadline_id`, `freshness_fence_ref`, `cohort_ref`, `clock_class`, `issue_ns`, `ack_deadline_ns`, `grace_deadline_ns`, `escalation_state`, `drift_slack_class` | authoritative fence-deadline mirror |
| `HeartbeatEpochRecord` | `heartbeat_epoch_id`, `node_or_session_ref`, `opened_at_ns`, `heartbeat_period_ns`, `miss_budget`, `last_seen_counter`, `suspicion_state`, `issuance_receipt_ref` | authoritative liveness mirror |
| `DeadlineEscalationReceipt` | `receipt_id`, `subject_ref`, `deadline_ref`, `old_state`, `new_state`, `drift_class`, `action_class`, `response_refs[]` | authoritative escalation receipt |
| `TimerShardStateRecord` | `timer_shard_id`, `runtime_ref`, `clock_class`, `heap_depth`, `nearest_deadline_ns`, `admission_state`, `backpressure_state`, `seal_receipt_ref` | runtime mirror |

Rules:
- `ClockSourceHealthRecord`, `DriftEstimateRecord`, and `HeartbeatEpochRecord` are runtime mirrors with legal consequences.

## 7. Canonical algorithms and protocol families

The design now introduces **10 new algorithm / protocol families**.

| Algorithm / protocol | Purpose |
|---|---|
| `sample_local_clock_health()` | sample local clock classes and classify local health |
| `advance_hlc_on_send_merge_or_publish()` | maintain HLC under local events and remote merges |
| `derive_deadline_slack_from_drift_class()` | turn drift class into deadline slack for leases/fences |
| `open_lease_deadline_window()` | open / renew lease deadline state |
| `open_fence_deadline_window()` | issue ack/grace/escalation deadlines for freshness fences |
| `reconcile_heartbeat_epoch_and_suspicion()` | update liveness and suspicion from missed/late heartbeats |
| `classify_deadline_miss_and_escalate()` | emit escalation receipts and choose hold/degrade/failover actions |
| `quarantine_untrusted_time_source()` | freeze sensitive actions under `drift_time_4.untrusted_time` |
| `render_narrative_time_from_receipt_hlc_and_realtime()` | produce operator-facing timestamps without changing truth |
| `control_time_fence_drift_protocol()` | distributed protocol family coordinating drift classes, lease/fence deadlines, and escalation consequences |

### 7.1 Protocol law

`control_time_fence_drift_protocol()` obeys these rules:
- no participant may infer authority solely from remote wall-clock values
- lease and fence deadlines always include drift slack from the current drift class
- missed heartbeats do not force failover directly; they stage suspicion, then quorum/receipt-backed movement
- local step regressions or suspend anomalies may freeze sensitive movement even if remote peers look healthy
- HLC values are for narrative ordering and tie-breaking metadata, not sovereign truth
- deadline escalation must emit receipts/findings so later cutover/failover narratives are replayable

## 8. Canonical timing assumptions

### 8.1 Monotonic and boottime law
- short worker/queue deadlines use `time_clock_1.mono_service_local`
- suspend-aware liveness/failover deadlines use `time_clock_2.boottime_local`
- raw latency measurements may use `time_clock_0.mono_raw_local`
- any path that can cross suspend/resume must not rely on raw monotonic alone

### 8.2 Realtime law
- NTP slew, leap smearing, or wall-clock jumps must never reorder authority

### 8.3 HLC law
- HLC merges on message receive / receipt ingest / publication emit
- HLC does not replace epochs, receipts, or anchor references

### 8.4 Drift / pause law
The system must tolerate:
- node skew larger than ideal budgets,
- VM steal time,
- scheduler stalls,
- suspend/resume,
- NTP step or daemon restart,
- leap-smear differences.

What changes under these conditions is:
- deadline slack,
- admission of sensitive actions,
- visibility/degrade class,
- and whether failover/handoff may proceed.

## 9. Lease, fence, and failover timing law

### 9.1 Lease law
- leases are renewed on boottime-local deadlines with drift slack
- expiry is not enough by itself to move authority
- expiry only opens the legal path to failover staging under witness/quorum law

### 9.2 Fence law
- every freshness fence has:
  - issue time,
  - ack deadline,
  - optional grace deadline,
  - escalation class,
  - and cohort-specific service/degrade consequences
- products may degrade to bounded-lag or blocked-visible states when fence deadlines pass
- charters must surface exact / bounded-lag / degraded / blocked truth from these states

### 9.3 Failover / cutover law
- failover, handoff, resize, and export revoke all depend on explicit transition receipts plus timing state
- timing may stage or block movement; it may not invent success
- any timing-triggered failover path must leave:
  - drift estimate,
  - escalation receipt,
  - and resulting quorum/failover receipts

## 10. Userspace and kernel parity

The same logical timing law must hold in:
- Rust userspace services (`policy_authority`, `posix_filesystem_adapter`, `block_volume_adapter`, `control_plane`, `explanation_query`)
- Rust-for-Linux future kernels

Implementation mechanics may differ:
- userspace timers may use epoll/timerfd/heap/timer-wheel
- kernel timers may use hrtimers/workqueues/RCU callbacks

But the following are shared:
- clock classes
- drift classes
- lease/fence deadline state machines
- escalation receipts/findings
- HLC merge law
- narrative-time non-authority law

## 11. Whole-system operational paths covered here

1. publication receipt emit -> HLC advance -> fence issue -> cohort ack -> frontier advance under drift slack
2. lease renewal -> missed heartbeat -> suspicion escalation -> witness/quorum-backed failover stage
3. suspend/step regression detection -> sensitive action freeze -> recovery / resumed admission after time health restoration
4. export resize or failover transition -> queue quiesce -> deadline escalation -> replay-safe resume
