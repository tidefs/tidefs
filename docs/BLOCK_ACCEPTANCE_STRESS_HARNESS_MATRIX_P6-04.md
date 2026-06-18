# block acceptance / stress harness matrix (v0.324)

> TFR-019 authority classification: Historical input. See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

This document is the production-depth source-of-truth for **`P6-04`**.

It answers the question:

**How does tidefs prove that `charter.block_volume.block_volume_adapter` is correct on Linux 7.0, first through userspace `ublk` and later through kernel block variants, without letting fio/blktests/guest filesystems become hidden architecture sovereignty?**

See also:
- `docs/BLOCK_VOLUME_PROJECTION_CHARTER_BLOCK_VOLUME_ADAPTER.md`
- `docs/UBLK_DAEMON_QUEUE_TOPOLOGY_P6-01.md`
- `docs/BLOCK_CACHE_FLUSH_FUA_DISCARD_LAW_P6-02.md`
- `docs/EXPORT_FENCING_RESIZE_FAILOVER_RUNTIME_P6-03.md`
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`

## 1. Scope and baseline

Baseline assumptions:
- **Linux baseline:** 7.0
- **Primary first implementation target:** `block_volume_adapter` userspace `ublk` adapter
- **Prepared later target:** `block_volume_adapter` kernel block implementation
- **Charter under test:** `charter.block_volume.block_volume_adapter`

This document governs:
- direct block semantics and ordering proof,
- guest-filesystem-on-volume acceptance proof,
- differential oracle and power-failure style campaigns,
- stress/soak/failover proof for `block_volume_adapter`,
- failure bucketing, stop-ship law, and release gates.

This document does **not** redefine:
- design rule-native authority,
- `policy_authority` request law,
- `schema_codec` receipt/schema law,
- or the `block_volume_adapter` charter itself.



Purpose:
- prove each named `block_volume_adapter` charter clause has at least one direct executable witness.

Suite families:
- `suite.block_volume_adapter.property.environment_boundary`
- `suite.block_volume_adapter.range_ordering.block_suite_1`

Typical cases:
- direct read/write ordering
- overlapping write/discard/zero transitions
- flush/FUA barrier semantics
- resize and export fencing
- replay cursor and transition recovery
- thin/overcommit refusal and reserve-visible denial
- block identity and geometry rendering

Purpose:
- prove common Linux filesystems can live on top of `block_volume_adapter` without `block_volume_adapter` lying about block semantics.

Suite family:
- `suite.block_volume_adapter.guest_fs.block_suite_2`

Minimum guest profiles:
- ext4 baseline
- xfs baseline
- btrfs baseline
- optional f2fs profile when enabled by policy

Mandatory scenario classes:
- mkfs
- mount / unmount
- fsync / remount
- metadata churn on guest fs
- sparse / discard capable guest workloads
- resize where the guest filesystem supports it

Purpose:
- prove ordered completion, barrier classes, and throughput/latency behavior under direct block workloads.

Suite family:
- `suite.block_volume_adapter.fio.block_suite_3`

Mandatory workload classes:
- sequential read / write
- random read / write
- mixed read/write
- sync-heavy write
- FUA-heavy write
- trim/discard/zero-range pressure
- queue-depth sweep
- block-size sweep

Purpose:
- compare `block_volume_adapter` behavior against reference Linux block paths under controlled scenarios.

Suite family:
- `suite.block_volume_adapter.diff_oracle.block_suite_4`

Reference oracle families:
- loopback file on ext4
- loopback file on xfs
- dm-flakey or equivalent fault-capable reference stack where available

- Linux block behavior is ambiguous in prose,
- request completion ordering is disputed,
- or flush/FUA/discard behavior needs external confirmation.

Purpose:
- prove no deadlock, hidden queue sovereignty, pin leak, cache corruption, or barrier collapse under sustained load.

Suite family:
- `suite.block_volume_adapter.stress.block_suite_5`

Mandatory stress classes:
- queue-depth saturation storm
- mixed flush/FUA storm
- discard/zero overlap storm
- resize while hot I/O storm
- export fence backlog storm
- memory-pressure and pin-drain storm
- registered-buffer exhaustion storm
- failover handoff under write load

Purpose:
- prove the charter stays honest when export runtime or authority movement changes underneath it.

Suite family:
- `suite.block_volume_adapter.failover_cutover.block_suite_6`

Mandatory scenarios:
- export fence while reads/writes are inflight
- resize prepare/commit with inflight work
- failover while dirty ranges exist
- replay cursor recovery after crash during barrier or resize transition
- revoke/stop under queue pressure

Purpose:
- prove format, replay, and adapter restart behavior do not violate `block_volume_adapter` claims.

Suite family:
- `suite.block_volume_adapter.upgrade_replay.block_suite_7`

Mandatory scenarios:
- crash during flush epoch
- crash during discard/zero transition
- replay after inflight request classification
- continuity-window acceptance and rejection
- rebuild of queue/runtime mirrors from authoritative records and receipts

## 3. Canonical matrix dimensions


### 3.1 Variant axis
- `variant.block_volume_adapter.userspace.ublk`
- `variant.block_volume_adapter.kernel.block` (future)

### 3.2 Guest / consumer axis
- `consumer.raw_block`
- `consumer.ext4`
- `consumer.xfs`
- `consumer.btrfs`
- `consumer.fsx_like`
- `consumer.mkfs_only`

### 3.3 Request-path axis
- `path.direct_read`
- `path.direct_write`
- `path.flush`
- `path.fua`
- `path.discard`
- `path.zero_range`
- `path.resize`
- `path.fence_transition`

### 3.4 Geometry axis
- block-size class
- queue-depth class
- alignment class
- sparse/thin class
- capacity-pressure class

### 3.5 Runtime-topology axis
- single export steady
- pressure/degrade
- resize transition
- failover/handoff
- revoke/stop

### 3.6 Fault axis
- `fault.enospc`
- `fault.eio`
- `fault.eintr`
- `fault.write_order_violation_probe`
- `fault.flush_timeout_or_retry`
- `fault.failover_mid_write`
- `fault.crash_replay`
- `fault.pin_pressure`

## 4. Charter-clause inventory law

The matrix is driven by named charter clauses, not only by tool names.

Mandatory clause families for `block_volume_adapter` are:
- `clause.block_identity_geometry_projection`
- `clause.read_write_ordering_and_completion`
- `clause.flush_fua_barrier_truth`
- `clause.discard_zero_resize_transition`
- `clause.export_fence_failover_replay_visibility`
- `clause.direct_cached_overlap_coherency`
- `clause.reserve_pressure_admission_and_denial`
- `clause.intentional_cuts_visible`

Every matrix row must point to one or more of these clauses.
Every failure bucket must point back to one or more of these clauses.

## 5. Harness profile taxonomy

`block_volume_adapter` acceptance is structured into named profiles instead of one vague “run fio” story.

### `profile.block_acceptance_profile_0.smoke`
Purpose:
- fastest viability proof, run on every serious integration loop.

Minimum contents:
- export attach / list / detach
- ext4 mkfs + mount + write + fsync + umount
- one short fio verify profile
- one flush/FUA probe

### `profile.block_acceptance_profile_1.quick_required`
Purpose:

Contents:
- guest-fs acceptance rows for ext4 and xfs
- direct workload rows for block-size / queue-depth sweep
- discard/zero/resize rows
- replay/failover smoke rows

### `profile.block_acceptance_profile_2.quick_pressure`
Purpose:
- force block charter behavior under pressure and degraded conditions.

Contents:
- low free-space budgets
- high pin pressure
- dirty/writeback backlog
- resize under load
- failover with inflight dirty epochs

### `profile.block_acceptance_profile_3.oracle`
Purpose:
- differential confirmation against loopback/reference stacks.

Contents:
- same workload row executed against:
  - `block_volume_adapter`
  - ext4-backed loop
  - xfs-backed loop
  - optional dm fault stack

### `profile.block_acceptance_profile_4.soak`
Purpose:
- sustained stress and leak/deadlock hunting.

Contents:
- long mixed fio campaigns
- repeated attach/detach cycles
- resize/failover stress bursts
- discard/zero overlap storms
- pin/register arena exhaustion tests

## 6. Failure bucket grammar and release gates

Every block-facing failure must classify into a canonical grammar.

Mandatory failure bucket families:
- `bucket.ordering_violation`
- `bucket.flush_or_fua_lie`
- `bucket.discard_zero_visibility_violation`
- `bucket.resize_transition_bug`
- `bucket.failover_replay_bug`
- `bucket.reserve_pressure_misclassification`
- `bucket.queue_runtime_deadlock_or_leak`
- `bucket.intentional_cut_misrendered`

Release gates are explicit and receipt-backed.

### `gate.block_volume_adapter.g0.smoke` — continuity: Block Volume Adapter (`block_volume_adapter`)
Requires:
- all `profile.block_acceptance_profile_0.smoke` rows green
- zero open ordering/barrier buckets

### `gate.block_volume_adapter.g1.quick_required` — continuity: Block Volume Adapter (`block_volume_adapter`)
Requires:
- all blocking `profile.block_acceptance_profile_1.quick_required` rows green
- no open `bucket.flush_or_fua_lie`
- no open `bucket.ordering_violation`
- no open `bucket.resize_transition_bug` above warning severity

### `gate.block_volume_adapter.g2.pressure_and_failover` — continuity: Block Volume Adapter (`block_volume_adapter`)
Requires:
- pressure and failover profiles executed
- all open buckets classified with receipts and explicit cut/bug lineage
- no open reserve-safety or replay-safety blockers

## 7. Outputs and artifact law

Every serious `block_volume_adapter` campaign must emit:
- row execution manifest
- canonical workload parameter set
- queue/runtime topology snapshot
- pressure/fence/transition receipts touched during the run
- coverage snapshot
- release gate receipt or blocking stop ticket

Mirror artifacts may include:
- fio JSON or text output
- guest-fs logs
- ublk runtime logs
- trace/latency histograms


## 8. Anti-regression rules

- do not treat fio success as enough by itself
- do not treat guest-fs green as enough by itself
- do not let queue-runtime counters become hidden truth
- do not let userspace `ublk` and future kernel block paths drift into separate gate languages
- do not allow a release gate without clause lineage and bucket grammar
