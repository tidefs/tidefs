# linux 7.0 baseline contract / supported subsystems (P0-01) (v0.357)

> TFR-019 authority classification: Historical input. See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

This document is the source-of-truth for the production-depth Linux 7.0
baseline contract and supported-subsystem law for tidefs.

It answers the question:

**What exactly may the live tidefs system assume about Linux 7.0 hosts and
subsystems — across first userspace services, clustered runtime, userspace
block export, and later kernel-prepared stages — without letting distro-local
convenience, newer-kernel drift, vendor offload pressure, or hidden platform
dependencies become architecture sovereignty?**

See also:
- `docs/END_TO_END_PRODUCTION_BLUEPRINT.md`
- `docs/BUILD_PACKAGING_FEATURE_MATRIX_P1-04.md`
- `docs/WORKSPACE_FAMILY_LAYOUT_CRATE_SERVICE_BOUNDARIES_P1-01.md`
- `docs/DOCTRINE_FAMILY_TO_RUST_TYPE_MAP_P2-01.md`
- `docs/POLICY_AUTHORITY_RUNTIME_SURFACE_P3-01.md`
- `docs/POSIX_FILESYSTEM_ADAPTER_DAEMON_TOPOLOGY_P5-01.md`
- `docs/UBLK_DAEMON_QUEUE_TOPOLOGY_P6-01.md`
- `docs/KERNEL_MODULE_FAMILY_MATRIX_ROLLOUT_ORDER_P7-01.md`
- `docs/RUST_FOR_LINUX_CRATE_TRAIT_BOUNDARIES_P7-02.md`
- `docs/TRANSPORT_SESSION_COHORT_GRAPH_P8-01.md`
- `docs/MEMBERSHIP_PLACEMENT_FAILURE_DOMAIN_MODEL_P8-02.md`
- `docs/UPGRADE_FAILOVER_CUTOVER_OPERATOR_RUNBOOKS_P9-03.md`
- `docs/PERFORMANCE_BUDGETS_SLO_REGRESSION_GATES_P10-03.md`
- `docs/KERNEL_PROGRESSION_STAIRCASE_AFTER_USERSPACE_SUCCESS_P11-04.md`
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`

## 1. Core result

The production design now has one explicit family for Linux baseline truth:

- one coordinating family: **`family.platform_linux_baseline.linux_baseline`**
- one baseline contract law:
  **`law.linux_7_0_baseline_supported_subsystem_contract.linux_baseline`**
- one canonical contract chain:
  - **service / stage / package target -> required support class -> admitted subsystem family -> primitive profile -> probe receipt -> gate / package / runbook binding**

The production design now also fixes:

- **10 stable subsystem families**
- **6 stable support / admission classes**
- **10 stable primitive-profile classes**
- **8 stable explicit-cut classes**
- **10 required record families**
- **10 required algorithms**

This means tidefs is no longer allowed to say only:

- “whatever modern Linux gives us should be fine,”
- “one daemon can require a newer kernel later if it helps,”
- “RDMA, SPDK, DPDK, eBPF, or vendor offloads can quietly become required if
  performance wants them,”
- “FUSE or ublk details can be treated as packaging or deployment trivia,”
- or “kernel-prepared stages can discover their real host assumptions during
  bring-up.”

It must instead say:

- which Linux subsystem family is required for each live surface,
- which primitive profile is the admitted baseline for that family,
- which service, package bundle, or migration stage may depend on it,
- which host probe receipt proves the dependency is really present,
- which missing primitives degrade lawfully versus force refusal,
- and which platform features are explicit non-baseline cuts rather than hidden
  future requirements.

The anti-regression rule is explicit:

**No service, package bundle, cutover stage, test gate, or future kernel step
may require a Linux feature outside the declared `linux_baseline` subsystem families,
primitive profiles, support classes, and explicit-cut records unless the design
center is amended first.**

## 2. Scope and boundaries

This document governs:

- the baseline Linux 7.0 host contract for all shipping userspace variants,
- the admitted subsystem families and primitive profiles for `policy_authority`, `posix_filesystem_adapter`,
  `block_volume_adapter`, `control_plane`, `explanation_query`, and observe/test surfaces,
- the clustered-runtime host assumptions consumed by `transport_session_0`, `membership_placement_0`, `operator_runbook_0`,
  `performance_budget_0`, and `cutover_control_0`,
- the kernel-prepared host assumptions needed before `kernel_gateway` and future `kernel_boundary`
  / `kmod` stages are admitted,
- the difference between required baseline support and explicit non-baseline
  cuts,
- and the receipt/gate bindings that stop package activation or stage promotion
  when the host contract is not satisfied.

That boundary is deliberate.
`P0-01` fixes **which Linux subsystem families and primitive profiles the whole
system may assume**.
It now also consumes the explicit `product_variant` product-variant matrix in
`docs/PRODUCT_VARIANT_MATRIX_P0-02.md`, so the 8 tracked live rows and their
mixed/kernel promotion ceilings are now bound onto these host-profile classes.
The std / `no_std` / userspace / kernel code-boundary law is now explicit in
`docs/STD_NO_STD_KERNEL_USERSPACE_BOUNDARY_RULES_P1-02.md`. It now also consumes
the explicit `vfs_boundary_mirror` UAPI / FFI / canonical-schema boundary law in
`docs/UAPI_FFI_CANONICAL_SCHEMA_BOUNDARY_RULES_P1-03.md`, so boundary mirrors,
wire layouts, kernel-visible structs, `repr(C)` call frames, and conversion
exactness are no longer allowed to drift from the declared design rule families.
It now also consumes the explicit `seam_map` shared design rule-native seam-map law in `docs/SHARED_DOCTRINE_NATIVE_SEAM_MAP_P0-03.md`, so seam ownership, client/boundary bindings, kernel-promotion cuts, and anti-leak rules are no longer allowed to drift from the declared cross-system registry. It now also consumes the explicit `non_authority_deletion` non-authority / deletion law in `docs/NON_AUTHORITY_DELETION_LAW_P0-04.md`, so live archived residue, archive-only carriers, tombstone/delete bindings, and non-authority proof are no longer allowed to drift from the declared product boundary.

This document now consumes the explicit `workspace_layout` workspace-family / crate-service-
boundary law in `docs/WORKSPACE_FAMILY_LAYOUT_CRATE_SERVICE_BOUNDARIES_P1-01.md`,
the explicit `type_map` design rule-family to Rust-type map in
`docs/DOCTRINE_FAMILY_TO_RUST_TYPE_MAP_P2-01.md`, the explicit `governance_surface_0`
authority-service law in `docs/POLICY_AUTHORITY_RUNTIME_SURFACE_P3-01.md`,
the explicit `posix_filesystem_adapter` daemon / process topology law in
`docs/POSIX_FILESYSTEM_ADAPTER_DAEMON_TOPOLOGY_P5-01.md`, the explicit `package_profile_catalog` build /
packaging / feature-matrix law in `docs/BUILD_PACKAGING_FEATURE_MATRIX_P1-04.md`,
the explicit `transport_session_0` transport/session/cohort law in
`docs/TRANSPORT_SESSION_COHORT_GRAPH_P8-01.md`, the explicit `membership_placement_0`
membership / placement / failure-domain law in
`docs/MEMBERSHIP_PLACEMENT_FAILURE_DOMAIN_MODEL_P8-02.md`, and the explicit
`kernel_boundary` kernel crate / trait boundary law in
`docs/RUST_FOR_LINUX_CRATE_TRAIT_BOUNDARIES_P7-02.md`, so host assumptions,
package activation, transport/runtime carriers, and future kernel staging are
no longer allowed to drift into distro-local convenience or hidden “modern
Linux probably has it” folklore.

It now also consumes the explicit `seam_map` shared design rule-native seam-map law in `docs/SHARED_DOCTRINE_NATIVE_SEAM_MAP_P0-03.md`, so seam ownership, client/boundary bindings, kernel-promotion cuts, and anti-leak rules are no longer allowed to drift from the declared cross-system registry. It now also consumes the explicit `non_authority_deletion` non-authority / deletion law in `docs/NON_AUTHORITY_DELETION_LAW_P0-04.md`, so live archived residue, archive-only carriers, tombstone/delete bindings, and non-authority proof are no longer allowed to drift from the declared product boundary. They may **not** widen the
Linux host contract beyond `linux_baseline`, reinterpret the declared `product_variant` row bindings,
or invent undeclared mixed/kernel host assumptions without first amending the
subsystem, primitive-profile, explicit-cut, and host-profile records fixed
here.

## 3. Repo anchor snapshot

The production law is grounded in real repo surfaces rather than pure future
prose:

  repo depends on Linux mount-helper, `/dev/fuse`, signal, readiness-pipe, and
  mount-lifetime process semantics rather than a generic cross-platform file-
  serving abstraction.
- `docs/UBLK_DAEMON_QUEUE_TOPOLOGY_P6-01.md`,
  `docs/EXPORT_FENCING_RESIZE_FAILOVER_RUNTIME_P6-03.md`, and
  already prove that the block-export plan is explicitly Linux `ublk` plus
  `io_uring` based rather than “some future userspace block shim.”
  userspace, not a hypothetical platform-neutral adapter abstraction.
- `docs/TRANSPORT_SESSION_COHORT_GRAPH_P8-01.md` and
  `docs/MEMBERSHIP_PLACEMENT_FAILURE_DOMAIN_MODEL_P8-02.md` already prove that
  clustered runtime law needs one explicit answer for socket transport, timer /
  deadline, and resource-accounting assumptions.
- `docs/KERNEL_LOCKING_RCU_PINNING_WORKQUEUE_MODEL_P7-03.md`,
  `docs/VFS_BLOCK_INTEGRATION_KERNEL_UAPI_LAW_P7-04.md`, and
  `docs/KERNEL_PROGRESSION_STAIRCASE_AFTER_USERSPACE_SUCCESS_P11-04.md` already
  prove that later kernel stages are prepared, but they remain later,
  receipt-bound, and subordinate to the first userspace baseline.

Production `P0-01` turns those anchors into one explicit Linux host contract.
The current repo already proves that Linux-specific substrate assumptions exist;
this law now fixes which of them are baseline, which are staged, and which are
explicit non-baseline cuts.

## 4. Metrics snapshot

| Metric | Count |
|---|---:|
| Stable subsystem families | 10 |
| Stable support / admission classes | 6 |
| Stable primitive-profile classes | 10 |
| Stable explicit-cut classes | 8 |
| Required record families | 10 |
| Required algorithms | 10 |

## 5. Linux 7.0 baseline contract law

### 5.1 Stable support / admission classes

| Support class | Meaning |
|---|---|
| `support.linux_baseline.common_userspace.k0` | required for every first-generation shipping userspace surface: `policy_authority`, `control_plane`, `explanation_query`, observe, packaging helpers, and common service runtime |
| `support.linux_baseline.posix_filesystem_adapter_adapter.k1` | additionally required when the `posix_filesystem_adapter` FUSE/POSIX adapter is admitted |
| `support.linux_baseline.block_volume_adapter_adapter.k2` | additionally required when the `block_volume_adapter` `ublk` block adapter is admitted |
| `support.linux_baseline.clustered_runtime.k3` | additionally required when distributed runtime, failover, or cluster traffic is admitted |
| `support.linux_baseline.future_kernel_stage.k4` | prepared but not required until `kernel_gateway` / `kernel_boundary` / `kmod` stages are explicitly admitted |
| `support.linux_baseline.explicit_cut.k5` | intentionally outside the first production baseline; may not silently become required |

### 5.2 Stable subsystem families

| Subsystem family | Baseline role | Support class | First consumers |
|---|---|---|---|
| `subsystem.linux_baseline.proc_supervision.s0` | process spawn, pid tracking, exit, restart, and crash observation substrate | `k0` | `control_plane`, `policy_authority`, `posix_filesystem_adapter`, `block_volume_adapter`, observe, runbooks |
| `subsystem.linux_baseline.fd_reactor_signals.s1` | readiness, wake, timer, and signal-driven event substrate | `k0` | `policy_authority`, `posix_filesystem_adapter`, `block_volume_adapter`, `control_plane`, observe |
| `subsystem.linux_baseline.async_io_uring.s2` | async storage / block I/O substrate and registered-buffer staging substrate | `k0` + `k2` | `policy_authority`, `block_volume_adapter`, bulk transfer, later zero-copy paths |
| `subsystem.linux_baseline.mount_vfs_admin.s3` | mount / unmount / statx / rename / sync and local VFS admin substrate | `k0` + `k1` | `posix_filesystem_adapter`, xfstests harness, local admin/runbook flows |
| `subsystem.linux_baseline.fuse_devfuse.s4` | `/dev/fuse` negotiation and userspace filesystem carrier | `k1` | `posix_filesystem_adapter`, xfstests, mount helper |
| `subsystem.linux_baseline.ublk_queue_control.s5` | `/dev/ublk-control`, queue/tag, and block-device userspace carrier | `k2` | `block_volume_adapter`, block harness, export/runtime cutovers |
| `subsystem.linux_baseline.socket_transport.s6` | first-generation inter-node stream transport substrate | `k3` | `transport_session_0`, `membership_placement_0`, failover/runbooks, shadow and state-transfer traffic |
| `subsystem.linux_baseline.resource_control_accounting.s7` | CPU/memory/FD/process pressure, accounting, and limits substrate | `k0` + `k3` | `posix_filesystem_adapter`, `block_volume_adapter`, `policy_authority`, transport/runtime budgets, perf/chaos gates |
| `subsystem.linux_baseline.crypto_rng_clock.s8` | randomness, digest/time, and monotonic clock substrate | `k0` | `secret_key_policy_0`, `identity_access_audit_0`, `performance_budget_0`, `cutover_control_0`, receipts, transport timing |
| `subsystem.linux_baseline.kernel_bridge_uapi.s9` | kernel headers / kbuild / Rust-for-Linux / admitted Linux-visible bridge substrate | `k4` | `kernel_boundary`, `kernel_gateway`, `kmod.posix_filesystem_adapter`, `kmod.block_volume_adapter`, optional later `kmod.policy_authority` |

### 5.3 Stable primitive-profile classes

| Primitive profile | Meaning |
|---|---|
| `primitive.linux_baseline.pidfd_wait_exec.p0` | `fork`/`exec`/`wait` plus pidfd-capable supervision and explicit crash observation |
| `primitive.linux_baseline.epoll_eventfd_timerfd_signalfd.p1` | one lawful fd-driven wake/timer/signal reactor profile |
| `primitive.linux_baseline.io_uring_core_registered.p2` | the admitted `io_uring` baseline for async storage and later registered-buffer work |
| `primitive.linux_baseline.mount_statx_rename_syncfs.p3` | the admitted local mount/VFS admin surface for `posix_filesystem_adapter`, xfstests, and runbook-visible sync/fence effects |
| `primitive.linux_baseline.devfuse_mount_helper_umount.p4` | the admitted FUSE/devfuse baseline with helper-compatible mount/unmount flow |
| `primitive.linux_baseline.ublk_control_tag_queue.p5` | the admitted `ublk` control/device/tag/queue baseline for `block_volume_adapter` |
| `primitive.linux_baseline.stream_socket_tcp_first.p6` | the admitted first-generation stream-transport baseline; plain TCP-class transport is required, while QUIC/RDMA remain later optional work |
| `primitive.linux_baseline.cgroup_rlimit_pressure_pidfd.p7` | the admitted resource-accounting baseline for process/FD/memory pressure and kill/stop observation |
| `primitive.linux_baseline.getrandom_clock_gettime_memfd.p8` | the admitted clock/random/scratch-buffer baseline for keys, receipts, timing, and bounded staging |
| `primitive.linux_baseline.headers_kbuild_rust_for_linux_uapi.p9` | the admitted kernel-prepared baseline for headers, build glue, Rust-for-Linux entry, and Linux-visible UAPI bridge work |

### 5.4 Stable explicit-cut classes

The following remain explicit non-baseline cuts unless the design center is
amended first:

| Explicit cut | Meaning |
|---|---|
| `cut.linux_baseline.rdma_required_fastpath.x0` | RDMA / RoCE or similar NIC-specific fast paths may not be required for correctness or first shipping admission |
| `cut.linux_baseline.spdk_dpdk_userspace_bypass.x1` | SPDK / DPDK / bypass data planes may not become hidden baseline carriers |
| `cut.linux_baseline.ebpf_or_fanotify_hidden_authority.x2` | eBPF, fanotify, or similar kernel hooks may not become hidden authority, policy, or repair channels |
| `cut.linux_baseline.out_of_tree_kernel_patch_required.x3` | no shipping surface may silently require an unpublished private kernel patch set; required Linux patches must live in `forgeadmin/linux`, be issue-bound, and be admitted as explicit release inputs |
| `cut.linux_baseline.custom_fuse_or_ublk_abi.x4` | no custom FUSE or `ublk` ABI fork may become the silent real baseline |
| `cut.linux_baseline.init_system_specific_truth.x5` | systemd, rc scripts, or any init-system detail may package/activate services but may not become architecture truth |
| `cut.linux_baseline.vendor_filesystem_or_device_manager_assumption.x6` | distro- or vendor-local helper paths may not become required hidden dependencies |
| `cut.linux_baseline.hardware_offload_as_correctness_dependency.x7` | any hardware acceleration may improve cost/perf but may not become the thing that makes the semantics correct |

### 5.5 Contract invariants

The Linux baseline contract is strict:

1. No shipping userspace variant may require features beyond Linux 7.0-era
   admitted subsystem families without first extending `linux_baseline`.
2. `posix_filesystem_adapter` may require `k1` and `block_volume_adapter` may require `k2`, but neither may widen the
   common baseline for `policy_authority`, `control_plane`, `explanation_query`, or observe helpers by accident.
3. Distributed runtime may assume `k3` only for admitted clustered variants; a
   single-node package may not silently depend on cluster-only transport or
   placement substrate.
4. Kernel-prepared work may assume `k4` only after `kernel_gateway`/`kernel_boundary`/`kmod` stage
   admission; it may not leak into first shipping userspace requirements.
5. Any missing required support class must produce a typed degrade or refusal
   before package activation, stage promotion, or release/cutover admission.
6. Any feature that falls into `k5` is an intentional non-promise, not a
   performance continuation that can quietly become necessary later.

## 6. Service / stage binding law

`linux_baseline` binds Linux host assumptions to live services and migration stages as
follows:

| Target | Required support classes | Notes |
|---|---|---|
| `posix_filesystem_adapter` userspace adapter and xfstests admission | `k0` + `k1` | must prove mount-helper and `/dev/fuse` readiness before activation |
| `block_volume_adapter` userspace block export and block harness admission | `k0` + `k2` | must prove admitted `ublk` + `io_uring` profile before export or stress gates |
| clustered userspace runtime, failover, and shadow/state-transfer coordination | `k0` + `k3` | transport, timing, and resource-accounting assumptions become gate-visible |
| later `kernel_gateway` / `kernel_boundary` / `kmod` stages | `k0` + `k4` | later kernel-prepared stages are additive and may not retroactively redefine `k0` |

The full product-variant matrix is now explicit in
`docs/PRODUCT_VARIANT_MATRIX_P0-02.md`.
It consumes these classes rather than inventing a second host contract.

## 7. Canonical Linux baseline/schema families

| Record | Purpose | Authority class |
|---|---|---|
| `LinuxBaselineContractRecord` | one declared Linux 7.0 baseline contract with admitted subsystem refs, admission rules, and explicit-cut refs | authoritative declaration |
| `LinuxSupportClassRecord` | one support / admission class with scope, degrade policy, and refusal rule | authoritative declaration |
| `LinuxSubsystemFamilyRecord` | one admitted subsystem family, role, support class, and first-consumer binding | authoritative declaration |
| `LinuxPrimitiveProfileRecord` | one admitted primitive profile for a subsystem family with required capabilities and forbidden fallback drift | authoritative declaration |
| `LinuxServiceStageBaselineBindingRecord` | binding from one service, package bundle, or migration stage to required support classes and subsystem families | authoritative binding |
| `LinuxExplicitCutRecord` | one intentional non-baseline cut with reason class, replacement rule, and refusal surface | authoritative refusal declaration |
| `LinuxBaselineProbeIntentRecord` | one planned host probe over required subsystem families, primitive profiles, and explicit cuts | authoritative/runtime intent |
| `LinuxBaselineProbeReceipt` | one observed host result set with admitted/missing/degraded subsystem verdicts | authoritative/runtime receipt |
| `LinuxKernelBridgeBaselineRecord` | one kernel-prepared baseline binding for headers, kbuild, Rust-for-Linux, and UAPI bridge expectations | authoritative declaration |

These families are added to `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`
by this turn.

## 8. Required algorithms

The production Linux-baseline law requires these algorithms to exist in the
shared algorithm set:

1. **`declare_linux_7_0_baseline_contract()`**
2. **`declare_linux_support_classes_and_subsystem_families()`**
3. **`bind_linux_primitive_profile_to_subsystem_family()`**
4. **`bind_service_or_stage_to_required_linux_support_classes()`**
5. **`probe_host_for_linux_baseline_capabilities_and_cuts()`**
6. **`classify_missing_primitive_as_degrade_or_refusal()`**
7. **`reject_out_of_baseline_dependency_or_required_cut()`**
8. **`bind_linux_baseline_baseline_to_package_profile_catalog_bundle_and_activation_stage()`**
9. **`bind_linux_baseline_baseline_to_gate_artifact_and_recall_requirements()`**
10. **`issue_linux_baseline_admission_receipt_or_stop_ticket()`**

## 9. Whole-system operational paths added by this law

1. single-node userspace release candidate -> `profile.package_profile_catalog.release_userspace.p3`
   binds `policy_authority`/`control_plane`/`explanation_query`/observe services to `support.linux_baseline.common_userspace.k0`
   -> host probe emits one `LinuxBaselineProbeReceipt` -> packages activate only
   when the declared Linux substrate is really present instead of assuming “some
   modern distro” is good enough
2. `posix_filesystem_adapter` xfstests or live mount admission -> `support.linux_baseline.posix_filesystem_adapter_adapter.k1`
   requires `subsystem.linux_baseline.mount_vfs_admin.s3` plus
   `subsystem.linux_baseline.fuse_devfuse.s4` -> mount helper, `/dev/fuse`, and sync/
   rename/statx-visible substrate are probed before `posix_filesystem_adapter` starts -> adapter
   runtime does not discover missing kernel support after the mount is already
   sovereign
3. `block_volume_adapter` block-export candidate -> `support.linux_baseline.block_volume_adapter_adapter.k2` requires
   `subsystem.linux_baseline.async_io_uring.s2` plus `subsystem.linux_baseline.ublk_queue_control.s5`
   -> `ublk`/`io_uring` readiness is admitted or refused before queue topology,
   perf gates, or export runbooks proceed -> `block_volume_adapter` does not inherit an undeclared
   userspace block shim
4. clustered userspace failover or shadow/state-transfer stage ->
   `support.linux_baseline.clustered_runtime.k3` binds socket transport, timing, and
   resource-accounting substrate -> `transport_session_0`, `membership_placement_0`, `operator_runbook_0`, `performance_budget_0`, and `cutover_control_0`
   consume one declared host contract instead of quietly assuming a transport or
   pressure model that exists nowhere in package or gate receipts
5. later kernel-prepared candidate or performance pressure proposal tries to
   require a hidden private kernel patch, RDMA-only fast path, or SPDK/DPDK
   carrier -> `reject_out_of_baseline_dependency_or_required_cut()`
   classifies the demand under one explicit-cut record ->
   `package_profile_catalog`, `operator_runbook_0`, `truth_view`, and stage
   gates emit one refusal / stop story instead of silently redefining the
   platform baseline. A visible TideFS Linux patch branch in `forgeadmin/linux`
   is allowed only when it is issue-bound, QEMU-proven, and admitted as an
   explicit release input.

## 10. Acceptance effect on the design pack

With this law settled:

- `P0-01` becomes detailed enough for later implementation planning,
- the repo now has one explicit answer to what Linux 7.0 actually means for
  live service, adapter, cluster, package, and later kernel-prepared admission,
- `package_profile_catalog`, `workspace_layout`, `type_map`, `governance_surface_0`, `posix_filesystem_adapter`, `block_volume_adapter`, `transport_session_0`, `membership_placement_0`, `performance_budget_0`, `cutover_control_0`, and
  `kernel_gateway` now share one host-contract grammar instead of package-local,
  daemon-local, or distro-local assumptions,
- broad implementation still makes sense to start, because the remaining work is
  no longer missing platform-baseline law,
- there are still **no** `L0` or `L1` production-design items,
- no tracked production-design work remains below `L3`,
- and the tracked production design ledger is now fully at `L3`.
