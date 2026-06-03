# kernel module family matrix and rollout order (P7-01) (v0.332)

This document is the production-depth source-of-truth for **P7-01**.

It answers one concrete question:


See also:
- `docs/END_TO_END_PRODUCTION_BLUEPRINT.md`
- `docs/KERNEL_LOCKING_RCU_PINNING_WORKQUEUE_MODEL_P7-03.md`
- `docs/VFS_BLOCK_INTEGRATION_KERNEL_UAPI_LAW_P7-04.md`
- `docs/KERNEL_MODULE_DEVELOPMENT_WORKFLOW_P7-05.md`
- `docs/POSIX_CHARTER_TEST_XFSTESTS_MATRIX_P5-04.md`
- `docs/BLOCK_ACCEPTANCE_STRESS_HARNESS_MATRIX_P6-04.md`
- `docs/FAULT_INJECTION_CHAOS_CORRUPTION_CAMPAIGNS_P10-02.md`
- `docs/FIRST_RUST_USERSPACE_IMPLEMENTATION_STAIRCASE_P11-03.md`
- `docs/CHECKPOINT_SNAPSHOT_REPLAY_CURSOR_PERSISTENCE_LAW_P2-05.md`

## 1. Outcome

The kernel rollout law is now explicit.

The production design now has:

- one coordinating family: **`family.kernel_module_rollout.kernel_module_0`**
- one shared prerequisite substrate: **`kmod.common.bridge.k0`**
- three tracked product kernel-module families:
  - **`kmod.posix_filesystem_adapter.vfs.k0`**
  - **`kmod.block_volume_adapter.block.k0`**
  - **`kmod.policy_authority.host.k0`** (optional and last)
- one fixed product-family rollout order:
  - **`posix_filesystem_adapter` first -> `block_volume_adapter` second -> `policy_authority` kernel-hosted last**
- one fixed first live kernel target:
  - **`kmod.posix_filesystem_adapter.vfs.k0`**
- one fixed first legal seam for that first target:
  - **`seam.kernel_module_0.posix_filesystem_adapter.namespace_cleanread.s0`**

That means tidefs is no longer allowed to say only:

- “we will move whichever kernel module looks easiest,”
- “the block path may go first because it seems narrower,”
- “the authority kernel can move once Rust is strong enough,”
- or “kernel rollout will decide its own gates later.”

It must instead say:

- which product kmod family is currently being considered,
- whether the work is only on the shared bridge substrate or on a shipping product family,
- which variant class is legal for that family,
- which userspace stage must already be complete,
- which existing row/profile/gate and chaos families must stay attached,
- which first seam is in scope and which scope is still forbidden,
- and which userspace surface is restored if rollback happens.

The decisive anti-regression rule is now explicit:

**Kernel rollout starts only after the all-Rust userspace soak stage `stage.userspace.mixed_soak_archive_ready.s7`, and every kernel family must inherit the same row ids, bucket grammar, artifact contracts, chaos campaigns, and rollback law that already govern userspace variants.**

## 2. Scope and boundaries

This document settles:

- the tracked kernel product-family matrix,
- the distinction between a shared kernel substrate and a real product kmod family,
- the fixed family rollout order,
- the first product-family target,
- the first legal seam for that first target,
- the earliest legal deployment variant for each family,
- and the cross-family non-waivable ordering constraints.

This document does **not** yet fully settle:

- the full kernel progression staircase and named kernel admission gates (`P11-04`).

The checkpoint/snapshot/replay-cursor law, operator-runbook law, secret/key-handling law, and performance/SLO law are now explicit in `docs/CHECKPOINT_SNAPSHOT_REPLAY_CURSOR_PERSISTENCE_LAW_P2-05.md`, `docs/UPGRADE_FAILOVER_CUTOVER_OPERATOR_RUNBOOKS_P9-03.md`, `docs/SECRETS_POLICY_STORAGE_KEY_HANDLING_LAW_P9-04.md`, and `docs/PERFORMANCE_BUDGETS_SLO_REGRESSION_GATES_P10-03.md`. But this document still settles the ordering law those later items must obey.

The Linux 7.0 build workflow for these families is fixed separately in
`docs/KERNEL_MODULE_DEVELOPMENT_WORKFLOW_P7-05.md`: Nix is the reproducible
acceptance layer, while ordinary module edits must use prepared-kernel
out-of-tree builds and disposable QEMU load tests. A product family may not
hide a full kernel rebuild loop, host module load, or private Linux source-tree
patch behind this rollout order.

## 3. Family classes and the support substrate

### 3.1 `kmod.common.bridge.k0` is required, but it is **not** a standalone product family

The repo already needed one shared kernel-side bridge family, but this pass makes its status explicit:

- `kmod.common.bridge.k0` is the prerequisite substrate beneath every future product kmod,
- it is implemented by shared Rust-for-Linux support code such as the current placeholder `kmod/tidefs_common_types`,
- and it does **not** count as one of the tracked product kernel module families.

Its legal contents are limited to shared bridge primitives such as:

- canonical identity / epoch / anchor mirror types,
- `binary_schema` parsing and rendering helpers,
- response-envelope render adapters,
- lock/RCU/pin/workqueue glue that consumes `P7-03`,

It may **not** own:

- policy publication truth,
- reserve or budget truth,
- checkpoint or replay-cursor truth,
- secret storage or key lifecycle,
- or a second parser / receipt / gate dialect for kernel-only use.

The reason is structural:

**the bridge substrate may make kernel code possible, but it may not become a disguised sovereignty center or a miscellaneous dumping ground for functionality that the product families were supposed to justify explicitly.**

### 3.2 Tracked product kernel-module families

The tracked product families are now exactly these three:

1. **`kmod.posix_filesystem_adapter.vfs.k0`**
   - VFS/POSIX-facing charter client in kernel space
   - still a client over userspace authority families

2. **`kmod.block_volume_adapter.block.k0`**
   - block/export-facing charter client in kernel space
   - still a client over userspace authority families

3. **`kmod.policy_authority.host.k0`**
   - optional, selected-domain kernel-hosted authority family
   - never the first target
   - legal only after the client families have already proved mixed userspace/kernel discipline

This reconciles the blueprint and ledger metrics:

- **planned product kernel module families remain `3`**,
- while `kmod.common.bridge.k0` remains a required support substrate instead of a fourth shipping product family.

## 4. Family matrix

The kernel module matrix is now fixed as follows.

|---|---|---|---|---|---|---|
| `kmod.posix_filesystem_adapter.vfs.k0` | POSIX/VFS charter client | client-only; may not own policy, reserve, or product admission truth | `variant.rs.mixed.userspace_kernel` after `stage.userspace.mixed_soak_archive_ready.s7` | `seam.kernel_module_0.posix_filesystem_adapter.namespace_cleanread.s0` | `suite.posix_filesystem_adapter.*`, `profile.test_architecture_3.shadow_cutover`, `profile.test_architecture_2.release_required`, `gate.posix_filesystem_adapter.kernel.readiness.g3`, `gate.cutover.shadow`, `gate.rollback.reentry`, `cutover_control_0` rows for Linux-facing fault/corruption pressure | all userspace `posix_filesystem_adapter` gates must already be satisfied; `P7-03` and `P7-04` remain mandatory |
| `kmod.block_volume_adapter.block.k0` | block/export charter client | client-only; may not own checkpoint, resize-policy, or failover sovereignty | `variant.rs.mixed.userspace_kernel` only after `posix_filesystem_adapter` family admission is already proven | `seam.kernel_module_0.block_volume_adapter.single_export_fixed_capacity.s1` | `suite.block_volume_adapter.*`, `profile.test_architecture_3.shadow_cutover`, `profile.test_architecture_2.release_required`, `profile.test_architecture_4.soak_disaster`, `gate.block_volume_adapter.g2.pressure_and_failover`, `gate.cutover.shadow`, `gate.rollback.reentry`, `cutover_control_0` rows for corruption/failover/export pressure, inherited `performance_budget_0` rows | `P2-05` must be explicit; shared `performance_budget_0` release floors must already be satisfied; replay/failover blockers may not be open |
| `kmod.policy_authority.host.k0` | optional selected-domain authority host | scoped kernel authority, but only for domains that have already earned it | `variant.rs.authoritative.kernel` only after both client families are already proven | `seam.kernel_module_0.policy_authority.product_admission_capsule.s2` | inherited `policy_authority`, `control_plane`, `explanation_query`, `migration_cutover_0`, `cutover_control_0`, and `performance_budget_0` rows; `profile.test_architecture_3.shadow_cutover`; `profile.test_architecture_4.soak_disaster`; `gate.cutover.shadow`; `gate.rollback.reentry`; inherited `kernel_gateway` stage gates from `docs/KERNEL_PROGRESSION_STAIRCASE_AFTER_USERSPACE_SUCCESS_P11-04.md` | `docs/RUST_FOR_LINUX_CRATE_TRAIT_BOUNDARIES_P7-02.md`, `docs/KERNEL_PROGRESSION_STAIRCASE_AFTER_USERSPACE_SUCCESS_P11-04.md`, `P9-03`, `P9-04`, and the client-family rollout must already be satisfied with shared `performance_budget_0` floors closed |

Two invariants are non-waivable:

1. **No product kernel family may invent a fresh gate grammar because the code crossed into the kernel.**

## 5. Fixed family rollout order

The product-family order is now fixed:

1. **`kmod.posix_filesystem_adapter.vfs.k0` first**
2. **`kmod.block_volume_adapter.block.k0` second**
3. **`kmod.policy_authority.host.k0` optional and last**

This is a repo-wide production order, not merely a preference for one deployment.

Product deployments may later ship a subset of already-admitted families, but no family may become the **first** serious kernel rollout target ahead of this order.

### 5.1 Why `posix_filesystem_adapter` is first — continuity: POSIX Filesystem Adapter (`posix_filesystem_adapter`)

`posix_filesystem_adapter` is first because it satisfies the strongest combination of leverage and safety:

- it is a **charter client**, not an authority center,
- it can improve the VFS-facing fast path without moving policy, reserve, or product truth into the kernel,
- and rollback is structurally cleaner because the mixed deployment can restore the earlier userspace `posix_filesystem_adapter` surface while userspace `policy_authority` remains authoritative.

In other words, `posix_filesystem_adapter` offers the first real kernel performance and fidelity opportunity **without** paying the highest sovereignty risk first.

### 5.2 Why `block_volume_adapter` is not first — continuity: Block Volume Adapter (`block_volume_adapter`)

`block_volume_adapter` is second because its pressure profile is harsher:

- block durability and export transition mistakes are less forgiving than the first `posix_filesystem_adapter` read/namespace fast path,
- `block_volume_adapter` relies more heavily on checkpoint/replay-cursor truth and cutover/runtime safety,
- and the block path cannot tolerate hidden queue-local durability folklore, resize ambiguity, or failover ambiguity.

`block_volume_adapter` therefore waits for:

- `P2-05` checkpoint/snapshot/replay-cursor law,
- and the shared `performance_budget_0` numeric regression thresholds from `docs/PERFORMANCE_BUDGETS_SLO_REGRESSION_GATES_P10-03.md`.

### 5.3 Why `policy_authority` kernel-hosted is last — continuity: Policy Authority (`policy_authority`)

`policy_authority` kernel-hosted is explicitly last and optional.

The word "optional" describes the rollout order: the kernel-hosted
`kmod.policy_authority.host.k0` family is the last candidate for
kernel admission and may be deferred or scoped to selected domains only.
It does **not** mean that a userspace policy-authority daemon is an
acceptable alternative for final full-kernel acceptance. Full-kernel
mode must not require any FUSE daemon, ublk daemon, policy/control
daemon, explanation/query daemon, transport helper daemon, or usermode
worker thread for normal mount, filesystem I/O, block I/O, writeback,
recovery, placement, reserve, or admission behavior. Any runtime
authority needed while the filesystem is mounted must either be
implemented in the Linux 7.0 kernel-side stack or be proven unnecessary
during operation.

The reason is simple:

**moving authority into the kernel before the charter-client families prove mixed userspace/kernel discipline would maximize the risk of hidden sovereignty, opaque rollback, secret leakage, and kernel-only truth dialects.**

So `kmod.policy_authority.host.k0` may not be:

- the first kernel target,
- or a broad “the authority just lives in kernel now” rewrite event.



But the residency rule is equally strict: once the kernel rollout has
progressed to the `s5` deployment stack (`selected_domain_kernel_authority`),
no userspace daemon or usermode worker thread may remain as a required
support surface for normal filesystem or block operation. The
`kmod.policy_authority.host.k0` family is the only mechanism provided for
closing the authority-residency gap; if it is not implemented for a given
deployment, the deployment has not achieved full-kernel acceptance and
must not claim it.

Mixed userspace/kernel mode, FUSE/ublk bring-up, shadow comparison, and
rollback/fallback modes are useful bring-up stages but cannot be counted
as final full-kernel acceptance. Predecessor K7 spine issues (#5289,
#5290, #5291) established the rollout order and mixed-mode proof but
did not settle the final no-usermode residency invariant.
If it happens at all, it happens only as a later, selected-domain move with explicit runbook, secret-handling, and kernel-stage law already settled.

## 6. The first legal seam: `seam.kernel_module_0.posix_filesystem_adapter.namespace_cleanread.s0` — continuity: POSIX Filesystem Adapter (`posix_filesystem_adapter`)

The first product kernel seam is now fixed:

- **family:** `kmod.posix_filesystem_adapter.vfs.k0`
- **deployment variant:** `variant.rs.mixed.userspace_kernel`
- **first seam id:** `seam.kernel_module_0.posix_filesystem_adapter.namespace_cleanread.s0`

This seam exists to make the first kernel move narrow, high-signal, and reversible.

### 6.1 In scope

The first `posix_filesystem_adapter` kernel seam may cover only the read-mostly namespace and clean-read surface:

- mount/super admission against already-published projection-root and policy mirrors,
- open + read + readahead on already-authorized handles,
- and `statx` rendering from canonical envelopes.

### 6.2 Explicitly out of scope

The first seam may **not** include:

- create / link / unlink / rename / mkdir / rmdir / symlink,
- dirty page-cache ownership,
- writeback, fsync/msync, or mutation durability decisions,
- writable mmap or `page_mkwrite` authority,
- xattr/ACL/lock/ioctl policy surfaces that can smuggle local truth,
- remount/freeze/thaw policy mutation,
- or any local kernel cache that can outvote canonical envelope, receipt, or transition-fence truth.

### 6.3 Fallback and rollback rule for the first seam

During the first seam:

- out-of-scope operations must fall back to the userspace `posix_filesystem_adapter` surface or be refused according to the existing charter law,
- mutation, dirtying, writable mmap, or authority-bearing requests may **not** be “partially handled” in-kernel by convenience,

The anti-regression rule is direct:

**the first seam is allowed to accelerate read-mostly VFS service, but it is not allowed to become a half-authoritative dirty-writeback subsystem by drift.**

## 7. Family-specific early-scope law

### 7.1 `kmod.posix_filesystem_adapter.vfs.k0` — continuity: POSIX Filesystem Adapter (`posix_filesystem_adapter`)

Early-scope rule:

- first real move is `seam.kernel_module_0.posix_filesystem_adapter.namespace_cleanread.s0`
- later mutation/writeback/mmap expansion is deferred to `P11-04`

Non-waivable rule:

- if the first `posix_filesystem_adapter` kernel path needs a local policy, budget, reserve, or product-decision shortcut, the rollout must stop rather than expanding scope informally.

### 7.2 `kmod.block_volume_adapter.block.k0` — continuity: Block Volume Adapter (`block_volume_adapter`)

Early-scope rule:

- first real move is `seam.kernel_module_0.block_volume_adapter.single_export_fixed_capacity.s1`
- one fixed-capacity export is allowed
- read/write, flush/FUA, discard/zero, queue limits, and completion render are in scope
- live resize, failover handoff, multi-export arbitration, and checkpoint truth are out of scope for the first kernel seam

Non-waivable rule:

- no first `block_volume_adapter` kernel move may rely on undeclared replay-cursor behavior or queue-local durability folklore.

### 7.3 `kmod.policy_authority.host.k0` — continuity: Policy Authority (`policy_authority`)

Early-scope rule:

- if this family ever becomes legal, the first admissible kernel authority seam is `seam.kernel_module_0.policy_authority.product_admission_capsule.s2`
- that means `domain.product_admission.primary` only
- policy publication, budget domains, and override-ticket authority remain outside the first kernel-hosted authority seam

Non-waivable rule:

- no kernel-hosted `policy_authority` move may begin with broad policy or secret-bearing surfaces.


Every kernel family now has one mandatory variant progression consequence.

The first admission variant is:

- **`variant.rs.mixed.userspace_kernel`**

not:

- a direct jump to `variant.rs.authoritative.kernel`,
- and not a module-local shadow mode that ignores the shared matrix architecture.

Every serious kernel family campaign must therefore inherit:

- the same row ids already required by `suite.posix_filesystem_adapter.*`, `suite.block_volume_adapter.*`, `suite.migration_cutover_0.*`, and future `policy_authority`/`control_plane`/`explanation_query` kernel-consuming rows,
- the same profile families `profile.test_architecture_2.release_required`, `profile.test_architecture_3.shadow_cutover`, and `profile.test_architecture_4.soak_disaster` where applicable,
- the same gate classes `gate.release.variant`, `gate.cutover.shadow`, and `gate.rollback.reentry`,
- the same `cutover_control_0` fault catalogs, hook bindings, schedule/seed manifests, and forbidden-outcome scans,
- and the same artifact map law from `type_map`.

Nothing about kernel rollout is allowed to replace those with:

- benchmark-only admission,
- module-load smoke-only admission,
- ad hoc sysrq/manual testing,
- or local kernel logs treated as proof.

## 9. Relationship to remaining unresolved production items

### `P7-02` Rust-for-Linux crate and trait boundaries

`P7-02` is now explicit in `docs/RUST_FOR_LINUX_CRATE_TRAIT_BOUNDARIES_P7-02.md`.
That law fixes the exact `no_std` / `alloc` / kernel crate split for:

- `kmod.common.bridge.k0`,
- `kmod.posix_filesystem_adapter.vfs.k0`,
- `kmod.block_volume_adapter.block.k0`,
- and optional `kmod.policy_authority.host.k0`.

It may refine implementation tasks later, but it may not change the family order or the first seam fixed here.

### `P11-04` kernel progression staircase after userspace success

`P11-04` is now explicit in `docs/KERNEL_PROGRESSION_STAIRCASE_AFTER_USERSPACE_SUCCESS_P11-04.md`. That law fixes the exact `kernel_gateway` stage ladder and named admission gates **inside** the order fixed here: three `posix_filesystem_adapter` stages, three `block_volume_adapter` stages, and optional three selected-domain `policy_authority` stages after `stage.userspace.mixed_soak_archive_ready.s7`.

It may refine implementation tasks later, but it may not reopen the question of which family is first.

### `P2-05` checkpoint / snapshot / replay-cursor persistence law

`P2-05` is now explicit in `docs/CHECKPOINT_SNAPSHOT_REPLAY_CURSOR_PERSISTENCE_LAW_P2-05.md`. That closes the previous design hole, but it also means `kmod.block_volume_adapter.block.k0` and any serious `kmod.policy_authority.host.k0` move must now consume one shared anchor law for checkpoints, snapshots, replay cursors, scan fallback, and fenced refusal instead of inventing kernel-local restart rules.

### `P9-03` runbooks and `P9-04` secrets/key-handling

`P9-03` is now explicit in `docs/UPGRADE_FAILOVER_CUTOVER_OPERATOR_RUNBOOKS_P9-03.md`. That closes the runbook-design hole, but it also means any kernel-hosted `policy_authority` move must inherit the shared `operator_runbook_0` grammar instead of inventing kernel-only rollout or rollback rituals. `P9-04` is now explicit in `docs/SECRETS_POLICY_STORAGE_KEY_HANDLING_LAW_P9-04.md`, which means a kernel authority family is not allowed to outpace the shared `secret_key_policy_0` handle/lease/rotation model or invent its own plaintext cache dialect.

### `P10-03` performance budgets / SLO / regression gates

`P10-03` is now explicit in `docs/PERFORMANCE_BUDGETS_SLO_REGRESSION_GATES_P10-03.md`.
It adds numeric floors to the same inherited release/cutover gates.
It may not invent a separate “kernel performance pass” that bypasses the shared matrix and artifact law.

## 9. Full-kernel residency invariant (K7-13)

The final full-kernel acceptance gate is now fixed as follows.

**Full-kernel mode** is the deployment state in which the filesystem operates
entirely in kernel space without any required userspace daemon or usermode
worker thread for normal operation. `tidefsctl` and non-resident query/operator
tools remain allowed only as UAPI clients.

Full-kernel mode must not require a FUSE daemon, ublk daemon, policy/control
daemon, explanation/query daemon, transport helper daemon, or usermode worker
thread for mount, filesystem I/O, block I/O, writeback, recovery, placement,
reserve, or admission behavior.

Any runtime authority needed while the filesystem is mounted must either be
implemented in the Linux 7.0 kernel-side stack (via the tracked product kmod
families) or be proven unnecessary during operation. Mixed userspace/kernel
deployments that still depend on FUSE, ublk, or any usermode daemon for
normal operation have not achieved full-kernel acceptance and must not be

The predecessor K7 spine issues (#5289, #5290, #5291) established the
family matrix, rollout order, first seam, and mixed-mode proof approach.
This section (K7-13) closes the remaining gap: the final no-usermode
residency invariant that distinguishes mixed bring-up from true full-kernel
acceptance.

## 10. Anti-regression rules

1. **No product kernel family may start before `stage.userspace.mixed_soak_archive_ready.s7`.**
2. **No family may go first ahead of `kmod.posix_filesystem_adapter.vfs.k0`.**
3. **`kmod.common.bridge.k0` may not become a hidden sovereignty center or a miscellaneous subsystem dump.**
4. **The first `posix_filesystem_adapter` seam may not own mutation, dirty writeback, writable mmap, or local policy truth.**
5. **`kmod.block_volume_adapter.block.k0` may not start without explicit checkpoint/replay-cursor law.**
6. **`kmod.policy_authority.host.k0` may not start before both client families and the remaining operator/security laws are proven.**
7. **No kernel variant may reset row ids, bucket grammar, artifact contracts, or rollback receipts.**
8. **No claimed full-kernel pass may depend on a FUSE daemon, ublk daemon, policy/control daemon, explanation/query daemon, transport helper daemon, or usermode worker thread for normal operation.**
9. **Mixed userspace/kernel and FUSE/ublk bring-up stages are bring-up scaffolding only; they do not constitute full-kernel acceptance.**
10. **Before claiming full-kernel acceptance, the deployment must prove either `kmod.policy_authority.host.k0` residency or that no runtime authority remains in userspace for mounted operation.**

## 12. Result

`P7-01` is closed when the repo can say, at production depth:

- which kernel product families exist,
- what the shared but non-product kernel substrate is,
- which family goes first,
- what the first legal seam is,
- which families are explicitly not first and why,

That condition is now met, and the K7-13 full-kernel residency invariant
(section 9) closes the remaining ambiguity that predecessor K7 spine issues
left open around mixed-mode versus final no-usermode acceptance.
