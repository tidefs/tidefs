# Rust-for-Linux crate and trait boundaries (P7-02) (v0.338)

This document is the production-depth source-of-truth for **P7-02**.

It answers one concrete question:

**How are future Rust-for-Linux kernel paths split into `no_std`, `alloc`, shared kernel-bridge, and leaf-module crates so that Linux integration stays fast without letting kernel types, convenience imports, or hidden authority leak across the canonical seam?**

See also:
- `docs/END_TO_END_PRODUCTION_BLUEPRINT.md`
- `docs/KERNEL_MODULE_FAMILY_MATRIX_ROLLOUT_ORDER_P7-01.md`
- `docs/KERNEL_LOCKING_RCU_PINNING_WORKQUEUE_MODEL_P7-03.md`
- `docs/VFS_BLOCK_INTEGRATION_KERNEL_UAPI_LAW_P7-04.md`
- `docs/KERNEL_MODULE_DEVELOPMENT_WORKFLOW_P7-05.md`
- `docs/CANONICAL_BINARY_ENCODE_DECODE_ENDIAN_CHECKSUM_LAW_P2-03.md`
- `docs/FORMAT_IDENTITY_UPGRADE_REPLAY_CONTINUITY_LAW_P2-04.md`
- `docs/CHECKPOINT_SNAPSHOT_REPLAY_CURSOR_PERSISTENCE_LAW_P2-05.md`
- `docs/SECRETS_POLICY_STORAGE_KEY_HANDLING_LAW_P9-04.md`
- `docs/PERFORMANCE_BUDGETS_SLO_REGRESSION_GATES_P10-03.md`
- `docs/DASHBOARDS_TRACES_OPERATOR_TRUTH_SURFACES_P10-04.md`

## Metrics snapshot

| Metric | Count |
|---|---:|
| Canonical crate strata | 4 |
| Fixed kernel-related crate families | 10 |
| Fixed trait families | 10 |
| Forbidden dependency edges | 10 |
| New schema families introduced here | 10 |
| New algorithm families introduced here | 10 |

## 1. Outcome

The Rust-for-Linux crate and trait law is now explicit.

The production design now has:

- one coordinating family: **`family.kernel_crate_boundary.kernel_boundary`**
- four fixed strata:
  - **`stratum.kernel_boundary.core.no_std.s0`**
  - **`stratum.kernel_boundary.bridge.alloc.s1`**
  - **`stratum.kernel_boundary.kernel.bridge.s2`**
  - **`stratum.kernel_boundary.kernel.leaf.s3`**
- ten fixed kernel-related crate families:
  - **`crate.kernel_boundary.core.ids_digest.c0`**
  - **`crate.kernel_boundary.core.binary_schema_feature_window.c1`**
  - **`crate.kernel_boundary.core.schema_codec_canonical_schema.c2`**
  - **`crate.kernel_boundary.alloc.mirror.c3`**
  - **`crate.kernel_boundary.alloc.render.c4`**
  - **`crate.kernel_boundary.alloc.observe.c5`**
  - **`crate.kernel_boundary.kernel.bridge.c6`**
  - **`crate.kernel_boundary.kernel.posix_filesystem_adapter.c7`**
  - **`crate.kernel_boundary.kernel.block_volume_adapter.c8`**
  - **`crate.kernel_boundary.kernel.policy_authority.c9`**
- one fixed dependency direction:
  - **`s0 -> s1 -> s2 -> s3`**
- one fixed packaging rule:
  - **`*-core`** means canonical `no_std`
  - **`*-alloc`** means owned mirror / render / observe helpers that may use `alloc` but still may not touch kernel APIs
  - **`kmod/tidefs_common_types`** is the only shared Rust-for-Linux abstraction bridge
  - **`kmod/tidefs_posix_filesystem_adapter`**, **`kmod/tidefs_block_volume_adapter`**, and optional later **`kmod/tidefs_policy_authority`** are leaf-only module families

The decisive anti-regression rule is now explicit:

**Linux types stop at `s2`, canonical authority truth stops before `s2`, and no product kmod may import another leaf kmod or a userspace control-plane implementation crate merely because it was convenient.**

That means tidefs is no longer allowed to say only:

- “we will sort out core vs kernel crates once the first kmod exists,”
- “the shared bridge can absorb whatever helpers the leafs need,”
- or “trait placement will emerge from implementation.”

It must instead say:

- which stratum a new type or trait belongs to,
- which existing workspace family owns the subcrate that defines it,
- which stratum is allowed to implement it,
- which data shape may cross the boundary,
- which dependency edges are forbidden even if Rust would compile them,
- and which gate must fail if a proposed helper would smuggle sovereignty into the kernel leaf graph.

## 2. Scope and boundaries

This document settles:

- the exact `no_std` / `alloc` / Rust-for-Linux / leaf split,
- the fixed kernel-related crate-family inventory,
- the direction of allowed dependency edges,
- the trait-family ownership map,
- the placement rule for Linux object wrappers,
- and the fixed anti-sprawl law for future `posix_filesystem_adapter`, `block_volume_adapter`, and optional `policy_authority` kmods.

This document now consumes the exact build / packaging / feature matrix that materializes these crate families in shipped artifacts in `docs/BUILD_PACKAGING_FEATURE_MATRIX_P1-04.md`.
The Linux 7.0 kernel-module development workflow is fixed in
`docs/KERNEL_MODULE_DEVELOPMENT_WORKFLOW_P7-05.md`: these crate and trait
boundaries must build through a prepared-kernel out-of-tree hot loop before
they are admitted through the broader Nix/QEMU acceptance target.

That boundary is deliberate.
`P7-02` fixes where code and traits are allowed to live.

## 3. The four-stratum law

### 3.1 `stratum.kernel_boundary.core.no_std.s0`

This is the canonical borrowed-view stratum.

It owns:

- stable identifiers, digests, enums, and class tags,
- `binary_schema` envelope and section grammar,
- `feature_window` format / continuity / fingerprint checks,
- borrowed `schema_codec` / `canonical_schema` receipt, checkpoint, snapshot, and replay-cursor views,
- stable request names, receipt kinds, bucket kinds, and gate-class enums,
- and value-only helper logic that must compile for both userspace and future kernel consumers.

It may **not** own:

- heap allocation,
- Rust-for-Linux types,
- Linux `inode` / `dentry` / `file` / `folio` / `bio` / `request_queue` wrappers,
- transport carriers,
- policy publication logic,
- secret lease brokerage,
- checkpoint or snapshot write pipelines,
- or dashboard / tracing UI logic.

`S0` therefore produces only:

- value types,
- borrowed decoded views,
- continuity verdicts,
- digest / fingerprint results,
- and stable enum-class render plans.

### 3.2 `stratum.kernel_boundary.bridge.alloc.s1`

This is the owned bridge / mirror / render / observe stratum.

It owns:

- owned mirror payloads derived from borrowed canonical views,
- redacted diagnostic summaries,
- render plans for Linux errno / flag / ioctl / queue-limit projection,
- authority-client request objects and response carriers that are still transport-agnostic,
- and read-only secret-handle / lease-view payloads that contain handles, epochs, digests, and capability classes but never long-lived plaintext.

It may use `alloc`, but it may **not** own:

- Rust-for-Linux types,
- live Linux object references,
- actual carrier / socket / ring / char-device wiring,
- authoritative policy publication,
- authoritative secret storage,
- or hidden caches that change legal truth.

`S1` is allowed to shape data so that `s2` can bind it to kernel mechanics, but it is not allowed to become a second sovereignty center.

### 3.3 `stratum.kernel_boundary.kernel.bridge.s2`

This is the only shared Rust-for-Linux abstraction bridge.

It maps `s0` and `s1` artifacts onto kernel mechanics such as:

- Rust-for-Linux object wrappers,
- lock / RCU / pin / workqueue wrappers already governed by `P7-03`,
- `super_block`, `dentry`, `inode`, `file`, folio, page-window, `bio`, `request`, and keyring-residency facades,
- and carrier-bound implementations of transport-agnostic traits from `s1`.

It may **not** own:

- `binary_schema` or `feature_window` parsing logic,
- policy evaluation,
- runbook execution,
- secret-envelope storage,
- checkpoint/snapshot writer authority,
- dashboard truth surfaces,
- or leaf-specific behavior that belongs only to `posix_filesystem_adapter`, `block_volume_adapter`, or optional `policy_authority`.

The entire point of `s2` is containment:

**all Linux and Rust-for-Linux type pressure stops here, and all cross-family shared kernel mechanics stop here.**

### 3.4 `stratum.kernel_boundary.kernel.leaf.s3`

This is the leaf-module stratum.

It contains only:

- `posix_filesystem_adapter` VFS-facing leaf behavior,
- `block_volume_adapter` block-facing leaf behavior,
- and optional later selected-domain `policy_authority` leaf behavior.

Each leaf may consume only the crate families and trait contracts declared for it.

A leaf may **not**:

- import another leaf,
- import userspace `control_plane` or `explanation_query` implementation crates,
- import secret-envelope or policy-store internals,
- import authoritative checkpoint/snapshot write code,

## 4. Fixed crate-family map

The kernel-related crate-family inventory is now fixed as follows.

| ID | Crate family | Stratum | Owned by existing workspace family or path | Naming / path rule | Legal contents | Forbidden contents |
|---|---|---|---|---|---|---|
| `c0` | `crate.kernel_boundary.core.ids_digest.c0` | `s0` | `crates/tidefs-types-*` | `*-core` | ids, epochs, leases, digest wrappers, fence and bucket enums | alloc, kernel APIs, transport code |
| `c1` | `crate.kernel_boundary.core.binary_schema_feature_window.c1` | `s0` | `crates/tidefs-schema_codec-*` shared schema subcrates | `*-core` | `binary_schema` envelopes, section headers, `feature_window` continuity windows, borrowed decode helpers | owned buffers, Linux render structs, transport carriers |
| `c2` | `crate.kernel_boundary.core.schema_codec_canonical_schema.c2` | `s0` | selected shared-core subcrates under `crates/tidefs-schema_codec-*` and authority-anchor helpers | `*-core` | response-envelope classes, receipt families, checkpoint/snapshot/cursor borrowed views, anchor digests | write pipelines, policy logic, kernel object wrappers |
| `c3` | `crate.kernel_boundary.alloc.mirror.c3` | `s1` | shared mirror helpers under existing `tidefs-policy_authority-*`, `tidefs-posix_filesystem_adapter-*`, and `tidefs-block_volume_adapter-*` families | `*-alloc` | owned mirror payloads, request objects, borrowed->owned lifts, read-only anchor/lease snapshots | Rust-for-Linux types, transport carriers, policy writers |
| `c4` | `crate.kernel_boundary.alloc.render.c4` | `s1` | shared render helpers under existing `tidefs-response_normalizer-*`, `tidefs-posix_filesystem_adapter-*`, and `tidefs-block_volume_adapter-*` families | `*-alloc` | errno/flag/ioctl/queue-limit render plans, cut-matrix outputs, stable field masks | raw Linux wrapper objects, ad hoc local errno folklore |
| `c6` | `crate.kernel_boundary.kernel.bridge.c6` | `s2` | `kmod/tidefs_common_types` | fixed shared path | Linux/Rust-for-Linux facades, trait implementations that touch kernel objects, lock/pin/workqueue glue | canonical parse logic, leaf-specific policy, cross-leaf business logic |
| `c7` | `crate.kernel_boundary.kernel.posix_filesystem_adapter.c7` | `s3` | `kmod/tidefs_posix_filesystem_adapter` | fixed leaf path | VFS/posix_filesystem_adapter leaf behavior, first-seam namespace clean-read glue, page-window leaf logic | `block_volume_adapter` imports, `policy_authority` authority imports, policy storage |
| `c8` | `crate.kernel_boundary.kernel.block_volume_adapter.c8` | `s3` | `kmod/tidefs_block_volume_adapter` | fixed leaf path | block/block_volume_adapter leaf behavior, queue/bio glue, fixed-capacity export seam logic | `posix_filesystem_adapter` imports, `policy_authority` imports, checkpoint writer authority |
| `c9` | `crate.kernel_boundary.kernel.policy_authority.c9` | `s3` | `kmod/tidefs_policy_authority` | fixed leaf path | optional later selected-domain `policy_authority` host behavior, capability mirrors, authority-host leaf logic only after admission | `posix_filesystem_adapter`/`block_volume_adapter` leaf reuse, `control_plane` server topology imports, secret-envelope storage |

One clarification is now fixed:

- `control_plane`, `explanation_query`, and dashboard/operator-truth products stay **userspace** implementation families.
- Kernel code may consume only transport-agnostic, handle-safe, render-safe traits exported from `s1` and implemented by `s2` / `s3`.
- The public/userspace carrier choice is now explicit in `docs/CONTROL_PLANE_SERVICE_API_CLI_TOPOLOGY_P9-01.md`; this document still fixes the trait seam rather than widening payloads or moving ownership across strata.

## 5. Fixed trait-family ownership map

The trait-family inventory is now fixed as follows.

| Trait family | Owning crate family | Legal implementors | Purpose | Must not cross |
|---|---|---|---|---|
| `trait.kernel_boundary.borrow_decode.t0` | `c1` / `c2` | `c0` / `c1` / `c2` | borrowed decode and continuity checks for `binary_schema`, `feature_window`, `schema_codec`, and `canonical_schema` artifacts | no alloc types, no Linux objects |
| `trait.kernel_boundary.anchor_cursor_view.t1` | `c2` | `c2` / `c3` | typed access to checkpoint, snapshot, and replay-cursor frontiers | no transport carriers, no writer authority |
| `trait.kernel_boundary.mirror_lift.t2` | `c3` | `c3` | convert borrowed canonical views into owned mirror payloads | no Rust-for-Linux wrappers |
| `trait.kernel_boundary.authority_client.t3` | `c3` | `c6` | carrier-agnostic request/receipt/response exchange with userspace authority surfaces | no netlink/ring/socket details outside `c6`; no policy logic |
| `trait.kernel_boundary.response_render.t4` | `c4` | `c4`, consumed by `c7` / `c8` through `c6` facades | canonical response -> Linux render plan for errno, flags, queue limits, ioctl fields | no local errno dialect, no hidden Linux-only semantic tables |
| `trait.kernel_boundary.pin_drain.t6` | `c6` | `c6` / `c7` / `c8` / `c9` | shared pin/fence/drain operations under `P7-03` and `P4-04` | no leaf-local reserve or authority shortcuts |
| `trait.kernel_boundary.bio_queue.t8` | `c6` | `c8` | request/bio queue, barrier, and completion helpers for `block_volume_adapter` leaf paths | no VFS logic, no checkpoint writer authority |
| `trait.kernel_boundary.secret_lease_view.t9` | `c6` | `c6`, later `c9` and read-only consumers in `c7` / `c8` as admitted | read-only handle / lease / capability / keyring-residency views under `secret_key_policy_0` | no plaintext secret storage, no lease issuance authority |

A crucial boundary is now explicit:

**`trait.kernel_boundary.authority_client.t3` and `trait.kernel_boundary.secret_lease_view.t9` fix the typed seam, not the carrier.**
The exact trait owner and stratum remain fixed here even though `P9-01` now chooses the concrete userspace carrier family. `control_plane` is bound to public `c0`/`c1` carriers and internal `c2` RPC stubs, but those choices may not move the trait family to a different stratum or widen the payloads beyond the handle-safe, canonical shapes fixed here.

## 6. Dependency DAG and forbidden edges

### 6.1 Allowed dependency direction

The dependency graph is now fixed:

- `s0` may depend only on `s0`
- `s1` may depend only on `s0` and `s1`
- `s2` may depend only on `s0`, `s1`, and `s2`
- each `s3` leaf may depend only on `s0`, `s1`, `s2`, and itself

No reverse edge is lawful.
No side edge between leaves is lawful.

### 6.2 Forbidden dependency edges

The following forbidden edges are now first-class law:

1. **`s0 -> s1` or any `s0 -> s2/s3` edge is forbidden.**
2. **`s1 -> s2` or any `s1 -> s3` edge is forbidden.**
3. **`c6 -> c7/c8/c9` is forbidden** so the shared bridge never becomes leaf-specific by drift.
4. **`c7 -> c8` is forbidden.**
5. **`c7 -> c9` is forbidden.**
6. **`c8 -> c7` is forbidden.**
7. **`c8 -> c9` is forbidden.**
8. **`c9 -> c7` or `c9 -> c8` is forbidden.**
9. **any leaf -> userspace `control_plane` / `explanation_query` implementation crate edge is forbidden**; only `t3` / `t9` carrier implementations in `c6` are lawful.
10. **any edge that lets `c0` / `c1` / `c2` change semantic layout, enum numbering, or continuity rules via feature flags is forbidden.**

Two more anti-regression consequences follow automatically:

- no leaf may import secret-envelope storage, wrapping-key lineage, or policy-store persistence internals,
- and no leaf may import authoritative checkpoint/snapshot writer code.

If a future helper needs those things, the design answer is not “just add an import.”
The design answer is “the helper is in the wrong stratum or the kernel family is trying to own the wrong truth.”

## 7. Family-specific leaf maps

### 7.1 `kmod.posix_filesystem_adapter.vfs.k0` — continuity: POSIX Filesystem Adapter (`posix_filesystem_adapter`)

`posix_filesystem_adapter` leaf work is fixed to:

- allowed crate families: `c0`, `c1`, `c2`, `c3`, `c4`, `c5`, `c6`, `c7`
- required trait families for the first seam:
  - `t0` borrowed decode
  - `t1` anchor/cursor view
  - `t2` mirror lift
  - `t3` authority client
  - `t4` response render
  - `t6` pin / drain
  - `t7` page window
- forbidden imports:
  - `c8`, `c9`
  - userspace `control_plane`/`explanation_query` implementation crates
  - secret-envelope storage and policy activation internals

The first seam `seam.kernel_module_0.posix_filesystem_adapter.namespace_cleanread.s0` is therefore forced to stay narrow:

- namespace and clean-read acceleration may live in `c7`,
- but any mutation, policy-bearing request, or wider authority move falls back through `t3` to the userspace authority surfaces already required by `P7-01`.

### 7.2 `kmod.block_volume_adapter.block.k0` — continuity: Block Volume Adapter (`block_volume_adapter`)

`block_volume_adapter` leaf work is fixed to:

- allowed crate families: `c0`, `c1`, `c2`, `c3`, `c4`, `c5`, `c6`, `c8`
- required trait families:
  - `t0` borrowed decode
  - `t1` anchor/cursor view
  - `t2` mirror lift
  - `t3` authority client
  - `t4` response render
  - `t6` pin / drain
  - `t8` bio queue
- forbidden imports:
  - `c7`, `c9`
  - checkpoint/snapshot writer internals
  - any queue-local durability dialect not backed by `c0` / `c1` / `c2` canon

`BlockVolumeAdapter` therefore stays a client leaf even when it gains kernel queue mechanics.
It may optimize queue and completion flow, but it may not move replay, resize-policy, or failover sovereignty into the leaf module.

### 7.3 `kmod.policy_authority.host.k0` — continuity: Policy Authority (`policy_authority`)

Optional later `policy_authority` leaf work is fixed to:

- allowed crate families: `c0`, `c1`, `c2`, `c3`, `c5`, `c6`, `c9`
- permitted trait families only after `P11-04` admission gates:
  - `t0` borrowed decode
  - `t1` anchor/cursor view
  - `t2` mirror lift
  - `t6` pin / drain
  - `t9` secret lease view
- forbidden imports:
  - `c7`, `c8`
  - userspace `control_plane` server topology crates
  - secret-envelope or wrapping-key persistence
  - dashboard / truth-surface product code

This keeps `policy_authority` kernel-hosting optional, selected-domain, and late.
The crate split may prepare for it, but the split does **not** license early authority migration.

## 8. Boundary with remaining unresolved production items

This document closes `P7-02` and now consumes the explicit `P1-04` build / packaging / feature matrix in `docs/BUILD_PACKAGING_FEATURE_MATRIX_P1-04.md`.

The boundary is deliberate:

- `P7-02` fixes where future kernel code and traits may live,
- `P11-04` is now explicit in `docs/KERNEL_PROGRESSION_STAIRCASE_AFTER_USERSPACE_SUCCESS_P11-04.md` and decides when each leaf crate family is allowed to become live,
- `P9-01` is now explicit in `docs/CONTROL_PLANE_SERVICE_API_CLI_TOPOLOGY_P9-01.md`, so userspace carrier choice is fixed to public `c0`/`c1` and internal `c2` without changing these trait ceilings,

## 9. Records required by this law

The central data-structures map now requires:

- `KernelCrateStratumRecord`
- `KernelCrateFamilyRecord`
- `KernelTraitContractRecord`
- `KernelTraitImplementationRecord`
- `KernelDependencyEdgeRecord`
- `KernelMirrorPayloadContractRecord`
- `KernelLinuxFacadeRecord`
- `KernelBridgeCapabilityRecord`
- `KernelLeafSeamAdapterRecord`
- `KernelBoundaryGateRecord`

## 10. Algorithms required by this law

The central algorithm map now requires:

- `declare_kernel_crate_strata_and_family_map()`
- `assign_owner_crate_for_trait_family()`
- `compile_kernel_dependency_dag_and_forbidden_edges()`
- `lift_borrowed_views_into_owned_kernel_mirror_payloads()`
- `bind_authority_client_trait_to_transport_stub_without_topology_leak()`
- `wrap_linux_objects_behind_bridge_facades_and_sleepability_rules()`
- `compile_leaf_seam_adapter_from_allowed_crates_traits_and_fallbacks()`
- `scan_for_sovereignty_leaks_or_cross_leaf_dependencies()`
- `issue_kernel_boundary_gate_or_stop_ticket()`

## 11. Acceptance effect on the design pack

With this law settled:

- `P7-02` becomes detailed enough for later implementation planning,
- future kernel work is no longer allowed to smear `no_std` canon, owned mirrors, Rust-for-Linux wrappers, and leaf behavior into one convenience graph,
- `kmod.common.bridge.k0` no longer has room to become a hidden sovereignty center,
- the `posix_filesystem_adapter` first seam from `P7-01` is now backed by a fixed crate-and-trait subset rather than a vague “kernel helpers later” promise,
- and the next unresolved production items are no longer crate-placement ambiguity but the later distributed/runtime detail that must consume the fixed `kernel_boundary`, `package_profile_catalog`, `shadow_pilot_0`, and `archive_control` laws.
