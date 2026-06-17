# std / no_std / kernel / userspace boundary rules (P1-02) (v0.362)

> TFR-019 authority classification: Historical input. See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

This document is the source-of-truth for the production-depth std / `no_std` /
kernel / userspace boundary rules for tidefs.

It answers the question:

**How does tidefs keep canonical design rule families, shared owned mirrors, live
userspace services, and future Rust-for-Linux leaves in one lawful graph
without letting `std`, kernel wrappers, feature flags, or hidden app-local
helpers leak sovereignty across environments?**

See also:
- `docs/END_TO_END_PRODUCTION_BLUEPRINT.md`
- `docs/WORKSPACE_FAMILY_LAYOUT_CRATE_SERVICE_BOUNDARIES_P1-01.md`
- `docs/LINUX_7_0_BASELINE_CONTRACT_SUPPORTED_SUBSYSTEMS_P0-01.md`
- `docs/PRODUCT_VARIANT_MATRIX_P0-02.md`
- `docs/DOCTRINE_FAMILY_TO_RUST_TYPE_MAP_P2-01.md`
- `docs/BUILD_PACKAGING_FEATURE_MATRIX_P1-04.md`
- `docs/POLICY_AUTHORITY_RUNTIME_SURFACE_P3-01.md`
- `docs/POSIX_FILESYSTEM_ADAPTER_DAEMON_TOPOLOGY_P5-01.md`
- `docs/RUST_FOR_LINUX_CRATE_TRAIT_BOUNDARIES_P7-02.md`
- `docs/KERNEL_PROGRESSION_STAIRCASE_AFTER_USERSPACE_SUCCESS_P11-04.md`
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`

## 1. Core result

The production design now has one explicit family for environment-boundary truth:

- one coordinating family:
  **`family.std_kernel_userspace_boundary.environment_boundary`**
- one topology law:
  **`law.std_no_std_alloc_kernel_userspace_boundary.environment_boundary`**
- one canonical boundary chain:
  - **design rule family / `type_map` row -> workspace family -> boundary domain -> feature profile -> dependency-edge class -> package/stage binding -> gate receipt**

The production design now also fixes:

- **6 stable boundary-domain classes**
- **7 stable feature-profile classes**
- **10 stable dependency-edge classes**
- **8 stable trait / surface-exposure classes**
- **10 required record families**
- **10 required algorithms**

This means tidefs is no longer allowed to say only:

- "we will keep one crate and hide the real split behind feature flags,"
- "portable canonical code can just depend on `std` for convenience,"
- "kernel leaves can import a little userspace runtime logic if it is shared,"
- "service roots can own authoritative planners if they stay small,"
- or "allocating owned mirrors and userspace runtime capsules are basically the
  same layer."

It must instead say:

- which compilation domain a crate or record family belongs to,
- which feature profile is legal for that domain,
- which dependency edges are admitted or refused,
- which types may stay portable `no_std`,
- which owned mirrors may use `alloc` but no OS/kernel substrate,
- which userspace surfaces may depend on Linux/userspace facilities,
- which kernel bridge and leaf surfaces may exist,
- and which receipt proves the environment split is still lawful.

The anti-regression rule is explicit:

**No future Rust code may collapse portable `no_std`, shared `alloc`, userspace
`std`, kernel-bridge, and kernel-leaf personalities into one convenience crate,
one hidden cfg maze, or one service root unless that move is first represented
in the declared `environment_boundary` boundary-domain, feature-profile, dependency-edge, and
trait-exposure records fixed here.**

## 2. Scope and boundaries

This document governs:

- the stable compilation domains used by future tidefs Rust code,
- the legal feature profiles for each domain,
- the binding from `type_map` owner-path families to those domains,
- the legal dependency directions across those domains,
- the rule that userspace service roots remain `std`-only roots and do not
  become canonical type owners,
- the rule that shared kernel-prepared crates stay portable or `alloc`-only
  until they cross the explicit Rust-for-Linux bridge,
- and the binding from those domain rules to `product_variant` variant rows, `package_profile_catalog` package
  profiles, `linux_baseline` host assumptions, and `userspace` / `kernel_gateway` stage ceilings.

That boundary is deliberate.
`P1-02` fixes **where `std`, `no_std`, `alloc`, userspace, and kernel code may
lawfully live and how those domains may depend on one another**.

It now consumes the explicit `workspace_layout` workspace-family / crate-service-boundary law
in `docs/WORKSPACE_FAMILY_LAYOUT_CRATE_SERVICE_BOUNDARIES_P1-01.md`, so crate
roots, service roots, and family edges are no longer allowed to drift from the
declared environment split. It now also consumes the explicit `linux_baseline` Linux 7.0
baseline contract in
`docs/LINUX_7_0_BASELINE_CONTRACT_SUPPORTED_SUBSYSTEMS_P0-01.md`, so
bounded bring-up, kernel-bridge, and kernel-leaf domains are no longer allowed to
smear host assumptions into portable crates. It now also consumes the explicit
`product_variant` product-variant matrix in `docs/PRODUCT_VARIANT_MATRIX_P0-02.md`, so the
declared bring-up-only, mixed-client-kernel, and kernel-self-sufficient
authority rows are no longer allowed to drift from the code-boundary law.
It now also consumes the explicit `type_map` design rule-family to Rust-type map in
`docs/DOCTRINE_FAMILY_TO_RUST_TYPE_MAP_P2-01.md`, the explicit `package_profile_catalog`
build/packaging law in `docs/BUILD_PACKAGING_FEATURE_MATRIX_P1-04.md`, the
explicit `governance_surface_0` authority-service law in
`docs/POLICY_AUTHORITY_RUNTIME_SURFACE_P3-01.md`, the explicit `posix_filesystem_adapter`
daemon/process-topology law in `docs/POSIX_FILESYSTEM_ADAPTER_DAEMON_TOPOLOGY_P5-01.md`, and
the explicit `kernel_boundary` Rust-for-Linux crate/trait boundary law in
`docs/RUST_FOR_LINUX_CRATE_TRAIT_BOUNDARIES_P7-02.md`, so canonical value
types, owned mirrors, service runtimes, and kernel bridges are no longer
allowed to drift into environment-local convenience.

It now also consumes the explicit `vfs_boundary_mirror` UAPI / FFI / canonical-schema boundary law in `docs/UAPI_FFI_CANONICAL_SCHEMA_BOUNDARY_RULES_P1-03.md`, so boundary mirrors, wire layouts, kernel-visible structs, `repr(C)` call frames, and conversion exactness are no longer allowed to drift from the declared design rule families. It now also consumes the explicit `seam_map` shared design rule-native seam-map law in `docs/SHARED_DOCTRINE_NATIVE_SEAM_MAP_P0-03.md`, so seam ownership, client/boundary bindings, kernel-promotion cuts, and anti-leak rules are no longer allowed to drift from the declared cross-system registry. It now also consumes the explicit `non_authority_deletion` non-authority / deletion law in `docs/NON_AUTHORITY_DELETION_LAW_P0-04.md`, so live archived residue, archive-only carriers, tombstone/delete bindings, and non-authority proof are no longer allowed to drift from the declared product boundary. They may **not** invent a second
environment split, a second feature-gate law, or a second userspace/kernel
boundary outside `environment_boundary`.

## 3. Repo anchor snapshot

The production law is grounded in real repo surfaces rather than pure future
prose:

  semantics, OS/runtime glue, and entry surfaces are materially different
  families rather than one ambient codebase.
  need `std`-class process / file / socket / signal / CLI surfaces instead of
  pretending to be portable core crates.
- `docs/WORKSPACE_FAMILY_LAYOUT_CRATE_SERVICE_BOUNDARIES_P1-01.md` already
  fixed the `crates/` / `apps/` / `xtask/` / `kmod/` top-level split and the 12
  workspace families; `P1-02` turns that workspace law into an explicit
  environment-boundary law.
- `docs/RUST_FOR_LINUX_CRATE_TRAIT_BOUNDARIES_P7-02.md` already fixed the
  kernel-side `s0 -> s1 -> s2 -> s3` stratum split. `P1-02` now binds that
  kernel-specific refinement back to the repo-wide `no_std` / `alloc` /
  userspace / kernel domains.
- `docs/PRODUCT_VARIANT_MATRIX_P0-02.md` and
  `docs/BUILD_PACKAGING_FEATURE_MATRIX_P1-04.md` already prove that bounded
  bring-up rows, mixed-client-kernel rows, and kernel-self-sufficient authority
  rows are real product rows, not future implementation promises. That is enough to
  prove the code-boundary law must be explicit before implementation starts.

## 4. Metrics snapshot

| Metric | Count |
|---|---:|
| Stable boundary-domain classes | 6 |
| Stable feature-profile classes | 7 |
| Stable dependency-edge classes | 10 |
| Stable trait / surface-exposure classes | 8 |
| Required record families | 10 |
| Required algorithms | 10 |

## 5. Boundary-domain law

### 5.1 Stable boundary-domain classes

The future Rust tree must use exactly these environment domains:

| Boundary domain | Meaning | Typical allowed substrate |
|---|---|---|
| `domain.environment_boundary.core_nostd.d0` | portable canonical `no_std` core | `core` only |
| `domain.environment_boundary.shared_alloc.d1` | portable owned mirrors / builders / collections / render buffers | `core` + `alloc`, no `std`, no kernel APIs |
| `domain.environment_boundary.userspace_std.d2` | live userspace libraries and runtimes | `std` plus admitted Linux/userspace substrate under `linux_baseline` |
| `domain.environment_boundary.kernel_bridge.d3` | shared Rust-for-Linux bridge / facade crates | Rust-for-Linux wrappers plus admitted `d0` / `d1` mirrors |
| `domain.environment_boundary.kernel_leaf.d4` | leaf kernel client or optional later selected-domain authority crates | Rust-for-Linux leaf implementations plus admitted `d0` / `d1` / `d3` |
| `domain.environment_boundary.test_xtask_std.d5` | non-shipping test, fuzz, perf, and `xtask` roots | `std` plus tool/harness substrate |

### 5.2 Domain invariants

The domain law is strict:

- `d0` may not allocate, open files, spawn tasks, hold OS handles, or wrap
  kernel objects.
- `d1` may allocate owned mirrors, builders, collection wrappers, and render
  buffers, but it may not import `std`, files, sockets, threads, `Arc`, kernel
  wrappers, or process state.
- `d2` is the only lawful domain for public userspace service roots, runtime
  reactors, process managers, mount/export carriers, operator CLIs, and archive
  readers.
- `d3` is the only lawful shared Rust-for-Linux bridge domain. It may wrap
  kernel objects and expose kernel-safe facade traits, but it may not become a
  second userspace runtime or a leaf charter implementation.
- `d4` is the only lawful kernel-leaf domain. It may implement admitted
  `posix_filesystem_adapter`, `block_volume_adapter`, or optional later selected-domain `policy_authority` leaves, but it may not
  depend on `d2` crates or userspace service roots.
- `d5` is non-shipping. It may depend on admitted shipping crates for proof
  work, but no shipping crate may depend back on `d5`.

## 6. Feature-profile and family-placement law

### 6.1 Stable feature-profile classes

| Feature profile | Primary domain | Meaning |
|---|---|---|
| `profile.environment_boundary.core_portable.p0` | `d0` | pure `#![no_std]` canonical core |
| `profile.environment_boundary.alloc_portable.p1` | `d1` | `#![no_std]` + `alloc` owned mirrors / builders / collection helpers |
| `profile.environment_boundary.userspace_library.p2` | `d2` | `std` userspace library/runtime crate |
| `profile.environment_boundary.userspace_service_root.p3` | `d2` | bounded mirror / CLI / tool root under `apps/` |
| `profile.environment_boundary.kernel_bridge.p4` | `d3` | shared Rust-for-Linux bridge/facade crate |
| `profile.environment_boundary.kernel_leaf.p5` | `d4` | leaf `posix_filesystem_adapter` / `block_volume_adapter` / optional later `policy_authority` kernel crate |
| `profile.environment_boundary.test_xtask.p6` | `d5` | non-shipping test/harness/`xtask` root |

### 6.2 Workspace-family placement rules

The default family-to-domain law is now fixed:

| Workspace family or root | Default admitted profiles | Must not host |
|---|---|---|
| `family.workspace_layout.types.f0` | `p0`, `p1` | `std` runtime state, kernel wrappers, service mains |
| `family.workspace_layout.schema_codec.f1` | `p0`, `p1` | `std` runtime state, kernel wrappers, app roots |
| `family.workspace_layout.policy_authority.f2` / `authority_publication.f3` / `claim_reserve_witness.f4` / `response_normalizer.f5` core crates | `p0`, `p1` | userspace reactor/task ownership, kernel leaf logic |
| `family.workspace_layout.policy_authority.f2` / `posix_filesystem_adapter.f6` / `block_volume_adapter.f7` / `control_plane.f8` / `explanation_query.f9` runtime/client crates | `p2` | kernel wrappers, app-local canonical structs |
| `apps/tidefs-policy-authority-daemon`, `apps/tidefs-posix-filesystem-adapter-daemon`, bounded mirror roots, `apps/tidefsctl`, and query/observe tools | `p3` | canonical `type_map` row ownership, portable core logic |
| `family.workspace_layout.observe.f10` | `p1`, `p2` | sovereign mutation truth, kernel leaf logic |
| `family.workspace_layout.test.f11` and `xtask/` roots | `p6` | shipping runtime ownership |
| `kmod/tidefs_common_types` and other shared kernel bridge crates | `p4` | userspace service roots, leaf-only charter logic |
| leaf `kmod/posix_filesystem_adapter`, `kmod/block_volume_adapter`, optional later `kmod/policy_authority` crates | `p5` | userspace imports, operator CLI logic |

### 6.3 `type_map` owner-path placement rule

The mapping from `type_map` owner-path families to `environment_boundary` domains is now fixed:

| `type_map` owner-path family | Default `environment_boundary` home |
|---|---|
| `path.type_map.ids.p0` and `path.type_map.scalars.p1` | `d0` |
| most `path.type_map.enums.p2` rows | `d0`; use `d1` only when owned heap payloads are unavoidable |
| borrowed `binary_schema` decode views and small canonical records | `d0` |
| owned mirrors, builders, collection wrappers, and render payload helpers | `d1` |
| userspace runtime capsules, process handles, async/queue state, and service caches | `d2` |
| kernel bridge facades and wrapper contracts | `d3` |
| leaf kernel state that owns charter-visible kernel objects | `d4` |

The anti-regression rule is explicit:

**A `type_map` row may move across crates only by preserving the declared `environment_boundary`
domain class. A service root, kernel leaf, or test harness may consume a row,
but it may not become the row's canonical owner unless the domain map changes
first.**

## 7. Dependency-edge and exposure law

### 7.1 Stable dependency-edge classes

| Edge class | Source -> target | Status | Meaning |
|---|---|---|---|
| `edge.environment_boundary.core_to_core.e0` | `d0 -> d0` | allowed | portable canonical crates may depend only on other portable canonical crates |
| `edge.environment_boundary.alloc_to_core.e1` | `d1 -> d0` | allowed | owned-mirror crates may depend on portable core crates |
| `edge.environment_boundary.userspace_to_core_alloc.e2` | `d2 -> d0/d1` | allowed | userspace runtimes consume portable core and owned mirrors |
| `edge.environment_boundary.service_root_to_userspace_libs.e3` | `p3 -> p2/p1/p0` | allowed | public binaries wire userspace libraries but do not own canonical truth |
| `edge.environment_boundary.kernel_bridge_to_core_alloc.e4` | `d3 -> d0/d1` | allowed | kernel bridge crates consume portable core and owned mirrors only |
| `edge.environment_boundary.kernel_leaf_to_bridge_core_alloc.e5` | `d4 -> d3/d1/d0` | allowed | leaf kmods may consume bridge facades plus portable shared payloads |
| `edge.environment_boundary.test_to_shipping.e6` | `d5 -> d0/d1/d2/d3/d4` | allowed one-way | harnesses may exercise shipping crates without becoming dependencies |
| `edge.environment_boundary.core_to_userspace_forbidden.e7` | `d0/d1 -> d2` | forbidden | portable crates may not import userspace runtime/process/filesystem state |
| `edge.environment_boundary.core_to_kernel_forbidden.e8` | `d0/d1 -> d3/d4` | forbidden | portable crates may not import Rust-for-Linux wrappers or leaf logic |
| `edge.environment_boundary.kernel_to_userspace_forbidden.e9` | `d3/d4 -> d2` | forbidden | kernel bridge/leaves may not import userspace services or runtimes |

### 7.2 Stable trait / surface-exposure classes

The public trait and type-exposure classes are now fixed:

| Exposure class | Legal homes | Meaning |
|---|---|---|
| `exposure.environment_boundary.value_core.x0` | `d0` | ids, digests, enums, tiny value traits |
| `exposure.environment_boundary.binary_schema.x1` | `d0`, `d1` | encode/decode/schema contracts without OS/kernel handles |
| `exposure.environment_boundary.view_builder.x2` | `d0`, `d1` | borrowed views and owned builders |
| `exposure.environment_boundary.authority_planner.x3` | `d0`, `d1` | deterministic planner/evaluator traits |
| `exposure.environment_boundary.userspace_client_runtime.x4` | `d2` | client/request/runtime traits that may use `std` |
| `exposure.environment_boundary.kernel_facade.x6` | `d3` | Rust-for-Linux wrapper/facade traits |
| `exposure.environment_boundary.test_only.x7` | `d5` | harness-only traits and helpers |

### 7.3 Exposure invariants

The exposure law is strict:

- canonical cross-domain APIs may not expose `std` process/file/socket types,
  kernel object wrappers, or test-only helper types as shared portable truth;
- one Cargo package may not offer both a userspace service-root personality and
  a kernel-leaf personality behind feature flags;
- userspace service roots may depend on canonical crates, but they may not own
  canonical records, `type_map` rows, or deterministic planners;
- kernel bridge crates may wrap Linux objects, but those wrapper types may not
  leak back into `d0`/`d1` portable APIs;
- and test/`xtask` crates may orchestrate shipping crates, but they may not
  publish shipping trait surfaces.

## 8. Variant, package, and stage binding law

The environment-boundary law is now tied explicitly to the product matrix:

- `profile.package_profile_catalog.release_userspace.p3` may ship only `d0`, `d1`, and `d2`
  closures; it may not require `d3` or `d4`.
- `profile.package_profile_catalog.release_mixed_client_kernel.p4` may ship the same userspace
  closure plus admitted `d3` / `d4` client leaves for `posix_filesystem_adapter` and `block_volume_adapter`, but
  userspace `policy_authority` remains sovereign.
- `profile.package_profile_catalog.release_kernel_authority.p5` may add `d4` selected-domain `policy_authority`
  authority leaves only after the declared `kernel_gateway` stages admit that move.
- `profile.package_profile_catalog.archive_nonlive.p6` remains non-live packaging and does not
  authorize a hidden userspace or kernel product row outside the declared
  `product_variant` matrix.
- `linux_baseline` host-subsystem assumptions apply only once code crosses into `d2`,
  `d3`, or `d4`; they do not widen the portable meaning of `d0` or `d1`.

## 9. Required record families

| Record family | Purpose |
|---|---|
| `StdBoundaryDomainRecord` | declares each `environment_boundary` boundary domain and its substrate law |
| `StdBoundaryFeatureProfileRecord` | declares each legal profile and its required cfg/features |
| `StdBoundaryFamilyPlacementRecord` | binds workspace families or roots to admitted `environment_boundary` profiles |
| `StdBoundaryTypeMapPlacementRecord` | binds `type_map` owner-path families and rows to `environment_boundary` domains |
| `StdBoundaryDependencyEdgeRecord` | declares allowed boundary edges |
| `StdBoundaryForbiddenEdgeRecord` | declares explicit forbidden imports / leak classes |
| `StdBoundaryTraitExposureRecord` | declares which trait/type exposure class a crate may publish |
| `StdBoundaryCfgContractRecord` | records cfg / feature rules and forbidden personality collapse |
| `StdBoundaryVariantBindingRecord` | binds `product_variant` rows and `package_profile_catalog` bundles to required `environment_boundary` closures |
| `StdBoundaryGateReceipt` | proves the crate/kmod graph still satisfies `environment_boundary` |

## 10. Required algorithms

| Algorithm | Purpose |
|---|---|
| `declare_environment_boundary_boundary_domains_and_profiles()` | declare the stable environment domains and feature profiles |
| `assign_workspace_family_or_root_to_environment_boundary_profile()` | bind workspace families, service roots, or kmod roots to legal profiles |
| `bind_type_map_owner_path_rows_to_environment_boundary_domains()` | bind design rule/type-map rows to portable, alloc, userspace, or kernel homes |
| `compile_environment_boundary_dependency_edges_and_forbidden_imports()` | produce the admitted and forbidden environment-edge graph |
| `lift_portable_rows_into_userspace_or_kernel_wrapper_surfaces()` | wrap portable rows lawfully without changing canonical ownership |
| `bind_product_variant_variant_and_package_profile_catalog_bundle_to_required_environment_boundary_closure()` | join product/package rows to their required code-boundary closure |
| `scan_workspace_and_kmod_graph_for_environment_boundary_violations()` | scan the graph for forbidden imports, feature collapses, or root misuse |
| `issue_environment_boundary_gate_receipt_or_stop_ticket()` | emit the gate receipt or refusal for the proposed environment graph |

## 11. Implementation consequences

The consequences for implementation are immediate:

- future `tidefs-types-*`, `tidefs-schema_codec-*`, and deterministic `policy_authority`/`authority_publication`/`claim_reserve_witness`
  /`response_normalizer` core crates must be designed to compile as `d0` or `d1` first,
- bounded userspace mirrors, CLIs, mount helpers, queue runtimes, and observe exporters
  belong in `d2` service/library profiles and may not drag `std` back into the
  portable core,
- `kmod/tidefs_common_types` and any shared Rust-for-Linux facade crates belong
  in `d3`,
- leaf kmods belong in `d4`,
- and any attempt to publish one multi-personality crate that can be both a
  userspace runtime and a kernel leaf is now explicitly unlawful.

This document fixes the policy classes that later refinement, review, planning, and implementation must preserve, and those later activities must now consume the explicit `seam_map` seam-map law together with the explicit `vfs_boundary_mirror` UAPI / FFI / canonical-schema boundary law.

## 12. Closeout

`P1-02` is now closed at production depth:

- the repo has one explicit std / `no_std` / `alloc` / userspace / kernel
  boundary law,
- workspace placement, type-map ownership, package profiles, and variant rows
  now consume the same `environment_boundary` grammar,
- and no tracked production-design work remains below `L3`; later refinement, review, planning, and implementation must now consume the explicit `seam_map` seam-map law together with the explicit `vfs_boundary_mirror` boundary law.
