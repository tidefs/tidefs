# workspace family layout / crate-service boundaries (P1-01) (v0.362)

This document is the source-of-truth for the production-depth Rust workspace
family layout and crate/service boundaries for tidefs.

It answers the question:

**How does tidefs turn the now-explicit design rule families, runtime laws,
package bundles, and future kernel boundaries into one lawful Rust workspace
graph without letting ad hoc crate roots, helper crates, service mains, or
test harnesses become hidden sovereignty?**

See also:
- `docs/END_TO_END_PRODUCTION_BLUEPRINT.md`
- `docs/DOCTRINE_FAMILY_TO_RUST_TYPE_MAP_P2-01.md`
- `docs/BUILD_PACKAGING_FEATURE_MATRIX_P1-04.md`
- `docs/POLICY_AUTHORITY_RUNTIME_SURFACE_P3-01.md`
- `docs/POSIX_FILESYSTEM_ADAPTER_DAEMON_TOPOLOGY_P5-01.md`
- `docs/RUST_FOR_LINUX_CRATE_TRAIT_BOUNDARIES_P7-02.md`
- `docs/CONTROL_PLANE_SERVICE_API_CLI_TOPOLOGY_P9-01.md`
- `docs/PUBLICATION_PIPELINE_RUNTIME_DECOMPOSITION_P3-02.md`
- `docs/RECEIPT_RESPONSE_RUNTIME_EMISSION_PATH_P3-03.md`
- `docs/DASHBOARDS_TRACES_OPERATOR_TRUTH_SURFACES_P10-04.md` (missing from the repository; see #1270)
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`

## 1. Core result

The production design now has one explicit family for workspace/layout truth:

- one coordinating family: **`family.workspace_service_surface.workspace_layout`**
- one topology law:
  **`law.workspace_family_root_crate_class_service_boundary.workspace_layout`**
- one canonical layout chain:

The production design now also fixes:

- **4 stable top-level Rust root classes**
- **6 stable workspace strata**
- **12 stable workspace families**
- **10 stable crate classes**
- **10 stable dependency-edge classes**
- **10 stable public service / CLI / tool roots**

This means tidefs is no longer allowed to say only:

- "we will discover the Cargo workspace while coding,"
- "service mains can keep a little core logic if convenient,"
- "tests can depend on anything and production can borrow back later,"
- "the kernel tree can vendor whatever userspace crates it happens to need,"
- or "one generic io/runtime crate can absorb whatever does not fit yet."

It must instead say:

- which top-level root a crate belongs to,
- which workspace family owns the crate,
- which crate class it belongs to,
- which other families it may depend on,
- which public binary or CLI root is allowed to wire it,
- which package bundle and stage ceilings it binds to,
- and which receipt proves the layout is still lawful.

The anti-regression rule is explicit:

**No future Rust code may introduce a new crate root, a new cross-family
runtime import, a service main that owns sovereign logic, or a catchall helper
crate unless that move is first represented in the declared `workspace_layout` root,
family, crate-class, dependency-edge, and service-root records fixed here.**

## 2. Scope and boundaries

This document governs:

- the top-level Rust roots: `crates/`, `apps/`, `xtask/`, and `kmod/`,
- the stable family prefixes under `crates/`,
- the legal crate classes that may appear inside those families,
- the legal dependency directions across families,
- the service / CLI / tool roots that may live under `apps/`,
- the binding from `type_map` owner-path families to workspace families,
- the binding from workspace families to `package_profile_catalog` package bundles and stage
  ceilings,
  surfaces.

This document now consumes the explicit `type_map` design rule-family to Rust-type map
in `docs/DOCTRINE_FAMILY_TO_RUST_TYPE_MAP_P2-01.md`.

That boundary is deliberate.
`P1-01` fixes **where Rust code is allowed to live and how crates may depend on
one another**.
It now also consumes the explicit `governance_surface_0` authority-service law in
`docs/POLICY_AUTHORITY_RUNTIME_SURFACE_P3-01.md`, the explicit `posix_filesystem_adapter`
daemon/process-topology law in `docs/POSIX_FILESYSTEM_ADAPTER_DAEMON_TOPOLOGY_P5-01.md`,
the explicit `publication_pipeline` publication-pipeline law in
`docs/PUBLICATION_PIPELINE_RUNTIME_DECOMPOSITION_P3-02.md`, the explicit `response_registry`
receipt/response-emission law in
`docs/RECEIPT_RESPONSE_RUNTIME_EMISSION_PATH_P3-03.md`, the explicit `package_profile_catalog`
build/packaging law in `docs/BUILD_PACKAGING_FEATURE_MATRIX_P1-04.md`, the
explicit `kernel_boundary` kernel crate/trait boundary law in
`docs/RUST_FOR_LINUX_CRATE_TRAIT_BOUNDARIES_P7-02.md`, and the explicit `truth_view`
operator-truth law in
`docs/DASHBOARDS_TRACES_OPERATOR_TRUTH_SURFACES_P10-04.md` (missing from the repository; see #1270), so service roots,
client crates, observe crates, stage bindings, and the userspace-versus-kernel
split are no longer allowed to drift into Cargo-local convenience.
It now also consumes the explicit `linux_baseline` Linux 7.0 baseline contract in `docs/LINUX_7_0_BASELINE_CONTRACT_SUPPORTED_SUBSYSTEMS_P0-01.md`, so admitted host assumptions, subsystem floors, and explicit non-baseline cuts are no longer allowed to drift from the declared package/stage bindings. It now also consumes the explicit `product_variant` product-variant matrix in `docs/PRODUCT_VARIANT_MATRIX_P0-02.md`, so declared bring-up-only, mixed-client-kernel, and kernel-self-sufficient authority rows are no longer allowed to drift from the declared host/package/stage bindings. It now also consumes the explicit `environment_boundary` std / `no_std` / userspace / kernel boundary law in `docs/STD_NO_STD_KERNEL_USERSPACE_BOUNDARY_RULES_P1-02.md`, so portable core, owned mirrors, userspace runtimes, Rust-for-Linux bridge crates, and leaf kernels are no longer allowed to drift from the declared environment split. It now also consumes the explicit `vfs_boundary_mirror` UAPI / FFI / canonical-schema boundary law in `docs/UAPI_FFI_CANONICAL_SCHEMA_BOUNDARY_RULES_P1-03.md`, so boundary mirrors, wire layouts, kernel-visible structs, `repr(C)` call frames, and conversion exactness are no longer allowed to drift from the declared design rule families. It now also consumes the explicit `seam_map` shared design rule-native seam-map law in `docs/SHARED_DOCTRINE_NATIVE_SEAM_MAP_P0-03.md`, so seam ownership, client/boundary bindings, kernel-promotion cuts, and anti-leak rules are no longer allowed to drift from the declared cross-system registry. It now also consumes the explicit `non_authority_deletion` non-authority / deletion law in `docs/NON_AUTHORITY_DELETION_LAW_P0-04.md`, so live archived residue, archive-only carriers, tombstone/delete bindings, and non-authority proof are no longer allowed to drift from the declared product boundary. They may **not** invent a second workspace graph, a second app-root grammar, or a second family/dependency law outside `workspace_layout`.

## 3. Repo anchor snapshot

The production law is grounded in real repo surfaces rather than pure future
prose:

  `tidefs_core`, `tidefs_io`, and `tidefs`. That is enough to prove that the
  future Rust tree must keep deterministic logic, runtime/OS glue, and entry
  façades distinct instead of recreating one ambient mega-crate.
  roots are materially different from inner semantics libraries.
  enough to prove that test/harness crates need their own family and may not
  become production dependencies by convenience.
- `docs/END_TO_END_PRODUCTION_BLUEPRINT.md` already names the 12 future crate
  families and the 10 future binary families; `P1-01` turns that list into one
  binding law instead of leaving it as architectural intention.

Production `P1-01` extends those anchors by fixing the workspace graph they
must eventually share.
The current reference still proves feasibility, but it does not yet embody the
full root/family/class/dependency law described here.

## 4. Metrics snapshot

| Metric | Count |
|---|---:|
| Stable top-level Rust root classes | 4 |
| Stable workspace strata | 6 |
| Stable workspace families | 12 |
| Stable crate classes | 10 |
| Stable dependency-edge classes | 10 |
| Stable public service / CLI / tool roots | 10 |
| Required record families | 10 |
| Required algorithms | 10 |

## 5. Top-level Rust root law

### 5.1 Stable root classes

The future Rust tree must use exactly these top-level root classes:

| Root class | Path | Purpose | Membership rule |
|---|---|---|---|
| `root.workspace_layout.crates.r0` | `crates/` | library crates that carry canonical types, APIs, deterministic cores, runtimes, clients, renders, observe helpers, and test support | member of the main userspace Cargo workspace |
| `root.workspace_layout.apps.r1` | `apps/` | bounded mirror, CLI, and non-library tool roots | member of the main userspace Cargo workspace |
| `root.workspace_layout.xtask.r2` | `xtask/` | non-shipping build/publish/check orchestration | may be in the workspace but may never host production runtime logic |
| `root.workspace_layout.kmod.r3` | `kmod/` | Rust-for-Linux bridge and leaf-module tree | **not** a member of the main userspace Cargo workspace |

### 5.2 Root invariants

The root law is strict:

- `crates/` is the only lawful root for reusable Rust libraries.
- `apps/` is the only lawful root for bounded mirror, CLI, and tool binaries.
- `xtask/` may orchestrate builds, gates, or publish steps, but it may not own
  canonical runtime logic, sovereign types, or control-plane truth.
- `kmod/` remains a sibling tree governed by `kernel_boundary`; it may mirror shared bridge
  contracts, but it may not silently vendor userspace runtime crates.
- there is no lawful fifth catchall root such as `common/`, `misc/`, or
  `runtime/` at repo top level.

## 6. Workspace stratum and family law

### 6.1 Stable workspace strata

The main userspace workspace must be understood in these strata:

| Stratum | Meaning |
|---|---|
| `stratum.workspace_layout.foundation.s0` | canonical value types and canonical schema/receipt families |
| `stratum.workspace_layout.authority.s1` | inner authority families that decide successors, claims, reserves, witnesses, and response language |
| `stratum.workspace_layout.product_adapter.s2` | product-facing adapter/client families (`posix_filesystem_adapter`, `block_volume_adapter`) |
| `stratum.workspace_layout.control_query.s3` | control-plane and explanation/query surface families |
| `stratum.workspace_layout.test.s5` | harnesses, fixtures, fuzz/chaos/perf helpers, and non-shipping proof support |

### 6.2 Stable workspace families

The stable families are now fixed:

| Workspace family | Path prefix | Stratum | Owns | Must not own |
|---|---|---|---|---|
| `family.workspace_layout.types.f0` | `crates/tidefs-types-*` | `s0` | canonical ids, scalar wrappers, enums, small value objects | service mains, runtime thread/async glue |
| `family.workspace_layout.schema_codec.f1` | `crates/tidefs-schema_codec-*` | `s0` | canonical receipt/schema/binary envelope families | product runtimes, CLI parsing |
| `family.workspace_layout.policy_authority.f2` | `crates/tidefs-policy_authority-*` | `s1` | `policy_authority` requests, traits, deterministic evaluation, runtime glue, clients | `posix_filesystem_adapter`/`block_volume_adapter`/`control_plane`/`explanation_query` service mains |
| `family.workspace_layout.authority_publication.f3` | `crates/tidefs-authority_publication-*` | `s1` | successor publication helpers and publication-specific deterministic logic | adapter runtimes or CLI roots |
| `family.workspace_layout.claim_reserve_witness.f4` | `crates/tidefs-claim_reserve_witness-*` | `s1` | claims, reserves, witnesses, repair/escrow/quorum logic | adapter runtimes or packaging helpers |
| `family.workspace_layout.response_normalizer.f5` | `crates/tidefs-response_normalizer-*` | `s1` | shared response-language and non-sovereign render helpers | service mains or authority mutation state |
| `family.workspace_layout.posix_filesystem_adapter.f6` | `crates/tidefs-posix_filesystem_adapter-*` | `s2` | FUSE/VFS-facing client/runtime crates and per-mount session support | `policy_authority` authority cores or control-plane daemon roots |
| `family.workspace_layout.block_volume_adapter.f7` | `crates/tidefs-block_volume_adapter-*` | `s2` | block/ublk-facing client/runtime crates and export support | `policy_authority` authority cores or control-plane daemon roots |
| `family.workspace_layout.control_plane.f8` | `crates/tidefs-control_plane-*` | `s3` | control-plane API/client/runtime helpers and admin-facing request surfaces | `policy_authority` authority cores or `posix_filesystem_adapter`/`block_volume_adapter` mount/export runtimes |
| `family.workspace_layout.explanation_query.f9` | `crates/tidefs-explanation_query-*` | `s3` | explanation/query API/client/render/runtime helpers | `policy_authority` authority cores or `posix_filesystem_adapter`/`block_volume_adapter` mount/export runtimes |
| `family.workspace_layout.test.f11` | `crates/tidefs-test-*` | `s5` | harness rows, fixtures, fault/perf drivers, conformance helpers | dependencies of shipping production crates |

## 7. Crate-class and naming law

### 7.1 Stable crate classes

Inside the workspace families above, only these crate classes are legal:

| Crate class | Typical suffix / path shape | Purpose |
|---|---|---|
| `class.workspace_layout.types.c0` | `*-types`, `*-ids`, `*-enums` | pure value types and closed vocabularies |
| `class.workspace_layout.schema.c1` | `*-schema`, `*-receipt`, `*-binary` | canonical `schema_codec` / `binary_schema` / continuity-bearing schema families |
| `class.workspace_layout.api.c2` | `*-api`, `*-contract`, `*-traits` | request families, trait surfaces, client/server contracts |
| `class.workspace_layout.runtime.c4` | `*-runtime`, `*-async`, `*-exec` | async/runtime/process/queue wiring under one owning family |
| `class.workspace_layout.client.c5` | `*-client` | typed clients that call another service family lawfully |
| `class.workspace_layout.render.c6` | `*-render`, `*-view`, `*-trace` | non-sovereign render / explanation / trace helpers |
| `class.workspace_layout.service_root.c8` | `apps/<binary-name>` | bounded mirror / CLI / tool roots only |
| `class.workspace_layout.test_or_xtask.c9` | `crates/tidefs-test-*`, `xtask/*` | non-shipping harness or orchestration code |

### 7.2 Naming and placement rules

The naming law is strict:

- every reusable library crate must begin with `tidefs-` and live under the
  owning `crates/tidefs-<family>-*` prefix;
- every public CLI or tool root, and every bounded non-production runtime mirror root, must live under `apps/` and use the shipping or mirror binary name directly (`apps/tidefs-policy-authority-daemon`, `apps/tidefsctl`, and so on);
- no `apps/` root may own canonical `type_map` types, deterministic core logic, or
  sovereign state machines;
- no `crates/` library may hide a second `main.rs`-style public entry root for
  a daemon or CLI;
- and there is no lawful generic `tidefs-io` Rust family that becomes the new
  home for unrelated runtime glue. OS/runtime glue lives under the owning family
  runtime crate.

### 7.3 `type_map` owner-path binding rule

The mapping from `type_map` owner-path families to workspace families is now fixed:

| `type_map` owner-path family | Default workspace-family home |
|---|---|
| `path.type_map.ids.p0` | `family.workspace_layout.types.f0` |
| `path.type_map.scalars.p1` | `family.workspace_layout.types.f0` |
| `path.type_map.enums.p2` | `family.workspace_layout.types.f0` or the owning family's `c0` crate when the enum is family-local |
| `path.type_map.records_runtime_receipts.p3` | owning family `c0`/`c1`/`c2` crates, or `family.workspace_layout.schema_codec.f1` when the record is canonical receipt/schema truth |
| `path.type_map.views_builders.p4` | owning family `c2`/`c3`/`c6` crates, never `apps/` roots |
| `path.type_map.bridges.p5` | owning surface family (`posix_filesystem_adapter`, `block_volume_adapter`, `control_plane`, `explanation_query`, `observe`) under `c2`/`c5`/`c6`, never `family.workspace_layout.types.f0` |

The anti-regression rule is explicit:

**`type_map` may move a type across crate roots only by preserving the declared
owner-path family and workspace-family home. `apps/` roots may consume those
rows, but they may not become their canonical owner.**

## 8. Family dependency-edge law

### 8.1 Stable dependency-edge classes

The family dependency grammar is now fixed:

| Edge class | Source family | Legal targets | Forbidden drift |
|---|---|---|---|
| `edge.workspace_layout.foundation_down.e0` | `types` | none upward | any dependency on authority, adapter, control/query, observe, or test |
| `edge.workspace_layout.schema_codec_on_types.e1` | `schema_codec` | `types` | adapter/service/runtime imports |
| `edge.workspace_layout.inner_authority_down.e2` | `authority_publication`, `claim_reserve_witness`, `response_normalizer` | `types`, `schema_codec`, same-family lower classes | `posix_filesystem_adapter`, `block_volume_adapter`, `control_plane`, `explanation_query`, or test-owned helpers |
| `edge.workspace_layout.policy_authority_inner_authority.e3` | `policy_authority` | `types`, `schema_codec`, `authority_publication`, `claim_reserve_witness`, `response_normalizer`, read-only observe helpers | `posix_filesystem_adapter`/`block_volume_adapter` runtimes, `control_plane`/`explanation_query` runtimes |
| `edge.workspace_layout.product_to_policy_authority_api.e4` | `posix_filesystem_adapter`, `block_volume_adapter` | `types`, `schema_codec`, `response_normalizer`, `policy_authority` `api`/`client`, read-only observe helpers | `policy_authority-core`, `policy_authority-runtime`, sibling product runtimes |
| `edge.workspace_layout.control_to_policy_authority_api.e5` | `control_plane`, `explanation_query` | `types`, `schema_codec`, `response_normalizer`, `policy_authority` `api`/`client`, read-only observe helpers | `policy_authority-core`, `policy_authority-runtime`, `posix_filesystem_adapter`/`block_volume_adapter` runtimes |
| `edge.workspace_layout.observe_read_only.e6` | `observe` | `types`, `schema_codec`, family `api`/receipt/render crates | mutable authority or product core/runtime crates |
| `edge.workspace_layout.test_wide_nonreverse.e7` | `test` | any library family as needed for proof | any reverse production dependency on `test` |
| `edge.workspace_layout.service_root_family_local.e8` | `apps/*` roots | own family runtime/client crates, `observe`, `types`, `schema_codec` | sibling family `core`/`runtime` imports by convenience |
| `edge.workspace_layout.kmod_bridge_only.e9` | `kmod/` tree | shared bridge contracts allowed by `kernel_boundary` together with the explicit `vfs_boundary_mirror` boundary law | direct import of userspace runtime or service-root crates |

### 8.2 Service-root ownership matrix

The public roots are now fixed:

| App root | Owner family | Legal direct dependencies |
|---|---|---|
| `apps/tidefs-policy-authority-daemon` | `policy_authority` | bounded non-production mirror only; `policy_authority-runtime`, `observe`, `types`, `schema_codec` |
| `apps/tidefs-posix-filesystem-adapter-daemon` | `posix_filesystem_adapter` | bounded non-production mirror only; `posix_filesystem_adapter-runtime`, `policy_authority-client`, `observe`, `types`, `schema_codec`, `response_normalizer-render` |
| `apps/tidefs-block-volume-adapter-daemon` | `block_volume_adapter` | bounded non-production mirror only; `block_volume_adapter-runtime`, `policy_authority-client`, `observe`, `types`, `schema_codec`, `response_normalizer-render` |
| `apps/tidefs-control-plane-daemon` | `control_plane` | bounded non-production mirror only; `control_plane-runtime`, `policy_authority-client`, `observe`, `types`, `schema_codec`, `response_normalizer-render` |
| `apps/tidefs-explanation-query-daemon` | `explanation_query` | bounded non-production mirror only; `explanation_query-runtime`, `policy_authority-client`, `observe`, `types`, `schema_codec`, `response_normalizer-render` |
| `apps/tidefs-observe-cored` | `observe` | `observe` crates plus read-only family API/render crates |
| `apps/tidefsctl` | `control_plane` | production-admitted operator CLI; `control_plane-client`, `observe`, `types`, `schema_codec`, `response_normalizer-render` |
| `apps/tidefsq` | `explanation_query` | production-admitted query CLI; `explanation_query-client`, `observe`, `types`, `schema_codec`, `response_normalizer-render` |
| `apps/tidefs-stress` | `test` | `test` crates plus admitted family clients/gate helpers |

### 8.3 Service-root invariants

The service-root law is strict:

- a public binary root may parse CLI args, env, unit-file config, and wire
  runtime components;
- a public binary root may not own canonical types, deterministic policy,
  durable state machines, or cross-family helper logic;
- `tidefsctl` and `tidefsq` remain client roots, not hidden authority/query
  runtimes;
- `tidefs-stress` is a tool root, not a sovereign runtime
  carriers;
- and no service root may reach across family boundaries to import another
  family's `*-runtime` crate directly.

## 9. Canonical workspace/schema families

| Record | Purpose | Authority class |
|---|---|---|
| `WorkspaceRootClassRecord` | one declared top-level Rust root class, path, and membership rule | authoritative declaration |
| `WorkspaceStratumRecord` | one workspace stratum, ordering position, and allowed family kinds | authoritative declaration |
| `WorkspaceFamilyRecord` | one stable family prefix, owning stratum, owned scope, and forbidden scope set | authoritative declaration |
| `WorkspaceCrateClassRecord` | one legal crate class, suffix pattern, and ownership rule | authoritative declaration |
| `WorkspaceCrateRecord` | one concrete library crate path, owning family, crate class, and package refs | authoritative/runtime declaration |
| `WorkspaceServiceRootRecord` | one concrete `apps/` root, owner family, public binary name, and allowed dependency classes | authoritative declaration |
| `WorkspaceDependencyEdgeRecord` | one allowed family dependency edge with source class, target class, and refusal policy | authoritative declaration |
| `WorkspaceForbiddenDependencyRecord` | one forbidden cross-family edge, reason class, and remediation rule | authoritative refusal declaration |
| `WorkspaceOwnerPathBindingRecord` | binding from one `type_map` owner-path family or row set to one workspace family and crate class | authoritative binding |

These families are added to `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`
by this turn.

## 10. Required algorithms

The production workspace-layout law requires these algorithms to exist in the
shared algorithm set:

1. **`declare_workspace_root_classes_and_membership_rules()`**
2. **`declare_workspace_strata_and_family_prefixes()`**
3. **`declare_crate_classes_and_suffix_patterns_for_family()`**
4. **`bind_type_map_owner_path_family_to_workspace_home()`**
5. **`declare_public_service_root_and_owner_family()`**
7. **`reject_cross_family_runtime_or_core_import_drift()`**
8. **`bind_workspace_family_to_package_profile_catalog_bundle_and_stage_ceiling()`**
9. **`bind_userspace_workspace_to_kmod_bridge_boundary_without_vendoring_runtime()`**
10. **`issue_workspace_layout_receipt_or_refusal_set()`**

## 11. Whole-system operational paths added by this law

1. design rule family or runtime law lands in the design set -> `type_map` row plus
   `WorkspaceOwnerPathBindingRecord` choose one lawful workspace family and
   crate class -> the future Rust implementation cannot place the type in an app
   root or random helper crate by convenience
2. `policy_authority` service implementation is materialized -> `crates/tidefs-policy_authority-api`,
   `crates/tidefs-policy-authority-core`, `crates/tidefs-policy-authority-runtime`, and
   `apps/tidefs-policy-authority-daemon` occupy distinct `workspace_layout` classes -> `control_plane`, `posix_filesystem_adapter`, and `explanation_query`
   consume `policy_authority` only through declared API/client crates instead of runtime
   reach-through
3. `posix_filesystem_adapter` bounded bring-up path is materialized -> `apps/tidefs-posix-filesystem-adapter-daemon` wires
   `apps/tidefs-posix-filesystem-adapter-daemon/src/runtime` plus admitted `policy_authority-client` and observe crates ->
   mount/bootstrap/runtime glue stays under `posix_filesystem_adapter` ownership instead of leaking
   into foundation crates or control-plane roots
4. `tidefsctl`, `tidefsq`, dashboards, and gate tools are materialized -> app
   surfaces -> operator tools stay non-sovereign and production crates never
   depend back on harness libraries
5. mixed or later kernel stages are built -> userspace workspace crates bind to
   `package_profile_catalog` bundles while `kmod/` binds only through the `kernel_boundary` bridge boundary ->
   the kernel tree does not silently vendor userspace runtimes or service roots

## 12. Acceptance effect on the design pack

With this law settled:

- `P1-01` becomes detailed enough for later implementation planning,
- the repo now has one explicit answer to where Rust libraries, service roots,
  test harnesses, orchestration crates, and the sibling `kmod/` tree lawfully
  live,
- `type_map`, `governance_surface_0`, `posix_filesystem_adapter`, `publication_pipeline`, `response_registry`, `package_profile_catalog`, `kernel_boundary`, and the future stage gates
  now share one workspace-family and dependency grammar instead of Cargo-local
  convenience,
- broad implementation already makes sense to start, because the remaining work
  is no longer missing workspace or runtime topology law,
- there are still **no** `L0` or `L1` production-design items,
- no tracked production-design work remains below `L3`,
- and later refinement, review, planning, and implementation must now consume the explicit `seam_map` seam-map law together with the explicit workspace-family boundary declared here.
