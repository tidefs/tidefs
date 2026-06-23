# Stub/Placeholder Inventory

**Issue**: [#713](https://github.com/tidefs/tidefs/issues/713)
**Date**: 2026-06-21
**Register**: TFR-013 (docs/REVIEW_TODO_REGISTER.md)
**Authority**: `docs/workspace-package-classification.md` covers package roles; this inventory covers non-package stub surfaces and package-level placeholder behavior the role table does not resolve.

## Classification Legend

| Disposition | Meaning |
| --- | --- |
| **Delete** | Stale, superseded, or never-implemented scaffolding with no live consumer. A follow-up removal issue is required. |
| **Implement** | Placeholder that represents a real product gap with a concrete follow-up implementation issue. |
| **Keep-as-harness** | Demo or harness surface intentionally non-production, preserved for signal collection. No action required beyond classification. |

---

## 1. Stage Wording Residue (Wave Zero / Pre-Alpha Labels)

These surfaces carry historical "Wave Zero" or pre-alpha stage language that no longer reflects current crate scope.

### 1.1 Wave Zero label in crate descriptions

- **Surface**: `apps/tidefs-posix-filesystem-adapter-daemon/Cargo.toml:9`
  - Current text: `description = "Wave Zero POSIX Filesystem Adapter userspace mirror surface stub for TideFS"`
  - Classification: **Delete** the "Wave Zero" and "stub" wording.
  - The daemon is now a live FUSE adapter with committed dispatch surfaces. Retaining "stub" is misleading.
  - Follow-up issue: #783 removes the "Wave Zero" and "stub" wording from this and sibling descriptions; replace with scoped adapter-operator description matching the package-role classification.

- **Surface**: `crates/tidefs-types-secret-key-policy-core/Cargo.toml:9`
  - Current text: `description = "secret_key_policy_0 record types and enums (P9-04) for Wave Zero tidefs"`
  - Classification: **Delete** the "Wave Zero" wording.
  - Follow-up issue: #783.

- **Surface**: `crates/tidefs-types-posix-filesystem-adapter-core/src/lib.rs:7`
  - Current text: `//! Wave Zero does not widen the POSIX surface yet`
  - Classification: **Delete** the "Wave Zero" phrasing.
  - Follow-up issue: #783.

### 1.2 Wave Zero label in xtask output

- **Surface**: `xtask/tidefs-xtask/src/main.rs:1774`
  - Current text: `println!("tidefs Wave Zero workspace summary");`
  - Classification: **Delete** the "Wave Zero" wording; replace with neutral label.
  - Follow-up issue: #783.

### 1.3 Wave Zero label in review docs

- **Surface**: `docs/WHOLE_REPO_REVIEW.md:688`
  - Current text: `daemon a Wave Zero stub;`
  - Classification: **Delete** the "Wave Zero stub" wording (update the review note to reference this inventory instead).
  - Follow-up issue: #783 updates `docs/WHOLE_REPO_REVIEW.md` after deletion issues close.

---

## 2. Placeholder Function Bodies

### 2.1 Algorithm Stubs (P5-01 daemon topology)

- **Surface**: `apps/tidefs-posix-filesystem-adapter-daemon/src/runtime/daemon_topology.rs:455-530`
  - Nine functions (algorithms #2-#10 from P5-01 section 10) that return `::default()` values and accept `_unused` parameters.
  - Functions: `normalize_mount_helper_argv_env_to_posix_filesystem_adapter_mount_intent`, `admit_posix_filesystem_adapter_mount_intent_under_package_policy_and_global_budget`, `spawn_posix_filesystem_adapter_session_runtime_and_transfer_mount_capsule`, `materialize_posix_filesystem_adapter_session_thread_sets_from_p5_02_and_p5_03_laws`, `bind_posix_filesystem_adapter_session_to_policy_authority_publication_pipeline_response_registry_and_observe_surfaces`, `issue_posix_filesystem_adapter_ready_or_refusal_receipt_and_release_mount_helper`, `drain_posix_filesystem_adapter_session_for_unmount_cutover_failover_or_pressure`, `classify_posix_filesystem_adapter_session_crash_or_abnormal_stop`, `recover_or_quarantine_posix_filesystem_adapter_session_after_crash_or_supervisor_restart`.
  - Classification: **Implement** — real daemon session lifecycle steps that currently have no body logic. Each function name declares a contract that must be fulfilled before product claims.
  - Follow-up issue: #784 implements daemon session lifecycle (scoped to one coherent slice of the topology state machine).

### 2.2 statfs() stub in vendored FUSE example

- **Surface**: `crates/tidefs-fuser/examples/simple.rs:1556`
  - Returns hardcoded `10_000` values for blocks/files and logs `warn!("statfs() implementation is a stub")`.
  - Has an inline `// Review debt TFR-016` comment.
  - Classification: **Implement** — the `simple.rs` example is a vendored/demo harness, but the stub is the only available statfs reference implementation.
  - Follow-up issue: #785 implements real statfs in the example or wires the engine's statfs into the example path.

### 2.3 FUSE_BMAP explicit non-support decision

- **Surface**: `docs/FUSE_BINDING_STRATEGY_AND_FEATURE_MATRIX_P1-05.md`
  - Resolution: #786 classifies `FUSE_BMAP` / `bmap()` as **Explicitly unsupported** for the current userspace adapter boundary.
  - Rationale: BMAP reports physical block-device addresses, while the daemon has no stable block-device address mapping to expose. FIEMAP remains the supported extent-query surface.
  - Classification: **Resolved** — no longer an unresolved ENOSYS/stub surface.

---

## 3. Test Stubs With Feature Gates

### 3.1 Claimed/NotReady feature gates in FUSE e2e smoke tests

- **Surface**: `apps/tidefs-posix-filesystem-adapter-daemon/tests/fuse_e2e_smoke.rs:19-20, 46-48, 821`
  - Defines a `FeatureGate` enum with `Claimed` and `NotReady` variants.
  - Phase B stubs section (line 821): tests gated behind `Claimed`/`NotReady` that are declared as stubs.
  - However, the actual test bodies (e.g., namespace-backed lookup tests) contain real assertions and exercise wired dispatch paths.
  - Classification: **Implement** — the `Claimed`/`NotReady` gate labels must be resolved to `Committed` for tests that exercise committed surfaces, or the stubs must be documented with concrete follow-up issues.
  - Follow-up issue: #787 audits FUSE e2e smoke test gates; promote tests whose dispatch surfaces are committed; file implementation issues for the remaining gated tests.

---

## 4. Kernel Compatibility Stubs

### 4.1 Kbuild BLAKE3 stubs

- **Surface**: `crates/tidefs-kmod-posix-vfs/src/mount.rs:121, 150, 733, 764, 871, 921`
  - BLAKE3-256 digest verification marked "unavailable (Kbuild stub)".
  - Mount path fails closed when BLAKE3 is unavailable.
- **Surface**: `crates/tidefs-block-kmod/src/dispatch.rs:1156, 1191`
  - Similarly marked "Kbuild stub" for lifecycle event digests.
- Classification: **Implement** — these are legitimate kernel-build limitations, not scaffolding. The BLAKE3 kernel compatibility story needs resolution: either port BLAKE3 to the kernel build or document the fail-closed policy as permanent.
- Follow-up issue: #788 resolves BLAKE3 availability in kernel builds; update stub markers to scoped TFR references.

### 4.2 ENOSYS returns in kernel VFS module

- **Surface**: `crates/tidefs-kmod-posix-vfs/tidefs_posix_vfs_main.rs:4574, 5539, 5701, 5709, 6376, 6384, 6486`
  - Current source review for #799 found fallocate, fiemap, and xattr paths are already wired outside those stale audit line numbers. The remaining target-file ENOSYS sites were fail-closed state paths (`getattr`, `read`, `write`, and `syncfs`) plus the `getlk`/`setlk` lock stubs.
- Classification: **Implement** — #799 resolves the current target-file ENOSYS sites by returning `ENODEV` for missing mounted pool or block-I/O authority and by backing `getlk`/`setlk` with a kernel-engine advisory byte-range lock table. Blocking `setlkw` remains explicitly out of scope in `crates/tidefs-kmod-posix-vfs/VFS-OPS-GAP-ANALYSIS.md`.
- Follow-up issue: #799 carries the implementation and focused validation record under TFR-018.

### 4.3 Kernel intent writer no-op stub

- **Surface**: `crates/tidefs-kmod-posix-vfs/src/kernel_intent_writer.rs:337`
  - Comment: "Kbuild stub — provides no-op types when kernel-intent-log is not available".
- Classification: **Keep-as-harness** — legitimate kernel-build compatibility shim.
- No action.

---

## 5. Planned Authority Surface Crates

The `docs/workspace-package-classification.md` role table marks 22 package roots as "planned authority surface; follow-up issue required". Each has substantial source code but is not yet authorized for product release claims.

Each crate now has a dedicated follow-up issue (#815–#836) scoped to establish its authority claim or reclassify it.

These are not stubs in the traditional sense (they contain real code and tests), but the classification gap means their product-readiness is placeholder status.

| Package | Issue | Role | Lines (lib.rs) | Notes |
| --- | --- | --- | ---: | --- |
| `tidefs-anti-entropy-auditor` | [#815](https://github.com/tidefs/tidefs/issues/815) | product-code | 1425 | Merkle tree exchange, comparator, scan scheduler; needs runtime validation |
| `tidefs-block-kmod` | [#816](https://github.com/tidefs/tidefs/issues/816) | adapter-operator | — | Authority established; kernel-build validation deferred to release gate |
| `tidefs-compaction` | [#817](https://github.com/tidefs/tidefs/issues/817) | product-code | 2693 | Full compaction engine with checkpoint/resume; needs runtime validation |
| `tidefs-crash-oracle` | [#818](https://github.com/tidefs/tidefs/issues/818) | proof-harness | 1827 | Authority established as current proof-harness: model crash matrices, runtime injection definitions, and runtime-report coverage validation; runtime product claims remain claim-gated |
| `tidefs-data-cleaner` | [#819](https://github.com/tidefs/tidefs/issues/819) | product-code | 684 | Cleanup work queue integration; needs runtime validation |
| `tidefs-distributed-model-check` | [#820](https://github.com/tidefs/tidefs/issues/820) | proof-harness | 173 | Deterministic distributed safety model checking; needs model coverage |
| `tidefs-env-fuse-model` | [#821](https://github.com/tidefs/tidefs/issues/821) | proof-harness | — | FUSE lifecycle environment model; needs model evidence |
| `tidefs-env-ublk-model` | [#822](https://github.com/tidefs/tidefs/issues/822) | proof-harness | — | uBLK qid/tag state model; needs model evidence |
| `tidefs-erasure-coded-store` | [#823](https://github.com/tidefs/tidefs/issues/823) | product-code | 2199 | Authority established for local EC object storage: placement-backed shard routing, degraded reads, shard-digest verification, flush repair, and store rebuild now have focused runtime coverage. Pool receipt/recovery integration remains outside this placeholder-inventory row. |
| `tidefs-geometry-convert` | [#824](https://github.com/tidefs/tidefs/issues/824) | product-code | 1194 | Pool geometry conversion (mirror/EC); needs runtime validation |
| `tidefs-kernel-cutover-runtime` | [#825](https://github.com/tidefs/tidefs/issues/825) | product-code | 424 | Cutover state machine, fence manager; needs kernel-mode validation |
| `tidefs-kmod-posix-vfs` | [#826](https://github.com/tidefs/tidefs/issues/826) | adapter-operator | — | Authority established for kernel VFS operations: implemented dispatch through kmod-bridge to VfsEngine; Tier 2 engine-backed mount with BLAKE3-verified committed-root selection and intent-log replay; xfstests coverage recorded in TFR-018 register entries; mount lifecycle, readdir, flock, and invalidate_folio mounted-kernel validation remain separately gated |
| `tidefs-model-core` | [#827](https://github.com/tidefs/tidefs/issues/827) | proof-harness | — | Authority established for pure deterministic VFS model; 16 tests cover all canonical operations, receipt validation, path parsing, fingerprinting, and invariant checking; used by oracle crates |
| `tidefs-offload-core` | [#828](https://github.com/tidefs/tidefs/issues/828) | product-code | 1948 | Non-authoritative offload descriptors; needs runtime validation |
| `tidefs-online-defrag` | [#829](https://github.com/tidefs/tidefs/issues/829) | product-code | 1641 | Online defragmentation; needs runtime validation |
| `tidefs-performance-contract` | [#830](https://github.com/tidefs/tidefs/issues/830) | product-code | 1629 | Performance admission and queue metadata; needs runtime validation |
| `tidefs-posix-filesystem-adapter-reply` | [#831](https://github.com/tidefs/tidefs/issues/831) | adapter-operator | — | FUSE reply construction; needs adapter validation |
| `tidefs-posix-guarantee-verifier` | [#832](https://github.com/tidefs/tidefs/issues/832) | proof-harness | — | POSIX guarantee verification; needs harness validation |
| `tidefs-secret-key-policy-runtime` | [#833](https://github.com/tidefs/tidefs/issues/833) | policy-tooling | — | Secret-key policy runtime (contains `CryptoPlaceholder` error variant); needs policy validation |
| `tidefs-snapshot-pruner` | [#834](https://github.com/tidefs/tidefs/issues/834) | product-code | 1949 | Snapshot pruner; needs runtime validation |
| `tidefs-two-node-harness` | [#835](https://github.com/tidefs/tidefs/issues/835) | proof-harness | — | Two-node cluster harness; needs QEMU validation |
| `tidefs-vfs-rpc` | [#836](https://github.com/tidefs/tidefs/issues/836) | product-code | 2884 | VFS RPC protocol; needs runtime validation |

Classification: **Implement** — each needs a dedicated follow-up issue to establish its authority claim or reclassify it. Issues #815–#836 carry the per-crate implementation scope.

Follow-up scope: #789 tracks the 22 planned-authority surfaces and has split the tracking surface into per-crate issues #815–#836 with disjoint expected write sets.

---

## 6. Non-Package Stub and Placeholder Surfaces

### 6.1 Dedup crate not live write-path authority

- **Surface**: `crates/tidefs-dedup/`
  - Listed in `docs/ARCHITECTURE.md` integrity layer with note "not live write-path authority".
- Classification: **Implement** — the crate exists but its integration into the write path is deferred.
- Follow-up issue: #790 wires dedup into the live write path or reclassifies it as historical design input.

### 6.2 Segment cleaner model surface

- **Surface**: `crates/tidefs-segment-cleaner/`
  - Listed in `docs/ARCHITECTURE.md` with note "model surface; live physical reclaim requires receipt-bound dead-object drains".
- Classification: **Implement** — the model surface exists but physical reclaim is incomplete.
- Follow-up issue: #791 completes the receipt-bound dead-object drain integration.

### 6.3 CryptoPlaceholder error variant

- **Surface**: `crates/tidefs-secret-key-policy-runtime/src/lib.rs:122, 798`
  - `CryptoPlaceholder` error variant and its emission path.
- Classification: **Implement** — placeholder for real cryptographic policy enforcement.
- Follow-up issue: #792 implements the cryptographic policy enforcement path; remove the placeholder error variant.

### 6.4 Transport endpoint type authority

- **Surface**: `crates/tidefs-transport/src/config.rs`
  - `TransportConfig` now stores the canonical `TransportAddr` endpoint type from `crates/tidefs-transport/src/addr.rs`.
- Classification: **Resolved by #793** — the historical Forgejo placeholder reference is replaced by the current GitHub endpoint authority.
- Residual boundary: storage-node RDMA disclosure maps either to a canonical `rdma://` `TransportAddr` or to the existing TCP fallback bind socket; opaque RDMA device strings are rejected instead of being preserved as a second endpoint ABI.

### 6.5 Cluster orchestrator scaffolding notes

- **Surface**: `crates/tidefs-cluster/src/pool_orchestrator.rs:5-19`
  - Comments mark `ClusterPoolOrchestrator` and `PoolTransport` trait as scaffolding.
- Classification: **Implement** — the orchestrator builds real per-node transport but is still classified as scaffolding.
- Follow-up issue: #794 promotes the orchestrator from scaffolding to product-code and resolves TFR-017 transport authority gates for this surface.

### 6.6 unimplemented!() in node-drain test mock

- **Surface**: `crates/tidefs-node-drain/src/runtime.rs:585`
  - `send_announce` mock returns `unimplemented!("use broadcast_announce for tests")`.
- Classification: **Keep-as-harness** — this is inside a test mock implementation (`#[cfg(test)]` context). The `broadcast_announce` method is the real implementation path.
- No action required.

### 6.7 Synthetic placeholder receipts in rebuild-runtime

- **Surface**: `crates/tidefs-rebuild-runtime/src/engine.rs:36, 169, 241; admission.rs:95, 163; completion.rs:109`
  - Comments and error variants describing synthetic placeholders used when real durable receipts are unavailable.
- Classification: **Implement** — the rebuild runtime has real logic but accepts synthetic placeholders for scaffolding callers.
- Follow-up issue: #795 removes synthetic placeholder acceptance paths and requires durable receipt evidence.

---

## 7. Documentation Stage Wording

### 7.1 Issue-era labels (OW-*, PC-*, NEXT-*) in source and docs

- **Surface**: issue #796 refreshed the repository scan at `92ed488a`
  with `rg -o "\b(?:OW|PC|NEXT)-[A-Z0-9][A-Z0-9-]*" .`.
  The active tree contains 153 files with 785 references: 556 `OW-*`, 160
  `PC-*`, and 69 `NEXT-*`.
  - `OW-*`: mixed current/historical design cross-references. Keep only where a
    scoped current spec/policy row, claim id, or GitHub issue now provides the
    authority; imported docs classified as historical input keep the label only
    as provenance, not current behavior evidence.
  - `PC-*`: mixed current/historical design cross-references. Current source
    gates may keep the label only when it names a current package, policy, or
    claim authority. Imported closeout docs classified as historical input must
    not be promoted by the label alone.
  - `NEXT-*`: stale Forgejo-era or stage-gate residue by default. Preserve only
    in historical input where the surrounding doc is explicitly historical;
    retarget or remove active source, harness, benchmark, flake, and security
    references through focused cleanup issues.
- Classification: **Implement** — the labels are not anonymous debt markers,
  but issue #796 confirms that the write set is too broad for one source edit.
  This slice records the classification and splits the retarget/removal work.
- Follow-up issues:
  - #980 covers block-volume and ublk adapter label retargeting.
  - #982 covers kernel/FUSE/POSIX adapter label retargeting.
  - #983 covers local-filesystem, local-object-store, and storage xtask label
    retargeting.
  - #984 covers distributed, placement, replication, rebuild, rebalance, and
    transport label retargeting.
  - #985 covers validation, security, benchmarking, and `flake.nix` label
    retargeting.

### 7.2 Forgejo references in unclassified docs

- **Surface**: Multiple docs under `docs/` and `docs/design/` still reference Forgejo issue numbers and URLs (e.g., `http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/...`).
  - This is tracked by TFR-019 and the `docs/DOCUMENTATION_AUTHORITY_REGISTER.md` initial open queue.
- Classification: **Implement** — already queued under TFR-019 documentation authority classification.
- Follow-up issue: #689 tracks the `docs/DOCUMENTATION_AUTHORITY_REGISTER.md` initial open queue (87 unclassified docs).

### 7.3 FUSE_BINDING_STRATEGY_AND_FEATURE_MATRIX maturity table

- **Surface**: `docs/FUSE_BINDING_STRATEGY_AND_FEATURE_MATRIX_P1-05.md`
  - Documents implemented, partial-boundary, and explicitly unsupported status for each FUSE operation.
  - `FUSE_BMAP` was resolved by #786 as explicit non-support for the current userspace adapter boundary.
  - #797 closed the historical non-BMAP FUSE feature-matrix stub triage, and #1081 refreshed the current callback audit in `docs/FUSE_OPERATION_COVERAGE_MATRIX.md`.
- Classification: **Resolved by matrix refresh** — source inspection of `FuseVfsAdapter` found no live daemon callback left as a fuser-default ENOSYS stub. Partial boundaries such as unsupported ioctl command numbers now live in the coverage matrix instead of this stub inventory.
- Follow-up issue: none from this audit; new FUSE behavior work should get a fresh issue with a non-overlapping source write set.

---

## 8. Keep-As-Harness Surfaces (No Action Required)

These surfaces are intentionally non-production and preserved for signal collection.

### 8.1 Demo apps

- `apps/tidefs-filesystem-demo` — classified as proof-harness; non-production Local Filesystem exercise.
- `apps/tidefs-store-demo` — classified as proof-harness; non-production Local Object Store exercise.
- Classification: **Keep-as-harness** — already correctly classified in `docs/workspace-package-classification.md`.
- No action.

### 8.2 Test stubs (legitimate test doubles)

- `StubPinLookup` in `crates/tidefs-receive-stream/tests/persistence_integration.rs` — test-only stub for mocking pin lookup.
- `StubPoolCore` / `SnapshotStubPoolCore` / `StubStorage` in `crates/tidefs-block-kmod/src/pool_core_backend.rs` — in-module test stubs.
- `StubLockBackend` in `crates/tidefs-posix-filesystem-adapter-workers-locks/src/lib.rs` — test-only lock backend.
- Classification: **Keep-as-harness** — legitimate test doubles.
- No action.

### 8.3 Kernel compatibility shims

- `KernelEngine` stub in `crates/tidefs-kmod-posix-vfs/tidefs_posix_vfs_main.rs:70` — kernel-resident VfsEngine stub.
- `no_std` stubs in `crates/tidefs-types-vfs-core/src/lib.rs:630, 1926` — minimal alloc-disabled stubs.
- `InternalKernelStub` carrier variant in `crates/tidefs-types-vfs-core/src/lib.rs:2062` — kernel RPC stub carrier.
- Classification: **Keep-as-harness** — legitimate kernel-build compatibility shims.
- No action.

### 8.4 Vendored FUSE binding

- `crates/tidefs-fuser/` — vendored FUSE protocol binding.
- Classification: **Keep-as-harness** — vendored third-party code.
- No action.

---

## 9. Surfaces Already Addressed by Existing Follow-Ups

These surfaces were identified as stub/placeholder during the audit but already have active follow-up issues or are tracked by existing registers.

- **TFR-017 transport/cluster authority** — covers `apps/tidefs-storage-node` cluster authority gap and `crates/tidefs-cluster` scaffolding; #793 and #794 track the endpoint and orchestrator placeholder surfaces identified here.
- **TFR-018 kernel VFS xfstests** — covers kernel VFS mount-path runtime coverage; #799 resolves the current ENOSYS operation-surface follow-up, while broader mounted-kernel runtime proof remains under TFR-018.
- **TFR-011 operator UAPI** — covers CLI command classification and admission gaps; existing operator UAPI issues #657, #658, #659, #660, and #662 carry current slices.
- **TFR-019 doc authority** — covers Forgejo references and unclassified imported docs; #689 tracks the remaining documentation authority queue.
- **Issue #276** — already deleted scaffold-transitional package roots.

---

## Follow-Up Issue Map

| Follow-Up Issue | Surface(s) | Disposition | Expected Write Set |
| --- | --- | --- | --- |
| #783 | Section 1 (Wave Zero labels in Cargo.toml, lib.rs, xtask, WHOLE_REPO_REVIEW.md) | Delete | 4-5 files |
| #784 | Section 2.1 (algorithm stubs in daemon_topology.rs) | Implement | `apps/tidefs-posix-filesystem-adapter-daemon/src/runtime/daemon_topology.rs` |
| #785 | Section 2.2 (statfs stub in simple.rs) | Implement | `crates/tidefs-fuser/examples/simple.rs` |
| #786 | Section 2.3 (FUSE_BMAP explicit non-support) | Resolved: explicit non-support | `docs/FUSE_BINDING_STRATEGY_AND_FEATURE_MATRIX_P1-05.md`, `docs/FUSE_OPERATION_COVERAGE_MATRIX.md`, `apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_vfs_adapter.rs` |
| #787 | Section 3.1 (Claimed/NotReady test gates) | Implement | `apps/tidefs-posix-filesystem-adapter-daemon/tests/fuse_e2e_smoke.rs` |
| #788 | Section 4.1 (Kbuild BLAKE3 stubs) | Implement | `crates/tidefs-kmod-posix-vfs/src/mount.rs`, `crates/tidefs-block-kmod/src/dispatch.rs` |
| #799 | Section 4.2 (kernel VFS ENOSYS returns) | Implement | `crates/tidefs-kmod-posix-vfs/tidefs_posix_vfs_main.rs` |
| #789 | Section 5 (22 planned-authority-surface crates) | Implement | Tracking issue; individual crate follow-ups |
| #790 | Section 6.1 (dedup crate) | Implement | `crates/tidefs-dedup/` |
| #791 | Section 6.2 (segment cleaner) | Implement | `crates/tidefs-segment-cleaner/` |
| #792 | Section 6.3 (CryptoPlaceholder) | Implement | `crates/tidefs-secret-key-policy-runtime/` |
| #793 | Section 6.4 (transport endpoint type authority) | Resolved: canonical `TransportAddr` | `crates/tidefs-transport/src/config.rs` |
| #794 | Section 6.5 (cluster orchestrator scaffolding) | Implement | `crates/tidefs-cluster/src/pool_orchestrator.rs` |
| #795 | Section 6.7 (synthetic placeholder receipts) | Implement | `crates/tidefs-rebuild-runtime/` |
| #796 | Section 7.1 (issue-era label audit and split) | Implement | `docs/STUB_PLACEHOLDER_INVENTORY.md`, `docs/REVIEW_TODO_REGISTER.md` |
| #980 | Section 7.1 block-volume and ublk label retargeting | Implement | Block-volume/ublk source, docs, and xtask block gate paths |
| #982 | Section 7.1 kernel/FUSE/POSIX label retargeting | Implement | Kernel/FUSE/POSIX adapter source and docs |
| #983 | Section 7.1 local-storage label retargeting | Implement | Local filesystem/object-store source, storage docs, and xtask storage gate paths |
| #984 | Section 7.1 distributed/transport label retargeting | Implement | Membership, placement, replication, rebuild, rebalance, transport source and docs |
| #985 | Section 7.1 validation/security/performance label retargeting | Implement | Validation, security, benchmarking, and `flake.nix` paths |
| #797 | Section 7.3 (FUSE feature matrix stubs) | Resolved: #1081 refreshed current callback matrix | `docs/FUSE_BINDING_STRATEGY_AND_FEATURE_MATRIX_P1-05.md`, `docs/FUSE_OPERATION_COVERAGE_MATRIX.md` |

The Wave Zero wording removal and the planned-authority tracking issue are the highest-priority slices because they touch the broadest surfaces with the lowest implementation risk.

---

## Verification

- Source/doc inspection completed against `origin/master` at `92ed488a`.
- Issue #796 refreshed section 7.1 and split the broad label-retargeting work
  into #980, #982, #983, #984, and #985.
- `git diff --check` passes for this inventory plus
  `docs/REVIEW_TODO_REGISTER.md`.
- No runtime, build, or test validation required for this docs-only inventory
  and classification slice.
- This inventory does not duplicate the `docs/workspace-package-classification.md` package-role audit; it focuses on non-package stub surfaces and package-level placeholder behavior the role table does not resolve.
- All 22 planned-authority-surface crates are enumerated for completeness; the role table already classifies them, but this inventory records their placeholder status for TFR-013 tracking.
