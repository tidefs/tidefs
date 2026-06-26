# TideFS Review Todo Register

This register is intentionally broad. It records areas found during the
whole-repo rename/import audit that block TideFS from making
OpenZFS/Ceph-class claims.

| Id | Area | Finding | Required Direction |
| --- | --- | --- | --- |
| TFR-002 | Workspace authority | Product code, harness code, historical scaffolding, and non-workspace packages are still interleaved. | Classify every package as product, harness, third-party, or delete candidate; remove ambiguous scaffolding. |
| TFR-003 | Todo hygiene | Debt was previously scattered through docs, comments, and issue-era markers. | Keep all durable debt here; convert inline notes to register pointers only. |
| TFR-004 | Dataset/inode authority | Dataset/mount identity and inode ownership need deep review; earlier audit suspected root-level inode list behavior. | Use `docs/INODE_NAMESPACE_AUTHORITY.md`: a dedicated dataset-scoped inode authority owns allocation, persisted IDs, root identity, and recovery seeding while namespace, FUSE lookup state, and inode-table registries remain projections. Implement the non-overlapping follow-ups #664, #665, #666, and #667 before closing this item. |
| TFR-005 | Timestamp/revision/on-disk format | POSIX timestamps, storage version fields, content object keys, scrub identity, replay ticks, rename metadata stamps, and serialized format fields are coupled. | Specify one authority model for POSIX time, generation, txg, object-version, and on-disk compatibility before changing behavior. |
| TFR-006 | Compression/encryption | Compression and encryption paths may bypass or duplicate raw object-store authority. | Use `docs/TRANSFORM_PIPELINE_AUTHORITY.md` as the #1063 boundary decision and close its non-overlapping follow-up map before claiming runtime conformance. |
| TFR-007 | Capacity/accounting | Allocation, quotas, statfs, reserves, and logical/physical accounting are split across crates. | Use `docs/CAPACITY_ACCOUNTING_AUTHORITY.md` as the boundary decision and close the linked follow-up issue map. |
| TFR-008 | Recovery/fsync/writeback/mmap | Recovery, fsync, dirty-page writeback, mmap, and page-cache authority are not proven as one contract. | Use `docs/PAGE_CACHE_WRITEBACK_AUTHORITY.md` for the integrated recovery/fsync/writeback/mmap durability boundary and follow-up map, and `docs/PAGE_CACHE_INVALIDATION_AUTHORITY.md` for the invalidation trigger, stale-generation, and FUSE/kernel/cluster lease model; then prove and test the end-to-end durability and cache-coherency contract. |
| TFR-010 | Snapshot/clone/send-receive/deadlist | Snapshot retention, deadlists, clone lineage, and send/receive are not one coherent storage model. | Use `docs/SNAPSHOT_CLONE_DEADLIST_AUTHORITY.md` for the local snapshot/clone/deadlist authority. Issue #1248 selected released-root derivation feeding the existing receipt-bound dead-object reclaim pipeline; implementation remains open under #1263, #1264, #1265, #1259, and #1266. Distributed snapshot shipping design is recorded in `docs/design/distributed-snapshot-shipping.md` (issue #1250); VFSSEND2 is the protocol foundation, section 7.2 records the initial scheduling/admission policy, and distributed deadlist triggers must call the #1248 derivation API rather than transmit deadlist entries. |
| TFR-011 | Operator CLI/UAPI | CLI, FUSE, ublk, kernel UAPI, and docs can describe different truths. | Define one public operator/UAPI boundary and keep internal crates behind it. |
| TFR-013 | Stub/placeholder stage | Several crates and docs still look like stage scaffolding rather than product behavior. | Classify placeholders explicitly and delete or implement them. |
| TFR-014 | Licensing/provenance | Fresh TideFS import must preserve Linux-style GPLv2+syscall-note licensing and third-party provenance. | Audit all package metadata and file-local notices after rename. |
| TFR-016 | Inline debt marker hygiene | Non-vendored source and active harness text still carried issue-era TODO/continuation wording. | Replace anonymous markers with register-addressed comments and treat old issue refs as historical context only. |
| TFR-017 | Transport/cluster authority | Cluster CLI, storage-node, send-buffer, epoch-fence, and orchestrator paths still expose staged or placeholder distributed behavior. | Define the transport authority, cross-replica comparison, dispatch, and backpressure semantics before multi-node claims. Distributed snapshot shipping design (#1250, `docs/design/distributed-snapshot-shipping.md`) selects VFSSEND2 as the send/receive protocol foundation and maps follow-up implementation issues; concrete transport binding (TCP, RDMA, etc.) remains deferred to this TFR-017 decision. |
| TFR-019 | Documentation authority drift | Imported docs still mix design intent, issue closeout records, maturity labels, and current-status claims. | Reclassify every doc as current policy, current spec, historical input, or delete candidate before relying on it. |
| TFR-020 | Test signal authority | Unit, integration, harness, policy, and marker tests are widespread enough that test count can outgrow product confidence. | Apply `docs/TEST_SIGNAL_POLICY.md`: keep product/invariant signal, demote marker/stale/scaffold signal, and make fixtures match the claim being proved. |
| TFR-021 | Nextgen verification contract authority | The verification/performance/offload plan needs one evidence chain instead of separate request-contract, model, trace, crash, performance, adapter, and offload systems. | Issue #1066 surveyed 30+ verification surfaces, chose unified evidence manifest with typed claim anchors (Model A, rejecting per-system bundles), mapped 11 evidence producers and 7 consumers, and recorded the follow-up issue map in `docs/NEXTGEN_VERIFICATION_PERFORMANCE_OFFLOAD_PLAN.md`. Keep high-value claim ids blocked until issue-scoped evidence and claims-gate support exist; the follow-up map names existing issues (#809-#835) and six new issue areas. |

## Current Review Notes

Detailed current review notes are recorded in `docs/WHOLE_REPO_REVIEW.md`.

Important 2026-06-01 findings:

- `TFR-001`: `docs/00_user_requirements.md` still contained stale
  version-closeout and checked-in scoreboard wording; status must be rebuilt
  from current source behavior.
- `TFR-020`: Test coverage is treated as signal quality, not test volume.
  `docs/TEST_SIGNAL_POLICY.md` is the current policy for adding, refactoring,
  deleting, or citing tests. The 2026-06-05 static review found heavy test mass
  across normal source files, dedicated test targets, and fixture-heavy
  surfaces; future cleanup should keep mounted/runtime/product and compact
  invariant tests, compress redundant branch tests, and remove or demote
  marker-only, stale-fixture, scaffold, and weakened-fixture claims.
- `TFR-020`: issue #500 adds `docs/TEST_SIGNAL_AUDIT.md`, classifying the
  scoped `crates/*/tests/`, inline `crates/*/src/`, and `apps/*/tests/`
  roots by product/invariant, harness/scaffold, and marker/stale signal. The
  audit records per-package counts, high-confidence marker/delete candidates,
  and claim-registry cross-references; it does not delete or refactor tests.
- `TFR-020`: issue #691 deletes the high-confidence comment-only and ignored
  non-Linux no-op tests named by the issue #500 marker/delete-candidate audit.
  The removed tests had no `validation/claims.toml` references; the surviving
  Linux FUSE validation tests continue to exercise mount lifecycle and basic
  I/O product paths. The same slice keeps daemon-, tool-, and
  runner-environment-dependent validation tests from reporting missing
  prerequisites or transient runner contention as product failures. Broader
  low-value fixture cleanup remains itemized by `docs/TEST_SIGNAL_AUDIT.md`
  and should stay issue-scoped to the owning code.
- `TFR-021`: issue #281 adds
  `docs/NEXTGEN_VERIFICATION_CONTRACT_ROADMAP.md` as the current planning
  authority for the nextgen verification, performance, and offload chain. The
  roadmap maps the architecture onto existing workspace anchors and records
  planned-blocked claim ids only. It does not close crash safety, performance
  isolation, kernel correctness, distributed correctness, accelerator
  correctness, TFR-008, TFR-017, or TFR-018.
- `TFR-002`: Earlier package-authority cleanup reported 148 packages and 148 workspace members.
  Five manifests are outside root workspace metadata after the abandoned POSIX
  adapter split-shard crates, broken `tidefs-chaos` app root, and five
  excluded non-fuzz scaffold type crates were deleted. The deleted scaffold
  roots were `tidefs-types-archive-control-core`,
  `tidefs-types-observe-core`, `tidefs-types-policy-authority-core`,
  `tidefs-types-shadow-pilot`, and `tidefs-types-truth-view-core`; each failed
  standalone manifest parsing because it inherited workspace fields while
  being excluded, and current reverse-reference review found no live code
  consumers outside stale docs/xtask classifier fixtures. The surviving
  archive/observe/policy/truth-view record surfaces already live in
  `tidefs-types-vfs-core` or product-local modules. The remaining excluded
  manifests are fuzz harnesses. The root fuzz manifest no longer depends on
  the missing `tidefs-schema-codec-outcome` crate, and its placeholder FUSE
  request target has been deleted. The four crate-local fuzz manifests now
  have explicit cargo-fuzz bin targets, dummy lib targets, and committed
  lockfiles, and pass standalone `cargo check --manifest-path ... --locked`;
  this repairs the harness manifests but does not close the
  product/harness/archive split.
  The four deleted POSIX split shards had no active workspace users, were
  outside Cargo metadata, and were already classified as consolidated into the
  adapter runtime; their removal is only one TFR-002 cleanup slice. Earlier
  metadata still showed direct dependencies on scaffold type crates from the
  POSIX adapter daemon; later cleanup removed those POSIX edges before issue
  #276 deleted the remaining scaffold type roots themselves. The standalone
  `tidefs-posix-filesystem-adapter-runtime` crate was deleted after source
  review showed the daemon owns the live runtime module. Imported docs
  still
  reference deleted control-plane, policy-authority, observe, and
  remain coupled.
- `TFR-002`: issue #276 removed the last three `scaffold-transitional`
  workspace members: `tidefs-types-control-plane-core`,
  `tidefs-types-publication-pipeline-core`, and
  `tidefs-types-response-registry-core`. Reverse-dependency review found only
  one stale optional `tidefs-validation` manifest edge to control-plane plus
  scaffold-internal publication/response edges to control-plane. The live
  control-plane, publication-pipeline, and response-registry record definitions
  already reside in `tidefs-types-vfs-core`, so the stale crate roots were
  deleted rather than reclassified. `docs/workspace-package-classification.md`
  now records 145 workspace members, 150 classified roots, and zero
  `scaffold-transitional` rows; `check-workspace-policy` treats any future
  scaffold-transitional row as drift. This reduces TFR-002/TFR-019 package
  authority debt but does not close either item because broader imported docs
  still carry historical package assumptions that need classification.
  The current
  `xtask` terminology, authority, and observe gates no longer require
  deleted or quarantined control-plane, policy-authority, observe, truth-view,
  `check-group terminology`, `check-terminology`, `check-human-api-aliases`,
  `check-authority-publication-spine`, `check-observation-substrate`,
  against current live workspace surfaces. This is not TFR-002 closure because
  other xtask groups and imported docs still carry issue-era labels and stale
  scaffold assumptions that need separate classification. The `tidefs-xtask`
  unit test suite now passes after removing the stale claims unit assertion for
  `open-work item 010` and updating the background-service framework marker
  check for the current `JobKind::Recovery` priority mapping.
  A later block/cluster gate cleanup removed active xtask requirements for the
  deleted `docs/MODULE_MAP.md`, `docs/STATUS.md`, `docs/FEATURE_MATRIX.md`,
  `docs/CURRENT_VS_FUTURE_CAPABILITIES.md`, and
  `docs/UBLK_ACCEPTANCE_BLOCKER_MAP_PC012A` files. Those checks now gate on
  current implementation and per-area design docs only. The adjacent block
  acceptance harness gate no longer depends on the deleted
  `docs/PUBLISHING_CHECKLIST.md`, and the live verification engine source now
  carries the `data_copy_2.verification_engine` component id required by the
  cluster gate.
  `docs/workspace-package-classification.md` is now regenerated from current
  Cargo metadata and manifest discovery as the package-role authority, and
  `check-workspace-policy` validates its counts, package roots, excluded fuzz
  roots, and retired scaffold-transitional boundary. `crates/README.md` and
  `apps/README.md` now defer to that authority instead of carrying competing
  package tables. This reduces TFR-002/TFR-019 drift but does not close either
  item: broader imported docs still need authority classification.
- `TFR-002`: issue #513 adds retired-role enforcement for both
  `scaffold-transitional` and `archive-delete-candidate` roles in
  `check-workspace-policy`, regenerates the classification table from current
  `cargo metadata` (152 workspace packages, 157 classified roots, zero
  retired-role rows), and marks `archive-delete-candidate` as retired in the
  role semantics. This hardens the TFR-002 workspace authority gate but does
  not close the item: the broader import cleanup and remaining dead-crate
  audit still need separate classification work.
- `TFR-002`: issue #681 maps the existing
  `docs/workspace-package-classification.md` authority to the required
  product, harness, third-party, and delete categories instead of creating a
  second drifting package table. The register now records 157 classified
  package roots, zero unclassified roots, zero disputed roots, and zero
  delete-classified roots; each package row keeps its machine-checked role and
  one-line disposition as the per-package justification.
- `TFR-004`: `LocalFileSystem` still has global inode and directory maps;
  before the #664 allocator slice it also carried a global `next_inode_id`.
  Namespace and inode-table crates maintain separate inode allocation
  authorities. The fresh root dataset catalog path now uses
  the same `ROOT_DATASET_ID = [0u8; 16]` as the mounted filesystem and
  SpaceBook bridge, and the FUSE mount path now pushes a resolved catalog
  `DatasetId` into `LocalFileSystem::mounted_dataset_id()` before wrapping the
  engine. Existing pre-rebuild catalogs whose `root` entry already carries a
  different ID now fail closed on mount. Under
  `docs/UNRELEASED_AUTHORITY_POLICY.md`, those retired pre-release catalogs are
  not a default migration target unless a future issue names a real external
  or operator-owned boundary. Namespace
  persistence can feed loaded inode IDs back into `LocalFileSystem` through
  `insert_inode_at()`, and FUSE lookup/forget paths wrap the separate
  `tidefs-inode-table` registry. The main code hotspots now carry
  register-backed `TFR-004` comments rather than anonymous TODOs.
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p
  tidefs-local-filesystem --locked
  root_dataset_catalog_id_matches_mounted_dataset_id`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p
  tidefs-posix-filesystem-adapter-daemon --locked
  mount_lookup_resolves_root_dataset`, and `git diff --check`. The adapter
  test build also repaired stale test initializers for `SyncGuarantee` and
  namespace `rdev` so this package can compile its focused dataset mount test.
- `TFR-004`: commit `0aac81e6` removes another hard-coded root bridge from
  committed space accounting. `LocalFileSystem::commit_space_delta()` now
  synchronizes store-layer `SpaceBook` counters with `mounted_dataset_id`
  instead of `ROOT_DATASET_ID`, so writes through a non-root mounted dataset
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p
  tidefs-local-filesystem --locked
  mounted_dataset_spacebook_counters_use_mounted_dataset_id`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p
  tidefs-local-filesystem --locked
  root_dataset_catalog_id_matches_mounted_dataset_id`, and `git diff --check`.
  This still does not close TFR-004: dataset-scoped inode identity and
  duplicate namespace/inode-table allocation authorities remain open, while
  old root catalog compatibility remains fail-closed unless a future issue
  names the boundary required by `docs/UNRELEASED_AUTHORITY_POLICY.md`.
- `TFR-004`: commit `b789492c` removes the remaining warning-only root dataset
  identity mismatch path. When a persisted dataset catalog contains `root` with
  an ID different from `ROOT_DATASET_ID`, `LocalFileSystem` now returns
  `FileSystemError::CorruptState` during open instead of mounting with
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p
  tidefs-local-filesystem --locked root_dataset_catalog_id_`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p
  tidefs-local-filesystem --lib --locked`, `cargo fmt -p
  tidefs-local-filesystem --check`, and scoped `git diff --check` for the
  touched files. This still does not close TFR-004: fail-closed refusal is the
  default old-catalog policy rather than a migration path, and inode allocation
  remains split across local filesystem, namespace, FUSE lookup registry, and
  inode-table paths.
- `TFR-004`: commit `ba5e7647` fixes a namespace-persistence allocator leak.
  The in-memory `PersistentInodeStore` now preserves explicit nonzero inode IDs
  in `InodeAttributes` and advances the bump allocator past them, matching the
  local-filesystem-backed store's root/bootstrap behavior instead of
  allocating a fresh unrelated inode behind `Namespace::with_persistent_stores`.
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace
  --locked persistent_inode_store_preserves_explicit_inode_ids`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-namespace
  --locked`, `cargo fmt -p tidefs-namespace --check`, and `git diff --check`.
  This still does not close TFR-004: the namespace, local filesystem, FUSE
  lookup registry, and `tidefs-inode-table` still do not share one
  dataset-scoped inode authority.
- `TFR-004`: commit `feaaa6b2` fixes an inode-table persistence fail-open
  path. `persist::load_header()` now reports a present but malformed
  inode-table header as corruption instead of reopening as a fresh empty table,
  and direct/full persisted inode loads now report corrupt present inode or
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p
  tidefs-inode-table --locked corrupt_`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p
  tidefs-inode-table --locked`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p
  tidefs-inode-table --no-default-features --features kernel --locked`,
  `cargo fmt -p tidefs-inode-table --check`, and `git diff --check`.
  This still does not close TFR-004: inode allocation remains split across
  local filesystem, namespace, FUSE lookup registry, and inode-table paths.
- `TFR-004` / `TFR-018`: commit `27cbcd67` fixes the local-filesystem-backed
  namespace persistence bridge for ordinary entry lifetime and special-node
  metadata. Non-shared persistent directory stores are no longer bootstrap-only
  inputs: `Namespace` hydrates delegated directory mirrors from the store and
  writes create, symlink, hard-link, mknod, mkdir, unlink, rename,
  `RENAME_NOREPLACE`, and `RENAME_EXCHANGE` operations through the delegated
  store. The LocalFileSystem bridge now synthesizes `.`/`..` rather than
  serializing real dot entries, updates parent directory link counts for
  bridge-level child-directory entry insert/remove, and can report a directory
  parent from real entries. Special nodes now keep metadata-only facets, mode
  type bits, directory entry kind, and `rdev` across the namespace
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target-namespace-persist cargo test -p
  tidefs-namespace --all-features --locked real_remount -- --nocapture`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target-namespace-persist cargo test -p
  tidefs-namespace --all-features --locked special -- --nocapture`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target-namespace-persist cargo test -p
  tidefs-types-vfs-core --locked facets_special_nodes_are_metadata_only`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target-namespace-persist cargo test -p
  tidefs-local-filesystem --locked
  bridge_dir_entry_updates_parent_link_count_and_parent_lookup`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target-namespace-persist cargo test -p
  tidefs-namespace --all-features --locked`, `cargo fmt -p tidefs-namespace -p
  tidefs-local-filesystem -p tidefs-types-vfs-core --check`, scoped
  `git diff --check`, and `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target-namespace-persist
  cargo clippy -p tidefs-namespace --all-targets --all-features --locked
  --message-format=short` with pre-existing dependency warnings only. This
  still does not close TFR-004 or TFR-018: generic `NamespaceEntry` intent
  insertion still has no device-number authority for replayed special-node
  `rdev`, the delegated store update sequence is not a crash-consistency proof,
  is still required for runtime mknod/rename claims.
- `TFR-004` / `TFR-018`: issue #667 narrows the special-node replay debt for
  local-filesystem create/mknod replay. `NamespaceCreateIntentRecord` embeds
  the authoritative `InodeRecord`, so intent encoding, recovery replay, and
  local namespace persistence validate a single entry/inode id, generation,
  mode, and kind before replaying metadata-only file, FIFO, character-device,
  block-device, and socket entries. The embedded inode record carries
  special-node `rdev`; the generic metadata-buffer mknod record now uses the
  same normalized `rdev` for local VFS mknod. This still does not close
  TFR-004 or TFR-018: dataset-scoped allocation, FUSE lookup-reference
  projection, old-catalog policy, and broader namespace replay authority remain
  in their dedicated follow-up slices.
- `TFR-004`: issue #655 adds `docs/INODE_NAMESPACE_AUTHORITY.md` as the
  design decision artifact for dataset-scoped inode identity. The decision
  selects a dedicated per-dataset inode authority, rejects namespace-owned
  durable allocation and the current global `LocalFileSystem` allocator as
  final owner models, keeps FUSE lookup/forget state as adapter reference
  projection only, and keeps old pre-release catalog mismatches fail-closed by
  default under `docs/UNRELEASED_AUTHORITY_POLICY.md`. Follow-up implementation
  is split into #664 for allocator ownership, #665 for FUSE lookup-reference
  projection, #666 for old catalog fail-closed policy refinement, and #667 for
  special-node `rdev` replay. This documentation slice does not implement
  runtime inode behavior and does not close TFR-004.
- `TFR-004`: issue #666 records the old-catalog policy refinement after issue
  #655. Root catalog absence on first mount is still initialized, but persisted
  dataset catalog bytes that cannot be decoded or loaded now fail closed
  during reopen instead of being treated as an empty catalog. Persisted `root`
  dataset ID mismatch also remains fail-closed. No migration or compatibility
  behavior is authorized unless a future issue names the external boundary or
  operator-owned data set, validation plan, and retirement/graduation criteria
  required by `docs/UNRELEASED_AUTHORITY_POLICY.md`. This does not implement
  dataset-scoped allocator extraction, FUSE lookup-reference ownership, or
  special-node `rdev` replay.
- `TFR-004`: issue #664 extracts the first runtime allocator boundary.
  `LocalFileSystem` now stores a dataset-scoped `DatasetInodeAuthority` instead
  of a bare global `next_inode_id`, uses it for fresh allocation, explicit
  `insert_inode_at()` IDs, root identity, persisted cursor emission, recovery
  seeding, changed-record import seeding, and snapshot rollback cursor
  preservation. Focused local-filesystem tests cover fresh allocation, explicit
  ID advancement, reopen cursor reconstruction, and snapshot rollback reuse
  prevention. This narrows allocator ownership but does not close TFR-004:
  local inode/directory maps remain filesystem-global, and FUSE lookup
  references, inode-table projection policy, and generic special-node `rdev`
  replay stay in the non-overlapping follow-up slices.
- `TFR-005`: the original local-filesystem audit found POSIX timestamp fields,
  `metadata_version`, `data_version`, content object keys, scrub identity,
  intent-log replay ticks, rename metadata stamps, and serialized format fields
  coupled through the same runtime records. The main projection, setattr,
  timestamp-update, and content-key hotspots carry register-backed markers.
  The current closeout map is
  `docs/TIMESTAMP_GENERATION_AUTHORITY.md` section 9. TFR-005 remains open
  until the delegated live runtime families, any conditional future-only
  coverage or ABI rows, and product-claim evidence support closure; stale
  source/documentation slices that are now closed are not remaining blockers.
- `TFR-005`: issues #325, #330, and #331 plus PR #348 separated POSIX
  wall-clock timestamp authority from storage generation and content-version
  identity. `PosixTimeRecord::from_generation` and
  `PosixTimeRecord::legacy_from_versions` are gone,
  `PosixTimeRecord::synthetic(now_ns)` is the named synthetic-inode boundary,
  format version < 5 inode records fail closed instead of reconstructing POSIX
  timestamps from storage fields, and `update_anonymous_size` no longer
  derives a version counter from `mtime_ns`. These closed slices are not
  remaining TFR-005 blockers.
- `TFR-005`: issue #499 produces the comprehensive
  `docs/TIMESTAMP_GENERATION_AUTHORITY.md` design authority document,
  replacing the guardrail version from issue #325. The design doc specifies
  crate-per-concept ownership, monotonicity/wraparound/epoch rules,
  cross-authority relationships, and on-disk format compatibility rules for
  version field changes. Section 9 now records the reconciled closeout map
  instead of a stale unresolved-site list.
- `TFR-005`: issue #694 resolves the intent-log replay and commit-group
  recovery decision. Recovery may initialize `generation`, `data_version`, and
  `metadata_version` from one accepted recovery tick, and later mounted writes
  intentionally let those identities diverge. Future executable coverage or
  runtime guards for that contract are conditional/future-only work, not a
  currently discovered unprepared blocker.
- `TFR-005`: issues #688 and #994 resolve the namespace-revision coupling.
  `InodeRecord` stores `subtree_rev` and `dir_rev`, encode/decode persist both
  counters through a backward-compatible tail extension, projections read the
  stored counters instead of `metadata_version`, and metadata/content mutation
  paths advance `subtree_rev` independently of `metadata_version`.
- `TFR-005`: issue #742 adds `docs/SCRUB_IDENTITY_AUTHORITY.md` as the local
  scrub identity boundary. It records that the content identity carried by
  `ScrubBlockId` is `(inode_id, data_version)` and excludes POSIX timestamps,
  wall-clock time, `metadata_version`, storage-generation ticks, and intent-log
  epochs from scrub identity authority. Issue #650 closed the mounted
  content-scrub read authority slice; live issues #651 and #652 own scrub
  routing and repair dispatch gating.
- `TFR-005`: issue #695 adds `docs/SEND_RECEIVE_VERSION_AUTHORITY.md`, issue
  #1002 adds the focused VFSSEND1 authority guards, and related sender/receive
  follow-ups #777 and #703 are closed. Send/receive stream versions own only
  envelope shape; local payload format versions own POSIX timestamp,
  `data_version`, and `metadata_version` layout. No separate
  timestamp/version reconciliation pass remains to prepare from this register.
- `TFR-005`: issue #746 adds `docs/CONTENT_OBJECT_VERSION_AUTHORITY.md` as the
  content-object version boundary. It records that `data_version` is the
  content identity token for `(inode_id, data_version)` content keys, not a
  reclaim clock, and names the separate reclaim liveness guard:
  `death_commit_group`, `stable_committed_txg`, replacement/base placement
  receipt epoch and generation evidence, and `OrphanReplayWatermark` when
  orphan recovery participates. Live issues #675 and #676 still own receipt
  consumer policy and rebake/reclaim trim implementation.
- `TFR-005`: issue #696 resolves the section 9 format-golden/codec gate for
  the current ABI by making VFS codec/vector manifest drift fail in focused
  tooling. Future serialized ABI changes, such as a local filesystem format
  version bump, remain conditional/future-only rows that must update golden
  vectors and codec surfaces atomically with the ABI change.
- `TFR-006`: Transform authority is still split across mounted-content
  compression, object-store device compression/encryption, helper compression
  and encryption crates, and inline content-addressed dedup. The
  `tidefs-compression` crate correctly warns that mounted writes use
  `ContentCompressionPolicy` and `encode_content_chunk`, but the pool also
  accepts device-level compression/encryption configs. `PoolStore` is
  transform-aware, while many mounted filesystem recovery, write, scrub,
  send/receive, reclaim, and intent-log paths still call `raw_primary_store()`
  or `raw_primary_store_mut()`, explicitly bypassing device transforms. Dedup
  hashes plaintext chunks, writes canonical objects through the raw store, and
  uses redirect checksums/refcounts that are not yet one transform-order
  contract.
- `TFR-006`: commit `ef2cb86c` repairs the public compression observability
  API boundary without widening transform authority. The public
  `LocalFileSystem::effective_compression_policy_report()` no longer returns
  the crate-local mutable `ContentCompressionPolicy`; it returns an owned
  `EffectiveCompressionPolicyReport` snapshot with algorithm, level, savings
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p
  tidefs-local-filesystem --locked
  compression_policy_report_is_public_snapshot`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p
  tidefs-local-filesystem --lib --locked`, `cargo fmt -p
  tidefs-local-filesystem --check`, and `git diff --check`. This removes the
  known `private_interfaces` warning but does not close TFR-006: compression,
  encryption, dedup, and raw-store bypass ordering still need one storage
  transform authority.
- `TFR-006`: commit `91a05295` repairs one pool-label transform subcase.
  `Device::is_encrypted()` now recurses through the compression wrapper, so
  encrypted+compressed devices still set `ENCRYPTION_INCOMPAT` and reopen as
  locked when the key is absent. The nearby transform-order comments now match
  current write flow: compression runs before the encrypted inner device stores
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p
  tidefs-local-object-store --locked
  locked_pool_detects_encrypted_device_behind_compression`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p
  tidefs-local-object-store --locked locked_pool`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p
  tidefs-local-object-store --locked pool_with_key_not_locked_put_get_works`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p
  tidefs-local-object-store --lib --locked`, and `git diff --check`.
  Package-wide `cargo fmt -p tidefs-local-object-store --check` still reports
  pre-existing formatting drift in unrelated object-store files/regions, so it
  remains open for the raw primary-store bypasses, mounted-content/device
  transform authority split, dedup ordering, checksum order, and key handling.
- `TFR-006`: issue #218 adds the checked raw-store inventory at
  `docs/MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY.md`. The source check
  guards current `raw_primary_store()` and `raw_primary_store_mut()` matches:
  `crates/tidefs-local-filesystem/src/lib.rs` has 67,
  `crates/tidefs-local-filesystem/src/crash_recovery.rs` has 1,
  `crates/tidefs-local-filesystem/src/journal_cleaner.rs` has 7,
  `crates/tidefs-local-filesystem/src/vfs_engine_impl.rs` has 6, and
  `crates/tidefs-local-object-store/src/pool/mod.rs` has 7 lower accessor or
  escape-hatch matches. The inventory classifies production mounted paths as
  transform-aware, metadata/raw-only, blocked, or owned by later
  receipt/placement issues, and it names the ordering terms plaintext identity,
  compression frame, encryption frame, checksum, raw media bytes, and reclaim
  identity. The device-level encryption/compression API surface remains unsafe
  to treat as an end-to-end mounted filesystem transform while blocked rows
  remain.
- `TFR-006`: issue #692 isolates crash-matrix raw commit-boundary staging
  behind the private `CrashMatrixRawStagingAuthority` in
  `crates/tidefs-local-filesystem/src/crash_recovery.rs`. The helper stages
  validation-only content, transaction inode, directory, superblock,
  malformed root-slot, and missing-transaction root-commit objects without
  exposing a mounted production write/read path or authorizing mounted
  device-level compression/encryption claims. Production blocked rows for
  content reads/writes, scrub/repair, send/receive, reclaim, intent-log, and
  directory/inode fallback recovery remain open.
- `TFR-006`: commit `8b5b0f70` makes the mounted local-filesystem
  device-transform helpers fail closed instead of silently claiming end-to-end
  encryption or compression. `LocalFileSystem` now rejects open configs with
  device-level encryption or compression using `FileSystemError::Unsupported`
  while the TFR-006 raw-store inventory has blocked production rows. The
  object-store pool transform stack still exists for lower-level pool use; this
  gate only prevents the mounted filesystem API from presenting incomplete
  transform coverage as a
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p
  tidefs-local-filesystem --locked
  device_transform_open_helpers_fail_closed_until_tfr_006_authority`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p
  tidefs-local-filesystem --lib --locked`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p
  tidefs-posix-filesystem-adapter-daemon --locked`, `cargo fmt -p
  tidefs-local-filesystem --check`, and `git diff --check`. TFR-006 remains
  open for the real transform-authority redesign.
- `TFR-007`: The code has a `CapacityAuthority`, but current behavior still
  bridges multiple capacity ledgers. `LocalFileSystem::statfs()` refreshes
  pool physical counters, updates the store-layer `SpaceBook`, derives block
  counters from `CapacityAuthority`, then starts from an allocator report and
  clamps through quota/effective capacity. Write, fallocate, reserve, truncate,
  punch-hole, zero-range, insert/collapse, and unlink-style paths still span
  quota tables, hierarchy checks, `CapacityAuthority` reservations,
  `SpaceAccounting` deltas, extent allocator state, reclaim deltas, obligation
  ledgers, and store-layer `SpaceBook` persistence. The capacity authority docs
  therefore overstate "single authority"; they describe a desired end state,
  not the complete production reality.
- `TFR-007`: `docs/CAPACITY_ACCOUNTING_AUTHORITY.md` records the authority
  decision for issue #680. Mounted dataset capacity is owned by
  `tidefs-local-filesystem::CapacityAuthority`, backed by
  `tidefs-space-accounting` and `tidefs-types-space-accounting-core`.
  Block allocation, dataset properties, cleanup/reclaim, dedup, inode table,
  POSIX adapter, and `tidefsctl` surfaces are classified as physical inputs,
  delta producers, projections, or reporting consumers. The document also
  records explicit non-claims and a follow-up issue map for the non-overlapping
  implementation slices needed before TFR-007 can close, including #857, #858,
  #859, #860, existing #790/#791/#785, and the gated runtime authority closeout
  row that must wait for overlapping #613/#761 local-filesystem capacity paths.
- `TFR-007`: commit `5a01cc11` fixes one zero-range accounting leak.
  `LocalFileSystem::zero_range()` now charges `CapacityAuthority` and physical
  `SpaceAccounting` only for holes that become allocated. Existing DATA and
  UNWRITTEN extents no longer consume capacity a second time, and UNWRITTEN
  extents are moved out of the reserved counter when the current implementation
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p
  tidefs-local-filesystem --locked zero_range_`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p
  tidefs-local-filesystem --lib --locked`, `cargo fmt -p
  tidefs-local-filesystem --check`, and scoped `git diff --check` for the
  touched files. TFR-007 remains open: statfs derivation, quota hierarchy,
  logical/reserved semantics, allocator extents, obligation ledger, and
  store-layer `SpaceBook` persistence still need one authority model.
- `TFR-007`: commit `3e1ab660` fixes one statfs projection leak.
  `fuse_statfs::engine_statfs()` now maps the canonical
  `LocalFileSystem::statfs()` counters directly instead of calling statfs for
  refresh/fsid work and then replacing block counters with raw
  `CapacityAuthority` values. `LocalFileSystem::statfs()` and `statvfs()` now
  share quota/effective-capacity block clamping, use a stable 4096-byte statfs
  reporting block size, and report configured inode capacity as `files` so
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p
  tidefs-local-filesystem --locked statfs_`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p
  tidefs-local-filesystem --locked statvfs_`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p
  tidefs-local-filesystem --lib --locked`, `cargo fmt -p
  tidefs-local-filesystem --check`, and scoped `git diff --check` for the
  touched files. TFR-007 remains open for the full authority model across
  quota hierarchy charging, logical/reserved semantics, allocator extents,
  obligation ledger, reclaim, and store-layer `SpaceBook` persistence.
- `TFR-008`: Durability and cache coherency are still split across several
  mechanisms rather than one contract. The local filesystem combines
  committed-root publication, data intent log, optional namespace intent-log
  buffer, commit-group state machine, sync gate, per-inode write buffers,
  `DirtySet`, range `DirtyPageTracker`, local page cache, hot-read cache, inode
  cache, and best-effort `Drop` commit. Fsync/fdatasync paths mix intent-log
  flush, targeted content-object sync, full `do_commit()`, `sync_data()`,
  sync-gate waiting, and store-wide `sync_all()`. Mount recovery replays the
  object-store intent log before opening the LOG_DEVICE, then separately runs
  commit-group recovery, txg replay, dataset-catalog side persistence, and the
  namespace recovery loop. The cache authority model names multiple dirty-data
  authorities, while the FUSE daemon adds writeback page cache, writeback inode
  cache, dirty-state ranges, block-volume dirty flushing, adapter txg barriers,
  and fsync-handler barriers. Mmap and kmod writeback remain open because the
  local intent log has `SharedMmapMsync` replay support, the POSIX matrix still
  records live mmap coherency as deferred, kmod trait defaults allow mmap/fault
  and cache callbacks without a complete engine contract, and kmod
  address-space writeback still depends on mounted-kernel engine authority.
- `TFR-008`: issue #329 makes crash claim evidence source-qualified at the
  claims gate. The model crash matrix remains model-only evidence, runtime
  crash evidence classes must not point at model-only artifacts, and a
  claims-gate review artifact records why write/fsync and rename crash claims
  remain planned or blocked until runtime crash evidence exists. This does not
  close TFR-008 and does not claim production crash safety, mounted runtime
  durability, or final recovery authority.
- `TFR-008`: issue #511 adds `docs/PAGE_CACHE_WRITEBACK_AUTHORITY.md` as the
  current authority document for dirty page lifecycle, writeback triggers,
  fsync/intent-log/recovery ordering, and the `tidefs-cache-coherency` /
  `tidefs-intent-log` boundary. The new claim path is
  `local.vfs.page_cache_writeback_authority.v1`. This narrows the contract and
  terminology, but it does not implement runtime writeback, close TFR-008, or
  validate crash safety. Issue #443 still owns the cache-coherency writeback
  proof, and issue #445 still owns intent-log replay idempotency.
- `TFR-008`: issue #736 adds
  `docs/PAGE_CACHE_INVALIDATION_AUTHORITY.md` as the companion invalidation
  authority for page-cache trigger granularity, advisory versus mandatory
  invalidation, stale-generation checks, and the FUSE/kernel/cluster lease
  model. This is a design boundary only: it does not implement FUSE
  notifications, kernel page-cache coherency, clustered lease plumbing, mmap
  fault behavior, or claim-gate evidence. Follow-up implementation is split
  across #752 for FUSE data-cache invalidation, #753 for kernel page-cache
  coherency fences, and #754 for clustered cache lease epoch invalidation.
- `TFR-008`: issue #1065 expands `docs/PAGE_CACHE_WRITEBACK_AUTHORITY.md`
  into the integrated recovery/fsync/writeback/mmap authority decision. The
  chosen boundary keeps durability in committed-root publication plus durable
  intent-log replay, keeps cache-core page state non-durable, keeps
  cache-coherency and lease crates authoritative for stale-generation fencing,
  and classifies FUSE/kmod page caches as projections. It also records explicit
  non-claims and the follow-up implementation map for dirty lifecycle
  unification, local fsync/recovery ordering, FUSE projection, kmod projection,
  and claim-gate evidence.
- `TFR-009`: Kernel residency is still a tiered bring-up, not terminal; TideFS
  is not yet full-kernel. The kernel-resident architecture doc explicitly says the
  current mounted operation slice uses a small fixed in-kernel namespace/data
  table and is not the final object/extent/intent-log engine, page-cache
  The block-kmod entrypoint opens a hard-coded `/dev/tidefs_pool_member`
  backing path and wraps it in a local `PoolCoreOps` adapter that still says
  it should be replaced by the canonical `KernelPoolCore` bridge. The
  entrypoint now refuses to register `/dev/tidefs` when that pool-backed
  backend is absent unless a Kbuild smoke job explicitly enables the
  `tidefs_block_kmod_bringup_backend` cfg, so the old silent in-kernel-buffer
  fallback no longer presents as production-shaped block authority. The common kmod
  `VfsEngine` trait defaults still return `ENOSYS` for block read/write,
  flush, discard, write-zeroes, and zero-range operations, while the Kbuild
  `RawBlockFile` flush path is a no-op that relies on guest-side sync. That is
  not yet one kernel-resident pool authority for VFS, block export, recovery,
  writeback, and remanence.
- `TFR-010`: Snapshot lifecycle is not single-sourced. Basic create/delete,
  clone create/delete/promote, hold-protected retention pruning, and catalog
  listing now share the local `SnapshotRecord`, dataset catalog, and lifecycle
  pin authority. Bookmark entries are non-retaining local anchors. The module
  now frames that shape as local lifecycle surface rather than ZFS-equivalent
  completeness. Send/receive exports current and snapshot roots, incremental
  export filters content by object key/checksum, and local incremental receive
  now refuses absent, loose, divergent, or unprotected base roots before
  publishing a new selected root. These paths are not unified with deadlist
  accounting, placement receipts, distributed send/receive authority, conflict
  resolution, or integrated snapshot reclaim.

  TFR-010 investigation outcome (issue #1246): `docs/SNAPSHOT_CLONE_DEADLIST_AUTHORITY.md`
  records the live snapshot/clone/send-receive behavior and cross-subsystem contracts.
  Deadlist integration design owned by #1248. Distributed snapshot shipping
  design decision recorded in `docs/design/distributed-snapshot-shipping.md`
  (issue #1250); VFSSEND2 selected as protocol foundation, and section 7.2
  records the initial scheduling/admission policy from #1261.
- `TFR-011`: Operator/UAPI authority is not yet one boundary.
  Commit `7dbb0759` removes the fake `pool list` parser surface instead of
  accepting a command whose handler only said scaffolding had been removed, and
  downgrades cluster placement/heal exercise wording to development
  diagnostics. Issue #239 adds a `tidefsctl` local-only admission table and
  wires privileged pool, device, dataset, snapshot, block, and defrag handlers
  through `LocalOnlyGuard`. Issue #243 removes the FUSE daemon's independent
  `cluster_authorized` boolean/raw-token pairing: `tidefsctl mount` constructs
  standalone mount authority, while `pool mount --cluster` carries a typed,
  validated `PoolLeaseToken` into daemon admission. Issue #278 gates the
  preview UAPI doc, tidefsctl book chapter, operator-authz boundary, and
  claims-gate policy against the exact command classification/admission table.
  Issue #656 chooses the current pre-alpha operator boundary: the `tidefsctl`
  command registry is the command-surface authority, admission stays in the
  privileged-admission registry, live-owner routes must fail closed without live
  evidence, and cluster prototypes/development diagnostics must not inherit
  final operator-UAPI wording. TFR-011 remains open for the mapped follow-ups:
  command-registry enforcement, live-owner routing audit, preview-UAPI
  cross-references, cluster diagnostic/prototype separation, runtime validation,
  and any future production UAPI or ABI freeze.
Issue #1267 records the current runtime-fed operator product-surface decision: no runtime-fed operator product surface exists, the P10-04 truth-surface law is missing from the repository, and no product carrier class is selectable until TFR-011 and TFR-017 close. The decision maps follow-ups for P10-04 disposition, TFR-011/TFR-017 closeout, and documentation cleanup.
- `TFR-012`: Device lifecycle and media privacy remain incomplete. Pool-member
  backing must be one byte-addressable media model: block devices for
  production and regular files for hidden development mode. Directory
  `LocalObjectStore` compatibility is not a valid pool-member device mode.
  Segment free still performs best-effort hole punching in that compatibility
  path, and that is not proven media erasure. The public `tidefsctl` parser now
  rejects directory object-store handles for device removal/rebuild, but the
  internal compatibility helper still imports labels, preloads all target
  objects, maps object ids locally, depends on supplied surviving store
  directories, maps synthetic device paths to directories, syncs survivors,
  and anchors removal on the target store. That is not yet a
  pool-authoritative add/remove/replace/remanence lifecycle. Issue #14 closes
  the narrow invalid-media/discard capability bug, and issue #16 establishes
  the explicit pool media contract: user pool-device admission rejects
  directories, `DeviceConfig` carries the backing kind, byte-addressable file
  and block devices share fixed-offset labels and single-segment object
  storage, directory compatibility no longer advertises discard, non-zero
  direct discard fails explicitly, and directory-only pool trim/free paths
  report zero bytes discarded. TFR-012 remains open for real discard-capable
  backing devices, segment-reclaim remanence, online replacement/removal
  authority, and byte-device remanence policy.
- `TFR-013`: stage words remain widespread; examples include CLI stubs,
  runners, old issue-era gate labels outside the first cleaned xtask gate set,
  and app/workspace classification docs that list deleted or quarantined
  packages as current surfaces.
- `TFR-013`: issue #681 confirms the current package classification authority
  has no `scaffold-transitional`, `archive-delete-candidate`, or other
  delete-classified package roots. Future dead-scaffolding package candidates
  must carry TFR-002/TFR-013 evidence and an issue-backed delete/archive plan
  instead of using a retired role as a holding area.
- `TFR-013`/`TFR-016`: commit `ccf087a4` removes one POSIX adapter
  structural/tracing module was deleted after `#![deny(dead_code)]` proved it
  markers were removed from live read/write/rename/flush/fsync dispatch
  surfaces, unused test/helper functions were deleted or converted into an
  executed append-handle unit test, and embedded NUL test literals were escaped
  so source scanners keep treating `fuse_vfs_adapter.rs` as text. Focused
  broader stage wording, `OW-*`/`PC-*`/`NEXT-*` labels, and stale scaffold
  authority remain open.
- `TFR-016`: active storage spec constants and their source-level tests/gates
  no longer use the issue-era `open-work item` phrase. The live strings now
  use TideFS storage/checksum item wording, and `xtask` does not require
  imported docs to carry that phrase as a marker. This is not closure:
  shorter `OW-*`, `PC-*`, and `NEXT-*` labels remain in source, xtask, and
  imported docs until each surface is renamed, classified as historical, or
  deleted.
- `TFR-016`: the focused short-label scan
  still reports 104 active non-doc files: 13 under `apps/`, 59 under
  5 under `xtask/`. The matching documentation scan reports 82 `docs/` files.
  The active residue clusters are storage/xtask gates, block-volume and ublk
  POSIX/FUSE/kernel `NEXT-*` notes, security/performance harness labels, and
  storage authority comments/tests. Cleanup policy: active source and current
  operator-facing text should use descriptive TideFS capability names, not
  issue labels as authority; historical issue labels may remain only in
  docs classified as historical input or in explicit provenance references.
  scripts no longer carry short issue-label authority. Fio workloads and ublk
  active non-doc short-label inventory dropped from 104 files to 96 files; the
  remaining surface is 13 `apps/`, 59 `crates/`, 16 `nix/`, 3 `scripts/`, and
  5 `xtask/` files.
- `TFR-016`: active `scripts/` no longer carry short issue-label authority
  either. The FUSE, kernel VFS, and metadata performance baseline scripts now
  use descriptive baseline names, no longer emit `issue` fields into their
  output directories or old issue-bound worker module paths. The focused
  `scripts/` scan for `OW-*`, `PC-*`, and `NEXT-*` returns no hits, and the
  active non-doc short-label inventory is now 93 files: 13 `apps/`, 59
  `crates/`, 16 `nix/`, and 5 `xtask/`.
- `TFR-016`/`TFR-019`: the kernel VFS performance Nix wrapper now matches the
  cleaned script policy: no `NEXT-*` label, no JSON `issue` field, no old
  issue-bound worker path, and no stale worker checkout for commit discovery.
  It also now copies the resolved `POSIX_VFS_KO` path instead of the undefined
  `POSIX_TFS_KO` variable. The active non-doc short-label inventory is now 92
  files: 13 `apps/`, 59 `crates/`, 15 `nix/`, and 5 `xtask/`. Broader Nix
  JSON `issue` fields, issue-numbered output paths, and packet headings still
  matches 26 `nix/` files.
- `TFR-016`/`TFR-019`: the kernel VFS long-haul soak Nix wrapper now uses
  `issue` field, and current `/root/tidefs` git metadata instead of a stale
  worker checkout. It also now copies the resolved `POSIX_VFS_KO` path instead
  of the undefined `POSIX_TFS_KO` variable. The active non-doc short-label
  inventory is now 91 files: 13 `apps/`, 59 `crates/`, 14 `nix/`, and 5
  scan still matches 25 `nix/` files.
- `TFR-016`/`TFR-019`: the kernel block partition/reread, queue-depth, and
  configurable/generic module paths, external scratch output paths without
  issue numbers, and current `/root/tidefs` git metadata. Their generated
  manifests no longer write JSON `issue` fields or old A-register provenance.
  The active non-doc short-label inventory is now 88 files: 13 `apps/`, 59
  residue scan still matches 22 `nix/` files.
- `TFR-016`/`TFR-019`: the kernel block crash-consistency, no-daemon, and fio
  configurable/generic module paths, issue-free external output directories,
  and current `/root/tidefs` git metadata. Their generated manifests no longer
  write JSON `issue` fields, old A-register provenance, or issue-numbered
  blocker text. The active non-doc short-label inventory is now 87 files: 13
  `apps/`, 59 `crates/`, 10 `nix/`, and 5 `xtask/`. The broader Nix
- `TFR-016`/`TFR-019`: the FUSE fio baseline, open-unlink/rename soak,
  product demo soak, namespace-scale QEMU, and namespace-scale host wrappers
  now avoid `NEXT-*` labels, JSON `issue` fields, and cwd-dependent git
  metadata in the cleaned QEMU wrappers. The active non-doc short-label
  inventory is now 84 files: 13 `apps/`, 59 `crates/`, 7 `nix/`, and 5
  `nix/` files. FUSE `fsx` and FUSE `xfstests` still need separate cleanup
  because their QEMU-pin paths remain issue-numbered.
  configurable/generic module paths, no JSON `issue` field, current
  `/root/tidefs` git metadata, and copies the resolved `POSIX_VFS_KO` module
  instead of the undefined `POSIX_TFS_KO` variable. The active non-doc
  residue scan now matches 13 `nix/` files.
  gate wording instead of `NEXT-*` or issue-number banners. The active non-doc
  short-label inventory is now 81 files: 13 `apps/`, 59 `crates/`, 4 `nix/`,
  10 `nix/` files.
- `TFR-015`/`TFR-016`/`TFR-019`: QEMU pin manifests now use
  helper no longer accepts issue ids. The FUSE fsx pin path, FUSE xfstests
  titles. The active non-doc short-label inventory remains 81 files, and the
- `TFR-016`/`TFR-018`/`TFR-019`: the remaining kernel/kmod Nix wrappers
  no longer emit old packet labels, issue fields, issue-numbered output paths,
  or worker worktree paths. The lockdep/KCSAN/KASAN, mount namespace,
  wording, current `/root/tidefs` git metadata, generic module output paths,
  and the resolved `POSIX_VFS_KO` module copy. The active non-doc short-label
  inventory is now 77 files: 13 `apps/`, 59 `crates/`, and 5 `xtask/`; the
- `TFR-016`: commit `5add9c63` removes the stale `NEXT-REL-013` label from
  the live `tidefsctl diag` and support-bundle documentation comments. The
  focused support-bundle scan now returns no `NEXT-REL-013` hits under
  `cargo check -p tidefsctl --locked` passes with `CARGO_TARGET_DIR` outside
  the repo. The active non-doc short-label inventory is now 74 files: 11
  `apps/`, 58 `crates/`, and 5 `xtask/`.
- `TFR-016`/`TFR-017`: commit `96d78e33` removes the stale `NEXT-MN-023`
  tracker label from live scrub/repair fanout comments in `tidefs-storage-node`
  and `tidefs-transport`. The focused scrub/repair scan now returns no
  `NEXT-MN-023` hits under `apps/tidefs-storage-node` or the transport
  replication module, and `cargo check -p tidefs-storage-node -p
  tidefs-transport --locked` passes with `CARGO_TARGET_DIR` outside the repo.
  This is label hygiene only: TFR-017 remains open for real cross-replica scrub
  comparison, repair authority, rollback, and recovery semantics. The active
  non-doc short-label inventory is now 71 files: 9 `apps/`, 57 `crates/`, and
  5 `xtask/`.
- `TFR-013`/`TFR-016`/`TFR-019`: issue #796 refreshes the `OW-*`, `PC-*`, and
  `NEXT-*` label audit at `92ed488a`. The focused scan finds 153 files with
  785 references: 556 `OW-*`, 160 `PC-*`, and 69 `NEXT-*`. `OW-*` and `PC-*`
  are mixed current/historical design cross-references that must be backed by a
  current authority row, claim id, or GitHub issue before they can be cited as
  current evidence. `NEXT-*` is stale Forgejo-era or stage-gate residue unless
  preserved inside a doc already classified as historical input. The write set
  is too broad for one behavior-free edit, so the retarget/removal work is
  split into #980, #982, #983, #984, and #985 with disjoint domain write sets;
  issue #796 records the classification and split without changing runtime
  behavior.
- `TFR-016`: issue #679 converts the remaining anonymous inline debt comments
  and active fixture/prose marker strings under `crates/` and `apps/` into
  register-addressed notes or neutral fixture words. Post-conversion
  `rg -c 'TODO|FIXME|HACK|XXX|TBD|CONTINUE' crates/ apps/` reports no matches,
  confirming zero anonymous markers in the issue scope.
- `TFR-014`: issue #508 completes the current package-metadata and Rust
  file-local notice audit. Root Cargo metadata reports all workspace packages
  as `GPL-2.0-only WITH Linux-syscall-note` except the vendored/patched
  `fuser` package, which remains MIT with provenance documented in
  `docs/LICENSING.md`. The five excluded cargo-fuzz harness manifests declare
  `GPL-2.0-only WITH Linux-syscall-note` explicitly. All tracked non-vendored
  Rust source files now carry first-line SPDX headers; TideFS-owned files use
  `GPL-2.0-only WITH Linux-syscall-note`, kernel module entry points keep their
  documented Linux-style `GPL-2.0` markers, and `crates/tidefs-fuser` source
  provenance is left untouched. `check-workspace-policy` now verifies these
  manifest, provenance, and Rust-header gates so future third-party imports or
  new exceptions must be documented before merge.
- `TFR-014`: issue #690 re-ran the licensing hygiene audit after the workspace
  metadata refresh. The focused manifest scan found 163 tracked `Cargo.toml`
  files and no missing license fields: 156 inherit the workspace license, six
  declare `GPL-2.0-only WITH Linux-syscall-note` explicitly, and
  `crates/tidefs-fuser/Cargo.toml` preserves upstream `MIT` provenance. The
  Rust source scan covered 1,664 `.rs` files under `apps/`, `crates/`,
  `xtask/`, and `kmod/`; outside the documented vendored `fuser` exception,
  every file starts with the expected TideFS SPDX header or one of the
  documented kernel `GPL-2.0` module markers. No open provenance item remains
  for this audit slice.
- `TFR-014`/`TFR-019`: the active repo rename surface is clean at the literal
  source level: the focused legacy-name scan over `/root/tidefs` reports no
  active hits outside excluded build output, lockfiles, and the vendored
  `tidefs-fuser` package; no tracked paths carry the old project name; no
  non-target path names carry the old project name; and Cargo metadata reports
  no workspace package names or manifest paths carrying it. The mechanical
  remote rename is now complete: `/root/tidefs` points at
  `http://172.16.106.12/forgejo/forgeadmin/tidefs.git`, live Forgejo reports
  `forgeadmin/tidefs`, and the checkout no longer needs a local
  `tidefs.forgejo-repo` override. This is still not full TFR-019 closure
  because imported documentation remains only partially classified.
  metadata. The current repo rule is external scratch output by default, with
  no checked-in run-output doctrine or release authority derived from old
  containers audited so far now use report terminology, including ublk
  integrity, kernel readdir, kernel directory namespace, FUSE inode metadata,
  page-cache writeback, no-daemon full-stack, crash-consistency, mmap fault, Nix
  the focused recovery-loop, intent-log, block-kmod, kmod-posix-vfs, and
  performance-gate docs/readmes. Old Nexus-era work/issue terminology has also
  follow-up source/comment pass also removed issue-specific artifact
  quarantine wording, historical no-daemon QEMU artifact paths, release-gate
  with focused old-phrase scans, `git diff --check`, Nix parse checks,
  formatting drift outside this cleanup. Broader `NEXT-*` tags, imported
  status docs, release scripts, and release-closeout wording still need
  classification and removal where they encode old authority. The first
  focused TFR-019 cleanup classified the 15 imported
  `closes open-work`, or `open-work item` wording as review material and
  removed that narrow closeout wording from them. TFR-019 remains broad, but
  GitHub issue #689 now classifies every path that remained in the initial open
  queue in `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`. Those new rows leave the
  documents as historical input until narrower source and claims-gate reviews
  can justify any future current-policy/current-spec promotion.
  no longer exposes `--require-issue`, and the operator-demo and
  of JSON `issue` fields or issue-numbered default run ids. Focused `nix/` and
  `scripts/` scans for that interface and JSON issue metadata now return no
  matches. A follow-up active-script scan found two benchmark runners still
  using issue numbers as default output identity; the FUSE fio and ublk perf
  directories and environment files. This keeps runtime output tied to
  follow-up fixed the performance baseline package loader and QEMU baseline
  JSON emitters on the same axis: comparator refs are now descriptive
  `issue` fields are optional parse compatibility only. A further xtask
  block-volume and cluster marker gates and dropped the deleted publishing
  checklist from the block acceptance gate; the broader TFR-015 surface
  remains open because imported docs still contain historical run paths and
  status doctrine.
- `TFR-002`/`TFR-013`/`TFR-016`/`TFR-019`: a fresh
  `tidefs-xtask check-group storage` run after the block/cluster cleanup
  proves the storage gate family is still not current authority. Passing
  early rows cover local object-store, recovery, integrity pipeline, scheduler,
  extent map, and dataset lifecycle source checks, but the group still fails
  on deleted `docs/STATUS.md`, `docs/FEATURE_MATRIX.md`,
  `docs/MODULE_MAP.md`, `docs/PUBLISHING_CHECKLIST.md`,
  `docs/PREVIEW_POSIX_SUBSET.md`, POSIX scoreboard/FUSE preview docs, and
  deleted adapter source files such as `fuse_preview.rs`. It also expects
  missing or changed product surfaces including `crates/tidefs-online-verifier`,
  `apps/tidefs-scrub` markers, orphan-index integration markers,
  `pub const fn new` constructors in btree/dir-index, and old `OW-*`/`PC-*`
  labels. Treat storage group cleanup as a multi-area authority rebuild, not a
  single missing-doc patch.
- `TFR-002`/`TFR-016`/`TFR-019`: the active `check-group storage`
  aggregate now runs only current live storage checks that match files present
  in the TideFS tree: local object-store, format/policy, local filesystem,
  recovery/no-fsck, integrity pipeline, mount invariant, root retention,
  xattr storage, background scheduler/orphan-reclamation, polymorphic extent
  map, dataset lifecycle, and space-accounting watermarks. The pass output no
  longer uses old issue/`OW-*`/`PC-*` labels. This does not close the
  individual retired/stale storage check commands; they remain a retarget or
  deletion queue under this register rather than release authority. The
  `check-group all` storage section now uses this same current aggregate
  instead of directly invoking retired preview/status/POSIX commands or the
  duplicated nested spacemap branch. A follow-up platform cleanup restored
  and retargeted the platform gate away from old `OW-*` marker requirements.
  The post-platform `check-group all` run still failed on non-storage authority
  work: 17 clippy warnings, stale extent-map and locator-table cluster
  markers, and 29 format-golden errors.
- `TFR-002`/`TFR-015`/`TFR-019`: the format-golden corpus now treats the
  manifest as the source fixture authority instead of retaining stale generated
  vectors beside it. `generate-format-golden` removes existing `.bin` vectors
  unmanifested `.bin` files. The stale outcome/control-plane/observe/
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-xtask --locked`,
  `cargo fmt -p tidefs-xtask -- --check`, and `git diff --check`. A current
  `check-group all` run now fails only on `policy/check-code-navigability`,
  with 80 clippy warnings.
- `TFR-002`/`TFR-015`/`TFR-019`: a deeper all-target clippy inventory showed
  that the code-navigability blocker was not only cosmetic warnings. Stale
  all-target compile failures existed in erasure-coded-store integration test
  configs, fuser all-features native backend selection, chunk-shipper test
  mutability, and a placement-runtime policy literal. Those compile blockers
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo clippy -p tidefs-erasure-coded-store -p fuser -p tidefs-chunk-shipper --all-targets --all-features --locked`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-erasure-coded-store --all-targets --locked`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-chunk-shipper --all-targets --locked`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p fuser --all-targets --all-features --locked --no-run`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo clippy -p tidefs-placement-runtime --all-targets --all-features --locked`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p tidefs-placement-runtime --all-targets --locked`,
  and `git diff --check`. A full
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo clippy --workspace --all-targets --all-features --locked --message-format=short`
  must be retargeted or pruned as its own authority slice rather than counted
  as a clean lint surface.
  pruned stale source-surface mirrors that referenced deleted POSIX runtime,
  observe, worker-meta, namespace, and writeback APIs, removed the old
  compile-only API mirror module, kept live worker-IO behavior smoke tests as
  `StoreOptions` literals to durable defaults with focused overrides. The
  previously-unreached capacity smoke helpers now run and exposed one stale
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo run -q -p tidefs-xtask -- check-claims-gate`,
  and `git diff --check`. A full
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo clippy --workspace --all-targets --all-features --locked --message-format=short`
  adapter FUSE mount harness, where reusable helpers compiled into multiple
  test crates under deny-level dead-code lints. The broad module-level
  `dead_code` allowance was removed; only `remount`, `create_read_write`,
  `open_read_only`, `read_all`, and `patterned_bytes` now carry item-local
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target-posix-harness cargo clippy -p tidefs-posix-filesystem-adapter-daemon --all-targets --all-features --locked --message-format=short`
  with the existing warning inventory only. This clears the hard POSIX harness
  blocker without closing the broader clippy warning inventory or TFR-018
  mounted edge work.
- `TFR-002`/`TFR-015`/`TFR-019`: the next POSIX adapter code-navigability
  slice removes the package-local clippy warning sites that remained after the
  harness blocker: duplicated `cfg`, missing `Default`, a derivable default,
  stale format strings, unit-value bindings in placement persistence, and an
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target-posix-warnings cargo clippy -p tidefs-posix-filesystem-adapter-daemon --all-targets --all-features --locked --message-format=short`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target-posix-warnings cargo test -p tidefs-posix-filesystem-adapter-daemon --lib --locked placement_recorder`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target-posix-warnings cargo test -p tidefs-posix-filesystem-adapter-daemon --lib --locked lock_dispatch`,
  and `git diff --check`. The focused clippy command still reports dependency
  crate warnings from the broader workspace inventory, but no new
  `tidefs-posix-filesystem-adapter-daemon` warnings. Package-wide
  `cargo fmt -p tidefs-posix-filesystem-adapter-daemon -- --check` remains red
  on pre-existing formatting drift and is not treated as a clean gate for this
  slice.
- `TFR-002`/`TFR-019`: the extent-map warning slice removes package-local
  clippy noise from two authority-adjacent paths without changing behavior.
  The B-tree serializer now asks the backing tree directly with `is_empty()`
  when deciding whether to emit the mandatory empty leaf page, and the kernel
  `rustfmt --check crates/tidefs-extent-map/src/btree.rs crates/tidefs-extent-map/src/kernel.rs`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target-extent-map-warnings cargo clippy -p tidefs-extent-map --all-targets --all-features --locked --message-format=short`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target-extent-map-warnings cargo test -p tidefs-extent-map --locked`,
  and `git diff --check`. The clippy command still reports dependency-crate
  warnings from the broader inventory, but no package-local
  `tidefs-extent-map` warnings. Package-wide
  `cargo fmt -p tidefs-extent-map -- --check` still reports pre-existing
  allocator formatting drift.
- `TFR-017`: Transport and cluster authority is not one product-grade runtime
  contract yet. Storage-node has a `RuntimeAuthority` spine and a
  transport-backed store path. Commit `b1517c76` closes the config-file
  authority bypass: JSON config now preserves live TCP/RDMA authority, carries
  `replication_factor`, and no longer falls back to the local store simply
  because startup came from a config file. Commit `d7d31643` separately restores
  storage-node test-build hygiene after the existing `carrier_policy` field.
  Distributed snapshot shipping design (#1250) selects VFSSEND2 as the protocol foundation; concrete transport binding (TCP, RDMA) remains open. TFR-017 remains open because the live store derives quorum from
  `replication_factor` and opens remote replica sessions. The narrow
  carrier-policy/runtime-fallback slice now checks policy before runtime
  RDMA-to-TCP demotion: `prefer` keeps disclosed TCP recovery, while `enforce`
  refuses both permanent RDMA carrier loss and reconnect-exhausted degradation
  before the session becomes TCP evidence. This does not close the remaining
  transport/cluster gaps: RDMA hardware validation, partition recovery,
  cross-replica scrub/repair, and distributed transaction authority. Commit
  `6954336d` improves one no-quorum subcase:
  `TransportReplicatedStore` now snapshots the previous primary payload before
  put/delete, restores the local primary on no-quorum failure, and sends
  best-effort compensating put/delete messages to replicas that acknowledged
  the failed mutation. This is not a distributed transaction law: sent but
  unacknowledged replicas, replica inventory, partition recovery, and
  scrub/repair authority remain open. Commit `eead3eff` fixes the narrow peer
  sync identity bug: `SyncResponse` now carries 32-byte `ObjectKey` values and
  the storage-node server reads local payloads by exact object key instead of
  converting key bytes through lossy UTF-8 and re-hashing them as names. This
  makes the existing sync response keyed by real local inventory entries.
  This receipt-authority slice makes `RepairObject` require a real shared
  `PlacementReceiptRef` and validates key, length, digest, policy shape, and
  target width before local repair writes, while scrub reports disclose that
  the storage-node object-store backend does not itself expose pool placement
  receipts. This is still not a full cross-replica inventory authority with digest
  comparison, epochs, membership/fencing, or repair selection.
  Multi-node scrub responses are still logged but not compared. Issue #738
  records the design decision in
  `docs/CROSS_REPLICA_SCRUB_COMPARISON_DESIGN.md`: repair writeback must be
  gated on receipt-bound, epoch-bound cross-replica comparison evidence, and
  unreconciled disagreements must fail closed as
  `ScrubRepairOutcome::CrossReplicaDisagreement`. The implementation split is
  #756 for transport exchange, #757 for deterministic comparison, and #758 for
  repair-dispatch gating. Repair source selection, recovery closure, and live
  TCP/RDMA runtime proof remain incomplete. Cluster
  pool docs and CLI also disagree: the orchestrator source still says live
  dispatch is not wired into the orchestrator, while `tidefsctl cluster pool
  create` has a TCP transport adapter and the placement/heal exercise commands
  are now explicitly classified as development diagnostics rather than final
  UAPI.
- `TFR-018`: initial kmod/xfstests edge fixes landed as separate commits, and
  the stale kmod `MountOptions` test initializers no longer block
  `cargo test -p tidefs-kmod-posix-vfs --tests --no-run --locked`.
  The K7 xfstests Nix runner now distinguishes a QEMU runner timeout before
  `harness-fail` rows with `QemuGuestTimeout`, and it avoids a final-row
  remount probe that could create unrelated noise after the requested set is
  exhausted. Its aggregate counters now count only requested xfstests rows for
  pass/fail/skipped status, while separately reporting infrastructure/probe row
  counts so helper rows cannot inflate or hide requested-test outcomes.
  lookup path: cached ENOENT remains valid only while the engine still reports
  lookup retry.
  Remaining kernel/POSIX edge wiring is broader than those fixes. The C shim
  registers `generic_file_mmap()` and `address_space_operations` callbacks for
  `read_folio`, `write_begin`, `write_end`, `dirty_folio`, and `writepages`.
  Issue #260 reconciles the prior Rust-source mismatch by documenting
  `DirtyFolioTracker`/`writeback_folios()`/`page_mkwrite` as source-model only
  and making the Rust direct mmap path fail closed. The live C writeback path
  copies folio bytes directly through `tidefs_posix_vfs_engine_write()`;
  `dirty_folio` deliberately avoids the engine from atomic MM paths. POSIX and
  xfstests coverage remain separate TFR-018 work. Each edge still needs
  runtime validation before broad closure.
- `TFR-018`: the first direct kmod page-cache reconciliation slice is now
  source- and Kbuild-checked. Engine-backed `write_iter` sends buffered writes
  through `generic_file_write_iter()`, while direct writes now run Linux
  generic write checks, privilege stripping, timestamp update, page-cache
  `generic_write_sync()`. Engine `copy_file_range` now rejects cross-superblock
  errors without hiding already-copied bytes. Address-space writeback now
  allocates and fills write-begin folios from the engine, unlocks/puts folios
  on every write-end path, treats allocation/short-write errors as real
  mapping errors, writes dirty folios through an opened engine handle, re-dirties
  failed writeback folios, and persists mtime/ctime after successful writeback.
  `cargo test -p tidefs-kmod-posix-vfs --locked copy_file_range`,
  `rustfmt --edition 2021 --check kmod/src/kernel_types.rs`, `git diff --check`,
  and Linux 7.0 Kbuild module compilation with output outside the repo. This
  does not close TFR-018: the C a_ops table still lacks readahead, writepage,
  prove the runtime contract.
- `TFR-018`: commit `e777ce9d` adds the next kmod page-cache mutation slice.
  Engine-backed fallocate now flushes and unmaps affected cached ranges before
  changes, runs size-dependent collapse/insert checks under `inode_lock()`, and
  rejects insert-range at or past EOF with Linux-shaped bounds. The same slice
  marks fallocate inode metadata dirty, records mapping errors from
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p
  tidefs-kmod-posix-vfs --locked fallocate`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p
  tidefs-kmod-bridge --locked`, `git diff --check`, and Linux 7.0 Kbuild
  module compilation with output under `/root/ai/tmp`. This still does not
  close TFR-018: mounted QEMU fallocate/writeback/mmap/direct-I/O behavior and
  the missing a_ops callbacks remain open.
- `TFR-018`: commit `e300e053` completes the matching Rust `KernelEngine`
  insert-range implementation behind the C shim admission path. Insert-range
  now shifts live write-buffer spans and live DATA/UNWRITTEN extents to the
  right of the insertion point, splits entries that straddle the insertion
  offset, grows inode size, and leaves the inserted range sparse instead of
  returning `EOPNOTSUPP` after the shim already admitted the operation.
  tidefs-kmod-posix-vfs --locked fallocate`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p
  tidefs-kmod-bridge --locked`,
  `rustfmt --edition 2021 --check
  crates/tidefs-kmod-posix-vfs/tidefs_posix_vfs_main.rs`, `git diff --check`,
  and Linux 7.0 Kbuild module compilation with output under `/root/ai/tmp`.
  This still does not close TFR-018: mounted QEMU insert-range/fallocate,
  writeback, mmap, and direct-I/O behavior plus the missing a_ops callbacks
  remain open.
- `TFR-018`: commit `67669445` fixes a kmod zero-range writeback hole. A
  staged zero writeback range can cross DATA extents, UNWRITTEN extents, and
  holes; the old flush path only persisted zeros when one DATA extent covered
  the whole staged range and otherwise treated zero entries as clean. The
  engine now finds every overlapping DATA live extent, writes zeros to only
  those physical ranges through the mounted pool I/O context, and leaves holes
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p
  tidefs-kmod-posix-vfs --locked fallocate`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p
  tidefs-kmod-bridge --locked`,
  `rustfmt --edition 2021 --check
  crates/tidefs-kmod-posix-vfs/tidefs_posix_vfs_main.rs`,
  `git diff --check`, and Linux 7.0 Kbuild module compilation with output
  under `/root/ai/tmp`. This still does not close TFR-018: mounted QEMU
  zero-range/writeback/mmap/direct-I/O behavior and the remaining a_ops
  callback contract remain open.
- `TFR-018`: commit `3e223d4d` tightens the engine-backed
  source Linux page-cache range before delegating to Rust; `KernelEngine` now
  also drains matching live source write-buffer entries to the mounted pool
  before running the read/write copy loop, instead of relying on transient
  passed: `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p
  tidefs-kmod-posix-vfs --locked copy_file_range`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p
  tidefs-kmod-bridge --locked`,
  `rustfmt --edition 2021 --check
  crates/tidefs-kmod-posix-vfs/tidefs_posix_vfs_main.rs`,
  `git diff --check`, and Linux 7.0 Kbuild module compilation with output
  under `/root/ai/tmp`. This still does not close TFR-018: mounted QEMU
  copy/writeback/mmap/direct-I/O behavior and the remaining a_ops callback
  contract remain open.
- `TFR-018`: commit `d8af4a16` tightens the live-data reserved-tail append
  guard. `KernelEngine::can_extend_live_data_tail()` now rejects any
  same-inode live extent overlap, including UNWRITTEN ranges, before allowing
  a DATA tail to grow into reserved physical space, and it rejects overlapping
  pending write-buffer entries before the direct-write path extends metadata.
  This prevents the small-write append fast path from creating overlapping
  live extent state when a fallocate/unwritten or staged write range occupies
  `rustfmt --edition 2021 --check
  crates/tidefs-kmod-posix-vfs/tidefs_posix_vfs_main.rs`, `git diff --check`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p
  tidefs-kmod-posix-vfs --locked fallocate --lib`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p
  tidefs-kmod-bridge --locked`, and Linux 7.0 Kbuild module compilation with
  output under `/root/ai/tmp/tidefs-kmod-posix-vfs/module-out-tail-reservation`.
  A broader `cargo test -p tidefs-kmod-posix-vfs --locked write --lib` run is
  not green in this checkout; it fails existing address-space, mmap, and
  writeback expectation tests outside the Kbuild entry file. This keeps
  TFR-018 open for the full writeback/mmap/runtime contract.
  checkpoints as rows are recorded and before guest diagnostics are collected,
  appends delayed diagnostic paths after collection, and classifies missing
  requested rows after a partial nonzero QEMU exit as harness failures instead
  `nix-instantiate --parse nix/vm/k7-vfs-xfstests-nixos-test.nix` and
  truth but does not turn a failed or timed-out xfstests run into product
  acceptance.
- `TFR-018`: the host K7 xfstests wrapper now also writes structured
  unchanged: Nix realizes artifacts, QEMU runs outside the Nix build sandbox,
  and the local host kernel is not used for filesystem behavior.
- `TFR-018`: the same wrapper now also classifies failures before QEMU launch
  when Nix cannot build the generated VM runner artifact. Those paths emit
  structured `NixVmArtifactBuildFailure` rows and retain `nix-vm-build.log`
  product behavior.
- `TFR-018`: the K7 xfstests wrapper now snapshots the TideFS source tree once
  at invocation start and passes that immutable store path to every generated
  NixOS VM build. Isolated rows no longer observe concurrent worktree edits or
  provenance; it does not change product behavior.
- `TFR-018`: commit `886c4a42` fixes the matching non-zero live writeback
  hole after the earlier zero-range slice. The previous flush path required a
  single DATA extent to cover each staged non-zero write-buffer entry, so
  writeback over sparse gaps or UNWRITTEN extents could fail instead of
  materializing the staged bytes. `KernelEngine` now creates DATA extents for
  missing or non-DATA spans before persisting each DATA segment through the
  mounted pool I/O context. The zero-writeback path remains sparse-preserving.
  crates/tidefs-kmod-posix-vfs/tidefs_posix_vfs_main.rs`,
  `git diff --check --cached -- crates/tidefs-kmod-posix-vfs/tidefs_posix_vfs_main.rs`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p
  tidefs-kmod-bridge --locked`, `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target
  cargo test -p tidefs-kmod-posix-vfs --locked fallocate --lib`, and Linux
  7.0 Kbuild module compilation with output under
  `/root/ai/tmp/tidefs-kmod-posix-vfs-writeback/module-out`. This still does
  not close TFR-018: mounted QEMU writeback, mmap, copy, direct-I/O, and the
  remaining a_ops callback contract remain open.
- `TFR-018`: commit `91419e2a` aligns the Rust `KernelEngine`
  `copy_file_range` loop with the C shim's partial-progress contract. The C
  shim already returns copied bytes in preference to a later error; the engine
  now stops and returns the byte count when destination writeback reports
  `ENOSPC` after earlier chunks were copied, while `ENOSPC` before any copied
  --check crates/tidefs-kmod-posix-vfs/tidefs_posix_vfs_main.rs`,
  `git diff --check -- crates/tidefs-kmod-posix-vfs/tidefs_posix_vfs_main.rs`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo test -p
  tidefs-kmod-posix-vfs --locked copy_file_range`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p
  tidefs-kmod-bridge --locked`, and Linux 7.0 Kbuild module compilation with
  output under `/root/ai/tmp/tidefs-kmod-posix-vfs-copy-enospc/module-out`.
  This is not mounted runtime closure for copy/writeback/mmap/direct-I/O.
- `TFR-018`: the C shim now carries explicit register-backed comments at the
  two `writepages` engine-failure sites explaining why the folio must be
  re-dirtied. `writeback_iter()` clears the folio dirty bit before returning
  it to the filesystem, so an engine error or short engine write must call
  `folio_redirty_for_writepage()` before `folio_end_writeback()` to preserve
  Linux 7.0 out-of-tree Kbuild module build against the prepared shared tree,
  producing `tidefs_posix_vfs.ko` under
  `/root/ai/tmp/tidefs-kmod-redirty-invariant/module-out` with the same
  pre-existing Rust objtool fall-through warnings. This is an invariant
  documentation slice, not mounted runtime closure.
- `TFR-018`: issue #258 narrows the mounted-kernel mmap/writeback proof to the
  live Linux 7.0 C/generic-filemap path. The authority chain is
  `tidefs_posix_vfs_file_mmap()` -> `generic_file_mmap()` ->
  C `read_folio`/`dirty_folio`/`writepages` -> Rust engine read/write/fsync
  bridge calls, with writeback failures re-dirtying folios for retry and
  truncate/direct-write invalidation using Linux page-cache discard helpers for
  the affected ranges. The Rust `KmodVfsVmOps`, `DirtyFolioTracker`, and
  page-authority direct C bridge remain unregistered/source-model only and are
  classified as unsupported in the mounted artifact. This first-boot row does
  not close crash-consistent mmap, broad xfstests, direct-I/O, FUSE
  writeback-cache correctness, placement receipt correctness, or distributed
  mmap coherency.
- `TFR-018`: issue #260 demotes the remaining Rust direct vm-ops bridge so it
  is fail-closed instead of product-looking. `KmodPosixVfs::mmap()` now
  returns `EOPNOTSUPP`, the Rust constructor is named
  `source_model_vm_ops()`, and docs/validation keep `custom-rust-vm-ops` as an
  explicit unsupported row. The only mounted first-boot mmap/writeback
  authority remains the C `generic_file_mmap()` plus C
  `address_space_operations` path from #258. TFR-008/TFR-018 stay open for
  crash-consistent mmap, broad xfstests, direct-I/O, FUSE writeback-cache
  correctness, placement receipt correctness, and distributed mmap coherency.
- `TFR-018`: issue #275 tightens the mounted C truncate/invalidation path
  without registering `.invalidate_folio` or reopening the Rust vm-ops source
  model. Engine-backed `setattr(ATTR_SIZE)` now takes the mapping invalidate
  lock, waits dirty mapped or buffered folios in the size-change range with
  `filemap_write_and_wait_range()`, unmaps and invalidates that range, then
  calls the Rust engine `setattr` bridge and applies `truncate_setsize()` to
  the canonical returned size. Truncate-extend uses the same C helper path over
  the extension range so stale folios from before the size change cannot become
  the authority for new zero-filled bytes. The kernel mmap validation artifact
  now requires mounted rows for truncate-down discard, truncate-extend zero
  reads, mapped dirty truncate-down with `msync`/`munmap`, remount readback,
  and buffered overwrite after a prior mapping. This reduces the mounted
  TFR-008/TFR-018 page-cache-invalidation gap, but does not close
  crash-consistent mmap, broad xfstests, direct-I/O, FUSE writeback-cache
  correctness, placement receipt correctness, or distributed mmap coherency.
- `TFR-018`: commit `822848b7` routes live inode writes through the active
  storage path when a mounted `KernelPoolCore` I/O context is available.
  `stage_live_inode_write()` now asks
  `write_live_data_range_to_storage()` to materialize/write the range, clears
  overlapping staged write-buffer bytes, updates inode size, and only falls
  back to the older staged/reserved path when active storage is unavailable.
  crates/tidefs-kmod-posix-vfs/tidefs_posix_vfs_main.rs`, `git diff --check`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo check -p
  tidefs-kmod-bridge --locked`, focused
  `tidefs-kmod-posix-vfs` `fallocate`, `write::tests::`, and
  `file::tests::dispatch_write` library tests, and Linux 7.0 Kbuild module
  compilation under `/root/ai/tmp/tidefs-kmod-live-write-active-storage/`.
  direct-I/O, or no-daemon closure.
- `TFR-018`: commit `38ac310e` fixes the mounted `generic/075` fallocate
  regression that remained after the live write storage-path slice. A
  buffered write can leave the dirty EOF folio resident when `fallocate()`
  extends allocation beyond EOF but still starts in the same page; the final
  focused source checks as the implementation commit plus QEMU outside the Nix
  sandbox:
  That run reported `generic/075` passed in Linux 7.0 mounted-kernel VFS with
  `passed=1`, `product_failures=0`, `harness_failures=0`, and
  `local_host_kernel_used=false`. This proves that specific fallocate/page-cache
  edge, not the broader TFR-018 writeback, mmap, direct-I/O, or no-daemon
  contract.
- `TFR-019`: Imported documentation still needs authority classification. The
  preview manual, getting-started guide, claims gate, and claims policy now use
  current tracked docs and current cluster-pool markers, and a live
  `check-claims-gate` run with
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target` passes against the canonical
  `forgeadmin/tidefs` Forgejo slug without a local repo override. This is not
  documentation closure:
  `docs/workspace-package-classification.md` now records the current
  148-package workspace plus five excluded fuzz package roots and is checked by
  `check-workspace-policy`. GitHub issue #689 classifies every remaining path
  from the initial open queue in `docs/DOCUMENTATION_AUTHORITY_REGISTER.md` as
  historical input, but broader process authority still needs deliberate
  completion. Historical-input rows cannot be treated as release truth without
  a later source and claims-gate review that promotes the specific document.
- `TFR-019`: The checksum/BLAKE3 authority slice for GitHub issue #332
  classified `docs/BLAKE3_USAGE_POLICY.md` as current policy only for BLAKE3
  placement and review. `docs/CHECKSUM_ARCHITECTURE_DESIGN.md`,
  `docs/design/1683-checksum-architecture-g3-pillar-design-spec.md`,
  `docs/design/end-to-end-checksum-architecture-g3-pillar.md`, and
  `docs/security/blake3-integrity-boundary.md` are historical input, not current
  production checksum, scrub self-heal, erasure-coded integrity, or tamper-proof
  root authority. This reduces the checksum/BLAKE3 documentation drift under
  TFR-019, but it does not close TFR-019 broadly and does not close any
  storage-integrity implementation or claim-registry item.
- `TFR-011`/`TFR-019`: the kernel and preview UAPI authority slice for GitHub
  issue #337 classifies the scoped kernel/UAPI documents in
  `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`. The scanned preview UAPI doc is
  current spec only for the checked tidefsctl command classification/admission
  table and current non-release VFS codec hook description; the adjacent old
  UAPI layout note is historical input because it points at the retired
  `tidefs-schema-codec-vfs-boundary` crate path. Kernel-resident architecture,
  workflow, rollout, and locking docs are current policy/spec only within their
  stated development, target-architecture, rollout, and source-level model
  scopes. This reduces TFR-011/TFR-019 drift but does not close full-kernel,
  broader operator UAPI, kernel residency, storage authority, block-volume,
  xfstests, crash-recovery, distributed, or documentation drift debt.
- `TFR-011`/`TFR-019`: GitHub issue #661 classifies
  `docs/OPERATOR_UAPI_AUTHORITY.md` as current spec for the issue #656
  pre-alpha operator UAPI boundary decision. The decision makes
  `COMMAND_SURFACES` and `command_admission` the current command-surface and
  privileged-admission authorities, keeps diagnostics and prototypes scoped by
  their weaker classes/routing, and preserves non-claims for production ABI
  freeze, kernelspace readiness, distributed operator maturity, remote policy
  authority, and release readiness. This reduces TFR-011/TFR-019 drift but does
  not close the follow-up implementation, cross-reference, claims-gate, runtime
  validation, or broad documentation-authority debt.
- `TFR-019`: GitHub issue #512 extends documentation-authority coverage across
  the remaining high-impact imported design surface not covered by the #497
  slice: architecture/local-format references, block-volume and ublk adapter
  source-boundary docs, FUSE/POSIX adapter docs, kernel/UAPI boundary docs, and
  operator/placement docs. The new rows in
  `docs/DOCUMENTATION_AUTHORITY_REGISTER.md` classify scoped source-boundary
  docs as current specs, the FUSE adapter bypass rule as current policy, and
  broad production-depth ledgers as historical input. GitHub issue #689 resolves
  the remaining initial-open-queue classifications by leaving the unpromoted
  design-subdir documents as historical input. TFR-019 remains open for any
  per-document source audit needed before promoting additional docs to current
  spec or policy.
- `TFR-019`: GitHub issue #1136 classifies `docs/REQUEST_CONTRACT.md` as
  current spec only for the TideFS-owned request/completion contract shape:
  portable `tidefs-types-vfs-core` records, the v1 `tidefs-schema-codec-vfs`
  fixed-width little-endian request/completion codecs, strict decoder
  rejections, and explicit unsupported request payloads. The slice reviewed the
  request-contract doc, authority register, index, nextgen verification and
  trace-oracle docs, claim-registry and scanned claims-gate surfaces, FUSE/uBLK
  environment-model references, model-core and trace-oracle references, and
  closed issues #282, #528, #751, and #1066 as historical lineage evidence.
  This reduces request-contract documentation-authority drift but does not
  close runtime adapter rewiring, FUSE, ublk, kernel VFS, RPC, storage,
  placement, rebuild, reclaim, offload, mounted-runtime validation,
  release-readiness, claims-gate closure, or broad TFR-019 debt.
- `TFR-019`: GitHub issue #1164 classifies
  `docs/design/coordination-pipeline-health-advancement-strategy.md` as
  historical input after reviewing the documentation authority register,
  `docs/INDEX.md`, `docs/GITHUB_PR_DEVELOPMENT.md`, and the file itself. The
  retained Forgejo labels, lane/blocking claims, deleted `docs/STATUS.md` and
  `docs/FEATURE_MATRIX.md` references, and health-score/dashboard machinery are
  archival context only. They are not current TideFS automation policy,
  implementation status, release-readiness evidence, or worker scheduling
  authority. TFR-019 remains open for the other unclassified #952
  status/matrix leftovers and any separate source/evidence review needed before
  promoting a document to current policy or current spec.
- `TFR-019`: GitHub issue #1165 classifies
  `docs/design/coordination-pipeline-status-update.md` as historical input after
  reviewing the authority register, this TFR-019 note set, the imported #1833
  design, `docs/INDEX.md`, `docs/GITHUB_PR_DEVELOPMENT.md`, and bounded lineage
  from the numbered status-update snapshots. The file's `STATUS.md`,
  `FEATURE_MATRIX.md`, lane-summary, health-score, and Forgejo label machinery
  are retired design input only; current TideFS coordination remains GitHub
  issues and pull requests plus the repo documentation entry points. This
  reduces status/matrix drift but does not classify the numbered status-update
  snapshots or promote a current automation, implementation-status,
  release-readiness, or worker-scheduling claim.
- `TFR-019`: GitHub issue #1234 classifies
  `docs/design/coordination-pipeline-status-update-1954.md` as historical input
  after reviewing the authority register, this TFR-019 note set, the imported
  #1954 status-update snapshot, `docs/INDEX.md`,
  `docs/GITHUB_PR_DEVELOPMENT.md`, the already-classified #1164 health-strategy
  and #1165 status-update-architecture rows, and bounded lineage from the main
  `coordination-pipeline-status-update.md` architecture document. The file's
  `STATUS.md`, `FEATURE_MATRIX.md`, lane-health, coordinator-proliferation,
  cluster-service implementation-status, deferred-wire-up, and Forgejo API/label
  machinery are retired Forgejo-era snapshot artifacts only; current TideFS
  coordination remains GitHub issues and pull requests plus the repo
  documentation entry points. This reduces status/matrix drift but does not
  classify the -1767, -1839, -1915, or -2054 snapshots or promote a current
  automation, implementation-status, release-readiness, or worker-scheduling
  claim.

- `TFR-019`: GitHub issue #1152 classifies
  `docs/design/1971-pool-import-export-7-phase-implementation-plan.md` as
  historical input after reviewing the documentation authority register, this
  TFR-019 note set, the imported Forgejo #1971 phase plan, closed #931/#934
  incumbent-comparison evidence, sibling #1137 context, bounded source/doc
  searches, `crates/tidefs-types-pool-label-core/`,
  `crates/tidefs-local-object-store/src/pool_importer.rs`,
  `crates/tidefs-local-object-store/src/pool_exporter.rs`,
  `crates/tidefs-local-object-store/src/device_manager.rs`,
  `crates/tidefs-local-object-store/src/device_health.rs`,
  `validation/claims.toml`, and `docs/CLAIM_REGISTRY.md`. The retained
  design-spec status, phase labels, "new"/"not yet implemented" source notes,
  Forgejo links, hot-spare, evacuation, online topology, cluster-lease, and
  public-capability wording are historical implementation-planning context
  only. This reduces the #952 status/matrix leftover set but does not promote a
  current pool import/export spec, product readiness, or broad pool lifecycle
  claim.

- `TFR-019`/`TFR-018`: the current xfstests harness authority slice repairs
  `xfstests-runner` as a diagnostic scoreboard wrapper, and sends output under
  runner help path no longer carries a bare `--per-test` command or duplicate
  parser/help entries. Current navigation docs no longer point readers at the
  or `docs/PUBLISHING_CHECKLIST.md` files, and `check-module-owners` is
  retargeted to the current PC-002 owner map plus `docs/INDEX.md` instead of
  passed `bash -n` for the touched xfstests scripts,
  `scripts/tidefs-xfstests-runner --help`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo run -q -p tidefs-xtask -- check-module-owners`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo run -q -p tidefs-xtask -- check-platform-scaffolding`,
  `CARGO_TARGET_DIR=/root/ai/tmp/tidefs-target cargo run -q -p tidefs-xtask -- check-claims-gate`,
  `cargo fmt -p tidefs-xtask -- --check`, and `git diff --check`. This does
  not close TFR-018 or Forgejo #6582: the `generic/001`-`generic/013` FUSE
  tranche still needs actual outside-sandbox QEMU execution and per-row
  classification.
- `TFR-018`: a first post-authority-cleanup FUSE xfstests runtime row now has
  launched `qemu-system-x86_64` outside the Nix build sandbox with KVM,
  booted Linux 7.0.0, mounted the TideFS FUSE adapter, and reported
  `passed=11`, `failed=0`, `blocked=0`, `skipped=0`. The passed rows include
  `xfstests_generic/001` plus FUSE mount, sanity, unmount, and daemon-stop
  rows; the copied boot log is
  with 329 lines. A follow-on run on commit `74a4be91` used
  and reported `passed=22`, `failed=0`, `blocked=0`, `skipped=0`. The passed
  rows include `xfstests_generic/002` through `xfstests_generic/013` plus the
  same FUSE mount, sanity, unmount, and daemon-stop checks; the copied boot log
  is
  with 373 lines. Together these runs classify the #6582
  `generic/001`-`generic/013` FUSE smoke tranche as PASS. This does not close
  TFR-018 broadly: recovery, fsync, writeback, mmap, cache authority, and
  mounted-kernel/no-daemon acceptance behavior still need separate review and matching
- `TFR-018`: the next FUSE xfstests runtime tranche also has current-head
  launched `qemu-system-x86_64` outside the Nix build sandbox with KVM,
  booted Linux 7.0.0, mounted the TideFS FUSE adapter, and reported
  `passed=47`, `failed=0`, `blocked=0`, `skipped=0`. The passed rows include
  `xfstests_generic/014` through `xfstests_generic/050` plus the FUSE mount,
  Together with the #6582 runs, this classifies the current
  `generic/001`-`generic/050` FUSE smoke surface as PASS. This still does not
  close TFR-018 broadly: recovery, fsync, writeback, mmap, cache authority,
  mounted-kernel/no-daemon acceptance behavior, and broader xfstests/fsx/
  printed after helper output without a trailing newline, and it backfills a
  late noisy rows such as fio/fsx failures visible in JSON instead of only in
  `qemu-boot.log`.
- `TFR-018`: the #6586 FUSE xfstests tranche now has current-head
  command
  launched `qemu-system-x86_64` outside the Nix build sandbox with KVM,
  booted Linux 7.0.0, mounted the TideFS FUSE adapter, and produced one
  structured row for every requested `generic/051` through `generic/100` test.
  The aggregate counters are `passed=12`, `failed=16`, `blocked=0`,
  `unsupported=15`, and `skipped=17`; the xfstests rows specifically are
  `generic/084` and `generic/086` PASS, 16 product FAIL rows
  (`generic/053`, `062`, `069`, `070`, `071`, `074`, `075`, `080`, `087`,
  `088`, `091`, `095`, `097`, `098`, `099`, `100`), 15 unsupported rows, and
  This classifies the #6586 tranche without claiming it passed and without
  closing TFR-018 broadly: the product failures and remaining recovery, fsync,
  writeback, mmap, cache-authority, mounted-kernel/no-daemon, fsx, fsstress,
  and broader xfstests work remain separate implementation/review items.
- `TFR-018`: commit `b26233d4` cleans per-row FUSE xfstests scratch/result
  stores before each guest row so one noisy row does not turn the following
  rows into unclassified residue. The #6588 FUSE xfstests tranche now has
  `b26233d4`, the command
  launched `qemu-system-x86_64` outside the Nix build sandbox with KVM,
  booted Linux 7.0.0, mounted the TideFS FUSE adapter, and produced one
  structured row for every requested `generic/101` through `generic/150` test.
  The aggregate counters are `passed=12`, `failed=15`, `blocked=0`,
  `unsupported=24`, and `skipped=9`; the xfstests rows specifically are
  `generic/103`, `generic/117`, and `generic/141` PASS, 14 product FAIL rows
  (`generic/105`, `109`, `112`, `113`, `120`, `124`, `126`, `127`, `129`,
  `130`, `131`, `132`, `133`, `135`), 24 unsupported rows, and 9 skipped rows.
  The extra failed row is the `unmount` teardown check reporting
  not as TFR-018 closure.
- `TFR-018`: the #6590 FUSE xfstests tranche now has current-head
  command
  launched `qemu-system-x86_64` outside the Nix build sandbox with KVM,
  booted Linux 7.0.0, mounted the TideFS FUSE adapter, and produced one
  structured row for every requested `generic/151` through `generic/200` test.
  The aggregate counters are `passed=10`, `failed=4`, `blocked=0`,
  `unsupported=43`, and `skipped=3`; the xfstests rows specifically had zero
  PASS rows, 4 product FAIL rows (`generic/169`, `184`, `192`, `198`), 43
  unsupported rows, and 3 skipped rows. The infrastructure rows, including
  `unmount` and `daemon_stop`, passed. A focused current-tree rerun recorded as
  `fuse-generic-184-20260603T183844Z.json`
  now passes `generic/184` after FUSE special-node `mknod` preserves device
  node type, `rdev`, and `/dev/null` write-through behavior. A second focused
  current-head rerun at
  `fuse-generic-192-20260603T190341Z.json`
  now passes `generic/192`. A focused patched-tree rerun at
  `fuse-generic-169-20260603T192830Z-fsgetxattr.json`
  now passes `generic/169` after `FS_IOC_FSGETXATTR` reports a Linux-shaped
  empty `struct fsxattr` and the xfstests helper keeps a stable per-device
  backing store across remounts. A focused patched-tree rerun at
  `fuse-generic-198-20260604T004023Z-final.json`
  now passes `generic/198` with `passed=12`, `failed=0`, `blocked=0`,
  `unsupported=0`, and `skipped=0` after sparse same-size direct-write
  overlays, open-unlink sparse anonymous data, deferred O_DIRECT flush
  behavior, and empty-mountpoint cleanup landed. This is still not TFR-018
  closure.
- `TFR-018`: commit `2bb253a6` makes the FUSE xfstests guest use the
  coreutils `mv` binary so `generic/245` is no longer classified by BusyBox
  wording alone. The #6592 FUSE xfstests tranche now has current-head
  command
  launched `qemu-system-x86_64` outside the Nix build sandbox with KVM,
  booted Linux 7.0.0, mounted the TideFS FUSE adapter, and produced one
  structured row for every requested `generic/201` through `generic/250` test.
  The aggregate counters are `passed=16`, `failed=10`, `blocked=0`,
  `unsupported=19`, and `skipped=15`; the xfstests rows specifically have 7
  PASS rows (`generic/208`, `210`, `211`, `212`, `221`, `246`, `248`), 9 FAIL
  rows (`generic/207`, `209`, `214`, `215`, `237`, `239`, `245`, `247`,
  `249`), 19 unsupported rows, and 15 skipped rows. The extra failed row is
  the `unmount` teardown check reporting `Device or resource busy`, while
  `daemon_stop` passed. The failures currently point at timeout hangs,
  fallocate/truncate EIO, ACL errno drift, ENOSPC/truncate output, a remaining
  coreutils `mv` expected-output mismatch, and missing expected `generic/247`
  Commit `07262209` also avoids claiming clean unmount in future FUSE
  xfstests manifests when the row data records teardown failure. This
  as TFR-018 closure.
- `TFR-018`: the #6594 FUSE xfstests tranche now has current-head
  command
  launched `qemu-system-x86_64` outside the Nix build sandbox with KVM,
  booted Linux 7.0.0, mounted the TideFS FUSE adapter, and produced one
  structured row for every requested `generic/251` through `generic/300` test.
  The aggregate counters are `passed=9`, `failed=7`, `blocked=0`,
  `unsupported=34`, and `skipped=10`; the xfstests rows specifically have
  zero PASS rows, 6 FAIL rows (`generic/257`, `258`, `263`, `285`, `286`,
  `294`), 34 unsupported rows, and 10 skipped rows. The extra failed row is
  the `unmount` teardown check reporting `Device or resource busy`, while
  `daemon_stop` passed. The failures currently point at readdir/inode-number
  drift, negative timestamp wrapping, fsx truncate EIO, SEEK_DATA/SEEK_HOLE
  sanity failure with cleanup EIO, a sparse seek timeout, and special-node or
  not as TFR-018 closure.
- `TFR-018`: the #6596 FUSE xfstests tranche now has current-head
  command
  launched `qemu-system-x86_64` outside the Nix build sandbox with KVM,
  booted Linux 7.0.0, mounted the TideFS FUSE adapter, and produced structured
  rows through `generic/345` before `generic/346` wedged in the mmap/write
  `holetest` path. The owned guest was terminated after the row had exceeded
  the 600s per-test timeout, and the rescued primary JSON recorded
  `generic/346` through `generic/350` as blocked because no parsed rows
  appeared after the hang. A tail run on the same commit classified
  scratch output at
  Commit `efe90d25` then copied coreutils `truncate` into the guest, and a
  focused run at
  passed `generic/315`, replacing the primary run's missing-command failure
  4 PASS rows (`generic/308`, `315`, `337`, `339`), 11 FAIL rows
  (`generic/306`, `307`, `309`, `310`, `313`, `318`, `319`, `323`, `340`,
  `344`, `345`), 1 BLOCKED row (`generic/346`), 18 unsupported rows, and
  16 skipped rows. The failures currently point at read-only/special-node
  expected-output drift, ACL and timestamp update drift, 600s timeout hangs,
  truncate-down timestamp drift, ACL inheritance/userns errno drift, and
  ENOSPC/ftruncate/file-exists behavior. This classifies the #6596 tranche as
- `TFR-018`: commit `4c3b6044` copies coreutils `md5sum` into the FUSE
  xfstests guest so rows that require checksum output no longer fail only
  because BusyBox/initrd lacks that command. The #6598 FUSE xfstests tranche
  the command
  launched `qemu-system-x86_64` outside the Nix build sandbox with KVM,
  booted Linux 7.0.0, mounted the TideFS FUSE adapter, and produced structured
  rows through `generic/395`; `generic/391` timed out after the 600s per-test
  bound, and the rescued JSON marked `generic/396` through `generic/418`
  blocked because no parsed rows appeared after the owned guest was stopped. A
  focused run at
  rechecked `generic/360` on committed head after the `md5sum` fix; the row
  still fails with a missing temporary-file cleanup line, so it is now a real
  product or exact-output failure rather than a missing-command harness
  failure. A committed-head tail run at
  classified `generic/396` through `generic/418` without blocked rows. The
  historical final #6598 xfstests-row classification had 2 PASS rows
  (`generic/377`, `403`), 8 FAIL rows (`generic/354`, `360`, `375`, `391`,
  `393`, `394`, `401`, `412`), 0 BLOCKED rows, 20 unsupported rows, and 38
  skipped rows. On 2026-06-04, current head rechecked `generic/375` with
  adapter file/directory regressions and a direct mounted FUSE reproduction;
  `generic/375` is no longer carried as an expected ACL failure. Remaining
  #6598 failures point at ENOSPC/ftruncate/file-exists behavior, missing temp
  cleanup after checksum, direct-I/O timeout, ftruncate EIO/ENOSPC behavior,
  special-node/find-by-type setup drift, and checksum read EIO. This classifies
  the #6598 tranche as no-go
- `TFR-018`: the #6587 Linux 7.0 mounted-kernel VFS xfstests tranche now has
  `tidefs_posix_vfs.ko` matching the generated NixOS VM kernel. The accepted
  matrix uses
  for `generic/061` through `generic/069`,
  for `generic/070`,
  for `generic/071` through `generic/074`,
  for `generic/075` and `generic/077` through `generic/080`,
  for `generic/076`,
  and
  Deferred rows from the shared `061-070` and `071-080` runs and the first
  final buckets are 23 PASS rows (`generic/056`, `058`, `059`, `060`, `061`,
  `062`, `063`, `064`, `065`, `066`, `067`, `070`, `071`, `072`, `075`,
  `076`, `080`, `088`, `089`, `090`, `096`, `097`, `098`), 11 product FAIL
  rows (`generic/057`, `069`, `073`, `074`, `083`, `084`, `085`, `086`,
  `087`, `092`, `100`), 12 unsupported rows, and 4 skipped rows, with no
  deferred, harness-fail, or environment-refusal rows in the accepted matrix.
  `forgeadmin/linux:tidefs/linux-7.0`; no Linux source patch is required for
  this classification issue. This classifies #6587 as no-go mounted-kernel
- `TFR-018`: the #6589 Linux 7.0 mounted-kernel VFS xfstests tranche now has
  `tidefs_posix_vfs.ko` matching the generated NixOS VM kernel. The accepted
  matrix uses
  for `generic/101` and `generic/102`,
  for `generic/103` through `generic/110`,
  for `generic/121` through `generic/127`,
  for `generic/128` through `generic/130`,
  and
  Rows after `generic/102` from the first shared `101-110` run and deferred
  `generic/128` through `generic/130` rows from the shared `121-130` run are
  final buckets were 14 PASS rows (`generic/101`, `103`, `104`, `106`, `107`,
  `109`, `112`, `117`, `120`, `124`, `126`, `131`, `132`, `141`), 3 product
  FAIL rows (`generic/102`, `127`, `129`), 29 unsupported rows, and 4 skipped
  rows, with no deferred, harness-fail, or environment-refusal rows in the
  accepted matrix. The product failures pointed at repeated clean remount/replay
  records `linux_ref: none` against `forgeadmin/linux:tidefs/linux-7.0`; no
  Linux source patch was required. Issue #335 / PR #336 narrowed this tranche
  by fixing mounted-kernel live-data allocator tail reuse: issue-branch
  `k7-vfs` dispatch
  https://github.com/tidefs/tidefs/actions/runs/27624454132 passed
  `generic/102`, `generic/127`, and `generic/129` with no product-fail,
  harness-fail, environment-refusal, deferred, unsupported, or skipped rows,
  and control dispatch https://github.com/tidefs/tidefs/actions/runs/27625310616
  kept `generic/101` passing. Broader TFR-018 recovery, fsync/syncfs,
  writeback, mmap, direct-I/O, no-daemon residency, and full xfstests coverage
  remain open; this is not TFR-018 closure.
- `TFR-018`: the #6591 Linux 7.0 mounted-kernel VFS xfstests tranche now has
  `tidefs_posix_vfs.ko` matching the generated NixOS VM kernel. The accepted
  matrix uses
  and
  `161-163` and tail `164-170` runs supersede it. The final buckets are 4 PASS
  rows (`generic/169`, `177`, `184`, `192`), no product FAIL rows, 43
  unsupported rows, and 3 skipped rows, with no deferred, harness-fail, or
  proof records `linux_ref: none` against `forgeadmin/linux:tidefs/linux-7.0`;
  no Linux source patch is required for this classification issue. This
  not as TFR-018 closure.
- `TFR-018`: the #6593 Linux 7.0 mounted-kernel VFS xfstests tranche now has
  `tidefs_posix_vfs.ko` matching the generated NixOS VM kernel. The accepted
  matrix uses
  for `generic/201` through `generic/204`,
  for `generic/205` through `generic/210`,
  for `generic/241` through `generic/247`, and
  for `generic/248` through `generic/250`. The first shared `201-210` run's
  deferred rows for `generic/205` through `generic/210` and the first shared
  `241-250` run's deferred rows for `generic/248` through `generic/250` are
  are 5 PASS rows (`generic/215`, `221`, `236`, `246`, `248`), 7 product FAIL
  rows (`generic/204`, `213`, `224`, `228`, `245`, `247`, `249`), 36
  unsupported rows, and 2 skipped rows, with no deferred, harness-fail, or
  proof records `linux_ref: none` against `forgeadmin/linux:tidefs/linux-7.0`;
  no Linux source patch is required for this classification issue. This
  not as TFR-018 closure.
- `TFR-018`: the #6595 Linux 7.0 mounted-kernel VFS xfstests tranche now has
  `tidefs_posix_vfs.ko` matching the generated NixOS VM kernel. The accepted
  matrix uses
  for `generic/251` through `generic/260`,
  for `generic/261` through `generic/270`,
  for `generic/271` through `generic/273`,
  for `generic/274`,
  for `generic/275`,
  for `generic/276` through `generic/280`,
  and
  The first shared `271-280` run's deferred rows for `generic/274` through
  and the post-row writeback/VRBT loops after `generic/274` and `generic/275`
  3 PASS rows (`generic/255`, `286`, `294`), 7 product FAIL rows
  (`generic/257`, `258`, `269`, `273`, `274`, `275`, `285`), 38 unsupported
  rows, and 2 skipped rows, with no deferred, harness-fail, or
  proof records `linux_ref: none` against `forgeadmin/linux:tidefs/linux-7.0`;
  no Linux source patch is required for this classification issue. This
  not as TFR-018 closure.
- `TFR-018`: the #6599 Linux 7.0 mounted-kernel VFS xfstests tranche now has
  `tidefs_posix_vfs.ko` matching the generated NixOS VM kernel. The helper
  module smoke at
  load with `Invalid module format`. The accepted matrix uses
  through `generic/361`,
  through `generic/371`,
  through `generic/387`,
  through `generic/403`, and the isolated-row replacement run
  for `generic/404` through `generic/418`. Post-timeout deferred rows,
  post-`generic/361` blanket mount failures, and the shared-run no-space tail
  (`generic/354`, `360`, `376`, `377`, `393`, `394`, `403`, `404`), 8
  product FAIL rows (`generic/361`, `371`, `387`, `401`, `409`, `410`,
  `411`, `416`), 32 unsupported rows, and 20 skipped rows, with no deferred,
  harness-fail, or environment-refusal rows in the accepted matrix. The
  `forgeadmin/linux:tidefs/linux-7.0`; no Linux source patch is required for
  this classification issue. This classifies #6599 as no-go mounted-kernel
- `TFR-018`: the #6597 Linux 7.0 mounted-kernel VFS xfstests tranche now has
  `tidefs_posix_vfs.ko` matching the generated NixOS VM kernel. The accepted
  matrix uses
  through `generic/316`,
  for isolated replacement rows `generic/317` through `generic/320`,
  and
  The shared-run no-space rows for `generic/317` through `generic/320` are not
  `309`, `310`, `315`, `316`, `321`, `325`, `335`, `337`, `338`, `341`,
  `343`, `348`), 11 product FAIL rows (`generic/306`, `313`, `320`, `322`,
  `336`, `339`, `340`, `342`, `344`, `345`, `346`), 21 unsupported rows, and
  5 skipped rows, with no deferred, harness-fail, or environment-refusal rows
  `linux_ref: none` against `forgeadmin/linux:tidefs/linux-7.0`; no Linux
  source patch is required for this classification issue. This classifies
  TFR-018 closure.
- `TFR-018`: issue #383 wires the mounted C `readahead` callback into the
  `address_space_operations` vtable via `tidefs_posix_vfs_readahead()` and
  updates the Rust `AddressSpaceOps::readahead` source model to populate
  clean page-cache state from the engine with authoritative readahead,
  prefetch, populate, and miss counters. The readahead slice of TFR-018
  is now closed; the C-to-Rust invalidate_folio/page-authority bridge
  slice remains open.
