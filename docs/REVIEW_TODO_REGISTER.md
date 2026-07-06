# TideFS Review Todo Register

This register is intentionally broad. It records areas found during the
whole-repo rename/import audit that block TideFS from making
OpenZFS/Ceph-class claims.

| Id | Area | Finding | Required Direction |
| --- | --- | --- | --- |
| TFR-002 | Workspace authority | Product code, harness code, historical scaffolding, and non-workspace packages are still interleaved. | Classify every package as product, harness, third-party, or delete candidate; remove ambiguous scaffolding. |
| TFR-003 | Todo hygiene | Debt was previously scattered through docs, comments, and issue-era markers. | Keep all durable debt here; convert inline notes to register pointers only. |
| TFR-004 | Dataset/inode authority | Dataset/mount identity and inode ownership need deep review; earlier audit suspected root-level inode list behavior. | Use `docs/INODE_NAMESPACE_AUTHORITY.md`: a dedicated dataset-scoped inode authority owns allocation, persisted IDs, root identity, and recovery seeding while namespace, FUSE lookup state, and inode-table registries remain projections. Implement the non-overlapping follow-ups #664, #665, #666, and #667 before closing this item. |
| TFR-005 | Timestamp/revision/on-disk format | POSIX timestamps, storage version fields, content object keys, scrub identity, replay ticks, rename metadata stamps, and serialized format fields are coupled. | Use `docs/TIMESTAMP_GENERATION_AUTHORITY.md` as the top-level authority model and section 9 closeout/delegation map, with the delegated companion authorities in `docs/CONTENT_OBJECT_VERSION_AUTHORITY.md`, `docs/SCRUB_IDENTITY_AUTHORITY.md`, `docs/SEND_RECEIVE_VERSION_AUTHORITY.md`, source-owned format/version constants, and `docs/UNRELEASED_AUTHORITY_POLICY.md` for pre-release compatibility boundaries. Keep TFR-005 open until delegated live families, conditional future-only ABI/coverage rows, and product-claim evidence support closure. |
| TFR-006 | Compression/encryption | Compression and encryption paths may bypass or duplicate raw object-store authority. | Use `docs/TRANSFORM_PIPELINE_AUTHORITY.md` as the #1063 boundary decision and close its non-overlapping follow-up map before claiming runtime conformance. |
| TFR-007 | Capacity/accounting | Allocation, quotas, statfs, reserves, and logical/physical accounting are split across crates. | Use `docs/CAPACITY_ACCOUNTING_AUTHORITY.md` as the boundary decision and close the linked follow-up issue map. |
| TFR-008 | Recovery/fsync/writeback/mmap | Recovery, fsync, dirty-page writeback, mmap, and page-cache authority are not proven as one contract. | Use `docs/PAGE_CACHE_WRITEBACK_AUTHORITY.md` for the integrated recovery/fsync/writeback/mmap durability boundary and follow-up map, and `docs/PAGE_CACHE_INVALIDATION_AUTHORITY.md` for the invalidation trigger, stale-generation, and FUSE/kernel/cluster lease model; then prove and test the end-to-end durability and cache-coherency contract. |
| TFR-009 | Kernel residency | Kernel-resident storage authority is tiered and not yet a production full-kernel/no-daemon claim. | Use `docs/KERNEL_RESIDENCY_AUTHORITY.md` as the boundary decision. `docs/KERNEL_RESIDENT_POOL_ENGINE_ARCHITECTURE.md` remains the target-architecture spec and evidence-tier map; close the follow-up implementation map before claiming kernel-resident storage authority. |
| TFR-010 | Snapshot/clone/send-receive/deadlist | Snapshot retention, deadlists, clone lineage, and send/receive are not one coherent storage model. | Use `docs/SNAPSHOT_CLONE_DEADLIST_AUTHORITY.md` for the local snapshot/clone/deadlist authority. Issue #1248 selected released-root derivation feeding the existing receipt-bound dead-object reclaim pipeline; implementation remains open under #1263, #1264, #1265, #1259, and #1266. Distributed snapshot shipping design is recorded in `docs/design/distributed-snapshot-shipping.md` (issue #1250); VFSSEND2 is the protocol foundation, section 7.2 records the initial scheduling/admission policy, and distributed deadlist triggers must call the #1248 derivation API rather than transmit deadlist entries. |
| TFR-013 | Stub/placeholder stage | Several crates and docs still look like stage scaffolding rather than product behavior. | Classify placeholders explicitly and delete or implement them. |
| TFR-014 | Licensing/provenance | Fresh TideFS import must preserve Linux-style GPLv2+syscall-note licensing and third-party provenance. | Audit all package metadata and file-local notices after rename. |
| TFR-016 | Inline debt marker hygiene | Non-vendored source, active validation scripts, and harness text still carried issue-era TODO/continuation/placeholder wording. | Replace anonymous markers with register-addressed comments and require explicit negative-test/refusal fixture classification for marker-word fixtures. |
| TFR-017 | Transport/cluster authority | Cluster CLI, storage-node, send-buffer, epoch-fence, and orchestrator paths still expose staged or placeholder distributed behavior. | Define the transport authority, cross-replica comparison, dispatch, and backpressure semantics before multi-node claims. Distributed snapshot shipping design (#1250, `docs/design/distributed-snapshot-shipping.md`) selects VFSSEND2 as the send/receive protocol foundation and maps follow-up implementation issues; concrete transport binding (TCP, RDMA, etc.) remains deferred to this TFR-017 decision. |
| TFR-019 | Documentation authority drift | Imported docs still mix design intent, issue closeout records, maturity labels, and current-status claims. | Use `docs/DOCUMENTATION_AUTHORITY_REGISTER.md` to reclassify every doc as current policy, current spec, historical input, explicit missing reference, or delete candidate before relying on it; successor/comparator wording lives in `docs/CLAIMS_GATE_POLICY.md`, and storage-intent receipt boundaries live in `docs/STORAGE_INTENT_POLICY_AUTHORITY.md`; record evidence-only and generated/derived handling roles without creating another status surface. |
| TFR-020 | Test signal authority | Unit, integration, harness, policy, and marker tests are widespread enough that test count can outgrow product confidence. | Apply `docs/TEST_SIGNAL_POLICY.md`: keep product/invariant signal, demote marker/stale/scaffold signal, and make fixtures match the claim being proved. |
| TFR-021 | Nextgen verification contract authority | Verification, performance, offload, adapter, model, trace, and crash evidence must flow through one claim/evidence chain instead of parallel roadmap documents. | Treat the old nextgen program map as historical lineage only. Current authority is `docs/CLAIMS_GATE_POLICY.md`, `validation/claims.toml`, generated `docs/CLAIM_REGISTRY.md`, evidence manifest schemas/source, focused subsystem docs, CI docs, and live GitHub issues/PRs for the exact slice. Keep high-value claim ids blocked until issue-scoped evidence and claims-gate support exist. |


## Current State

### TFR-002: Workspace authority
Still open. Issues #276, #513, #681 removed scaffold-transitional crate roots and established retired-role enforcement; check-workspace-policy validates 157 classified packages with zero scaffold-transitional rows. Imported docs and xtask gates still carry stale package assumptions that need separate classification. #681 mapped the package-classification authority to product/harness/third-party/delete categories.

### TFR-003: Todo hygiene
Still open. Inline comments use register-backed TFR markers; anonymous TODOs have been converted. Remaining debt lives in this register only.

### TFR-004: Dataset/inode authority
Still open. #655 added `docs/INODE_NAMESPACE_AUTHORITY.md` as the design decision artifact; #664 extracted the first dataset-scoped allocator boundary; #665 (FUSE lookup-reference projection), #666 (old-catalog policy), and #667 (special-node rdev replay) remain open follow-ups. Local inode/directory maps remain filesystem-global.

### TFR-005: Timestamp/revision/on-disk format
Still open. Delegated to `docs/TIMESTAMP_GENERATION_AUTHORITY.md` section 9 closeout map with companion authorities in `docs/CONTENT_OBJECT_VERSION_AUTHORITY.md`, `docs/SCRUB_IDENTITY_AUTHORITY.md`, and `docs/SEND_RECEIVE_VERSION_AUTHORITY.md`. Closed slices: #325, #330, #331, #348 (POSIX timestamp separation), #499 (comprehensive authority doc), #694 (intent-log replay/recovery), #688, #994 (namespace-revision coupling), #742 (scrub identity), #695, #1002 (VFSSEND1 guard), #746 (content-object version), #696 (format-golden/codec gate). Remains open until delegated live runtime families and product-claim evidence.

### TFR-006: Compression/encryption
Still open. #1063 is the boundary decision (`docs/TRANSFORM_PIPELINE_AUTHORITY.md`); #218 added the raw-store inventory at `docs/MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY.md`, now refreshed through the FUSE inode-metadata validation slice. Mounted local-filesystem device-transform open helpers fail closed for device-level compression/encryption configs while transform authority redesign remains open before runtime conformance claims.

### TFR-007: Capacity/accounting
Still open. #680 produced `docs/CAPACITY_ACCOUNTING_AUTHORITY.md`; #1191 moved fallocate/zero_range admissions to CapacityAuthority reservation lifecycle; #1467 split residual ledgers into non-overlapping follow-ups #1504 (SpaceBook persistence), #1505 (physical-pool inputs), #1506 (reclaim evidence), #1507 (dedup obligations), and #1508 (final consumer wiring). Multiple accounting leak fixes landed but the full authority model across quota hierarchy, obligation ledger, and store-layer persistence remains open.

### TFR-008: Recovery/fsync/writeback/mmap
Still open. #511 added `docs/PAGE_CACHE_WRITEBACK_AUTHORITY.md`; #736 added `docs/PAGE_CACHE_INVALIDATION_AUTHORITY.md`; #1065 expanded into the integrated recovery/fsync/writeback/mmap authority decision. Follow-ups #752 (FUSE data-cache invalidation), #753 (kernel page-cache coherency), #754 (clustered cache lease) remain open. #329 made crash claim evidence source-qualified. Runtime crash safety and mounted durability are not proven.

### TFR-009: Kernel residency
Still open. Delegated to `docs/KERNEL_RESIDENCY_AUTHORITY.md` and target-architecture spec `docs/KERNEL_RESIDENT_POOL_ENGINE_ARCHITECTURE.md`. Full-kernel/no-daemon wording remains a blocked future scope until the follow-up implementation map closes.

### TFR-010: Snapshot/clone/send-receive/deadlist
Still open. Authority in `docs/SNAPSHOT_CLONE_DEADLIST_AUTHORITY.md`. #1248 selected released-root derivation feeding the receipt-bound dead-object reclaim pipeline; implementation remains under #1263, #1264, #1265, #1259, #1266. Distributed snapshot shipping: #1250, `docs/design/distributed-snapshot-shipping.md`, VFSSEND2 protocol.

### TFR-013: Stub/placeholder stage
Still open. OW-*, PC-*, NEXT-* labels remain in source, xtask, and imported docs (#796 audit: 153 files, 785 references). Cleanup is ongoing through focused per-surface issues.

### TFR-014: Licensing/provenance
Still open. GPLv2+syscall-note licensing and third-party provenance audit remains.

### TFR-016: Inline debt marker hygiene
Still open. Non-vendored source, active validation scripts, and harness text cleaned of anonymous TODOs. The workspace hygiene check now rejects anonymous marker wording in tracked `nix/vm`, `scripts`, and non-generated `validation` harness text unless the surrounding text classifies a negative-test or refusal fixture. Short-label inventory reduced to ~71 files (9 apps/, 57 crates/, 5 xtask/) from initial ~104. Remaining OW-*/PC-*/NEXT-* labels need per-surface classification and cleanup.

### TFR-017: Transport/cluster authority
Still open. `docs/TRANSPORT_CLUSTER_AUTHORITY.md` is the authority; `docs/CROSS_REPLICA_SCRUB_COMPARISON_DESIGN.md` records the cross-replica comparison and scrub authority. #1250 distributed snapshot shipping design. Concrete transport binding, multi-node claims, and production distributed-runtime remain deferred.

### TFR-019: Documentation authority drift
Still open. `docs/DOCUMENTATION_AUTHORITY_REGISTER.md` is the current classifier; all imported docs must be classified as current policy, current spec, historical input, missing, or delete candidate before reliance. Closed classification slices: #689 (initial open queue), #512 (high-impact design surface), #1637 (block-volume/uBLK), #1136 (request contract), #1586 (Forgejo-era closeout deletions), #1152 (pool import/export), #332 (BLAKE3/checksum), #337 (kernel/UAPI), #661 (operator UAPI). Broader per-document source audits still needed.

### TFR-020: Test signal authority
Still open. `docs/TEST_SIGNAL_POLICY.md` is the current policy. Issues #500 and #691 are historical static-audit slices; #691 removed high-confidence comment-only and non-Linux no-op tests. Future cleanup must stay issue-scoped per the policy.

### TFR-021: Nextgen verification
Still open. Closed historical slices chose a unified evidence manifest with typed claim anchors and deleted older roadmap roots. The current authority is no longer a living follow-up map in `docs/NEXTGEN_VERIFICATION_PERFORMANCE_OFFLOAD_PLAN.md`; use `docs/CLAIMS_GATE_POLICY.md`, `validation/claims.toml`, generated `docs/CLAIM_REGISTRY.md`, evidence manifest schemas/source, focused subsystem docs, CI docs, and live GitHub issues/PRs for issue-scoped verification work.

### TFR-001: User requirements
Historical finding only. `docs/00_user_requirements.md` contained stale version-closeout wording; status rebuilt from current source behavior. Not a current register entry.

### TFR-011: Kernel and preview UAPI
TFR-011 closed by #1278 after rechecking the pre-alpha operator UAPI boundary decision (#656, `docs/OPERATOR_UAPI_AUTHORITY.md`). Follow-ups #657-#662 closed; #1267 product-surface decision landed. TFR-011 no longer a live register blocker.

### TFR-012: Device lifecycle and media privacy
Still open. `docs/DEVICE_LIFECYCLE_REMANENCE_AUTHORITY.md` records the #1276 boundary; #1536 added zero-visible vs. media-privacy boundary. Follow-up map: byte-device discard, segment-reclaim remanence, online removal/replacement, zeroing and media privacy policy, cryptographic erase/key-lifecycle.

### TFR-015: Release surface
Historical/deferred. Format-golden corpus and release-script cleanup addressed; remaining imported docs with historical run paths and status doctrine need per-surface classification under TFR-019.

### TFR-018: POSIX/VFS mounted completeness
Still open. FUSE xfstests classification: #6582 (generic/001-013 PASS), #6586, #6587 (Linux 7.0 kmod), #6589, #6590, #6591, #6593, #6594, #6595, #6596, #6597, #6598, #6599. Mounted-kernel kmod: #258 (mmap/writeback proof), #260 (direct vm-ops bridge demotion), #275 (truncate/invalidation), #383 (readahead callback, closed). Recovery, fsync/syncfs, writeback, mmap, direct-I/O, no-daemon residency, and full xfstests coverage remain open; this is not TFR-018 closure.
