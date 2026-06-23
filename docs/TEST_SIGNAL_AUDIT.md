# Test Signal Audit

Issue #500 audit of the test roots named by `docs/TEST_SIGNAL_POLICY.md` and TFR-020. Issue #691 removed the high-confidence marker/delete candidates from that audit without changing product behavior, crate manifests, or validation artifacts; it also made touched validation tests skip cleanly when their daemon, tool, or runner-environment prerequisites are absent or contended.

## Scope And Method

- Audited `crates/*/tests/`, inline `#[cfg(test)]`/`#[test]` roots under `crates/*/src/`, and `apps/*/tests/`.
- Counted Rust test functions with `#[test]`, `#[tokio::test]`, `#[async_std::test]`, `#[rstest]`, and `cfg_attr(..., test)` style attributes.
- Folded policy/tooling tests into **harness/scaffold** because issue #500 asks for three count columns rather than a separate policy/tooling count.
- Counted marker/stale only when the body was an explicit no-op/trivial assertion or constructor-only smoke with no observed invariant. `#[should_panic]` constructor checks and helper-driven assertions were treated as invariant signal.
- App inline tests under `apps/*/src/`, fuzz targets, benches, trace files, and external GitHub Actions rows are outside this issue's requested roots.

## Summary

| Category | Count | Notes |
| --- | ---: | --- |
| Product/invariant signal | 30809 | Mounted/runtime product tests plus compact internal invariants. |
| Harness/scaffold signal | 1712 | Harness, validation, artifact-verifier, and policy/tooling tests. |
| Marker/stale/delete-candidate signal | 0 | Issue #691 removed the high-confidence no-op/trivial/constructor-only tests from the original audit. |
| Total scoped test functions | 32521 | Across 146 packages with in-scope tests. |

## Package Audit

Action keys: **K** keep/cite as product or invariant signal; **H** cite only as harness/policy evidence; **M** review marker/stale delete candidates when the owning area is touched.

| Package | Test root paths | Product/invariant | Harness/scaffold | Marker/stale | Action |
| --- | --- | ---: | ---: | ---: | --- |
| `fuser` | `crates/tidefs-fuser/src/ (inline)`, `crates/tidefs-fuser/tests/` | 1776 | 0 | 0 | K |
| `tidefs-anti-entropy-auditor` | `crates/tidefs-anti-entropy-auditor/src/ (inline)`, `crates/tidefs-anti-entropy-auditor/tests/` | 155 | 14 | 0 | K, H |
| `tidefs-auth` | `crates/tidefs-auth/src/ (inline)`, `crates/tidefs-auth/tests/` | 364 | 0 | 0 | K |
| `tidefs-background-scheduler` | `crates/tidefs-background-scheduler/src/ (inline)`, `crates/tidefs-background-scheduler/tests/` | 194 | 0 | 0 | K |
| `tidefs-binary_schema-checksum` | `crates/tidefs-binary_schema-checksum/src/ (inline)`, `crates/tidefs-binary_schema-checksum/tests/` | 66 | 0 | 0 | K |
| `tidefs-binary_schema-core` | `crates/tidefs-binary_schema-core/src/ (inline)`, `crates/tidefs-binary_schema-core/tests/` | 250 | 0 | 0 | K |
| `tidefs-binary_schema-framing` | `crates/tidefs-binary_schema-framing/src/ (inline)`, `crates/tidefs-binary_schema-framing/tests/` | 138 | 14 | 0 | K, H |
| `tidefs-block-allocator` | `crates/tidefs-block-allocator/src/ (inline)`, `crates/tidefs-block-allocator/tests/` | 279 | 0 | 0 | K |
| `tidefs-block-kmod` | `crates/tidefs-block-kmod/src/ (inline)` | 403 | 0 | 0 | K |
| `tidefs-block-volume-adapter-core` | `crates/tidefs-block-volume-adapter-core/src/ (inline)`, `crates/tidefs-block-volume-adapter-core/tests/` | 176 | 0 | 0 | K |
| `tidefs-block-volume-adapter-daemon` | `apps/tidefs-block-volume-adapter-daemon/tests/` | 59 | 0 | 0 | K |
| `tidefs-block-volume-adapter-ublk-control-runtime` | `crates/tidefs-block-volume-adapter-ublk-control-runtime/src/ (inline)`, `crates/tidefs-block-volume-adapter-ublk-control-runtime/tests/` | 546 | 0 | 0 | K |
| `tidefs-btree` | `crates/tidefs-btree/src/ (inline)`, `crates/tidefs-btree/tests/` | 406 | 0 | 0 | K |
| `tidefs-cache-coherency` | `crates/tidefs-cache-coherency/src/ (inline)` | 4 | 0 | 0 | K |
| `tidefs-cache-core` | `crates/tidefs-cache-core/src/ (inline)`, `crates/tidefs-cache-core/tests/` | 484 | 55 | 0 | K, H |
| `tidefs-checksum-tree` | `crates/tidefs-checksum-tree/src/ (inline)`, `crates/tidefs-checksum-tree/tests/` | 164 | 0 | 0 | K |
| `tidefs-chunk-shipper` | `crates/tidefs-chunk-shipper/src/ (inline)`, `crates/tidefs-chunk-shipper/tests/` | 297 | 4 | 0 | K, H |
| `tidefs-claim-ledger` | `crates/tidefs-claim-ledger/src/ (inline)`, `crates/tidefs-claim-ledger/tests/` | 145 | 0 | 0 | K |
| `tidefs-cleanup-engine` | `crates/tidefs-cleanup-engine/src/ (inline)` | 104 | 0 | 0 | K |
| `tidefs-cleanup-job-core` | `crates/tidefs-cleanup-job-core/src/ (inline)` | 85 | 0 | 0 | K |
| `tidefs-cleanup-queue-core` | `crates/tidefs-cleanup-queue-core/src/ (inline)`, `crates/tidefs-cleanup-queue-core/tests/` | 110 | 0 | 0 | K |
| `tidefs-clock-timing` | `crates/tidefs-clock-timing/src/ (inline)`, `crates/tidefs-clock-timing/tests/` | 259 | 0 | 0 | K |
| `tidefs-cluster` | `crates/tidefs-cluster/src/ (inline)`, `crates/tidefs-cluster/tests/` | 452 | 0 | 0 | K |
| `tidefs-commit_group` | `crates/tidefs-commit_group/src/ (inline)`, `crates/tidefs-commit_group/tests/` | 384 | 0 | 0 | K |
| `tidefs-compaction` | `crates/tidefs-compaction/src/ (inline)` | 173 | 0 | 0 | K |
| `tidefs-compression` | `crates/tidefs-compression/src/ (inline)`, `crates/tidefs-compression/tests/` | 137 | 0 | 0 | K |
| `tidefs-coordination-strategy` | `crates/tidefs-coordination-strategy/src/ (inline)`, `crates/tidefs-coordination-strategy/tests/` | 89 | 0 | 0 | K |
| `tidefs-crash-oracle` | `crates/tidefs-crash-oracle/src/ (inline)` | 19 | 0 | 0 | K |
| `tidefs-data-cleaner` | `crates/tidefs-data-cleaner/src/ (inline)` | 18 | 0 | 0 | K |
| `tidefs-dataset-catalog` | `crates/tidefs-dataset-catalog/src/ (inline)` | 88 | 0 | 0 | K |
| `tidefs-dataset-feature-flags` | `crates/tidefs-dataset-feature-flags/src/ (inline)`, `crates/tidefs-dataset-feature-flags/tests/` | 92 | 0 | 0 | K |
| `tidefs-dataset-lifecycle` | `crates/tidefs-dataset-lifecycle/src/ (inline)`, `crates/tidefs-dataset-lifecycle/tests/` | 382 | 0 | 0 | K |
| `tidefs-dataset-properties` | `crates/tidefs-dataset-properties/src/ (inline)` | 72 | 0 | 0 | K |
| `tidefs-dedup` | `crates/tidefs-dedup/src/ (inline)` | 52 | 0 | 0 | K |
| `tidefs-derived-catalog` | `crates/tidefs-derived-catalog/src/ (inline)` | 78 | 0 | 0 | K |
| `tidefs-device-removal` | `crates/tidefs-device-removal/src/ (inline)`, `crates/tidefs-device-removal/tests/` | 63 | 0 | 0 | K |
| `tidefs-dir-index` | `crates/tidefs-dir-index/src/ (inline)`, `crates/tidefs-dir-index/tests/` | 581 | 0 | 0 | K |
| `tidefs-distributed-model-check` | `crates/tidefs-distributed-model-check/src/ (inline)` | 27 | 0 | 0 | K |
| `tidefs-durability-layout` | `crates/tidefs-durability-layout/src/ (inline)`, `crates/tidefs-durability-layout/tests/` | 229 | 18 | 0 | K, H |
| `tidefs-encryption` | `crates/tidefs-encryption/src/ (inline)`, `crates/tidefs-encryption/tests/` | 205 | 0 | 0 | K |
| `tidefs-env-fuse-model` | `crates/tidefs-env-fuse-model/src/ (inline)` | 9 | 0 | 0 | K |
| `tidefs-env-ublk-model` | `crates/tidefs-env-ublk-model/src/ (inline)` | 7 | 0 | 0 | K |
| `tidefs-erasure-coded-store` | `crates/tidefs-erasure-coded-store/src/ (inline)`, `crates/tidefs-erasure-coded-store/tests/` | 92 | 0 | 0 | K |
| `tidefs-erasure-coding` | `crates/tidefs-erasure-coding/src/ (inline)`, `crates/tidefs-erasure-coding/tests/` | 116 | 0 | 0 | K |
| `tidefs-extent-map` | `crates/tidefs-extent-map/src/ (inline)`, `crates/tidefs-extent-map/tests/` | 778 | 0 | 0 | K |
| `tidefs-flow-commit-coordinator` | `crates/tidefs-flow-commit-coordinator/src/ (inline)`, `crates/tidefs-flow-commit-coordinator/tests/` | 130 | 0 | 0 | K |
| `tidefs-frame` | `crates/tidefs-frame/src/ (inline)`, `crates/tidefs-frame/tests/` | 78 | 0 | 0 | K |
| `tidefs-gc-pin-set` | `crates/tidefs-gc-pin-set/src/ (inline)`, `crates/tidefs-gc-pin-set/tests/` | 48 | 0 | 0 | K |
| `tidefs-geometry-convert` | `crates/tidefs-geometry-convert/src/ (inline)` | 23 | 0 | 0 | K |
| `tidefs-incremental-job-core` | `crates/tidefs-incremental-job-core/src/ (inline)`, `crates/tidefs-incremental-job-core/tests/` | 50 | 0 | 0 | K |
| `tidefs-inode-attributes` | `crates/tidefs-inode-attributes/src/ (inline)`, `crates/tidefs-inode-attributes/tests/` | 444 | 0 | 0 | K |
| `tidefs-inode-table` | `crates/tidefs-inode-table/src/ (inline)`, `crates/tidefs-inode-table/tests/` | 284 | 0 | 0 | K |
| `tidefs-intent-log` | `crates/tidefs-intent-log/src/ (inline)`, `crates/tidefs-intent-log/tests/` | 251 | 0 | 0 | K |
| `tidefs-invalidation-feed` | `crates/tidefs-invalidation-feed/src/ (inline)` | 13 | 8 | 0 | K, H |
| `tidefs-kernel-cutover-runtime` | `crates/tidefs-kernel-cutover-runtime/src/ (inline)`, `crates/tidefs-kernel-cutover-runtime/tests/` | 76 | 0 | 0 | K |
| `tidefs-kernel-storage-io` | `crates/tidefs-kernel-storage-io/src/ (inline)` | 39 | 0 | 0 | K |
| `tidefs-kmod-posix-vfs` | `crates/tidefs-kmod-posix-vfs/src/ (inline)`, `crates/tidefs-kmod-posix-vfs/tests/` | 1115 | 0 | 0 | K |
| `tidefs-lease` | `crates/tidefs-lease/src/ (inline)`, `crates/tidefs-lease/tests/` | 198 | 0 | 0 | K |
| `tidefs-lease-manager` | `crates/tidefs-lease-manager/src/ (inline)`, `crates/tidefs-lease-manager/tests/` | 136 | 0 | 0 | K |
| `tidefs-local-filesystem` | `crates/tidefs-local-filesystem/src/ (inline)`, `crates/tidefs-local-filesystem/tests/` | 2140 | 27 | 0 | K, H |
| `tidefs-local-object-store` | `crates/tidefs-local-object-store/src/ (inline)`, `crates/tidefs-local-object-store/tests/` | 1267 | 50 | 0 | K, H |
| `tidefs-locator-table` | `crates/tidefs-locator-table/src/ (inline)`, `crates/tidefs-locator-table/tests/` | 131 | 0 | 0 | K |
| `tidefs-lock-service` | `crates/tidefs-lock-service/src/ (inline)` | 71 | 0 | 0 | K |
| `tidefs-membership-epoch` | `crates/tidefs-membership-epoch/src/ (inline)`, `crates/tidefs-membership-epoch/tests/` | 896 | 0 | 0 | K |
| `tidefs-membership-live` | `crates/tidefs-membership-live/src/ (inline)`, `crates/tidefs-membership-live/tests/` | 1505 | 0 | 0 | K |
| `tidefs-membership-types` | `crates/tidefs-membership-types/src/ (inline)` | 102 | 0 | 0 | K |
| `tidefs-model-core` | `crates/tidefs-model-core/src/ (inline)` | 8 | 0 | 0 | K |
| `tidefs-namespace` | `crates/tidefs-namespace/src/ (inline)` | 222 | 13 | 0 | K, H |
| `tidefs-node-drain` | `crates/tidefs-node-drain/src/ (inline)` | 230 | 13 | 0 | K, H |
| `tidefs-node-join` | `crates/tidefs-node-join/src/ (inline)` | 240 | 0 | 0 | K |
| `tidefs-object-io` | `crates/tidefs-object-io/src/ (inline)`, `crates/tidefs-object-io/tests/` | 65 | 0 | 0 | K |
| `tidefs-offload-core` | `crates/tidefs-offload-core/src/ (inline)` | 7 | 0 | 0 | K |
| `tidefs-online-defrag` | `crates/tidefs-online-defrag/src/ (inline)` | 50 | 0 | 0 | K |
| `tidefs-orphan-index` | `crates/tidefs-orphan-index/src/ (inline)` | 106 | 0 | 0 | K |
| `tidefs-partition-runtime` | `crates/tidefs-partition-runtime/src/ (inline)` | 115 | 6 | 0 | K, H |
| `tidefs-performance-contract` | `crates/tidefs-performance-contract/src/ (inline)` | 7 | 0 | 0 | K |
| `tidefs-permission` | `crates/tidefs-permission/src/ (inline)`, `crates/tidefs-permission/tests/` | 176 | 0 | 0 | K |
| `tidefs-placement-planner` | `crates/tidefs-placement-planner/src/ (inline)` | 124 | 0 | 0 | K |
| `tidefs-placement-runtime` | `crates/tidefs-placement-runtime/src/ (inline)` | 142 | 0 | 0 | K |
| `tidefs-pool-allocator` | `crates/tidefs-pool-allocator/src/ (inline)` | 45 | 0 | 0 | K |
| `tidefs-pool-import` | `crates/tidefs-pool-import/src/ (inline)` | 94 | 0 | 0 | K |
| `tidefs-pool-scan` | `crates/tidefs-pool-scan/src/ (inline)`, `crates/tidefs-pool-scan/tests/` | 243 | 0 | 0 | K |
| `tidefs-posix-acl` | `crates/tidefs-posix-acl/src/ (inline)` | 126 | 0 | 0 | K |
| `tidefs-posix-filesystem-adapter-daemon` | `apps/tidefs-posix-filesystem-adapter-daemon/tests/` | 459 | 0 | 0 | K |
| `tidefs-posix-filesystem-adapter-reply` | `crates/tidefs-posix-filesystem-adapter-reply/src/ (inline)` | 61 | 0 | 0 | K |
| `tidefs-posix-filesystem-adapter-workers-io` | `crates/tidefs-posix-filesystem-adapter-workers-io/src/ (inline)` | 9 | 0 | 0 | K |
| `tidefs-posix-filesystem-adapter-workers-locks` | `crates/tidefs-posix-filesystem-adapter-workers-locks/src/ (inline)` | 39 | 0 | 0 | K |
| `tidefs-posix-guarantee-verifier` | `crates/tidefs-posix-guarantee-verifier/src/ (inline)` | 30 | 0 | 0 | K |
| `tidefs-posix-semantics` | `crates/tidefs-posix-semantics/src/ (inline)` | 73 | 0 | 0 | K |
| `tidefs-quorum-write` | `crates/tidefs-quorum-write/src/ (inline)` | 44 | 0 | 0 | K |
| `tidefs-quorum-write-runtime` | `crates/tidefs-quorum-write-runtime/src/ (inline)`, `crates/tidefs-quorum-write-runtime/tests/` | 276 | 0 | 0 | K |
| `tidefs-rebalance-planner` | `crates/tidefs-rebalance-planner/src/ (inline)` | 13 | 0 | 0 | K |
| `tidefs-rebuild-planner` | `crates/tidefs-rebuild-planner/src/ (inline)` | 126 | 0 | 0 | K |
| `tidefs-rebuild-runtime` | `crates/tidefs-rebuild-runtime/src/ (inline)`, `crates/tidefs-rebuild-runtime/tests/` | 115 | 0 | 0 | K |
| `tidefs-receive-stream` | `crates/tidefs-receive-stream/src/ (inline)`, `crates/tidefs-receive-stream/tests/` | 59 | 0 | 0 | K |
| `tidefs-reclaim` | `crates/tidefs-reclaim/src/ (inline)` | 87 | 0 | 0 | K |
| `tidefs-reclaim-queue-core` | `crates/tidefs-reclaim-queue-core/src/ (inline)` | 296 | 0 | 0 | K |
| `tidefs-recovery-loop` | `crates/tidefs-recovery-loop/src/ (inline)` | 155 | 0 | 0 | K |
| `tidefs-relocation-planner` | `crates/tidefs-relocation-planner/src/ (inline)` | 120 | 0 | 0 | K |
| `tidefs-replica-health` | `crates/tidefs-replica-health/src/ (inline)`, `crates/tidefs-replica-health/tests/` | 269 | 3 | 0 | K, H |
| `tidefs-replicated-object-store` | `crates/tidefs-replicated-object-store/src/ (inline)`, `crates/tidefs-replicated-object-store/tests/` | 116 | 0 | 0 | K |
| `tidefs-replication` | `crates/tidefs-replication/src/ (inline)` | 137 | 0 | 0 | K |
| `tidefs-replication-model` | `crates/tidefs-replication-model/src/ (inline)` | 280 | 0 | 0 | K |
| `tidefs-reserve-ledger` | `crates/tidefs-reserve-ledger/src/ (inline)` | 60 | 0 | 0 | K |
| `tidefs-schema-codec-posix-filesystem-adapter` | `crates/tidefs-schema-codec-posix-filesystem-adapter/src/ (inline)` | 14 | 0 | 0 | K |
| `tidefs-schema-codec-vfs` | `crates/tidefs-schema-codec-vfs/src/ (inline)` | 44 | 0 | 0 | K |
| `tidefs-scrub-core` | `crates/tidefs-scrub-core/src/ (inline)`, `crates/tidefs-scrub-core/tests/` | 301 | 0 | 0 | K |
| `tidefs-secret-key-policy-runtime` | `crates/tidefs-secret-key-policy-runtime/src/ (inline)` | 21 | 24 | 0 | K, H |
| `tidefs-segment-cleaner` | `crates/tidefs-segment-cleaner/src/ (inline)` | 198 | 26 | 0 | K, H |
| `tidefs-send-stream` | `crates/tidefs-send-stream/src/ (inline)`, `crates/tidefs-send-stream/tests/` | 164 | 0 | 0 | K |
| `tidefs-shard-group` | `crates/tidefs-shard-group/src/ (inline)` | 64 | 0 | 0 | K |
| `tidefs-snapshot-pruner` | `crates/tidefs-snapshot-pruner/src/ (inline)` | 64 | 0 | 0 | K |
| `tidefs-space-accounting` | `crates/tidefs-space-accounting/src/ (inline)` | 248 | 0 | 0 | K |
| `tidefs-spacemap-allocator` | `crates/tidefs-spacemap-allocator/src/ (inline)` | 127 | 0 | 0 | K |
| `tidefs-storage-node` | `apps/tidefs-storage-node/tests/` | 30 | 0 | 0 | K |
| `tidefs-tdma-scheduler` | `crates/tidefs-tdma-scheduler/src/ (inline)`, `crates/tidefs-tdma-scheduler/tests/` | 345 | 0 | 0 | K |
| `tidefs-trace-oracle` | `crates/tidefs-trace-oracle/src/ (inline)`, `crates/tidefs-trace-oracle/tests/` | 41 | 0 | 0 | K |
| `tidefs-transport` | `crates/tidefs-transport/src/ (inline)`, `crates/tidefs-transport/tests/` | 2866 | 0 | 0 | K |
| `tidefs-two-node-harness` | `crates/tidefs-two-node-harness/src/ (inline)`, `crates/tidefs-two-node-harness/tests/` | 0 | 153 | 0 | H |
| `tidefs-types-cache-lattice-core` | `crates/tidefs-types-cache-lattice-core/src/ (inline)` | 24 | 0 | 0 | K |
| `tidefs-types-claim-ledger-core` | `crates/tidefs-types-claim-ledger-core/src/ (inline)` | 12 | 0 | 0 | K |
| `tidefs-types-dataset-feature-flags-core` | `crates/tidefs-types-dataset-feature-flags-core/src/ (inline)` | 33 | 0 | 0 | K |
| `tidefs-types-dataset-lifecycle-core` | `crates/tidefs-types-dataset-lifecycle-core/src/ (inline)` | 89 | 0 | 0 | K |
| `tidefs-types-deferred-cleanup-core` | `crates/tidefs-types-deferred-cleanup-core/src/ (inline)` | 28 | 0 | 0 | K |
| `tidefs-types-extent-map-core` | `crates/tidefs-types-extent-map-core/src/ (inline)` | 42 | 0 | 0 | K |
| `tidefs-types-incremental-job-core` | `crates/tidefs-types-incremental-job-core/src/ (inline)` | 72 | 0 | 0 | K |
| `tidefs-types-orphan-index-core` | `crates/tidefs-types-orphan-index-core/src/ (inline)` | 69 | 0 | 0 | K |
| `tidefs-types-package-profile-catalog` | `crates/tidefs-types-package-profile-catalog/src/ (inline)` | 24 | 0 | 0 | K |
| `tidefs-types-polymorphic-directory-index-core` | `crates/tidefs-types-polymorphic-directory-index-core/src/ (inline)` | 49 | 0 | 0 | K |
| `tidefs-types-polymorphic-xattr-core` | `crates/tidefs-types-polymorphic-xattr-core/src/ (inline)` | 30 | 0 | 0 | K |
| `tidefs-types-pool-label-core` | `crates/tidefs-types-pool-label-core/src/ (inline)` | 58 | 0 | 0 | K |
| `tidefs-types-posix-filesystem-adapter-core` | `crates/tidefs-types-posix-filesystem-adapter-core/src/ (inline)` | 14 | 0 | 0 | K |
| `tidefs-types-reclaim-queue-core` | `crates/tidefs-types-reclaim-queue-core/src/ (inline)` | 69 | 0 | 0 | K |
| `tidefs-types-secret-key-policy-core` | `crates/tidefs-types-secret-key-policy-core/src/ (inline)` | 7 | 12 | 0 | K, H |
| `tidefs-types-space-accounting-core` | `crates/tidefs-types-space-accounting-core/src/ (inline)` | 82 | 0 | 0 | K |
| `tidefs-types-transport-session` | `crates/tidefs-types-transport-session/src/ (inline)` | 38 | 0 | 0 | K |
| `tidefs-types-vfs-core` | `crates/tidefs-types-vfs-core/src/ (inline)` | 81 | 0 | 0 | K |
| `tidefs-types-vfs-owned` | `crates/tidefs-types-vfs-owned/src/ (inline)` | 32 | 0 | 0 | K |
| `tidefs-ublk-abi` | `crates/tidefs-ublk-abi/src/ (inline)` | 40 | 0 | 0 | K |
| `tidefs-validation` | `crates/tidefs-validation/src/ (inline)`, `crates/tidefs-validation/tests/` | 0 | 1272 | 0 | H |
| `tidefs-verification-engine` | `crates/tidefs-verification-engine/src/ (inline)` | 60 | 0 | 0 | K |
| `tidefs-vfs-engine` | `crates/tidefs-vfs-engine/src/ (inline)` | 384 | 0 | 0 | K |
| `tidefs-vfs-rpc` | `crates/tidefs-vfs-rpc/src/ (inline)` | 14 | 0 | 0 | K |
| `tidefs-witness-set` | `crates/tidefs-witness-set/src/ (inline)`, `crates/tidefs-witness-set/tests/` | 302 | 0 | 0 | K |
| `tidefs-workload` | `crates/tidefs-workload/src/ (inline)`, `crates/tidefs-workload/tests/` | 26 | 0 | 0 | K |
| `tidefs-xattr-storage` | `crates/tidefs-xattr-storage/src/ (inline)` | 175 | 0 | 0 | K |

## Marker And Delete Candidates

Issue #691 deleted the high-confidence marker/stale candidates found by the original audit. No active marker/delete-candidate rows remain in this scoped audit; broader low-value cleanup should still happen issue-by-issue with the owning code.

## Named Claim And Contract Cross-References

The rows below identify tests that prove named contracts or feed claim evidence. A row only strengthens a registry claim when `validation/claims.toml` already accepts that evidence class; model-only or harness-only evidence must not be cited as runtime crash, kernel, ublk, or production storage proof.

| Claim or contract | Product/invariant or harness signal | Audit note |
| --- | --- | --- |
| `storage.write_fsync.crash_safety.v1`, `local.vfs.write_fsync_crash.v1` | `tidefs-crash-oracle` inline tests `model_crash_matrices_cover_required_classifications_and_boundaries`, `forbidden_recoveries_include_minimized_traces_and_state_diffs`, `model_report_json_round_trips`; `tidefs-local-filesystem` real-directory crash matrix tests; app FUSE `fsync_durability`/`fuse_crash_recovery` runtime smoke roots | Model-only and focused product signal. Registry status remains planned/blocked until runtime crash-oracle evidence exists. |
| `namespace.rename.atomicity.v1`, `local.vfs.rename_atomic_crash.v1` | `tidefs-crash-oracle` `rename_claim_new_name_state_comes_from_contract_replay`; app FUSE rename/crash roots such as `rename_mount_integration`, `fuse_rename_link_symlink`, `crash_recovery_ops` | Model-only and focused product signal. Runtime crash claim remains blocked in `validation/claims.toml`. |
| `scheduler.dirty_debt.no_hidden.v1`, `perf.local.no_unbounded_dirty_debt.v1` | `tidefs-performance-contract` tests `admission_permits_conserve_dirty_debt`, `dynamic_tuning_cannot_bypass_hard_dirty_caps`, `dirty_age_cap_blocks_new_dirty_admission`, `stale_charge_cannot_bypass_dirty_age_cap`, `budgeted_queue_requires_and_returns_permits` | Invariant/model signal for admission and budget accounting; not a runtime queue-depth artifact. |
| `scrub.foreground_read.protected.v1`, `perf.local.foreground_read_not_blocked_by_scrub.v1` | `tidefs-performance-contract` tests `unscheduled_scrub_blocks_foreground_read_counterexample` and `service_curve_protects_foreground_read_and_bounds_scrub`; `tidefs-validation` scrub performance harness tests | Model/harness signal only until runtime scrub/read artifact exists. |
| `offload.ready.non_authoritative.v1` | `tidefs-offload-core` tests `descriptor_codec_round_trips_and_rejects_bad_layout`, `cpu_reference_crc32c_completes_with_matching_lease`, `cpu_reference_xor_parity_generates_single_shard`, `scrub_digest_is_deterministic_and_length_sensitive`, `completion_codec_and_validator_reject_mismatches`, `stale_or_short_leases_are_rejected`, `cpu_backend_rejects_mismatched_slices` | Validated non-authoritative offload claim; still not GPU/FPGA/DMA/kernel/RDMA/storage-runtime proof. |
| `ublk.qid_tag.exactly_once_completion.v1` | `tidefs-env-ublk-model` qid/tag lifecycle tests; `tidefs-validation/src/ublk_completion_artifact.rs` tests `accepts_bounded_runtime_completion_artifact`, `rejects_duplicate_completion_for_generation`, `rejects_stale_generation_completion` | Model plus bounded artifact-verifier signal; registry still planned until required review/evidence complete. |
| `ublk.started_export.live_service_loop.v1` | `tidefs-validation/src/ublk_started_export_admission_artifact.rs` tests `accepts_started_export_admission_artifact`, `rejects_start_dev_without_live_queue_ownership`, `rejects_incomplete_queue_tag_coverage`, `rejects_started_export_without_request_observation`, `accepts_cleanup_failure_as_visible_claim_state`, `rejects_embedded_verifier_mismatch` | Harness/artifact-verifier signal for bounded started-export evidence; not broad block-device readiness. |
| `kernel.teardown.no_work_after.v1` | `tidefs-kmod-posix-vfs/src/kernel_env_model.rs` tests `kernel_env_model_*`, especially deterministic teardown proof and artifact match tests | Source-model proof signal only; registry notes it is not mounted Linux runtime evidence. |

## Audit Conclusions

- The dominant signal is real product/invariant coverage, but several large crates still have enough scaffold history that future test work should name the claim being proved before adding volume.
- `tidefs-validation` and `tidefs-two-node-harness` are useful harness evidence. They should not be cited as product proof unless paired with the runtime row or artifact named by the claim registry.
- The claim-linked crash, ublk, performance, offload, and kernel tests mostly provide model, invariant, or artifact-verifier signal. `validation/claims.toml` remains the authority for whether that evidence is sufficient for product wording.
- The marker/delete-candidate cleanup is intentionally conservative. Issue #691 removed only tests with high-confidence trivial or constructor-only bodies; broader low-value cleanup should happen issue-by-issue with the owning code.
