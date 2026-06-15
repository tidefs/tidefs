# Workspace Package Classification

Updated from current Cargo metadata and on-disk manifest discovery for issue #286 on 2026-06-15.
This document is the package-role authority for TideFS workspace selection and TFR-002/TFR-019 reduction.
It is enforced by `cargo run -p tidefs-xtask -- check-workspace-policy`.

This is not a production-readiness claim. TideFS remains a pre-alpha filesystem/storage stack with architectural debt tracked in `docs/REVIEW_TODO_REGISTER.md`.

## Current Counts

| Counted set | Value |
| --- | ---: |
| Workspace packages | 150 |
| Explicitly excluded package roots | 5 |
| Discovered package manifests | 155 |
| Classified package roots | 155 |

## Role Semantics

| Role | Meaning |
| --- | --- |
| `product-code` | Current filesystem, storage, metadata, data-path, type, codec, maintenance, transport, or distributed-subsystem implementation surface. This role is not release proof. |
| `adapter-operator` | App, kernel, block, FUSE, CLI, or operator-facing bridge surface. These are entrypoints or adapters, not broad capability claims. |
| `policy-tooling` | Repo policy, developer tooling, package profile, authentication, claim, or secret-key policy surface. |
| `proof-harness` | Validation, deterministic harness, demo, oracle, or workload surface used to collect signal. |
| `vendored-third-party` | Vendored upstream dependency carried in-tree with separate provenance. |
| `standalone-fuzz` | Cargo-fuzz package intentionally excluded from the root workspace and checked as standalone harness material. |
| `scaffold-transitional` | Retired TFR-002 role for stale workspace scaffolding. No current package root is assigned this role; future scaffold recovery requires a prepared issue and current-role classification instead. |
| `archive-delete-candidate` | Package root that should not stay active without an explicit issue. No current package root is assigned this role. |

## Role Counts

| Role | Count |
| --- | ---: |
| `product-code` | 117 |
| `adapter-operator` | 14 |
| `policy-tooling` | 8 |
| `proof-harness` | 10 |
| `vendored-third-party` | 1 |
| `standalone-fuzz` | 5 |
| `scaffold-transitional` | 0 |
| `archive-delete-candidate` | 0 |

## Package Role Authority

| Package root | Package | Cargo status | Role | Disposition |
| --- | --- | --- | --- | --- |
| `apps/tidefs-block-volume-adapter-daemon` | `tidefs-block-volume-adapter-daemon` | `workspace-member` | `adapter-operator` | operator entrypoint for the ublk adapter; live runtime validation required before release claims. |
| `apps/tidefs-filesystem-demo` | `tidefs-filesystem-demo` | `workspace-member` | `proof-harness` | demo entrypoint and proof harness; non-production Local Filesystem exercise only. |
| `apps/tidefs-posix-filesystem-adapter-daemon` | `tidefs-posix-filesystem-adapter-daemon` | `workspace-member` | `adapter-operator` | operator entrypoint and FUSE validation harness; preview mount surface only. |
| `apps/tidefs-scrub` | `tidefs-scrub` | `workspace-member` | `adapter-operator` | operator entrypoint for scrub/repair plumbing; not release proof by itself. |
| `apps/tidefs-storage-node` | `tidefs-storage-node` | `workspace-member` | `adapter-operator` | operator entrypoint for storage-node experiments; cluster authority remains TFR-017. |
| `apps/tidefs-store-demo` | `tidefs-store-demo` | `workspace-member` | `proof-harness` | demo entrypoint and proof harness; non-production Local Object Store exercise only. |
| `apps/tidefsctl` | `tidefsctl` | `workspace-member` | `adapter-operator` | operator entrypoint for CLI/UAPI work; TFR-011 and TFR-019 remain open. |
| `crates/tidefs-anti-entropy-auditor` | `tidefs-anti-entropy-auditor` | `workspace-member` | `product-code` | planned authority surface; follow-up issue required before release claims. |
| `crates/tidefs-auth` | `tidefs-auth` | `workspace-member` | `policy-tooling` | current policy/tooling surface; not a production-readiness claim. |
| `crates/tidefs-background-scheduler` | `tidefs-background-scheduler` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-binary_schema-checksum` | `tidefs-binary_schema-checksum` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-binary_schema-core` | `tidefs-binary_schema-core` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-binary_schema-core/fuzz` | `tidefs-binary_schema-core-fuzz` | `workspace-excluded` | `standalone-fuzz` | standalone-checkable fuzz package; keep mirrored in workspace.exclude until restored or made an issue-backed archive/delete candidate. |
| `crates/tidefs-binary_schema-framing` | `tidefs-binary_schema-framing` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-block-allocator` | `tidefs-block-allocator` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-block-kmod` | `tidefs-block-kmod` | `workspace-member` | `adapter-operator` | planned authority surface for adapter or kernel work; follow-up issue required before release claims. |
| `crates/tidefs-block-volume-adapter-core` | `tidefs-block-volume-adapter-core` | `workspace-member` | `adapter-operator` | current adapter/operator surface; capability claims remain behind focused validation. |
| `crates/tidefs-block-volume-adapter-ublk-control-runtime` | `tidefs-block-volume-adapter-ublk-control-runtime` | `workspace-member` | `adapter-operator` | current adapter/operator surface; capability claims remain behind focused validation. |
| `crates/tidefs-btree` | `tidefs-btree` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-cache-coherency` | `tidefs-cache-coherency` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-cache-core` | `tidefs-cache-core` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-checksum-tree` | `tidefs-checksum-tree` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-chunk-shipper` | `tidefs-chunk-shipper` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-claim-ledger` | `tidefs-claim-ledger` | `workspace-member` | `policy-tooling` | current policy/tooling surface; not a production-readiness claim. |
| `crates/tidefs-cleanup-engine` | `tidefs-cleanup-engine` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-cleanup-job-core` | `tidefs-cleanup-job-core` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-cleanup-queue-core` | `tidefs-cleanup-queue-core` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-clock-timing` | `tidefs-clock-timing` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-cluster` | `tidefs-cluster` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-commit_group` | `tidefs-commit_group` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-compaction` | `tidefs-compaction` | `workspace-member` | `product-code` | planned authority surface; follow-up issue required before release claims. |
| `crates/tidefs-crash-oracle` | `tidefs-crash-oracle` | `workspace-member` | `proof-harness` | planned authority surface for model-only crash oracle validation; follow-up issue required before it can support runtime release claims. |
| `crates/tidefs-compression` | `tidefs-compression` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-coordination-strategy` | `tidefs-coordination-strategy` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-data-cleaner` | `tidefs-data-cleaner` | `workspace-member` | `product-code` | planned authority surface; follow-up issue required before release claims. |
| `crates/tidefs-dataset-catalog` | `tidefs-dataset-catalog` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-dataset-feature-flags` | `tidefs-dataset-feature-flags` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-dataset-lifecycle` | `tidefs-dataset-lifecycle` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-dataset-properties` | `tidefs-dataset-properties` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-dedup` | `tidefs-dedup` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-derived-catalog` | `tidefs-derived-catalog` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-device-removal` | `tidefs-device-removal` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-dir-index` | `tidefs-dir-index` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-durability-layout` | `tidefs-durability-layout` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-encryption` | `tidefs-encryption` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-env-ublk-model` | `tidefs-env-ublk-model` | `workspace-member` | `proof-harness` | bounded uBLK qid/tag state model evidence only; runtime block-volume claims remain blocked on focused artifacts. |
| `crates/tidefs-erasure-coded-store` | `tidefs-erasure-coded-store` | `workspace-member` | `product-code` | planned authority surface; follow-up issue required before release claims. |
| `crates/tidefs-erasure-coding` | `tidefs-erasure-coding` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-extent-map` | `tidefs-extent-map` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-flow-commit-coordinator` | `tidefs-flow-commit-coordinator` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-frame` | `tidefs-frame` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-fuser` | `fuser` | `workspace-member` | `vendored-third-party` | vendored dependency for FUSE adapter builds; provenance is tracked in docs/LICENSING.md. |
| `crates/tidefs-gc-pin-set` | `tidefs-gc-pin-set` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-geometry-convert` | `tidefs-geometry-convert` | `workspace-member` | `product-code` | planned authority surface; follow-up issue required before release claims. |
| `crates/tidefs-incremental-job-core` | `tidefs-incremental-job-core` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-inode-attributes` | `tidefs-inode-attributes` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-inode-table` | `tidefs-inode-table` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-intent-log` | `tidefs-intent-log` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-invalidation-feed` | `tidefs-invalidation-feed` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-kernel-cutover-runtime` | `tidefs-kernel-cutover-runtime` | `workspace-member` | `product-code` | planned authority surface; follow-up issue required before release claims. |
| `crates/tidefs-kernel-storage-io` | `tidefs-kernel-storage-io` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-kmod-posix-vfs` | `tidefs-kmod-posix-vfs` | `workspace-member` | `adapter-operator` | planned authority surface for adapter or kernel work; follow-up issue required before release claims. |
| `crates/tidefs-lease` | `tidefs-lease` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-lease-manager` | `tidefs-lease-manager` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-local-filesystem` | `tidefs-local-filesystem` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-local-filesystem/fuzz` | `tidefs-local-filesystem-fuzz` | `workspace-excluded` | `standalone-fuzz` | standalone-checkable fuzz package; keep mirrored in workspace.exclude until restored or made an issue-backed archive/delete candidate. |
| `crates/tidefs-local-object-store` | `tidefs-local-object-store` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-local-object-store/fuzz` | `tidefs-local-object-store-fuzz` | `workspace-excluded` | `standalone-fuzz` | standalone-checkable fuzz package; keep mirrored in workspace.exclude until restored or made an issue-backed archive/delete candidate. |
| `crates/tidefs-locator-table` | `tidefs-locator-table` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-lock-service` | `tidefs-lock-service` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-membership-epoch` | `tidefs-membership-epoch` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-membership-live` | `tidefs-membership-live` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-membership-types` | `tidefs-membership-types` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-model-core` | `tidefs-model-core` | `workspace-member` | `proof-harness` | planned authority surface for trace and oracle validation; follow-up issue required before it can support release claims. |
| `crates/tidefs-namespace` | `tidefs-namespace` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-node-drain` | `tidefs-node-drain` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-node-join` | `tidefs-node-join` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-object-io` | `tidefs-object-io` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-offload-core` | `tidefs-offload-core` | `workspace-member` | `product-code` | planned authority surface for non-authoritative offload descriptor, lease, CPU reference, and completion validation; not a GPU/FPGA production acceleration claim. |
| `crates/tidefs-online-defrag` | `tidefs-online-defrag` | `workspace-member` | `product-code` | planned authority surface; follow-up issue required before release claims. |
| `crates/tidefs-orphan-index` | `tidefs-orphan-index` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-partition-runtime` | `tidefs-partition-runtime` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-performance-contract` | `tidefs-performance-contract` | `workspace-member` | `product-code` | planned authority surface for performance admission and queue metadata; follow-up issue required before release claims. |
| `crates/tidefs-permission` | `tidefs-permission` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-placement-planner` | `tidefs-placement-planner` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-placement-runtime` | `tidefs-placement-runtime` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-pool-allocator` | `tidefs-pool-allocator` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-pool-import` | `tidefs-pool-import` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-pool-scan` | `tidefs-pool-scan` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-posix-acl` | `tidefs-posix-acl` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-posix-filesystem-adapter-reply` | `tidefs-posix-filesystem-adapter-reply` | `workspace-member` | `adapter-operator` | planned authority surface for adapter or kernel work; follow-up issue required before release claims. |
| `crates/tidefs-posix-filesystem-adapter-workers-io` | `tidefs-posix-filesystem-adapter-workers-io` | `workspace-member` | `adapter-operator` | current adapter/operator surface; capability claims remain behind focused validation. |
| `crates/tidefs-posix-filesystem-adapter-workers-locks` | `tidefs-posix-filesystem-adapter-workers-locks` | `workspace-member` | `adapter-operator` | current adapter/operator surface; capability claims remain behind focused validation. |
| `crates/tidefs-posix-guarantee-verifier` | `tidefs-posix-guarantee-verifier` | `workspace-member` | `proof-harness` | planned authority surface for validation; follow-up issue required before it can support release claims. |
| `crates/tidefs-posix-semantics` | `tidefs-posix-semantics` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-quorum-write` | `tidefs-quorum-write` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-quorum-write-runtime` | `tidefs-quorum-write-runtime` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-rebalance-planner` | `tidefs-rebalance-planner` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-rebuild-planner` | `tidefs-rebuild-planner` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-rebuild-runtime` | `tidefs-rebuild-runtime` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-receive-stream` | `tidefs-receive-stream` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-reclaim` | `tidefs-reclaim` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-reclaim-queue-core` | `tidefs-reclaim-queue-core` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-recovery-loop` | `tidefs-recovery-loop` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-relocation-planner` | `tidefs-relocation-planner` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-replica-health` | `tidefs-replica-health` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-replicated-object-store` | `tidefs-replicated-object-store` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-replication` | `tidefs-replication` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-replication-model` | `tidefs-replication-model` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-reserve-ledger` | `tidefs-reserve-ledger` | `workspace-member` | `policy-tooling` | current policy/tooling surface; not a production-readiness claim. |
| `crates/tidefs-schema-codec-posix-filesystem-adapter` | `tidefs-schema-codec-posix-filesystem-adapter` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-schema-codec-vfs` | `tidefs-schema-codec-vfs` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-scrub-core` | `tidefs-scrub-core` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-secret-key-policy-runtime` | `tidefs-secret-key-policy-runtime` | `workspace-member` | `policy-tooling` | planned authority surface for policy work; follow-up issue required before release claims. |
| `crates/tidefs-segment-cleaner` | `tidefs-segment-cleaner` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-send-stream` | `tidefs-send-stream` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-shard-group` | `tidefs-shard-group` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-snapshot-pruner` | `tidefs-snapshot-pruner` | `workspace-member` | `product-code` | planned authority surface; follow-up issue required before release claims. |
| `crates/tidefs-space-accounting` | `tidefs-space-accounting` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-spacemap-allocator` | `tidefs-spacemap-allocator` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-tdma-scheduler` | `tidefs-tdma-scheduler` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-trace-oracle` | `tidefs-trace-oracle` | `workspace-member` | `proof-harness` | current proof harness; test signal only and not a product capability claim. |
| `crates/tidefs-transport` | `tidefs-transport` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-two-node-harness` | `tidefs-two-node-harness` | `workspace-member` | `proof-harness` | planned authority surface for validation; follow-up issue required before it can support release claims. |
| `crates/tidefs-types-cache-lattice-core` | `tidefs-types-cache-lattice-core` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-types-claim-ledger-core` | `tidefs-types-claim-ledger-core` | `workspace-member` | `policy-tooling` | current policy/tooling surface; not a production-readiness claim. |
| `crates/tidefs-types-dataset-feature-flags-core` | `tidefs-types-dataset-feature-flags-core` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-types-dataset-lifecycle-core` | `tidefs-types-dataset-lifecycle-core` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-types-deferred-cleanup-core` | `tidefs-types-deferred-cleanup-core` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-types-extent-map-core` | `tidefs-types-extent-map-core` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-types-incremental-job-core` | `tidefs-types-incremental-job-core` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-types-orphan-index-core` | `tidefs-types-orphan-index-core` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-types-package-profile-catalog` | `tidefs-types-package-profile-catalog` | `workspace-member` | `policy-tooling` | current policy/tooling surface; not a production-readiness claim. |
| `crates/tidefs-types-polymorphic-directory-index-core` | `tidefs-types-polymorphic-directory-index-core` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-types-polymorphic-xattr-core` | `tidefs-types-polymorphic-xattr-core` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-types-pool-label-core` | `tidefs-types-pool-label-core` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-types-posix-filesystem-adapter-core` | `tidefs-types-posix-filesystem-adapter-core` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-types-reclaim-queue-core` | `tidefs-types-reclaim-queue-core` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-types-secret-key-policy-core` | `tidefs-types-secret-key-policy-core` | `workspace-member` | `policy-tooling` | current policy/tooling surface; not a production-readiness claim. |
| `crates/tidefs-types-space-accounting-core` | `tidefs-types-space-accounting-core` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-types-transport-session` | `tidefs-types-transport-session` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-types-vfs-core` | `tidefs-types-vfs-core` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-types-vfs-owned` | `tidefs-types-vfs-owned` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-ublk-abi` | `tidefs-ublk-abi` | `workspace-member` | `adapter-operator` | current adapter/operator surface; capability claims remain behind focused validation. |
| `crates/tidefs-validation` | `tidefs-validation` | `workspace-member` | `proof-harness` | current proof harness; test signal only and not a product capability claim. |
| `crates/tidefs-validation/fuzz` | `tidefs-validation-fuzz` | `workspace-excluded` | `standalone-fuzz` | standalone-checkable fuzz package; keep mirrored in workspace.exclude until restored or made an issue-backed archive/delete candidate. |
| `crates/tidefs-verification-engine` | `tidefs-verification-engine` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-vfs-engine` | `tidefs-vfs-engine` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-vfs-rpc` | `tidefs-vfs-rpc` | `workspace-member` | `product-code` | planned authority surface; follow-up issue required before release claims. |
| `crates/tidefs-witness-set` | `tidefs-witness-set` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `crates/tidefs-workload` | `tidefs-workload` | `workspace-member` | `proof-harness` | current proof harness; test signal only and not a product capability claim. |
| `crates/tidefs-xattr-storage` | `tidefs-xattr-storage` | `workspace-member` | `product-code` | current product component; capability claims remain limited by the review register. |
| `fuzz` | `tidefs-fuzz` | `workspace-excluded` | `standalone-fuzz` | standalone-checkable fuzz package; keep mirrored in workspace.exclude until restored or made an issue-backed archive/delete candidate. |
| `kmod` | `tidefs-kmod-bridge` | `workspace-member` | `adapter-operator` | current adapter/operator surface; capability claims remain behind focused validation. |
| `xtask/tidefs-xtask` | `tidefs-xtask` | `workspace-member` | `policy-tooling` | policy gate and developer tooling entrypoint; validates this classification authority. |

## Zero-Reverse And Transitional Dispositions

Zero reverse dependencies do not imply deletion. They mean the package is an entrypoint, a planned authority surface, a harness, vendored code, or a TFR-002 follow-up subject as listed below.

| Package root | Package | Role | Disposition |
| --- | --- | --- | --- |
| `apps/tidefs-filesystem-demo` | `tidefs-filesystem-demo` | `proof-harness` | demo entrypoint and proof harness; non-production Local Filesystem exercise only. |
| `apps/tidefs-scrub` | `tidefs-scrub` | `adapter-operator` | operator entrypoint for scrub/repair plumbing; not release proof by itself. |
| `apps/tidefs-storage-node` | `tidefs-storage-node` | `adapter-operator` | operator entrypoint for storage-node experiments; cluster authority remains TFR-017. |
| `apps/tidefs-store-demo` | `tidefs-store-demo` | `proof-harness` | demo entrypoint and proof harness; non-production Local Object Store exercise only. |
| `apps/tidefsctl` | `tidefsctl` | `adapter-operator` | operator entrypoint for CLI/UAPI work; TFR-011 and TFR-019 remain open. |
| `crates/tidefs-anti-entropy-auditor` | `tidefs-anti-entropy-auditor` | `product-code` | planned authority surface; follow-up issue required before release claims. |
| `crates/tidefs-block-kmod` | `tidefs-block-kmod` | `adapter-operator` | planned authority surface for adapter or kernel work; follow-up issue required before release claims. |
| `crates/tidefs-compaction` | `tidefs-compaction` | `product-code` | planned authority surface; follow-up issue required before release claims. |
| `crates/tidefs-crash-oracle` | `tidefs-crash-oracle` | `proof-harness` | planned authority surface for model-only crash oracle validation; follow-up issue required before it can support runtime release claims. |
| `crates/tidefs-data-cleaner` | `tidefs-data-cleaner` | `product-code` | planned authority surface; follow-up issue required before release claims. |
| `crates/tidefs-env-ublk-model` | `tidefs-env-ublk-model` | `proof-harness` | bounded uBLK qid/tag state model evidence only; runtime block-volume claims remain blocked on focused artifacts. |
| `crates/tidefs-erasure-coded-store` | `tidefs-erasure-coded-store` | `product-code` | planned authority surface; follow-up issue required before release claims. |
| `crates/tidefs-geometry-convert` | `tidefs-geometry-convert` | `product-code` | planned authority surface; follow-up issue required before release claims. |
| `crates/tidefs-kernel-cutover-runtime` | `tidefs-kernel-cutover-runtime` | `product-code` | planned authority surface; follow-up issue required before release claims. |
| `crates/tidefs-kmod-posix-vfs` | `tidefs-kmod-posix-vfs` | `adapter-operator` | planned authority surface for adapter or kernel work; follow-up issue required before release claims. |
| `crates/tidefs-model-core` | `tidefs-model-core` | `proof-harness` | planned authority surface for trace and oracle validation; follow-up issue required before it can support release claims. |
| `crates/tidefs-offload-core` | `tidefs-offload-core` | `product-code` | planned authority surface for non-authoritative offload descriptor, lease, CPU reference, and completion validation; not a GPU/FPGA production acceleration claim. |
| `crates/tidefs-online-defrag` | `tidefs-online-defrag` | `product-code` | planned authority surface; follow-up issue required before release claims. |
| `crates/tidefs-performance-contract` | `tidefs-performance-contract` | `product-code` | planned authority surface for performance admission and queue metadata; follow-up issue required before release claims. |
| `crates/tidefs-posix-filesystem-adapter-reply` | `tidefs-posix-filesystem-adapter-reply` | `adapter-operator` | planned authority surface for adapter or kernel work; follow-up issue required before release claims. |
| `crates/tidefs-posix-guarantee-verifier` | `tidefs-posix-guarantee-verifier` | `proof-harness` | planned authority surface for validation; follow-up issue required before it can support release claims. |
| `crates/tidefs-secret-key-policy-runtime` | `tidefs-secret-key-policy-runtime` | `policy-tooling` | planned authority surface for policy work; follow-up issue required before release claims. |
| `crates/tidefs-snapshot-pruner` | `tidefs-snapshot-pruner` | `product-code` | planned authority surface; follow-up issue required before release claims. |
| `crates/tidefs-two-node-harness` | `tidefs-two-node-harness` | `proof-harness` | planned authority surface for validation; follow-up issue required before it can support release claims. |
| `crates/tidefs-vfs-rpc` | `tidefs-vfs-rpc` | `product-code` | planned authority surface; follow-up issue required before release claims. |
| `xtask/tidefs-xtask` | `tidefs-xtask` | `policy-tooling` | policy gate and developer tooling entrypoint; validates this classification authority. |

## Excluded Manifest Authority

The root `workspace.exclude` list and the `workspace-excluded` rows above must match exactly. Each excluded root is a fuzz package today; if one stops being standalone-checkable, it must move to an issue-backed archive/delete candidate instead of silently drifting outside Cargo metadata.

| Package root | Package | Disposition |
| --- | --- | --- |
| `crates/tidefs-binary_schema-core/fuzz` | `tidefs-binary_schema-core-fuzz` | standalone-checkable fuzz package; keep mirrored in workspace.exclude until restored or made an issue-backed archive/delete candidate. |
| `crates/tidefs-local-filesystem/fuzz` | `tidefs-local-filesystem-fuzz` | standalone-checkable fuzz package; keep mirrored in workspace.exclude until restored or made an issue-backed archive/delete candidate. |
| `crates/tidefs-local-object-store/fuzz` | `tidefs-local-object-store-fuzz` | standalone-checkable fuzz package; keep mirrored in workspace.exclude until restored or made an issue-backed archive/delete candidate. |
| `crates/tidefs-validation/fuzz` | `tidefs-validation-fuzz` | standalone-checkable fuzz package; keep mirrored in workspace.exclude until restored or made an issue-backed archive/delete candidate. |
| `fuzz` | `tidefs-fuzz` | standalone-checkable fuzz package; keep mirrored in workspace.exclude until restored or made an issue-backed archive/delete candidate. |

## Boundary Rules Enforced By Xtask

`check-workspace-policy` validates this document against Cargo metadata, discovered package manifests, and root `workspace.exclude`. It fails when a workspace member or excluded package root is missing from the table, when package names or counts drift, when excluded manifests diverge from root Cargo policy, when any package root is classified as `scaffold-transitional` after issue #276, or when product/operator/tooling packages depend on `archive-delete-candidate` packages.

Issue #276 audited the prior scaffold-transitional type roots. Cargo metadata showed only an optional `tidefs-validation` manifest edge to `tidefs-types-control-plane-core`, plus scaffold-internal edges from `tidefs-types-publication-pipeline-core` and `tidefs-types-response-registry-core` to that same crate. Documentation references were limited to this authority, `crates/README.md`, `docs/REVIEW_TODO_REGISTER.md`, stale review material in `docs/ARCHITECTURE.md`, and xtask policy/terminology fixtures. The live control-plane, publication-pipeline, and response-registry record definitions are already present in `tidefs-types-vfs-core`; the stale package roots were deleted rather than reclassified.
