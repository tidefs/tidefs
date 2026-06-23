# Cargo Metadata Audit

Generated for issue [#1074](https://github.com/tidefs/tidefs/issues/1074) on 2026-06-23.

## Summary

Total workspace members: 157 (including 1 vendored third-party crate).

| Field | Present | Missing | Notes |
| --- | ---: | ---: | --- |
| `license` | 157 | 0 | 156 TideFS crates: `GPL-2.0-only WITH Linux-syscall-note`; 1 vendored third-party (`fuser`): `MIT` |
| `repository` | 157 | 0 | All 156 TideFS crates now inherit `https://github.com/tidefs/tidefs` from workspace |
| `homepage` | 157 | 0 | All 156 TideFS crates now inherit `https://github.com/tidefs/tidefs` from workspace |
| `description` | 157 | 0 | `tidefs-block-volume-adapter-core` was the sole crate missing this; now fixed |
| `documentation` | 157 | 0 | All 156 TideFS crates now inherit `https://github.com/tidefs/tidefs` from workspace |
| `readme` | 40 | 117 | Auto-detected from on-disk `README.md`; 40 crates have crate-level README files |

## Fix Applied

- Added `homepage` and `documentation` to `[workspace.package]` in root `Cargo.toml`.
- Added `repository.workspace = true`, `homepage.workspace = true`, `documentation.workspace = true` to all 156 TideFS member crate `Cargo.toml` files (excluding the vendored `fuser` crate).
- Added a `description` for `tidefs-block-volume-adapter-core`.

## Readme Coverage

40 crates have a `README.md` in their package root and Cargo auto-detects the `readme` field. The remaining 117 crates do not have crate-level README files; best-effort README coverage is recorded below.

### Crates With Crate-Level README

tidefs-block-allocator, tidefs-block-kmod, tidefs-block-volume-adapter-daemon, tidefs-block-volume-adapter-ublk-control-runtime, tidefs-claim-ledger, tidefs-cleanup-engine, tidefs-cleanup-queue-core, tidefs-cluster, tidefs-distributed-model-check, tidefs-durability-layout, tidefs-env-ublk-model, tidefs-extent-map, tidefs-inode-table, tidefs-intent-log, tidefs-kernel-cutover-runtime, tidefs-kernel-storage-io, tidefs-kmod-bridge, tidefs-kmod-posix-vfs, tidefs-local-filesystem, tidefs-membership-epoch, tidefs-membership-live, tidefs-model-core, tidefs-namespace, tidefs-node-drain, tidefs-offload-core, tidefs-performance-contract, tidefs-pool-allocator, tidefs-posix-filesystem-adapter-daemon, tidefs-receive-stream, tidefs-recovery-loop, tidefs-replication, tidefs-replication-model, tidefs-scrub-core, tidefs-segment-cleaner, tidefs-storage-node, tidefs-trace-oracle, tidefs-transport, tidefs-validation, tidefs-vfs-engine

### Crates Without Crate-Level README

tidefs-anti-entropy-auditor, tidefs-auth, tidefs-background-scheduler, tidefs-binary_schema-checksum, tidefs-binary_schema-core, tidefs-binary_schema-framing, tidefs-block-volume-adapter-core, tidefs-btree, tidefs-cache-coherency, tidefs-cache-core, tidefs-checksum-tree, tidefs-chunk-shipper, tidefs-cleanup-job-core, tidefs-clock-timing, tidefs-commit_group, tidefs-compaction, tidefs-compression, tidefs-coordination-strategy, tidefs-crash-oracle, tidefs-data-cleaner, tidefs-dataset-catalog, tidefs-dataset-feature-flags, tidefs-dataset-lifecycle, tidefs-dataset-properties, tidefs-dedup, tidefs-derived-catalog, tidefs-device-removal, tidefs-dir-index, tidefs-encryption, tidefs-env-fuse-model, tidefs-erasure-coded-store, tidefs-erasure-coding, tidefs-filesystem-demo, tidefs-flow-commit-coordinator, tidefs-frame, tidefs-gc-pin-set, tidefs-geometry-convert, tidefs-incremental-job-core, tidefs-inode-attributes, tidefs-invalidation-feed, tidefs-lease, tidefs-lease-manager, tidefs-local-object-store, tidefs-locator-table, tidefs-lock-service, tidefs-membership-types, tidefs-node-join, tidefs-object-io, tidefs-online-defrag, tidefs-orphan-index, tidefs-partition-runtime, tidefs-permission, tidefs-placement-planner, tidefs-placement-runtime, tidefs-pool-import, tidefs-pool-scan, tidefs-posix-acl, tidefs-posix-filesystem-adapter-reply, tidefs-posix-filesystem-adapter-workers-io, tidefs-posix-filesystem-adapter-workers-locks, tidefs-posix-guarantee-verifier, tidefs-posix-semantics, tidefs-quorum-write, tidefs-quorum-write-runtime, tidefs-rebalance-planner, tidefs-rebuild-planner, tidefs-rebuild-runtime, tidefs-reclaim, tidefs-reclaim-queue-core, tidefs-relocation-planner, tidefs-replica-health, tidefs-replicated-object-store, tidefs-reserve-ledger, tidefs-schema-codec-posix-filesystem-adapter, tidefs-schema-codec-vfs, tidefs-scrub, tidefs-secret-key-policy-runtime, tidefs-send-stream, tidefs-shard-group, tidefs-snapshot-pruner, tidefs-space-accounting, tidefs-spacemap-allocator, tidefs-storage-intent-core, tidefs-storage-intent-local-media-capability, tidefs-storage-intent-media-capability-refresh, tidefs-storage-intent-policy, tidefs-storage-intent-remote-media-capability, tidefs-store-demo, tidefs-tdma-scheduler, tidefs-two-node-harness, tidefs-types-cache-lattice-core, tidefs-types-claim-ledger-core, tidefs-types-dataset-feature-flags-core, tidefs-types-dataset-lifecycle-core, tidefs-types-deferred-cleanup-core, tidefs-types-extent-map-core, tidefs-types-incremental-job-core, tidefs-types-orphan-index-core, tidefs-types-package-profile-catalog, tidefs-types-polymorphic-directory-index-core, tidefs-types-polymorphic-xattr-core, tidefs-types-pool-label-core, tidefs-types-posix-filesystem-adapter-core, tidefs-types-reclaim-queue-core, tidefs-types-secret-key-policy-core, tidefs-types-space-accounting-core, tidefs-types-transport-session, tidefs-types-vfs-core, tidefs-types-vfs-owned, tidefs-ublk-abi, tidefs-verification-engine, tidefs-vfs-rpc, tidefs-witness-set, tidefs-workload, tidefs-xattr-storage, tidefs-xtask, tidefsctl

## Vendored Third-Party

`fuser` (vendored in `crates/tidefs-fuser/`) retains its upstream metadata including `license = "MIT"`, `repository = "https://github.com/cberner/fuser"`, and `documentation = "https://docs.rs/fuser"`. No changes were made to this crate.
