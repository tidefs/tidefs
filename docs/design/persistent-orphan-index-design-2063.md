# Persistent Orphan Index — Design Specification

**Issue**: [#2063](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/2063)
**Status**: design-spec
**Maturity**: design-spec — Rust wire-up implementation deferred to wire-up issues
**Lane**: storage-core
**Kind**: design
**Depends on**: #1207 (design anchor), #1621 (consolidated design), #1961 (wire-up design),
  #1373 (Phase 1 core types), #1383 (OrphanIndexRoot), #1267 (commit_group state machine),
  #1212 (deferred cleanup), #1219 (dataset lifecycle), #1179 (background scheduler),
  #1257 (B+tree CoW persistence), #1220 (on-media format), #1289 (polymorphic directory index),
  #1232 (snapshot deadlist), #1215 (space accounting)
**Supersedes**: #1207, #1621, #1961 — this is the canonical sealed design

---

## Abstract

The persistent orphan index is a dataset-scoped, key-only B+tree that tracks
nlink==0 inodes for bounded-memory, cursor-resumable crash recovery. It
replaces the naive O(total-inodes) mount-time scan with an O(orphans) indexed
approach. The index is rooted in DatasetMetadataV1.orphan_index_root with
8-byte big-endian OrphanKey entries and zero-byte values. Recovery operates
under a configurable OrphanRecoveryBudget, is idempotent across crashes, and
integrates with the commit_group commit pipeline, BackgroundReclaim, and deferred
cleanup infrastructure.

Phase 1 implementation is complete across three no_std crates (126 tests).
Rust wire-up across 9 integration points is deferred to wire-up issues.
