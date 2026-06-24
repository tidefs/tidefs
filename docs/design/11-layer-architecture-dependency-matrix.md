# 11-Layer Architecture Dependency Matrix

**Issue**: Historical Forgejo issue
[#1284](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1284)
**Status**: historical-input
**Priority**: Historical P1
**Lane**: historical docs
**Kind**: historical tracking
**Milestone**: Historical DESIGN-M1: Storage Foundation (Layers 0-2)
**Last updated**: 2026-05-03

> **HISTORICAL DESIGN INPUT — NOT CURRENT AUTHORITY**
>
> This file is imported Forgejo-era coordination material for the May 2026
> DESIGN issue set. Its Forgejo issue numbers, DESIGN milestone rows,
> `claimed`/`ready`/`open`/`done` labels, critical-path and parallelization
> tables, sequencing notes, and recent-change records are historical input
> only.
>
> Do not use this matrix as live GitHub scheduling authority, implementation
> status, release-readiness evidence, or current product architecture policy.
> Current TideFS work-selection and status authority comes from live GitHub
> issues and pull requests plus repo docs classified as current policy or
> current spec by
> [`docs/DOCUMENTATION_AUTHORITY_REGISTER.md`](../DOCUMENTATION_AUTHORITY_REGISTER.md).

## Abstract

The imported Forgejo design model organized TideFS architecture into 11 layers
grouped into 4 milestone blocks. This document mapped each historical DESIGN
issue to its layer, recorded cross-issue dependencies, identified
parallelization-safe groups, and traced a critical path from L0 (format
contracts) through L11 (cluster orchestration).

The matrix is preserved as historical design input for later source and
documentation review. It is not maintained as the single source of truth for
work sequencing, current implementation status, release readiness, or product
architecture direction.

---

## 1. Layer Architecture Overview

| Layer | Name | Milestone | Description |
|-------|------|-----------|------------|
| L0 | Format Architecture | DESIGN-M1 | Three-contract organizing principle, format lifecycle, methodology |
| L1 | On-Media Storage | DESIGN-M1 | Record format, extent maps, locators, shards, allocator, device layout |
| L2 | Transaction Model | DESIGN-M1 | Writeback, commit ordering, intent log, space accounting |
| L3 | VFS Engine / Namespace | DESIGN-M2 | API contract, rename atomicity, lock hierarchy, orphan index, dataset lifecycle |
| L4 | Background Services | DESIGN-M2 | Background service framework, GC, compaction, defrag, ARC cache, prefetch |
| L5 | Coherency + Tiering | DESIGN-M2 | FUSE coherency profiles, FlashTier/cache device tiering |
| L6 | Data Services | DESIGN-M3 | Checksums, compression, encryption, dedup, reflink, adaptive recordsize |
| L7 | Integrity Services | DESIGN-M3 | Scrub/repair/resilver, metadata redundancy, sector alignment, snapshot retention |
| L8 | Cluster Simnet | DESIGN-M4 | Deterministic protocol testing harness |
| L10 | Cluster Data Plane | DESIGN-M4 | ublk volumes, mmap coherency, snapshots, send/receive, BULK plane, erasure coding |
| L11 | Cross-cutting | DESIGN-M4 | FUSE binding, trace emission, scheduling classes, resource governor |

### 1.1 Bedrock Issues

In the historical design model, five Forgejo issues formed architectural
bedrock. Their design decisions cascaded into multiple dependents. Treat these
rows as imported dependency context, not as current GitHub issue status or a
current downstream coordination rule:

| Bedrock | Layer | Issue | Description |
|---------|-------|-------|------------|
| B1 | L1 | #1220 | On-media record format — referenced by 9 downstream issues |
| B2 | L1 | #1285 | Extent maps + locator tables — referenced by 5 downstream issues |
| B3 | L3 | #1213 | VFS Engine API contract — referenced by 8 downstream issues |
| B4 | L4 | #1179 | Background service framework — referenced by 6 downstream issues |
| B5 | L9 | #1209 | MEMBERSHIP service — referenced by 7 downstream issues |

---

## 2. Full Dependency Matrix by Layer

### L0 — Format Architecture

| Issue | Title | Status | Dependencies | Dependents |
|-------|-------|--------|-------------|------------|
| #1250 | Three-contract architecture | claimed/ready | — | #1220, #1213, #1235 (conceptual foundation for all contracts) |
| #1238 | Unified on-media format lifecycle | ready | #1250, #1220 | #1223, #1245, #1246 (format evolution gates) |
| #1236 | RFP-Core translation methodology | done | — | All implementation issues (mechanical port rules) |
| #1279 | ZFS/Ceph design mistake coverage matrix | claimed/ready | — | Cross-referenced by all DESIGN issues |

**Parallelization**: #1250, #1236, #1279 are independent and can proceed in parallel.
#1238 depends on #1250 and #1220.

### L1 — On-Media Storage

| Issue | Title | Status | Dependencies | Dependents |
|-------|-------|--------|-------------|------------|
| #1220 | On-media record format | done ★ | #1250 | #1223, #1224, #1225, #1285, #1286, #1267, #1245, #1246, #1287 |
| #1223 | Dataset feature flags | done | #1220, #1238 | Extent map extensions, format evolution |
| #1224 | Torn-commit recovery | done | #1220 | #1190 (writeback recovery path) |
| #1225 | V1 extent map tristate | done | #1220 | #1285, #1257 |
| #1285 | Extent maps + locator tables | done ★ | #1220, #1225 | #1286, #1190, #1265, #1257, #1276 |
| #1286 | Shard groups, replicas, rebake | done | #1220, #1285 | #1222, #1249 (shard → erasure coding) |
| #1222 | Rebake architecture | open | #1286 | #1265 (defrag uses rebake pathway) |
| #1189 | Spacemap/allocator (G1) | done | — | #1215 |
| #1193 | Device layout policies | done | — | Pool scaling, segment sizing |

**Parallelization groups**:
- Group L1-A (complete): #1220, #1189, #1193 — independent foundations
- Group L1-B (complete): #1223, #1224, #1225 — depend on #1220; parallel with each other
- Group L1-C (complete): #1285, #1286 — depend on #1220/#1225; #1286 depends on #1285 (serial)
- Group L1-D (open): #1222 — depends on #1286

★ = Bedrock issue

### L2 — Transaction Model

| Issue | Title | Status | Dependencies | Dependents |
|-------|-------|--------|-------------|------------|
| #1190 | Writeback + transaction model | claimed | #1220, #1224, #1285 | L3+ write-path semantics |
| #1267 | Canonical commit ordering + commit_group | done | #1220, #1190 | All L3-L4 transactional ops |
| #1252 | Intent log / LOG_DEVICE | done | #1190, #1267 | — |
| #1215 | Space accounting model | done ★ | #1189 | #1181 (ENOSPC), #1485 (cleaner watermarks) |

**Parallelization**: #1267, #1252 depend on #1190 (serial chain: #1190 → {#1267, #1252} parallel).

### L3 — VFS Engine / Namespace

| Issue | Title | Status | Dependencies | Dependents |
|-------|-------|--------|-------------|------------|
| #1213 | VFS Engine API contract | done ★ | #1250 | #1205, #1206, #1207, #1219, #1232, #1216, #1233, #1235 |
| #1205 | Rename atomicity spec | claimed | #1213 | — |
| #1206 | Lock hierarchy + concurrency | done | #1213 | #1248 (distributed locks) |
| #1207 | Persistent orphan index | done | #1213 | — |
| #1219 | Dataset lifecycle state machine | done | #1213 | #1282 (dataset rename) |
| #1232 | Snapshot deadlist pinning | done | #1213 | #1258 (atomic snapshot coordination) |
| #1278 | Metadata engine parallelism | open | #1213, #1206 | — |

**Parallelization groups**:
- Group L3-A (complete): #1206, #1207, #1219, #1232 — all depend on #1213; parallel with each other
- Group L3-B (open): #1205, #1278

★ = Bedrock issue

### L4 — Background Services + Caching

| Issue | Title | Status | Dependencies | Dependents |
|-------|-------|--------|-------------|------------|
| #1179 | Background service framework | done ★ | — | #1180, #1181, #1197, #1239, #1265, #1288 |
| #1180 | Refcount delta cleanup | done | #1179 | — |
| #1181 | ENOSPC pressure handling | open ★ | #1179, #1215 | — |
| #1197 | B+tree compaction | done | #1179 | — |
| #1239 | Universal incremental cursor | done ★ | #1179 | All resumable background jobs |
| #1265 | Online defrag | done | #1179, #1239, #1285, #1222 | — |
| #1192 | Weighted ARC cache | open ★ | — | #1256 |
| #1268 | Workload-signature materialization | open | — | #1247 |
| #1247 | Prefetch/readahead architecture | open | #1268 | #1256 |

**Parallelization groups**:
- Group L4-A (complete): #1180, #1197, #1239 — all depend on #1179; parallel with each other
- Group L4-B (complete): #1265 — depends on #1179 + #1239 + #1285 + #1222
- Group L4-C (open): #1181 (parallel:safe), #1192 (parallel:safe), #1268
- Group L4-D (open): #1247 — depends on #1268

★ = Bedrock issue

### L5 — Coherency + Tiering

| Issue | Title | Status | Dependencies | Dependents |
|-------|-------|--------|-------------|------------|
| #1184 | Named coherency profiles | claimed/ready | #1213 | FUSE daemon caching |
| #1256 | Cache device tiering / FlashTier | open | #1192, #1247 | — |

**Parallelization**: #1184 and #1256 are independent.

### L6 — Data Services

| Issue | Title | Status | Dependencies | Dependents |
|-------|-------|--------|-------------|------------|
| #1287 | Checksum architecture | done | #1220 | #1288 (scrub verification) |
| #1257 | Adaptive recordsize | open | #1225, #1285 | Extent shaping |
| #1276 | Cross-dataset reflink | open ★ | #1285 | — |
| #1255 | Deduplication | open ★ | — | — |
| #1253 | Per-dataset property framework | open ★ | — | #1245, #1246, #1277 |
| #1245 | Compression strategy | open ★ | #1220, #1238, #1253 | — |
| #1246 | Encryption-at-rest strategy | open ★ | #1220, #1238, #1253 | — |

**Parallelization groups**:
- Group L6-A (open, parallel:safe): #1255, #1253, #1245, #1246, #1185 — independent designs
- Group L6-B (open): #1257, #1276 — share extent map dependency

★ = parallel:safe within L6

### L7 — Integrity Services

| Issue | Title | Status | Dependencies | Dependents |
|-------|-------|--------|-------------|------------|
| #1288 | Scrub/repair/resilver | done | #1179, #1287 | — |
| #1281 | Metadata redundancy fallback | open | — | — |
| #1280 | Variable device sector alignment | open | — | — |
| #1277 | Snapshot limits/retention | open ★ | #1253 | — |

**Parallelization groups** (L7-A, all open): #1281, #1280, #1277 parallel.

### L8 — Cluster Simnet

| Issue | Title | Status | Dependencies | Dependents |
|-------|-------|--------|-------------|------------|
| #1175 | Deterministic cluster simnet | open | L9-L10 protocol specs | Protocol correctness testing |

### L9 — Cluster Coordination

| Issue | Title | Status | Dependencies | Dependents |
|-------|-------|--------|-------------|------------|
| #1209 | MEMBERSHIP service | done ★ | — | #1208, #1217, #1260, #1283, #1248, #1258, #1249 |
| #1217 | Admin proxy model | claimed | #1209 | — |
| #1260 | Node lifecycle management | open ★ | #1209 | — |
| #1283 | Bounded membership state | open ★ | #1209 | — |
| #1228 | Security/identity model | open ★ | — | #1246 (encryption keys) |
| #1243 | ADMIN service wire protocol | open ★ | #1217 | — |
| #1248 | Distributed lock service | open | #1209, #1206 | — |

**Parallelization groups**:
- Group L9-A (complete): #1209
- Group L9-B (parallel:safe): #1260, #1283, #1228, #1243 — independent of each other
- Group L9-C: #1208, #1217 (claimed), #1248 (depends on #1206)

★ = parallel:safe within L9

### L10 — Cluster Data Plane

| Issue | Title | Status | Dependencies | Dependents |
|-------|-------|--------|-------------|------------|
| #1216 | ublk block volume surface | open | #1213 | — |
| #1259 | mmap cluster coherency | open | — | — |
| #1258 | Atomic snapshot coordination | open | #1209, #1232 | — |
| #1251 | Dataset send/receive | open | — | — |
| #1229 | BULK plane protocol | claimed/ready ★ | — | — |
| #1240 | Derived views | open | — | — |
| #1249 | CRUSH placement (G4) | done | #1209, #1286 | — |
| #1275 | Online pool geometry conversion | open | #1249 | — |
| #1282 | Online dataset rename | open | #1219 | — |

**Parallelization groups**:
- Group L10-A (open, parallel:safe): #1229, #1216, #1259, #1251, #1240, #1282 — independent
- Group L10-B (open): #1258 (depends on #1209, #1232), #1275 (depends on #1249)

### L11 — Cross-cutting

| Issue | Title | Status | Dependencies | Dependents |
|-------|-------|--------|-------------|------------|
| #1233 | FUSE binding strategy | done | #1213 | — |
| #1235 | VfsEngine trace emission | open | #1213 | — |
| #1241 | Unified scheduling classes | needs-review | — | #1210, FUSE scheduling, #1229, #1208 |
| #1237 | Resource governor | (merged into #1241) | #1179, #1241 | Cache admission, memory pressure |

**Parallelization**: #1235 and #1241 are independent.

---

## 3. Dependency Graph (Critical Path)

```
L0: #1250 ─────────────────────────────────────────────────────────────────────┐
     │                                                                          │
L1:  ├── #1220 ──┬── #1223 (∥)                                                 │
     │           ├── #1224 (∥) ──────────────┐                                  │
     │           ├── #1225 (∥) ──┐            │                                 │
     │           └── #1285 ──────┤            │                                 │
     │               │           │            │                                 │
     │           #1286          #1257        │                                  │
     │               │                      │                                  │
     │           #1222               ┌──────┘                                  │
     │                              │                                          │
L2:  │   #1190 ◄──── #1224 ────────┤                                          │
     │    │                         │                                          │
     │    ├── #1267 (∥)            │                                          │
     │    └── #1252 (∥)            │                                          │
     │                             │                                          │
L3:  ├── #1213 ──┬── #1206 (∥)────┼── #1248 (L9)                              │
     │           ├── #1207 (∥)     │                                           │
     │           ├── #1219 (∥)────┼── #1282 (L10)                              │
     │           ├── #1232 (∥)────┼── #1258 (L10)                              │
     │           └── #1205        │                                            │
     │                            │                                            │
L4:  │   #1179 ──┬── #1180 (∥)    │                                            │
     │           ├── #1197 (∥)    │                                            │
     │           ├── #1239 (∥)────┤                                            │
     │           └── #1181        │                                            │
     │                            │                                            │
L5:  │   #1184                    │                                            │
     │                            │                                            │
L6:  │   #1287 ──────────────────┤                                            │
     │                            │                                            │
L7:  │   #1288 ◄── #1179 + #1287 │                                            │
     │                            │                                            │
L9:  └── #1209 ──┬── #1208       │                                            │
                 ├── #1217       │                                            │
                 └── #1249 ─────┤                                            │
                                │                                            │
L10:                            ├── #1229 (∥)                                 │
                                ├── #1216 (∥)                                 │
                                ├── #1259 (∥)                                 │
                                └── #1251 (∥)                                 │
                                                                            │
L11: #1241 ◄────────────────────────────────────────────────────────────────┘
```

**Legend**: `──` = depends on, `(∥)` = can parallelize with siblings, `★` = bedrock

---

## 4. Parallelization Groups

In the historical Forgejo claim model, issues within a group could be claimed
and worked on simultaneously. Groups were ordered by dependency: groups later
in the list depended on groups earlier in the list (or were independent). These
tables are not live GitHub scheduling authority.

### P0 — No-dependency, always safe

| Group | Issues | Status |
|-------|--------|--------|
| P0-A | #1250, #1236, #1279 | #1236 done; #1250 claimed; #1279 claimed |
| P0-B | #1189, #1193 | Both done |

### P1 — L1 format (depends on L0)

| Group | Issues | Status |
|-------|--------|--------|
| P1-A | #1223, #1224, #1225 | All done |
| P1-B | #1285 | Done |
| P1-C | #1286 | Done |
| P1-D | #1222 | Open |

### P2 — L2 transaction (depends on L1)

| Group | Issues | Status |
|-------|--------|--------|
| P2-A | #1190 | Claimed |
| P2-B | #1267, #1252, #1215 | All done |

### P3 — L3 VFS + L4 background (depends on L2 bedrock)

| Group | Issues | Status |
|-------|--------|--------|
| P3-A | #1213, #1179 | Both done |
| P3-B | #1206, #1207, #1219, #1232, #1180, #1197, #1239 | All done |
| P3-C | #1205 (claimed), #1278, #1181 (∥), #1265 | #1265 done; others open |

### P4 — L5 coherency + L6 data services + L7 integrity (mostly independent)

| Group | Issues | Status |
|-------|--------|--------|
| P4-A | #1184, #1192 (∥), #1268, #1256 | Various; #1184 claimed |
| P4-B | #1287, #1288 | Both done |
| P4-C | #1255 (∥), #1253 (∥), #1245 (∥), #1246 (∥), #1185 (∥) | All open |
| P4-D | #1257, #1276, #1277 (∥), #1281, #1280 | All open |

### P5 — L9 coordination + L10 data plane (depends on prior layers)

| Group | Issues | Status |
|-------|--------|--------|
| P5-A | #1209, #1249 | Both done |
| P5-B | #1208 (claimed), #1217 (claimed) | Claimed |
| P5-C | #1260 (∥), #1283 (∥), #1228 (∥), #1243 (∥) | All open |
| P5-D | #1229 (claimed), #1216, #1259, #1251, #1240, #1282 | #1229 claimed; rest open |
| P5-E | #1248, #1258, #1275 | All open |

### P6 — L8 simnet + L11 cross-cutting

| Group | Issues | Status |
|-------|--------|--------|
| P6-A | #1175 | Open |
| P6-B | #1235, #1241 | #1241 needs-review; #1235 open |

---

## 5. Critical Path

The longest dependency chain from L0 to completion:

```
#1250 → #1220 → #1285 → #1190 → #1267 → #1213 → #1206 → #1248 → #1258 → deployment
```

**Estimated issue count on critical path**: 10 (all DESIGN-only)
**Status**: 8 of 10 done; #1190 (claimed), #1248 (open)

### Secondary critical paths

1. **Format → Integrity**: `#1220 → #1287 → #1288` (all done)
2. **Format → Data Services**: `#1220 → #1285 → #1257` (#1257 open)
3. **Membership → Cluster**: `#1209 → #1260 → #1258` (#1260, #1258 open)

---

## 6. Status Summary

### By Milestone

| Milestone | Total | Done | Claimed | Open | % Complete |
|-----------|-------|------|---------|------|-----------|
| DESIGN-M1 (L0-L2) | 20 | 15 | 3 | 2 | 75% |
| DESIGN-M2 (L3-L5) | 18 | 13 | 2 | 3 | 72% |
| DESIGN-M3 (L6-L7) | 12 | 2 | 0 | 10 | 17% |
| DESIGN-M4 (L8-L11) | 21 | 4 | 4 | 13 | 19% |
| **Total** | **71** | **34** | **9** | **28** | **48%** |

### By Priority

| Priority | Total | Done | Claimed | Open |
|----------|-------|------|---------|------|
| P0 | 2 | 1 | 1 | 0 |
| P1 | 19 | 15 | 4 | 0 |
| P2 | 50 | 18 | 4 | 28 |

### Open Issues Requiring Attention

| Priority | Count | Issues |
|----------|-------|--------|
| P0 | 0 | — |
| P1 | 0 | — |
| P2 | 28 | #1222, #1181, #1278, #1192, #1268, #1247, #1256, #1257, #1276, #1255, #1253, #1245, #1246, #1185, #1281, #1280, #1277, #1175, #1260, #1283, #1228, #1243, #1248, #1216, #1259, #1258, #1251, #1275, #1240, #1282, #1235 |

---

## 7. Recent Changes (Session 2026-05-02)

### Merges
- #1226 + #1211 → closed, subsumed by #1237 (unified resource governor)
- #1266 → closed, merged into #1215 (space accounting extended with per-directory quotas)
- #1274 → closed, merged into #1241 (scheduling classes extended with per-dataset QoS)

### Splits
- #1191 → #1285 (extent maps + locators) + #1286 (shards, replicas, rebake)
- #1221 → #1287 (checksums + verification) + #1288 (scrub, repair, resilver)

### New Issues Created
| #1285 | Extent maps and locator tables: core data structures |
| #1286 | Shard groups, replicas, and rebake pathway |
| #1287 | End-to-end checksum architecture and integrity verification |
| #1288 | Scrub, repair, and resilver orchestration |

### Labeling
All 68 previously-unlabeled DESIGN issues now labeled with area:, lane:, priority:, kind:.

### Dependency Blocks
Bedrock issues #1220, #1213, #1179, #1209, #1285 have explicit dependency-block comments.

---

## 8. Serial Write Surfaces

The historical snapshot recorded these serial write surfaces:

| Surface | Path | Rule |
|---------|------|------|
| Local filesystem | `crates/tidefs-local-filesystem/src/lib.rs` | One active issue at a time |
| Local object store | `crates/tidefs-local-object-store/src/lib.rs` | One active issue at a time |

Non-code DESIGN issues in that snapshot did not touch these surfaces.
Historical implementation issues were expected to check Forgejo claim status
before editing; current TideFS work must use live GitHub issue/PR coordination
and repo docs classified as current policy or current spec.

---

## 9. Historical Issue State Reference

The Forgejo query below was the authority path for this imported snapshot only.
It is not current TideFS work-selection, scheduling, implementation-status, or
release-readiness authority. For current work, use live GitHub issues and pull
requests plus repo docs classified as current policy or current spec.

```
curl -u forgeadmin:TOKEN \
  http://172.16.106.12/forgejo/api/v1/repos/forgeadmin/tidefs/issues/<number>
```

Labels `codex:ready`, `codex:claimed`, `codex:needs-review`, `codex:blocked`, and
`codex:done` are historical Forgejo-era labels in this context. Do not treat
them as live coordination state.

Do not use `~/ai/bin/tidefs-claim status` or this matrix to preselect current
TideFS product direction.
