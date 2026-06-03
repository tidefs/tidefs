# ZFS and Ceph Design Mistake Coverage Matrix

**Issue**: [#1279](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1279)
**Status**: tracking
**Priority**: P0
**Lane**: docs

## Purpose

Systematic audit of known ZFS and Ceph design mistakes, mapping each to the tidefs
DESIGN issue that addresses it. This tracking document ensures we don't repeat any
of the competition's architectural errors.

Status: **COVERED** = design issue exists with explicit coverage;
**PARTIAL** = issue exists but needs hardening (comment added);
**GAP** = no coverage.

---

## ZFS Design Mistakes (28 enumerated)

| # | Mistake | tidefs coverage | Issue |
|---|---------|----------------|-------|
| 1 | No block pointer rewrite (BPR) — can't defrag online | COVERED | #1265 (online defrag) |
| 2 | Tree-ordered resilver — slow random IO | COVERED | #1221 (integrity/repair) + comment |
| 3 | Sequential (not parallel) resilver — days for large pools | COVERED | #1221 + comment (parallel resilver) |
| 4 | No reflink dedup — only block-level DDT with massive RAM cost | COVERED | #1255 (dedup with DDT tiering) |
| 5 | ZIL write amplification — sync data written twice | COVERED | #1252 + comment (pointer-based ZIL) |
| 6 | No directory-level quotas — only dataset quotas | COVERED | #1266 (per-directory quotas) |
| 7 | Single-threaded commit_group sync — bottleneck on large pools | COVERED | #1267 + comment (parallel SYNC) |
| 8 | ARC limited to 50% RAM — historical Linux default issue | COVERED | #1237 (unified resource governor) |
| 9 | No online compression algorithm change — send/recv required | COVERED | #1245 + comment (lazy re-compress) |
| 10 | Pool fragmentation over time — metaslab fragmentation | COVERED | #1265 (defrag), #1189 (spacemap), #1193 (layout) |
| 11 | No encryption key rotation — only master key re-wrap | COVERED | #1246 + comment (true DEK rotation) |
| 12 | Fixed recordsize per dataset — can't adapt per file or online | COVERED | #1257 (adaptive recordsize) |
| 13 | Snapshot count degradation — deadlist processing stalls pool | COVERED | #1232 + comment (O(freed) destroy, resumable) |
| 14 | No per-dataset snapshot limit enforcement — external sanoid only | COVERED | #1277 (snapshot limits + retention) |
| 15 | LOG_DEVICE failure can cause pool import failure | COVERED | #1252 + comment (LOG_DEVICE never blocks import) |
| 16 | No rebalance after device addition — new writes only | COVERED | #1254 (pool topology) |
| 17 | No hot spare auto-replacement — requires operator action | COVERED | #1260 (node lifecycle: staged drain) |
| 18 | Send/recv fragile — resume-after-interrupt added late, still fragile | COVERED | #1251 (send/recv with resume) |
| 19 | No cross-dataset copy offload — must send/recv | COVERED | #1276 (cross-dataset reflink/copy offload) |
| 20 | DDT in-memory only — no disk spill, can't scale | COVERED | #1255 (DDT L1/L2/L3 tiering) |
| 21 | FlashTier is write-once — no cache warming after reboot | COVERED | #1256 (FlashTier cluster-aware, persistent) |
| 22 | No per-tenant cache partitioning — one tenant evicts another | COVERED | #1237 + comment (cache domains) |
| 23 | No per-dataset IOPS/bandwidth QoS — no tenant isolation | COVERED | #1274 (per-dataset QoS) |
| 24 | Slow pool import — serial device discovery | COVERED | #1254 + comment (parallel device discovery) |
| 25 | No online pool geometry conversion — mirror<->parity_raid impossible | COVERED | #1275 (geometry conversion) |
| 26 | Striped write padding waste — recordsize misalignment | COVERED | #1257 (adaptive recordsize) + #1264 (switching) |
| 27 | ZIL replay single-threaded — slow import after crash | COVERED | #1252 + comment (parallel ZIL replay) |
| 28 | No partial pool export — can't split a pool | COVERED | #1254 + comment (partial pool export) |

## Ceph Design Mistakes (17 enumerated)

| # | Mistake | tidefs coverage | Issue |
|---|---------|----------------|-------|
| 1 | CRUSH complexity — straw2 is notoriously hard to reason about | COVERED | #1249 + comment (simpler-than-CRUSH) |
| 2 | PG count frozen at pool creation — hard to change | COVERED | #1249 + comment (no PG equivalent, lazy re-placement) |
| 3 | OSD maps grow unboundedly with cluster history | COVERED | #1249 + comment (deterministic hash, no epoch history) |
| 4 | MDS single-threaded for namespace ops — ~10-50K ops/sec | COVERED | #1278 (metadata engine parallelism) |
| 5 | CephFS snapshot is per-directory, not per-filesystem — confusing | COVERED | #1258 (cluster atomic snapshots), #1232 (deadlist) |
| 6 | No quota support — CephFS quotas are best-effort, buggy | COVERED | #1266 (per-directory quotas, hard enforcement) |
| 7 | No native CephFS compression — only at RADOS/BlueStore level | COVERED | #1245 (compression, per-dataset) |
| 8 | OSD compaction storms under high churn — RocksDB + raw device | COVERED | #1181 (ENOSPC handling), #1179 (background services) |
| 9 | BlueStore fragmentation — unpredictable space usage | COVERED | #1265 (online defrag), #1193 (layout policies) |
| 10 | No send/recv equivalent for CephFS | COVERED | #1251 (send/recv) |
| 11 | Recovery prioritization is coarse — per-OSD, not per-object | COVERED | #1249 + comment (per-extent recovery priority) |
| 12 | MDS failover can be slow — journal replay serial | COVERED | #1260 (node lifecycle), #1278 (metadata parallelism) |
| 13 | No native CephFS encryption — only RBD/messenger level | COVERED | #1246 (encryption-at-rest) |
| 14 | MDS cache trimming aggressive — causes latency spikes | COVERED | #1237 (resource governor), #1176 (cache-lattice) |
| 15 | No subvolume quota isolation — tenants share MDS cache + IOPS | COVERED | #1266 (quotas), #1274 (QoS), #1237 (cache domains) |
| 17 | Not truly POSIX — hard links broken, no O_TMPFILE for years | COVERED | #1213 (VFS engine), #1233 (FUSE binding), #1198 (POSIX library) |

---

Every ZFS and Ceph design mistake has at least one tidefs DESIGN issue addressing
it. Where existing issues needed hardening, targeted comments were added (first
session: 8 comments on #1221, #1245, #1246, #1254, #1249, #1252, #1267, #1237).

New DESIGN issues created specifically to close ZFS/Ceph gaps (first session):
#1274 (QoS), #1275 (geometry conversion), #1276 (cross-dataset reflink),
#1277 (snapshot limits), #1278 (metadata parallelism).

---

## ZFS Design Mistakes — Second Pass (10 additional, this session)

| # | Mistake | tidefs coverage | Issue |
|---|---------|----------------|-------|
| 29 | ashift immutability — sector alignment baked in at device creation, can't add 4K-native drives later without wasting space | COVERED | #1280 (variable device sector alignment) |
| 30 | Special device single point of failure — metadata-only device failure destroys ENTIRE pool even though data devices are intact | COVERED | #1281 (metadata redundancy fallback) |
| 31 | Dataset rename requires unmount — dataset identity tied to mount point, renaming disrupts applications | COVERED | #1282 (online dataset rename) |
| 32 | ZIL is pool-wide — sync=always on one dataset forces ZIL writes for all datasets; per-dataset ZIL policy impossible | COVERED | #1252 + comment 16134 (per-dataset ZIL policy) |
| 33 | Pool-wide commit_group sync — fsync on one dataset flushes all pool dirty data; no dataset-level durability isolation | COVERED | #1267 + comment 16136 (dataset-isolated commit_group barriers) |
| 34 | mmap torn write visibility — page cache not synchronized with commit_group boundaries; readers see intermediate states | COVERED | #1259 + comment 16137 (mmap torn-write prevention) |
| 35 | No write-intent bitmap — crash recovery scope is O(pool size), not O(in-flight writes); entire pool must be verified | COVERED | #1190 + comment 16140 (bounded crash recovery scope) |
| 36 | Scrub is pool-wide with no per-dataset prioritization — critical datasets wait days for sequential pool scrub | COVERED | #1221 + comment 16138 (per-dataset scrub scheduling) |
| 37 | Send/recv resumable state lost on pool export — multi-TB send must restart from zero after export | COVERED | #1251 + comment 16139 (externally storable resume tokens) |
| 38 | Sub-file and sub-directory snapshots don't exist — dataset-level only; forces dataset proliferation for isolation | COVERED | #1232 + comment 16162 (sub-file snapshot scope) |

## Ceph Design Mistakes — Second Pass (5 additional, this session)

| # | Mistake | tidefs coverage | Issue |
|---|---------|----------------|-------|
| 18 | Monitor OOM — OSDMap grows unboundedly with cluster history, monitors store ALL epochs in memory | COVERED | #1283 (bounded cluster membership state) |
| 19 | CRUSH rebalancing is catastrophic — small topology change triggers petabytes of data movement with no budget/pause | COVERED | #1249 + comment 16141 (bounded lazy rebalancing) |
| 20 | MDS journal replay is O(journal), not O(dirty) — failover replays entire journal regardless of actual dirty count | COVERED | #1278 + comment 16142 (O(dirty) metadata replay) |
| 21 | Unbounded OSD memory growth — RocksDB block cache grows with workload, no hard cap, per-OSD 4-8GB+ | COVERED | #1237 + comment 16143 (per-tenant cache isolation with hard caps) |
| 22 | No per-tenant cache isolation — one tenant's working set evicts another's; noisy neighbor destroys cache hit rates | COVERED | #1237 + comment 16143 (per-tenant cache partitioning) |

---

## Summary

**38 ZFS design mistakes mapped: 38 COVERED.**
**22 Ceph design mistakes mapped: 22 COVERED.**

Total: **60 ZFS+Ceph design mistakes, all COVERED by at least one tidefs DESIGN issue.**

New DESIGN issues created across both sessions for uncovered gaps:

First session:
- #1274 (per-dataset IOPS/bandwidth QoS)
- #1275 (online pool geometry conversion)
- #1276 (cross-dataset reflink/copy offload)
- #1277 (per-dataset snapshot limits + retention)
- #1278 (metadata engine parallelism)

Second session:
- #1280 (variable device sector alignment: anti-ashift)
- #1281 (metadata redundancy fallback: anti-special-device-SPOF)
- #1282 (online dataset rename: anti-unmount-requirement)
- #1283 (bounded cluster membership state: anti-monitor-OOM)

Hardening comments added to existing issues (first session, 8 issues):
#1221 (parallel resilver, per-dataset scrub), #1245 (lazy re-compress),
#1246 (true DEK rotation), #1254 (parallel device discovery, partial pool export),
#1249 (simpler-than-CRUSH, no PG equivalent), #1252 (pointer-based ZIL,
LOG_DEVICE-never-blocks-import, parallel ZIL replay), #1267 (parallel SYNC),
#1237 (cache domains).

Hardening comments added to existing issues (second session, 10 issues):
#1252 (per-dataset ZIL), #1267 (dataset-isolated commit_group), #1259 (mmap torn-write),
#1221 (per-dataset scrub), #1251 (externally storable resume tokens),
#1190 (write-intent bitmap), #1249 (bounded lazy rebalancing),
#1278 (O(dirty) replay), #1237 (per-tenant cache isolation),
#1232 (sub-file snapshots)

## Verification methodology

Each mistake was verified by:
1. Reading the relevant tidefs DESIGN issue body to confirm explicit coverage of the anti-pattern
2. Where coverage was implicit or partial, adding a comment with explicit design requirements
3. Where no coverage existed, creating a new DESIGN issue

## Maintenance

When a new DESIGN issue is created, check this matrix to see if it addresses an
already-tracked mistake. When a ZFS or Ceph release introduces a new known
limitation, add it to this matrix.

This tracking document mirrors Forgejo issue #1279 and should stay synchronized
with it.
