# Torn-Commit Recovery Contract: Journal Scanning Fallback

**Issue**: [#1224](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1224)
**Status**: design-spec
**Priority**: P1
**Lane**: storage-core
**Depends on**: P2-05 (checkpoint/snapshot/replay cursor persistence law), #1221 (integrity G3)
**Extracted from**: tidefs v0.262 Python design book (§2 "Failure model", §12 "Device system area", §16 "Checkpoints and root commits")

## Abstract

This document defines the torn-commit recovery contract for tidefs. When the
system-area checkpoint pointers are intact, pool open follows the fast path:
fallback recovery path scans all journal segments to identify the latest valid
commit, rebuilds in-memory state from that commit, and rebuilds the checkpoint
pointers.

## 1. Core Result

The torn-commit recovery contract establishes:

- **Two-tier recovery model**: fast path (intact pointers) and fallback path (journal scanning)
- **Self-identifying commit records**: each commit carries magic bytes, monotonic `commit_commit_group: u64`, CRC covering the full payload, and references to all metadata roots
- **Operator visibility**: a "recovery degraded" flag surfaces when fallback recovery was required

## 2. Two-Tier Recovery Model

### 2.1 Fast Path (Normal)


```
Pool::open()
  → read system-area header
  → read latest checkpoint pointer
  → reconstruct in-memory state from committed metadata roots
  → resume service
```

### 2.2 Fallback Path (Torn/Corrupt)

Triggered when:
- System-area checkpoint pointers are unreadable (media error, torn write)
- Pointers reference out-of-range segment offsets
- Any root pointer in the commit is outside valid segment ranges

```
Pool::open()
  → read system-area header → FAIL
  → enter fallback recovery
  → scan all journal segments for valid commit records
  → identify latest valid commit (highest commit_group with valid checksum + consistent roots)
  → rebuild in-memory state
  → rebuild checkpoint pointers in system area
  → set recovery-degraded flag
  → resume service
```

## 3. Commit Structure Requirements

Each commit record must satisfy the following to enable scan-based recovery:

| Requirement | Rationale |
|---|---|
| **Self-identifying magic bytes** | Scanner can locate commits without external pointers |
| **Record kind field** | Distinguishes commit records from other segment data |
| **Monotonic `commit_commit_group: u64`** | Enables selection of the latest valid commit |
| **CRC covering full payload** | Detects torn/corrupted commits during scan |
| **All metadata root pointers** | Single commit contains everything needed to reconstruct pool state |
| **Known alignment boundary** | Scanner can stride efficiently without byte-by-byte scanning |

### 3.1 Root Pointers Carried by Each Commit

Each commit record must reference:

- Dataset catalog root
- Inode table root
- Extent refcounts root (space accounting)
- Spacemap allocation root
- Pool-map root (device topology)
- Optional: snapshot lineage anchor

### 3.2 Commit Record Layout

```
+-------------------+  ← alignment boundary (e.g., 512-byte)
| magic: [u8; 8]    |  "TIDECOMM"
| record_kind: u8    |  COMMIT_RECORD = 0x01
| commit_commit_group: u64    |  monotonic, never decreases
| crc: u32           |  covers bytes from payload_len through end of payload
| payload_len: u32   |  length of variable payload in bytes
+-------------------+
| root_pointers[]    |  catalog, inode_table, refcounts, spacemap, pool_map
| segment_ranges[]   |  valid (start, end) for each segment at commit time
| flags: u32         |  RECOVERY_DEGRADED, SNAPSHOT_ANCHOR, etc.
| reserved: [u8; N]  |  padding to alignment
+-------------------+
```

## 4. System-Area Layout

### 4.1 Dual Checkpoint Pointers

The system area maintains two (optionally three) checkpoint pointer slots:

```
+--------------------------+  ← system-area base
| magic: [u8; 8]           |  "TIDEFS01"
| version: u32             |
| flags: u32               |
+--------------------------+
| checkpoint_ptr[0]: u64   |  segment-relative offset to latest commit
| checkpoint_gen[0]: u64   |  generation counter
+--------------------------+
| checkpoint_ptr[1]: u64   |  fallback pointer (previous commit)
| checkpoint_gen[1]: u64   |
+--------------------------+
| (optional) ptr[2]: u64   |  tertiary pointer for 3-way majority
| (optional) gen[2]: u64   |
+--------------------------+
| system_area_crc: u32     |  covers all system-area fields above
+--------------------------+
```

### 4.2 Update Protocol

When writing a new commit:
1. Write the new commit record to the journal segment
2. Wait for the commit write to complete (FUA/barrier)
3. Update checkpoint_ptr[1] ← previous checkpoint_ptr[0] (preserve fallback)
4. Update checkpoint_ptr[0] ← new commit offset
5. Update system_area_crc
6. Write system area to media

This ensures that even if the system-area write is torn, at least one of
checkpoint_ptr[0] or checkpoint_ptr[1] (and the previous commit it points to)
remains valid — or the fallback scanner can recover from journal segments.

## 5. Scanning Recovery Algorithm

### 5.1 High-Level Algorithm

```
fn scan_recover(journal_segments: &[Segment]) -> Result<Commit, RecoveryError> {
    let mut best: Option<Candidate> = None;

    for segment in journal_segments.iter() {
        let mut offset = segment.start;
        while offset + COMMIT_ALIGNMENT <= segment.end {
            let record = read_at(offset);
            if record.magic == COMMIT_MAGIC
               && record.record_kind == COMMIT_RECORD
               && crc_valid(&record)
            {
                let candidate = Candidate {
                    commit_group: record.commit_commit_group,
                    offset,
                    segment_id: segment.id,
                    roots: record.root_pointers,
                    ranges: record.segment_ranges,
                };
                    best = select_best(best, candidate);
                }
            }
            offset += COMMIT_ALIGNMENT;
        }
    }

    best.ok_or(RecoveryError::NoValidCommit)
}
```

### 5.2 Candidate Selection Rules

1. Prefer the candidate with the highest `commit_commit_group`
2. If two candidates have the same `commit_commit_group` (torn write), prefer the one with valid CRC
3. If both have valid CRC at the same commit_group (unlikely), prefer the one in the lower segment ID (earlier in journal write order)
4. Reject any candidate whose root pointers are outside valid segment ranges

### 5.3 Complexity

- **Time**: O(N) where N = total journal bytes / COMMIT_ALIGNMENT
- **Alignment stride**: 512 bytes (or configurable via format parameter)


Before accepting a recovered commit, the following checks must pass:

### 6.1 Commit-Level Checks

| Check | Failure Meaning |
|---|---|
| CRC of commit record valid | Torn or corrupted commit payload |
| `commit_commit_group` is monotonic (≥ previous opened commit_group) | Replay ordering violation |
| Magic bytes present | Not a commit record |

### 6.2 Root Pointer Checks

| Check | Failure Meaning |
|---|---|
| All root pointers are within valid segment ranges | Pointer corruption |

### 6.3 Cross-Consistency Checks

| Check | Failure Meaning |
|---|---|
| Dataset catalog → inode table pointer is valid | Orphaned catalog |
| Spacemap checkpoint is internally consistent | Corrupted space accounting |
| Dataset catalog entries reference valid inodes | Dangling references |

### 6.4 Acceptance Criteria

All checks in 6.1, 6.2, and 6.3 must pass. Any failure discards the candidate
and continues scanning. If no candidate passes all checks, recovery fails with
`RecoveryError::NoValidCommit` and the pool refuses to open.

## 7. Degraded-Mount Flag

### 7.1 Definition

When fallback recovery is used, the pool sets a **recovery-degraded** flag:

```
flags::RECOVERY_DEGRADED: u32 bit 0 = 1
```

This flag is:
- Set during pool open when fallback recovery is triggered
- Persisted in the rebuilt system area
- Cleared only after a successful clean unmount with intact system-area write
- Surfaced to the operator via pool status commands and health metrics

### 7.2 Operator-Visible Indicators

| Surface | Content |
|---|---|
| Pool status | `recovery: degraded` (vs `recovery: normal`) |
| Health metric | `tidefs_pool_recovery_degraded{pools="<uuid>"} 1` |
| Log message | `WARN recovery: system-area pointers corrupted, recovered from journal scan at commit_group=<N>` |
| Dashboard | Pool health shows amber (degraded) instead of green |

### 7.3 Recovery from Degraded State

The pool remains fully operational in degraded state. To clear the flag:
1. Ensure all pending writes are committed
2. Perform a clean checkpoint (this regenerates valid system-area pointers)
3. Unmount (or export) the pool cleanly
4. On next open with intact system area, the flag is cleared

## 8. Edge Cases and Error Handling

### 8.1 Empty Pool (No Commits Exist)

If no commit records are found in any journal segment, the pool opens as a
fresh (newly formatted) pool. This is not an error — it is the normal path
for a freshly created pool.

### 8.2 All Commits Corrupted

- Recovery fails
- Pool refuses to open
- Operator is presented with `RecoveryError::NoValidCommit` and the path to
  all scanned segments
- Manual recovery tools (future: `tidefs recover`) may attempt deeper repair

### 8.3 Partial Segment Write During Crash

If a crash occurs mid-write to a journal segment:
- The partially written commit fails CRC → discarded by scanner
- Any previously committed data in earlier segments remains valid
- The scanner continues past the partial write (alignment stride skips torn data)

### 8.4 System-Area Corruption Without Commit Loss

If system-area pointers are corrupted but the latest commit is intact:
- Fast path fails
- Fallback scanner finds the latest commit (same one the pointers should have referenced)
- Recovery succeeds with degraded flag set
- Checkpoint pointers are rebuilt pointing to the same commit
- No data loss — recovery is transparent to stored data

## 9. Relationship to Existing Infrastructure

### 9.1 Complements

- **P2-05**: Checkpoint/snapshot/replay cursor persistence law — defines the fast-path checkpoint structure; this spec defines the fallback when those structures are corrupted
- **P2-03**: Binary encode/decode/checksum law — CRC format and endian conventions used in commit records
- **P2-04**: Format identity/upgrade/replay continuity law — commit format versioning and replay compatibility

### 9.2 Implementation Order

1. Commit record format (this spec §3) must be finalized before any on-disk format work
2. System-area layout (this spec §4) must be implemented in the pool open/export path
3. Scanning recovery (this spec §5) is implemented as a fallback in `Pool::open()`
5. Degraded flag (this spec §7) is surfaced through existing pool status infrastructure
6. Test plan (this spec §10) exercises all paths

## 10. Test Plan

### 10.1 Deterministic Corruption Tests

Each test case specifies:
- Initial pool state (commits at commit_group 1, 2, 3, ...)
- Corruption target (which bytes are corrupted)
- Expected recovery outcome (which commit_group is recovered, degraded flag state)

| Test ID | Initial State | Corruption | Expected Result |
|---|---|---|---|
| TC-01 | 3 commits (commit_group 1,2,3), clean system area | Corrupt checkpoint_ptr[0] | Recovers commit_group 3 from ptr[1] or scan, degraded=true |
| TC-02 | 3 commits, clean system area | Corrupt checkpoint_ptr[0] and ptr[1] | Recovers commit_group 3 from journal scan, degraded=true |
| TC-03 | 3 commits, clean system area | Corrupt system_area_crc | Scanner recovers commit_group 3, degraded=true |
| TC-04 | 3 commits, clean system area | Corrupt latest commit CRC | Scanner recovers commit_group 2 (previous valid), degraded=true |
| TC-05 | 3 commits, clean system area | Corrupt commit magic in commit_group 3 | Scanner recovers commit_group 2, degraded=true |
| TC-07 | 1 commit (commit_group 1), clean system area | Corrupt system area + commit CRC | Recovery fails, NoValidCommit |
| TC-08 | Empty pool (no commits) | Corrupt system area | Opens as fresh pool, no degraded flag |
| TC-09 | 5 commits, torn write at commit_group 5 | Two partial records at commit_group 5, one valid at commit_group 4 | Scanner picks commit_group 4 (highest valid), degraded=true |
| TC-10 | 3 commits, clean system area | All checkpoint_ptr slots zeroed | Scanner recovers commit_group 3, degraded=true |

### 10.2 Integration with Crash Injection Harness

These tests are designed for the deterministic crash injection harness (#1230).
Each test case maps to:
- A specific `CrashInjectionBoundary` variant (e.g., `ROOT_COMMIT_SYNC`)
- A corruption pattern applied after crash before restart
- An assertion on pool state after mount-time recovery


- Document review: design-spec self-consistency, coverage of all six deliverables
- Future implementation gate: Rust tests implementing TC-01 through TC-10 in the crash harness

## 11. Deliverables Checklist

- [x] Commit record format requirements (self-identifying, CRC'd, monotonic commit_group) — §3
- [x] System-area layout with dual checkpoint pointers — §4
- [x] Degraded-mount flag and operator-visible recovery indicators — §7
- [x] Test plan: deterministic corruption of checkpoint pointers + expected recovery outcome — §10

## 12. References

- tidefs v0.262 Python design book: §2 "Failure model", §12 "Device system area", §16 "Checkpoints and root commits"
- `docs/CHECKPOINT_SNAPSHOT_REPLAY_CURSOR_PERSISTENCE_LAW_P2-05.md` — fast-path checkpoint law
- `docs/CANONICAL_BINARY_ENCODE_DECODE_ENDIAN_CHECKSUM_LAW_P2-03.md` — binary encoding/checksum conventions
- `docs/FORMAT_IDENTITY_UPGRADE_REPLAY_CONTINUITY_LAW_P2-04.md` — format versioning and replay continuity
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md` — authoritative data structure definitions
- Issue #1221 — integrity G3 (torn commit detection)
- Issue #1230 — deterministic crash injection harness
