# Cross-Replica Scrub Comparison Design

**Status**: Decision record
**Issue**: [#738](https://github.com/tidefs/tidefs/issues/738)
**Date**: 2026-06-21
**TFR link**: TFR-017

## Purpose

Local scrub can currently prove that one local content object matches or
does not match the checksum evidence available to that replica. It cannot yet
prove which replica is correct when replicas disagree, nor can it safely turn
a peer response into repair writeback authority.

This decision defines the cross-replica comparison contract that must sit
between local scrub evidence and repair dispatch. The comparison contract
consumes `ScrubBlockId`-keyed evidence, placement receipt identity, membership
epoch evidence, and checksum-layer evidence from each replica. It produces a
reconciled decision before repair code may choose a source or write repaired
bytes.

This is a design record only. It does not implement cross-replica scrub,
transport messaging, transport framing, network I/O, or repair dispatch.

## Evidence Reviewed

- `docs/REVIEW_TODO_REGISTER.md` TFR-017: transport/cluster authority remains
  open for cross-replica scrub/repair, digest comparison, epochs, membership
  fencing, and repair source selection.
- `docs/MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY.md`: the mounted
  scrub/repair boundary is `ScrubBlockId + current data_version + plaintext
  content identity + checksum-layer evidence + placement/receipt evidence`.
- `crates/tidefs-local-filesystem/src/scrub.rs`: local scrub reports
  `ScrubBlockId` for inline content, manifests, and content chunks, and
  compares local checksums only.
- `crates/tidefs-local-filesystem/src/records.rs`: `ContentChunkRef` carries
  `checksum`, `data_version`, and `placement_receipt_generation`; generation
  zero is receiptless.
- `crates/tidefs-scrub-core/src/`: scrub-core already has repair scheduling,
  receipt evidence gates, a staged multi-node fanout coordinator, and repair
  ledger types, but no reconciled cross-replica comparison result.
- `docs/TRANSPORT_CLUSTER_AUTHORITY.md` and #672: transport owns
  session-local admission and backpressure mechanics; membership/runtime
  authority owns epoch, roster, and fencing decisions.
- #18, #674, and #675: placement receipt authority is the local/distributed
  source of truth for replica placement, read source selection, scrub, repair,
  and rebuild consumers.
- #616 and `docs/SNAPSHOT_CLONE_DEADLIST_AUTHORITY.md`: consistency decisions
  should carry explicit evidence, commit/epoch bounds, bounded progress, and a
  fail-closed verification gate rather than inferring correctness from a
  convenient scan.

## Non-Goals

- Do not design the transport wire format, message framing, retry protocol, or
  network I/O.
- Do not implement the comparison engine, request/response exchange, repair
  source selection, or writeback.
- Do not close TFR-017. This decision only narrows the scrub comparison
  authority needed by later implementation issues.
- Do not replace #18, #674, or #675 placement receipt authority.
- Do not replace #650, #651, or #652 mounted transform-aware scrub/repair
  evidence.

## Decision Summary

TideFS will use a receipt-bound, epoch-bound comparison model:

1. A comparison candidate is keyed by `ScrubBlockId`, checksum layer, object
   key, current content generation, placement receipt epoch, and placement
   receipt generation.
2. Each replica reports evidence that is authoritative only for that replica:
   local checksum result, local read outcome, receipt identity observed by that
   replica, membership epoch, and source freshness.
3. The comparison engine normalizes all evidence before classification. It
   rejects evidence with a mismatched subject, checksum layer, receipt epoch,
   receipt generation, object key, target policy, or membership epoch.
4. Repair dispatch may write back only from a reconciled comparison record.
   First-clean-peer, topology-only, directory-scan, and transport-success-only
   repair source selection are forbidden.
5. Unreconciled disagreements fail closed as
   `ScrubRepairOutcome::CrossReplicaDisagreement` before any local or remote
   writeback.

## Comparison Authority

The cross-replica scrub comparison engine owns the digest comparison decision.
It does not own:

- placement receipt issuance or target selection;
- membership epoch or roster decisions;
- transport session admission, backpressure mechanics, or wire framing;
- local mounted transform identity;
- repair writeback.

It consumes those authorities as evidence. The comparison result is the only
cross-replica evidence repair dispatch may consume when a repair candidate is
multi-replica.

## Evidence Model

### Subject Key

`ScrubBlockId` remains the stable scrub subject for mounted content:

- `inode_id`
- `data_version`
- `kind`
  - `InlineContent`
  - `ContentManifest`
  - `ContentChunk { chunk_index }`

Cross-replica comparison must extend that subject with the evidence needed to
prove every replica is talking about the same bytes:

- content object key;
- expected logical length when available;
- checksum layer and checksum algorithm;
- current inode generation when available;
- current `data_version`;
- placement receipt epoch;
- placement receipt generation;
- membership epoch used to contact the peer;
- redundancy policy identity and target count.

`ScrubBlockId` alone is not sufficient for writeback. Two replicas with the
same inode id, data version, and chunk index are comparable only when their
receipt and checksum-layer evidence also match.

### Per-Replica Evidence

Each replica contributes evidence with this ownership:

| Field | Authority | Comparison rule |
|---|---|---|
| `replica_id` / member id | Membership authority | Names the reporting replica. It must be in the committed roster for the comparison epoch. |
| `ScrubBlockId` | Local scrub authority | Must exactly match the comparison subject. |
| object key | Placement/content authority | Must match the receipt-bound object key for the subject. |
| local checksum | Reporting replica | Authoritative only for bytes read by that replica under the named checksum layer. |
| remote checksum | Remote reporting replica | Authoritative only for that remote replica and only after subject, receipt, and epoch checks pass. |
| checksum layer | Scrub/content authority | Evidence from different layers is not comparable. A fast local checksum and a BLAKE3 payload digest need a named mapping before comparison. |
| content generation | Local filesystem authority | Must not be older than the candidate generation; newer content makes the candidate stale. |
| placement receipt epoch | Placement/membership authority | Must match the receipt epoch used to authorize the target set. |
| placement receipt generation | Placement authority | Must match the generation bound to the content reference or receipt ref. |
| redundancy policy and target count | Placement authority | Must be policy-satisfying; synthetic or malformed receipts are not repair authority. |
| membership epoch | Membership authority | Must match or be explicitly compatible with the comparison epoch. |
| freshness frontier/source epoch | Repair-source evidence authority | Prevents an old source response from being reused after membership or content authority advanced. |
| read outcome | Reporting replica | `Clean`, `Mismatch`, `Missing`, `Unreadable`, `NoChecksum`, `ReceiptStale`, and transport/epoch/backpressure failures remain distinct evidence classes. |

### Comparable Evidence

The following evidence can be compared across replicas:

- content chunk checksum evidence for the same `ContentChunk` subject, object
  key, checksum layer, placement receipt epoch, and placement receipt
  generation;
- inline content evidence only after the transform-aware scrub boundary names
  the plaintext content identity and receipt evidence for the bytes being
  compared;
- content manifest evidence for the same manifest object key and receipt
  generation. Manifest agreement can prove the chunk list is consistent, but
  it cannot by itself authorize chunk writeback;
- missing/unreadable evidence for a receipt target, because absence is part of
  the repair decision.

The following evidence is not comparable for repair writeback:

- receiptless chunk evidence where `placement_receipt_generation == 0`;
- evidence from different checksum layers without an explicit mapping;
- synthetic placement receipts;
- evidence from a different membership epoch unless the membership authority
  explicitly establishes that it remains valid for the comparison epoch;
- topology-only replica lists;
- a transport success result without subject, receipt, and checksum evidence.

## Reconciliation Rules

The comparison engine first rejects stale or mismatched evidence, then
classifies the remaining evidence for one comparison candidate.

| Evidence state | Reconciliation result | Repair dispatch gate |
|---|---|---|
| Every authoritative receipt target reports the expected checksum for the same subject, layer, receipt epoch, and receipt generation. | `CleanAgreement`. | No repair writeback. A prior local finding is stale or already cleared. |
| One replica reports mismatch or unreadable, and every other authoritative target reports the expected checksum under the same receipt. | `SingleReplicaCorruption`. | Repair may be considered only for the corrupt local target, from the clean receipt-bound source set, after stale-generation checks pass. |
| The local replica reports mismatch and at least one remote target reports the expected checksum, but another current receipt target is missing evidence. | `IncompleteComparison`. | No writeback until the missing target is either evidenced, fenced out by membership authority, or the policy-specific implementation issue defines and validates that the remaining source set is sufficient. |
| A remote replica reports mismatch while the local replica and other targets report the expected checksum. | `RemoteReplicaCorruption`. | The local node must not write remote state from this comparison. It may emit suspect evidence for the remote repair owner. |
| Replicas report two or more non-expected checksum values for the same subject, or disagree about which checksum is expected. | `CrossReplicaDisagreement`. | Fail closed as `ScrubRepairOutcome::CrossReplicaDisagreement`. |
| All reachable replicas agree on a checksum that differs from the receipt or manifest expected checksum. | `ChecksumAuthorityDisagreement`. | Fail closed as `ScrubRepairOutcome::CrossReplicaDisagreement`; no replica has proven itself a clean source. |
| Any evidence carries a stale data generation, stale receipt generation, stale membership epoch, or mismatched object key. | `StaleEvidence`. | No writeback. The caller must refresh evidence from current authority. |
| A current receipt target returns `NoChecksum` for a block that requires a checksum. | `MissingChecksumEvidence`. | No writeback; treat as missing comparison evidence, not as clean data. |
| A current receipt target is unreachable, backpressured, or epoch-rejected. | `MissingReplicaEvidence`. | No writeback unless later policy-specific code establishes that the target is no longer authoritative for this receipt epoch. |

The comparison engine must preserve negative evidence. A missing or
backpressured peer is not a clean peer, and a clean peer on a stale receipt is
not a repair source.

## Repair Dispatch Gate

Repair dispatch must receive a comparison record before any multi-replica
writeback. The record must include:

- comparison subject (`ScrubBlockId`, object key, checksum layer);
- placement receipt epoch and generation;
- membership epoch;
- participating replica ids and per-replica outcomes;
- reconciled classification;
- clean source set, when the classification permits one;
- corrupt target set, when the classification names one;
- stale/missing/disagreement evidence when the classification forbids repair.

Dispatch rules:

1. A candidate without a comparison record is not writeback-eligible.
2. A candidate whose comparison record is stale relative to current local
   inode generation, data version, or receipt generation is not writeback-
   eligible.
3. `SingleReplicaCorruption` can permit local writeback only when a clean
   source set is receipt-bound, policy-satisfying, and freshness-valid.
4. `CrossReplicaDisagreement`, `ChecksumAuthorityDisagreement`,
   `IncompleteComparison`, `MissingReplicaEvidence`, and `StaleEvidence`
   are fail-closed for writeback.
5. Existing stale-generation/content-advanced refusal remains authoritative
   even when cross-replica comparison is clean.

The repair-dispatch follow-up must add or route through
`ScrubRepairOutcome::CrossReplicaDisagreement` for unreconciled disagreement.
Missing evidence may get a more specific non-writeback outcome, but it must not
fall through to reconstruction or mark-corrupt writeback.

## Transport Surface Requirements

The #672 split authority model applies directly:

- Transport owns session-local admission, send capacity, queueing,
  backpressure watermarks, and typed send/session failure evidence.
- Membership/runtime authority owns committed roster, epoch advancement,
  fencing, and peer departure decisions.
- Placement authority owns the receipt epoch, receipt generation, redundancy
  policy, object key, target count, and payload digest.
- The cross-replica scrub comparison layer owns request scheduling, response
  normalization, and reconciliation.

The comparison protocol therefore requires transport to provide only these
surfaces:

- admitted sessions to peers in the committed roster for the comparison
  membership epoch;
- outbound sends stamped or guarded by the epoch evidence required by #672;
- typed failures for admission refusal, peer departure, stale epoch, future
  epoch, closed session, timeout, and backpressure;
- bounded fanout so scrub comparison cannot create unbounded send queues;
- response correlation identity so stale responses cannot satisfy a newer
  comparison candidate;
- no silent success path: a delivered response must still be checked by the
  comparison engine against subject, receipt, epoch, and checksum-layer
  evidence.

The scrub comparison layer owns the comparison request/response exchange above
transport. Transport carries and gates the exchange; it does not decide which
replica is correct.

## Follow-Up Implementation Issues

The design split is:

1. [#756](https://github.com/tidefs/tidefs/issues/756)
   `cross-replica-scrub-transport`: exchange receipt-bound comparison
   evidence through the scrub fanout/transport surface.
2. [#757](https://github.com/tidefs/tidefs/issues/757)
   `cross-replica-scrub-engine`: implement deterministic reconciliation of
   multi-replica checksum evidence.
3. [#758](https://github.com/tidefs/tidefs/issues/758)
   `cross-replica-scrub-repair`: gate repair writeback on a reconciled
   comparison record and fail closed as
   `ScrubRepairOutcome::CrossReplicaDisagreement` when replicas disagree.

These issues leave #674 primary receipt fanout, #675 receipt-driven local
read/scrub/repair/rebuild consumers, #650/#651 local transform-aware scrub,
#652 mounted repair evidence, and #18 placement receipt authority as adjacent
or prerequisite authorities rather than taking over their behavior. Where #758
needs repair or local-filesystem writeback paths, it is explicitly gated on
#652/#675 coordination. If a later implementation finds that an expected write
set overlaps an active PR branch, that implementation issue must defer or
narrow before source edits.

## What This Decision Does Not Close

- TFR-017 remains open until transport, comparison, repair dispatch, recovery,
  partition handling, and runtime proof are implemented and validated.
- This decision does not make multi-node scrub a product-grade repair path.
- This decision does not prove mounted device-level compression or encryption;
  the mounted transform inventory remains blocked by its existing production
  rows.
- This decision does not authorize repair from a single clean peer response,
  from current topology alone, or from receiptless local scrub evidence.
