# Pool Import, Export, And Device Topology Boundary

This file is the single surviving documentation surface for the pool
import/export and online device-topology family after the TFR-019 / GitHub
issue #1590 duplicate-family collapse. The deleted
`docs/design/*pool-import-export*` files were Forgejo-era lineage,
phase-planning, and sealed-design material; git history and issue history
preserve that record.

## Current Source Boundary

The current source-backed pool import/export boundary is:

- `crates/tidefs-types-pool-label-core/src/lib.rs`: `PoolLabelV1`,
  pool/device enums, label encoding, sealing, and checksum verification.
- `crates/tidefs-pool-scan/src/lib.rs`: device scan, label reading, membership
  validation, committed-root discovery, rebuild planning, and scan results.
- `crates/tidefs-pool-import/src/lib.rs`: pool activation, committed-root
  recovery, intent-log replay, and mount-readiness support.
- `crates/tidefs-local-object-store/src/pool_importer.rs`: local object-store
  pool import protocol.
- `crates/tidefs-local-object-store/src/pool_exporter.rs`: local object-store
  export state transition.
- `crates/tidefs-local-object-store/src/device_manager.rs`: add, remove, and
  replace device label updates.
- `crates/tidefs-local-object-store/src/device_health.rs`: device health state
  used by topology management.
- `crates/tidefs-local-object-store/src/pool/mod.rs`: durable removal and
  replacement evidence, allocation fences, receipt-backed evacuation/rebuild,
  reduced or same-cardinality topology publication, and redundant byte-device
  label writes.
- `crates/tidefs-local-filesystem/src/vfs_engine_impl.rs` and `recovery.rs`:
  mounted-owner receipt reconciliation, authenticated-root refresh, and
  label-intent-bound interrupted lifecycle recovery.
- `apps/tidefsctl/src/commands/device.rs`: live-owner-only administrative
  offline/online, local removal, present-member replacement, and recovery-only
  missing-member rebuild routing with truthful operator projection.

This document does not supersede source. If source and this summary disagree,
source plus focused validation wins and this file must be corrected.

## Durable Missing-Member Identity

New local Pool label writes carry `TopologyRosterV1` after `DeviceLayoutV1`
inside each 256 KiB label copy. The roster is a versioned, BLAKE3-checksummed,
ordered array of device GUIDs; an array offset is the durable member index.
Its generation and count must match the enclosing label, and each label's own
index must resolve to its own device GUID.

Every surviving roster for one import must agree byte-for-byte in member
order. Corrupt, truncated, duplicate, stale, partial, or conflicting roster
authority fails closed. A complete rosterless label family can still supply all
member identities directly, but an incomplete read-only import requires the
canonical roster so missing GUIDs are never inferred from paths, receipts, or
cluster membership.

The mounted local Pool projects this authority to live-owner `pool status` as
health, read-only/read-write access, expected/present/missing counts, and an
indexed GUID/presence list. Ordinary read-only degraded import remains
side-effect-free. Only the explicit `--read-only --rebuild-only` owner may arm
the exact scoped rebuild below; no path authorizes general writable degraded
import.

## Durable Device-Lifecycle Authority

`PoolLifecycleV1` follows the canonical roster in each label copy. It is a
versioned, BLAKE3-checksummed record containing a monotonic sequence, the exact
topology generation, an operation kind (`Clear`, `DeviceRemoval`, or
`DeviceReplacement`), and a checksummed opaque payload. Removal payloads bind
the Pool GUID, target member index and GUID, and successor topology generation.
Replacement payloads bind the Pool GUID, target index, old/new GUIDs, successor
generation, rebuild progress, and terminal state. Recorded paths describe the
current runtime locator; they do not select durable member identity.

Pool scan chooses the highest complete topology and, within it, only exact
same-sequence lifecycle agreement. Missing, corrupt, stale, conflicting, or
mixed-operation records fail closed. Pool import reads those selected copy
offsets and preserves the roster and lifecycle bytes through activation and
export, including when a completed backup family must be selected after an
interrupted primary promotion. At one exact topology/lifecycle generation, a
complete `Active` family is the import successor of its complete `Exported`
predecessor, while `Destroyed` is terminal; a partial state transition leaves
only its predecessor complete. Ordinary label rewrites retain matching
lifecycle authority. A later unrelated topology writes a higher `Clear`
tombstone rather than silently carrying stale completed evidence. No
`.tidefs_device_removal_pending` or
`.tidefs_device_replacement_evidence` host file is recovery authority.

## Offline Destroy Publication

Offline destroy first resolves and validates the exact complete label family
for every supplied member and derives one identity-preserving `Destroyed`
label from that authority. It writes and rereads the trailing copy on every
member before writing and rereading the primary copy. Before trailing-family
completion the predecessor primary family remains complete; afterward the
complete terminal family supersedes it. A successful non-zeroing destroy
therefore leaves both redundant copies terminal rather than depending on
selection of one offset.

When explicit label-area zeroing is requested, destroy starts only after both
terminal families verify. It zeroes, syncs, and rereads every full trailing
256 KiB label area before doing the same to the primaries. During the final
stage, any interruption leaves either a complete terminal primary family or
too few valid labels to assemble the Pool. Success leaves no valid label copy.
One-label-size fixtures alias the two offsets and are written once. This order
is Pool discovery and stale-label hygiene only; it does not erase data regions
or establish media privacy, secure erase, sanitization, or decommissioning.

## Mounted Online Removal Boundary

The bounded local removal path is owned by the reachable mounted filesystem,
not by an offline CLI helper. It syncs mounted state, authenticates every active
current filesystem typed root, authenticates every data-retaining
snapshot-table record owned by those filesystems against its catalog entry,
typed Pool snapshot root, exact captured filesystem-root reference, valid
traversal-root identity, and complete captured content graph, and validates
every canonical Pool-runtime volume graph. The mounted filesystem also requires
its live lifecycle pins; opening an independent filesystem reconstructs pins
from the authenticated successor records. Independently mountable filesystem
dataset clones and non-active filesystem roots refuse before it publishes the
removal label intent and allocation-fences the target. Pool
evacuation then rewrites every receipt-backed logical object to surviving
members while the target stays attached. For each unmounted independent
filesystem, the same owner copy-on-writes changed content manifests, durably
queues predecessor manifests, and publishes its successor typed root before
refreshing the mounted root ring. Volume roots, volume snapshots, and volume
clones carry immutable keys and digests rather than placement generations, so
their typed roots remain unchanged while all referenced maps and chunks
relocate.

For each retained snapshot or snapshot-table clone of an admitted filesystem whose
captured graph contains relocated receipts, the owner loads the authenticated
captured state, copy-on-writes affected content manifests, durably queues the
predecessor manifests, and prepares a replacement authenticated filesystem
root. The corresponding snapshot records, catalog generations, and typed Pool
snapshot sources then advance with their owning filesystem state in one
canonical Pool-root transition. Mounted lifecycle pins advance in the same live
mutation; independent pins reconstruct from the successor records on reopen.
Ordinary commits still reject any typed snapshot-root disagreement; device
lifecycle authorizes only the exact preflight-authenticated predecessor.
Snapshot-specific files, a second Pool owner, and a parallel snapshot store are
not introduced.

Chunk relocation advances placement-receipt generations. The mounted owner
therefore validates survivor payload identity, writes changed content
manifests under new inode data-version keys, and authenticates all resulting
inode and manifest references in one filesystem transaction. It never
overwrites predecessor-manifest bytes before that replacement root commits.
Label-intent-bound recovery can consequently select the old or new
authenticated root after any interruption: an old root admits only its
unchanged predecessor manifest plus successor receipts that validate the same
chunk identity, length, checksum, and payload. The owner then turns every one
of the four retained filesystem root slots before detaching the target.
Arbitrary receipt regressions or manifest changes remain corruption.

After higher-layer roots are durable, Pool authority detaches the target and
stages the reduced ordered GUID roster to redundant label copies on every
survivor. Each copy is read back and verified before the lifecycle intent
clears. Import and scan select the highest complete checksummed roster and lifecycle
agreement; a partial higher generation cannot supersede the previous complete
topology, and a retired member's stale lower-generation label plus removal
intent does not restore membership. The successor carries a higher clear
tombstone after the topology is verified.

The operator result reports evacuation counts, committed topology generation,
and remaining members. It explicitly provides no secure-erase,
media-remanence, sanitization, or decommissioning guarantee. Failed-device
loss, replacement/rebuild, writable degraded operation, simultaneous
multi-mounted filesystem atomic removal, and filesystem dataset clones remain
separate work.

## Mounted Present-Member Replacement Boundary

The bounded replacement path also belongs to the reachable mounted owner. It
admits only an exact writable two-member `Replicated { copies: 2 }` Pool, one
mounted filesystem, any number of authenticated active unmounted independent
filesystem roots, any number of checksum-validated co-owned Pool-runtime
volume, volume-snapshot, and volume-clone roots, any number of authenticated
data-retaining snapshot-table roots owned by every admitted filesystem, no
independently mountable filesystem dataset clone, and a distinct blank
same-backing candidate at least as large as the readable old member. Durable
versioned checksummed
label evidence binds the Pool GUID, full old/new device GUIDs, member index,
next topology generation, subject inventory, verified receipt progress, bytes
rebuilt, and terminal state. Old/new paths remain descriptive locators resolved
only after GUID/index topology authority.

Preparation installs the candidate at the old member's durable index while
retaining the old member as an attached allocation-fenced predecessor. It
rebuilds every current old-member receipt subject onto the survivor plus
replacement, verifies newer receipts exclude the old GUID and include the new
GUID, syncs both successor members, and suppresses ordinary label publication.
The mounted owner then applies the same copy-on-write content-manifest and
complete authenticated-root-ring reconciliation used by removal. Only after
those roots are durable does Pool authority detach the old runtime member,
write and reread both backup and primary same-cardinality label families, and
record completed evidence with safe detach.

An interruption before topology publication reopens the old label topology,
restores the exact label evidence before receipt recovery, mutation-fences
ordinary writes, and resumes with the same replacement GUID. A completed
replacement reimports from only the survivor plus replacement. Operator output
reports rebuild counts, exact identity, topology generation, completion and
detach safety while explicitly claiming no secure erase, media remanence,
sanitization, or decommissioning. Absent or unreadable old members, writable
degraded replacement, erasure coding, filesystem dataset clones, simultaneous
multi-mounted filesystem atomicity, and hot-spare policy remain separate work.

## Mounted Administrative Offline And Online Boundary

The bounded administrative availability path belongs to the reachable writable
local mounted owner of an exact two-member `Replicated { copies: 2 }` Pool.
`device offline` and `device online` name one present member by its full durable
GUID. The owner refuses an unknown GUID, incomplete or differently ordered
topology, read-only or recovery-only ownership, a non-two-copy policy, and an
active removal or replacement before changing the member state.

Administrative offline first syncs mounted and Pool state. The member label's
`device_health` byte retains the underlying Online, Degraded, or Faulted value
in its low bits and records administrative exclusion in bit 7. Every member
label also carries `DEVICE_ADMIN_OFFLINE_INCOMPAT`, so an importer that does not
understand the exclusion must refuse rather than allocate to the offline
member. The owner advances the topology generation, writes and rereads the
complete backup label family, and only then writes and rereads the primary
family. Before backup-family completion the predecessor family remains
complete; after completion the higher complete backup is authoritative even if
primary promotion is interrupted. A reopen can therefore select one complete
old-or-new state and an idempotent retry can converge both copies.

An offline member is excluded from ordinary allocation candidates, placement
capacity, and dedicated intent-log health/routing. Pool health becomes
`Degraded`. For the admitted exact two-copy policy, any new write that cannot
retain both replicas refuses during placement planning before payload or
placement-receipt mutation. Existing receipt-authenticated data remains
readable, and `device status` reports each durable index, full GUID, presence,
and operational state in both human and explicit `--json` output. Export and
reimport preserve the label bit and the degraded/offline projection.

Online readmission first requires the target's exact current GUID and durable
index plus a complete selected label topology. It inventories physical current
placement receipts across both members, rejects corrupt, conflicting, or
unstable receipt authority, verifies every current receipt copy, and verifies
every receipt-bound replica or shard identity, length, digest, and payload. A
faulted underlying health state refuses readmission. Only after verification
does the owner clear the offline bit, advance the topology generation, and
publish and reread the successor backup and primary families; exact-width
writes resume only after that publication succeeds.

This boundary is administrative availability control for one still-present
member. It is not physical detach, missing-device recovery, replacement,
rebuild, general writable degraded operation, erasure or clustered placement
administration, hot-spare activation, secure erase, sanitization,
media-remanence treatment, a support-admission statement, or a
production-readiness claim.

## Mounted Missing-Member Rebuild Boundary

The bounded missing-member path belongs to an explicitly recovery-only local
mounted owner. It admits exactly one surviving member of an exact two-member
`Replicated { copies: 2 }` byte-addressable Pool through `pool mount
--read-only --rebuild-only --devices <survivor>`. The FUSE namespace,
ordinary recovery, timestamps, writeback, background work, reclaim, and every
ordinary VFS mutation remain read-only. Cluster ownership, snapshot mounts,
and broader mutation or fault tuning are refused. `device rebuild` is the one
typed local-only command routed to that live owner.

The request names the full missing GUID from the durable ordered roster and a
distinct blank same-backing candidate at least as large as the survivor. The
owner refuses wrong GUIDs, complete or non-two-copy topology, candidate
identity/capacity/backing mismatch, missing or corrupt survivor receipts or
payloads, unresolved lifecycle state, and any ordinary read-only owner before
unauthorized candidate mutation. Before candidate initialization, redundant
versioned checksummed lifecycle evidence binds the Pool GUID, missing
index/GUID, new GUID and path, predecessor and successor topology generations,
subject inventory and progress, and terminal state. Paths remain descriptive
runtime locators; GUID/index label authority selects the lifecycle.

With a scoped Pool mutation capability armed only for the command, every
current receipt that named the absent member must have one authenticated clean
survivor target with matching length, digest, and payload. The Pool publishes
a higher two-target receipt to survivor plus replacement. The mounted owner
then applies the same authenticated preflight, copy-on-write content-manifest
reconciliation, durable predecessor queueing, independent-filesystem and
snapshot-table typed-root publication, Pool-runtime volume-graph preservation,
and complete mounted-root-ring rotation used by present-member lifecycle.
Only after those roots are durable may Pool authority publish and reread both
same-cardinality label families with the fresh replacement GUID at the missing
member's durable index and commit terminal evidence.

Reopen restores evidence from the selected label family before receipt
recovery. An interruption before candidate or receipt publication resumes the
same new GUID and candidate locator; an interruption during mounted root
reconciliation accepts only authenticated predecessor/successor root
transitions; and an interruption after successor topology publication binds
the operator's original missing GUID to the exact new GUID/index transition
until terminal evidence commits. No host marker file or runtime directory is
recovery authority. Success allows a normal writable reopen from survivor plus
replacement while the recovery owner itself remains read-only.

This row does not recover data missing or corrupt on the survivor, admit
general writable degraded operation, rebuild erasure-coded or clustered
placement, activate hot spares, support simultaneous multi-mounted owners,
establish media-remanence or decommissioning guarantees, make a mode
support-admitted, or make TideFS production-ready.

## Authority Limits

This file is not product-readiness evidence for hot spares, general evacuation,
cluster-aware pool ownership, arbitrary online topology conversion, hardware
failure survival, availability, operational safety, or incumbent comparison
claims. The mounted sections describe only the exact local present-member and
one-missing-member boundaries above.
Those scopes require current source evidence, runtime validation, and claim IDs
where they become publishing-facing claims.

The current guarantee is narrow: TideFS has concrete pool-label,
pool-scan/import, local import/export, and device-manager code paths in the
crates named above. Its present-member mounted lifecycle preserves active
current independent filesystem roots and canonical Pool-runtime volume roots
through one imported owner; this is not simultaneous multi-mounted-filesystem
atomicity. Broad operational behavior must be checked against source and
validation before it is cited.
