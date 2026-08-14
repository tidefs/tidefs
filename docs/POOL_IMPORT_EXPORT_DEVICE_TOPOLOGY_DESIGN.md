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
  marker-bound interrupted-removal recovery.
- `apps/tidefsctl/src/commands/device.rs`: live-owner-only local removal and
  replacement routing with truthful operator projection.

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
indexed GUID/presence list. This boundary adds truthful read-only degraded
status only; it does not authorize writable degraded import or rebuild.

## Mounted Online Removal Boundary

The bounded local removal path is owned by the reachable mounted filesystem,
not by an offline CLI helper. It syncs mounted state, validates every canonical
Pool-runtime volume graph, refuses before evacuation when an independently
rooted filesystem or filesystem-sourced snapshot/clone needs another owner,
persists a removal marker, and allocation-fences the target. Pool evacuation
then rewrites every receipt-backed logical object to surviving members while
the target stays attached. Volume roots, volume snapshots, and volume clones
carry immutable keys and digests rather than placement generations, so their
typed roots remain unchanged while all referenced maps and chunks relocate.

Chunk relocation advances placement-receipt generations. The mounted owner
therefore validates survivor payload identity, writes changed content
manifests under new inode data-version keys, and authenticates all resulting
inode and manifest references in one filesystem transaction. It never
overwrites predecessor-manifest bytes before that replacement root commits.
Marker-bound recovery can consequently select the old or new authenticated
root after any interruption: an old root admits only its unchanged predecessor
manifest plus successor receipts that validate the same chunk identity,
length, checksum, and payload. The owner then turns every one of the four
retained filesystem root slots before detaching the target. Arbitrary receipt
regressions or manifest changes remain corruption.

After higher-layer roots are durable, Pool authority detaches the target and
stages the reduced ordered GUID roster to redundant label copies on every
survivor. Each copy is read back and verified before the marker clears. Import
and scan select the highest complete checksummed roster; a partial higher
generation cannot supersede the previous complete topology, and a retired
member's stale lower-generation label does not restore membership.

The operator result reports evacuation counts, committed topology generation,
and remaining members. It explicitly provides no secure-erase,
media-remanence, sanitization, or decommissioning guarantee. Failed-device
loss, replacement/rebuild, writable degraded operation, independently mounted
filesystem atomic removal, and filesystem snapshot/clone root rewriting remain
separate work.

## Mounted Present-Member Replacement Boundary

The bounded replacement path also belongs to the reachable mounted owner. It
admits only an exact writable two-member `Replicated { copies: 2 }` Pool, one
mounted filesystem, any number of checksum-validated co-owned Pool-runtime
volume, volume-snapshot, and volume-clone roots, no independently rooted
filesystem or filesystem-sourced snapshot/clone, and a distinct blank
same-backing candidate at least as large as the readable old member. Durable
versioned checksummed evidence binds the Pool GUID, full old/new device GUIDs
and paths, member index, next topology generation, subject inventory, verified
receipt progress, bytes rebuilt, and terminal state.

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
restores the exact evidence, mutation-fences ordinary writes, and resumes with
the same replacement identity. A completed replacement reimports from only the
survivor plus replacement. Operator output reports rebuild counts, exact
identity, topology generation, completion and detach safety while explicitly
claiming no secure erase, media remanence, sanitization, or decommissioning.
Absent or unreadable old members, writable degraded replacement, erasure
coding, independently mounted filesystem atomicity, and hot-spare policy remain
separate work.

## Authority Limits

This file is not product-readiness evidence for hot spares, general evacuation,
cluster-aware pool ownership, arbitrary online topology conversion, hardware
failure survival, availability, operational safety, or incumbent comparison
claims. The mounted sections describe only the exact present-member,
single-filesystem local boundaries above.
Those scopes require current source evidence, runtime validation, and claim IDs
where they become publishing-facing claims.

The current guarantee is narrow: TideFS has concrete pool-label,
pool-scan/import, local import/export, and device-manager code paths in the
crates named above. Its present-member mounted lifecycle preserves canonical
Pool-runtime volume roots; this is not general multi-filesystem atomicity.
Broad operational behavior must be checked against source and validation before
it is cited.
