# ADR-0003: Shard Groups, Replicas, and Rebake Pathway

Date: 2026-05-05
Status: Accepted

## Context

Erasure-coded and replicated data in TideFS must transition between redundancy
schemes as dataset properties change, devices fail, or cluster topology shifts.
This "rebaking" — converting data from one redundancy encoding to another — is
safety-critical: a bug during rebake can silently corrupt data or violate
durability guarantees.

Traditional systems (Ceph, ZFS) handle this through ad-hoc scrubbing and
resilvering with limited cross-policy flexibility. TideFS needed a unified
model that:
- Treats shard groups (EC stripes) and replicas as first-class citizens
- Provides atomic rebake transitions with crash safety
- Integrates with the durability ladder (6 redundancy policies)
- Honors per-dataset `RedundancyPolicy` settings

## Decision

Adopt a **shard-groups-replicas-rebake** architecture with these elements:

1. **ShardGroupV1**: on-media encoding of an erasure-coded stripe group with
   k data shards + m parity shards, metadata (generation, policy, birth COMMIT_GROUP),
   and per-shard integrity digests.

2. **ReplicaLifecycle** state machine: `Healthy → Degraded → Rebuilding →
   Healthy` with explicit `Stale` and `Tombstone` terminal states for
   decommissioned replicas.

3. **RebakeService**: background service that executes a 7-phase atomic pipeline:
   (1) candidate selection, (2) read source data, (3) re-encode to target
   policy, (4) write new shards, (5) update metadata atomically, (6) verify
   integrity, (7) release old shards. Crash at any phase is recoverable.

4. **DurabilityMonitor**: per-dataset watchdog that escalates when redundancy
   drops below policy threshold, triggering emergency rebake if necessary.

5. **6 redundancy policies**: `None`, `Replicated(2)`, `Replicated(3)`,
   `ErasureCoded(4,2)`, `ErasureCoded(8,3)`, `ErasureCoded(16,4)` — forming
   a durability ladder from basic to extreme resilience.

6. **Ingest window bounding**: new writes are placed in an ingest journal
   (single-replica) and rebaked to the target policy within a bounded window,
   preventing unbounded vulnerability.

7. **Read-path shard assembly**: reads from EC shard groups reconstruct from
   any k-of-(k+m) available shards, with fast-path for aligned reads from
   healthy full-stripe groups.

## Consequences

- Atomic rebake transitions with crash safety at every pipeline phase.
- Per-dataset policy changes trigger rebake automatically via the DurabilityMonitor.
- Emergency rebake on device failure preserves redundancy guarantees.
- Ingest journal bounding limits vulnerability window to seconds/minutes.
- ShardGroupV1 on-media format is forward-compatible via versioned magic.
- Increased complexity in read path (shard assembly) and write path (ingest
  journal → rebake). Mitigated by fast-path for aligned full-stripe reads.

Design spec: `docs/design/2068-shard-groups-replicas-rebake-pathway-design.md`
Issues: [#1781](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1781),
[#1782](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1782),
[#1806](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1806),
[#1963](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/1963),
[#2068](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/2068)
