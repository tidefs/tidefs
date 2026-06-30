# ADR-0003: Shard Groups, Replicas, and Rebake Pathway

Date: 2026-05-05
Status: Historical input

This imported ADR recorded Forgejo-era shard/rebake target architecture. It is
not current distributed redundancy, rebake, recovery, availability, durability,
or successor authority.

TFR-019 / GitHub issue #1590 deleted the duplicate shard/rebake design lineage
that this ADR used to cite. Current narrow authority lives in:

- `docs/LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md`
- `docs/POOL_WIDE_REDUNDANCY_PLACEMENT_CONTRACT.md`
- live source and validation for the specific placement, receipt, rebuild, or
  reclaim behavior being cited

The original ADR body remains available in git history.
