# tidefs-replication-model

This crate provides deterministic replication, placement, rebuild, and
durability model types. It is a source/model evidence lane, not a networked
repair runtime.

## Repair-Source Receipt Manifests

`RepairSourceReceiptManifest` records the bounded evidence used to consider a
candidate repair source:

- source node id and dataset id
- object or extent identity
- evidence digest
- membership epoch, source epoch, freshness frontier, and expiry epoch
- accepted or rejected decision
- validation tier
- required and provided evidence classes
- related claim and issue references

`RepairSourceReceiptVerifier` checks the manifest against a local model
context. It rejects unknown source ids, stale receipts, mismatched membership
epochs, missing evidence digests, and accepted decisions that do not provide
the required evidence.

These receipts are intentionally insufficient for distributed runtime repair
claims. Passing verification means only that the manifest is coherent bounded
model/source evidence; it does not schedule repair work, prove remote runtime
behavior, validate transport safety, or move bytes.
