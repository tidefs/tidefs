# tidefs-distributed-model-check

This crate is a deterministic, bounded model checker for distributed TideFS
safety properties. It records model-only evidence for combined epoch, lease,
quorum, and placement invariants; it does not validate storage-node runtime,
transport, RDMA, production cluster, cluster CLI, or multi-process behavior.

The combined safety receipt is emitted by
`DistributedSafetyReceipt::for_system`. A receipt labeled
`distributed-combined-safety-model` fails closed unless it lists the required
invariants:

- `no_stale_epoch_commit`
- `no_active_lease_epoch_conflict`
- `no_false_quorum_success`
- `no_conflicting_committed_writers`
- `no_rebuild_before_receipt`

Current model bounds are `MAX_MODEL_NODES = 7`, `MAX_MODEL_EPOCH = 16`,
`MAX_MODEL_LEASES_PER_NODE = 8`, and `MAX_MODEL_QUORUM_WRITES = 16`.
Receipts also report the explored node count, step count, epoch records,
active lease records, quorum write records, placement receipt records, rebuild
attempts, and pending network messages for the scenario under check.

The fixture at
`validation/artifacts/distributed/combined-safety-receipt.json` is bounded
model evidence only. Distributed runtime claims remain blocked on future
storage-node, transport, multi-process, production cluster, and RDMA evidence.
