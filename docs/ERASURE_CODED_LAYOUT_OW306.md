# Erasure-Coded Layout Model OW-306

## Source Boundary

OW-306 executable erasure-coded layout slice is implemented in
`crates/tidefs-replication-model`.

The model is intentionally deterministic and bounded. It covers one
single-parity XOR stripe over object/root payload bytes:

- `ErasureLayoutPolicy` admits a fixed data-shard count, one parity shard, and a
  fixed shard length.
- `encode_single_parity_erasure_stripe()` splits payload bytes into padded data
  shards and derives the parity shard by XOR.
- `decode_single_parity_erasure_stripe()` reconstructs complete payload bytes
  from available shards.
- A single missing data shard is rebuilt from parity plus the remaining data
  shards.
- A missing parity shard is rebuilt from the data shards.
- too many missing shards and simultaneous data/parity loss are explicit refusal
  states.


The implementation-tracked non-release tests cover:

- complete stripe decode round trip;
- single missing data shard rebuild;
- missing parity shard rebuild;
- refusal when two data shards are missing;
- refusal when one data shard and parity are missing.


```text
tidefs-xtask check-erasure-coded-layout
```

## Non-Claims

This is not a production Reed-Solomon implementation. It does not add networked
erasure-coded placement, async data movement, kernel/block-device erasure
coding, or a distributed-storage production runtime. It is a implementation-tracked non-release model
for layout/decode/rebuild decisions after the replicated object/root and
rebuild/backfill/rebalance models.
