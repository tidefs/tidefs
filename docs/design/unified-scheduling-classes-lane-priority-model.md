# Unified Scheduling Classes And Lane Priority Model

Status: source-backed pointer, not independent product authority.

This file remains because `docs/STORAGE_INTENT_POLICY_AUTHORITY.md` and
`crates/tidefs-storage-intent-scheduler/src/lib.rs` cite the shared lane
vocabulary. Source code is the authority for the actual lane records,
admission logic, and scheduler behavior.

## Current Authority

- `crates/tidefs-types-transport-session/src/lib.rs` defines `LaneClass`,
  `LaneConfig`, and `TransportLaneBudgetRecord`.
- `crates/tidefs-storage-intent-scheduler/src/lib.rs` maps storage-intent
  records onto that lane vocabulary and owns source-backed admission/refusal
  behavior for the first #862 slice.
- `docs/STORAGE_INTENT_POLICY_AUTHORITY.md` owns the broader storage-intent
  policy surface and non-claim boundaries.

## Lane Vocabulary

The retained shared vocabulary is the five-variant `LaneClass` enum:

- `Control`
- `Metadata`
- `Demand`
- `Speculative`
- `Background`

Current priority, starvation, latency, drop/reorder, and budget behavior must
come from the source constants and tests that consume those variants.

## Non-Claims

This pointer does not claim global QoS correctness, no-hidden-queue proof,
bounded dirty debt, storage-intent performance, distributed scheduling,
production readiness, or successor/comparator standing. Those claims remain
behind source implementation, validation artifacts, `validation/claims.toml`,
and `docs/CLAIMS_GATE_POLICY.md`.
