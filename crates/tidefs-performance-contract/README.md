# tidefs-performance-contract

`tidefs-performance-contract` owns the first typed performance-correctness
contract for local TideFS work. It is a `no_std` crate with an `alloc` feature
for queue and oracle helpers.

The crate models:

- `WorkClass` and `ResourceDomain` labels for foreground, background, and
  dirty-debt work;
- `AdmissionPermit` as a linear, must-use token for conserving admitted dirty
  bytes and operations;
- `BudgetedQueue` as an alloc-backed queue that requires a permit for every
  enqueued dirty item;
- `ServiceCurve` as the typed budget describing how a work class may be served
  per scheduling tick;
- `WriteAdmissionState` and `WriteAdmissionConfig` as the hard local dirty
  byte/op/age admission envelope;
- `WorkloadEnvelope` and `PerformanceReceipt` as metadata that names the
  workload scope, environment profile, resource domains, measurement vector,
  budget decision, validation tier, and claim ids for a comparable artifact.

This crate is not throughput proof. It is the narrow contract that hidden
dirty work must become visible to admission and queue metadata before stronger
performance claims can be made.

Performance receipts are metadata until paired with runtime artifact evidence.
A receipt can say which workload, comparator or baseline policy, validation
tier, and claim ids an artifact is meant to cover; it does not by itself prove
that the runtime path met a performance budget or that hidden dirty work has
been eliminated.
