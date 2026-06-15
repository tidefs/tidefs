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
  byte/op/age admission envelope.

This crate is not throughput proof. It is the narrow contract that hidden
dirty work must become visible to admission and queue metadata before stronger
performance claims can be made.
