# Test Signal Policy

TideFS tests protect observable product behavior and difficult correctness
boundaries. Keep a test only when its failure identifies a plausible product
defect, a distinct diagnostic invariant, or a necessary harness fault.

## Signal Priority

For a product change, use the smallest meaningful test at the strongest
applicable outer boundary. The boundaries are the carriers named by the
[Product Contract](../README.md#product-contract): `tidefsctl`, a mounted
filesystem, a block device or export, operator-visible runtime state, and a
kernel entrypoint only when the contract explicitly admits it. This is product
signal.

Keep a compact internal invariant test only when it materially shortens
diagnosis of a failure that would be ambiguous or expensive to isolate through
the carrier. It must protect a stable correctness rule rather than a private
implementation layout.

Keep harness signal only when the harness is necessary to reach the product
boundary or control a relevant platform or fault mode. A harness check must
show that the harness can perform that job faithfully; it is not evidence that
the product behavior itself works.

When several layers exercise the same behavior, retain the strongest outer
product test plus the smallest useful diagnostic invariant. Separate tests are
justified when different platforms or fault modes carry distinct risks. Remove
tests that provide no product, diagnostic, or necessary harness signal.

## Fixtures

A test must not imply behavior that its fixture weakens or bypasses.

- Durability, integrity, recovery, and corruption tests use
  production-equivalent verification, commit, stop or crash, and reopen paths.
- Security tests use production-equivalent algorithms and session semantics
  with synthetic test material. Production credentials, keys, and user data
  never belong in tests or artifacts.
- Fast or relaxed options narrow the behavior tested and must be explicit in
  the test name or nearby explanation.
- A test that bypasses a mounted, kernel, block, or transport boundary is
  internal signal only for that boundary.
- For unreleased internal formats, redesign or delete stale fixtures instead
  of adding compatibility behavior without a current external consumer; see
  the [Unreleased Authority Policy](UNRELEASED_AUTHORITY_POLICY.md).

## Placement

- Keep small pure invariants that need private access in inline `#[cfg(test)]`
  modules.
- Test public crate behavior in the crate's `tests/` directory.
- Put mounted, QEMU, xfstests, ublk, kernel, RDMA, and multi-process behavior in
  the dedicated harness or CI lane for that runtime.
- Move large test blocks when they obscure production logic, but avoid broad
  mechanical moves whose only result is rearrangement.

## Proportional Validation

The changed product risk selects the validation lane. During implementation,
run focused touched-package checks after a coherent change. Before readiness,
run the smallest carrier case that exercises the changed behavior.

Crash, durability, integrity, FUSE, kernel, block, and distributed changes use
the corresponding real fault or runtime lane. Broad xfstests, fsx, fio, QEMU,
kernel, ublk, RDMA, distributed, or whole-workspace suites belong at a relevant
milestone, release candidate, or when the failure cannot first be narrowed.
After the final rebase, repeat only checks invalidated by the new patch.

A flaky required test is fixed, temporarily quarantined with an owner and
expiry, or removed when it has no retained signal. It is never silently
ignored.
