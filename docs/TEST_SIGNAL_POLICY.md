# Test Signal Policy

TideFS tests exist to increase product confidence. They are not a delivery
surface by themselves, and a larger test count is not evidence that the
filesystem is healthier.

This policy is current TideFS repo policy. It applies to foreground Codex work,
managed TideFS Codex Nexus work, review, and future cleanup. Do not encode
these project-specific rules in Nexus or Factory automation. Current TideFS
Codex Nexus work must stay mechanics-only and derive work selection from live
GitHub issue/PR state plus repo docs; Factory and legacy automation remain
parked unless separately reauthorized.

## Core Rule

Prefer tests that prove externally meaningful TideFS behavior over tests that
preserve implementation shape, historical issue closeout text, or marker
strings.

Every test change must be classified as one of:

- **Product signal**: proves mounted filesystem, block, kernel, storage,
  recovery, durability, transport, or operator behavior through the real public
  boundary for that layer.
- **Invariant signal**: proves a compact internal invariant that would be hard
  to observe through an outer boundary, such as codec round trips, authenticated
  record rejection, allocator accounting, or state-machine ordering.
- **Harness signal**: proves a test runner, mount harness, QEMU wrapper, parser,
  or CI adapter. Harness signal is useful only when named as harness signal and
  must not be used as product proof.
- **Policy/tooling signal**: proves a repo guard such as licensing, claims,
  documentation authority, or workspace classification. Policy/tooling signal
  must avoid brittle source-marker checks when a structured check is practical.
- **Low-value signal**: preserves string markers, issue-era wording, fixture
  shape, redundant branch behavior, or a stale assertion. Low-value signal
  should be deleted, compressed, or replaced when touched.

## What To Keep

Keep and strengthen tests that exercise:

- mounted FUSE or kernel behavior through real operations;
- crash/reopen, fsync, writeback, mmap, direct I/O, sparse writes, and recovery;
- xfstests, fsx, fsstress, fio, QEMU, Kbuild, module-load, ublk, and RDMA lanes;
- durable on-disk format compatibility and corruption rejection;
- security boundaries using real key material and production session semantics;
- small pure invariants where exhaustive unit coverage is cheaper and clearer
  than an outer integration test.

When a focused unit test and an integration test prove the same behavior, keep
the outer product test and only keep the unit test if it isolates a failure
mode the product test cannot diagnose well.

## What To Avoid

Do not add or preserve tests whose main value is:

- raising test count;
- asserting that a doc/source string contains a marker phrase;
- proving that a placeholder, scaffold, or deferred surface exists;
- locking down private helper names or exact intermediate structure;
- passing under `StoreOptions::test_fast()` or equivalent weakened options while
  claiming durable integrity, recovery, or production-read behavior;
- turning a stale xfstests expectation, fixture issue, or harness limitation
  into production code churn;
- keeping ignored tests as a roadmap or issue tracker.

Marker/source-presence checks are allowed only as transitional guardrails for a
specific review register item. Prefer structured parsing, cargo metadata, public
API behavior, or runtime validation.

## Fixture Rules

Test fixtures must not silently weaken the behavior being claimed.

- If a test claims checksum, integrity, durable-read, or corruption behavior, it
  must use production-equivalent verification settings.
- If a test uses fast or relaxed options, its name or surrounding comments must
  make the narrowed claim explicit.
- If a fixture bypasses FUSE, kernel, ublk, or transport runtime boundaries,
  the test must not be cited as proof for those boundaries.
- If a test is about an unreleased internal format, remove or redesign wrong
  expectations instead of preserving compatibility stubs by default. See
  `docs/UNRELEASED_AUTHORITY_POLICY.md` before keeping a stale pre-release
  fixture as a compatibility or migration claim.

## Placement

Use the narrowest placement that keeps production code readable:

- Inline `#[cfg(test)]` modules are fine for small pure invariants that need
  private access.
- Move large test blocks out of production files when they make the logic hard
  to scan.
- Put public crate behavior in crate `tests/`.
- Put mounted, QEMU, xfstests, ublk, kernel, RDMA, and multi-process behavior in
  the dedicated harness or CI lane for that runtime.

Avoid sweeping mechanical test moves. When refactoring, improve one touched
surface at a time and keep commits bisectable.

## Review Checklist

When adding, modifying, or deleting tests, answer these before committing:

1. What product or invariant claim does this test prove?
2. Is this claim already covered at a stronger outer boundary?
3. Does the fixture use production-equivalent durability, checksum, security,
   and recovery settings for the claim being made?
4. Would a failure identify a real TideFS defect, or only a stale assertion,
   marker, fixture, or harness problem?
5. Should this be a unit test, integration test, xfstests/QEMU row, or no test?

Test-only commits remain prohibited. Test cleanup should ship with the product
or policy change that makes the old test redundant, stale, or misleading.

## Initial Audit Signal

The 2026-06-05 static review found heavy test mass and uneven signal:

- 1,595 Rust files in the tree;
- 1,427 Rust files with `#[cfg(test)]` or test attributes;
- 1,056 non-test-named Rust source files with test markers;
- 362 dedicated Rust test files;
- 148 workspace packages and 345 Cargo integration-test targets;
- roughly 35k Rust test attributes;
- many uses of `StoreOptions::test_fast()` or explicit disabled read
  verification in test fixtures.

These numbers are not targets. They are the reason to optimize for stronger
test signal, not higher test count.
