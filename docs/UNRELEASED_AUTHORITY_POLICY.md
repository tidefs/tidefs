# Unreleased Authority Policy

Maturity: current policy guardrail.

This document is a current policy guardrail. It does not declare a release-readiness
verdict. The release-readiness boundary, including required evidence families,
explicit non-claims, and the distinction between gate-local receipts and whole-product
admission, is defined in `docs/RELEASE_READINESS_VERDICT_CONTRACT.md`.
TideFS has not had a public release. Internal formats, fixtures, daemons,
transport paths, and design sketches in this repository are pre-release work
unless a current GitHub issue or current policy document names an external
ABI, protocol, or operator-owned data set that must be preserved.

## Core Rule

Do not add or preserve legacy, backward-compatibility, migration, downgrade, or
fallback behavior for unreleased TideFS data by default. For an unreleased
surface, choose the correct current authority, remove the stale path, or
quarantine it as historical/test-only input.

This applies to code, tests, design docs, operator docs, and review closeout
wording. A stale pre-release path is not a product compatibility contract.

## Allowed Compatibility

Compatibility work is allowed only when it names the real boundary being
preserved:

- Linux, POSIX, kernel, syscall, or third-party ecosystem behavior;
- a wire protocol, on-disk format, or operator data set that has actually been
  shipped outside the pre-release tree;
- a temporary bridge explicitly tracked by a GitHub issue with owner, scope,
  validation, and removal or graduation criteria.

If none of those applies, do not design a migration path around old internal
TideFS data. Pick the current format or authority and make stale fixtures fail,
move, or disappear.

## Naming

Avoid naming active pre-release code paths "legacy" or presenting them as
product compatibility surfaces. Prefer names that state what the path actually
does, such as:

- current authority;
- retired pre-release path;
- historical input;
- receiptless path;
- non-pool store;
- external compatibility boundary.

Use "legacy" only when referring to an actual external contract or a historical
artifact that is not part of current product design.

## Review Checklist

Before adding compatibility, migration, downgrade, or fallback behavior, verify
that the issue or PR answers all of these:

1. What released external boundary or operator-owned data requires this path?
2. What current authority would be simpler if no released boundary existed?
3. How is the compatibility path validated through the real boundary?
4. What condition removes, retires, or graduates the path?
5. How does the wording avoid claiming that pre-release leftovers are product
   compatibility promises?
