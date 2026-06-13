# ADR-0006: License Compliance with cargo-deny

Date: 2026-05-05
Status: Accepted

## Context

TideFS is a `GPL-2.0-only WITH Linux-syscall-note` codebase that consumes Rust
crates from the public ecosystem. Without systematic license enforcement, a
transitive dependency could introduce an unapproved license expression or
unclear provenance that conflicts with the documented TideFS licensing model.

The project needed:
- Automated, CI-enforceable license checking
- A clear policy on which licenses are acceptable
- Explicit denial of dependency licenses outside the approved TideFS policy
- Clarification of edge cases (multi-license crates like `ring` and `webpki`)

## Decision

Adopt `cargo-deny` as the canonical license compliance tool with the following
policy encoded in `deny.toml`:

1. **Permissive allowlist**: Accept Apache-2.0, BSD-2-Clause, BSD-3-Clause,
   BSL-1.0, CC0-1.0, ISC, MIT, MPL-2.0, OpenSSL, Unicode-3.0,
   Unicode-DFS-2016, Zlib, and variants (Apache-2.0 WITH LLVM-exception).

2. **Unapproved-license denial**: Any direct or transitive dependency carrying
   a license outside the approved allowlist is rejected at CI time.

3. **Explicit allowlist**: Accepted dependency licenses remain explicit in
   `deny.toml` rather than relying on a broad default.

4. **Multi-license clarification**: `ring` (ISC AND MIT AND OpenSSL) and
   `webpki` (ISC) have explicit `[licenses.clarify]` entries to resolve
   ambiguous SPDX expressions.

5. **Validation command**: Run `cargo deny check licenses` from the Nix
   development shell when auditing or changing dependency license policy.

6. **Unlicensed dependency handling**: Dependencies without explicit license
   expressions require upstream metadata or an explicit `[licenses.clarify]`
   entry before acceptance.

## Consequences

The cargo-deny policy keeps dependency license compliance visible and catches
license/provenance drift before it enters the tree.

- The explicit allowlist makes the policy transparent to contributors and
  auditors.
- Multi-license crates like `ring` are correctly recognized rather than
  spuriously rejected.
- Unapproved dependency licenses fail immediately, preventing silent license
  contamination.
- The `deny.toml` is the single source of truth for license policy; all
  changes to accepted licenses go through this file.

Design artifact: `deny.toml`
Related:
  `flake.nix`
