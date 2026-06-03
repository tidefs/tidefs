# ADR-0006: License Compliance with cargo-deny

Date: 2026-05-05
Status: Accepted

## Context

TideFS is a proprietary codebase that consumes Rust crates from the public
ecosystem. Without systematic license enforcement, a transitive dependency
could introduce a copyleft license (e.g., GPL, AGPL) that would create legal
risk for the proprietary distribution model.

The project needed:
- Automated, CI-enforceable license checking
- A clear policy on which licenses are acceptable
- Explicit denial of copyleft licenses incompatible with proprietary use
- Clarification of edge cases (multi-license crates like `ring` and `webpki`)

## Decision

Adopt `cargo-deny` as the canonical license compliance tool with the following
policy encoded in `deny.toml`:

1. **Permissive allowlist**: Accept Apache-2.0, BSD-2-Clause, BSD-3-Clause,
   BSL-1.0, CC0-1.0, ISC, MIT, MPL-2.0, OpenSSL, Unicode-3.0,
   Unicode-DFS-2016, Zlib, and variants (Apache-2.0 WITH LLVM-exception).

2. **Copyleft denial**: Explicitly deny AGPL-3.0, GPL-2.0, GPL-3.0, LGPL-2.0,
   LGPL-3.0. Any crate (direct or transitive) carrying one of these licenses
   is rejected at CI time.

3. **OSI/FSF free allowance**: `allow-osi-fsp-free = "both"` to accept
   permissively-licensed crates recognized by either OSI or FSF.

4. **Multi-license clarification**: `ring` (ISC AND MIT AND OpenSSL) and
   `webpki` (ISC) have explicit `[licenses.clarify]` entries to resolve
   ambiguous SPDX expressions.

5. **Build-gate integration**: `cargo deny check licenses` runs as part of

6. **Unlicensed denial**: `unlicensed = "deny"` — no crate without an explicit
   SPDX license expression is permitted.

## Consequences

  license compliance, catching copyleft taint before it enters the tree.
- The explicit allowlist and denylist make the policy transparent to
  contributors and auditors.
- Multi-license crates like `ring` are correctly recognized rather than
  spuriously rejected.
  immediately, preventing silent license contamination.
- The `deny.toml` is the single source of truth for license policy; all
  changes to accepted licenses go through this file.

Design artifact: `deny.toml`
Related:
  `flake.nix`
