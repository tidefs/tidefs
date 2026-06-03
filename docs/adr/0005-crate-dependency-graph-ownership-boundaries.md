# ADR-0005: Crate Dependency Graph and Ownership Boundaries

Date: 2026-05-05
Status: Accepted

## Context

TideFS had grown to 177 `tidefs-*` crates with no single canonical record of
how they relate, which crate owns which architectural concern, and where
changes risk cascading breakage. Without explicit ownership boundaries:

- New contributors could not determine where to place new types or algorithms.
- Refactors risked introducing cyclic dependencies or violating layering.
- Parallel Codex workers risked conflicts on high-fan-out crates (serial write
  surfaces).
- No formal naming convention existed, leading to inconsistent crate names.

## Decision

Adopt a five-category crate taxonomy with explicit ownership boundaries:

1. **Foundation Types** (38 crates): `no_std`-compatible pure data types,
   wire formats, enums, newtypes. Owns *what* data looks like, not *how* it
   is processed. Naming: `tidefs-types-<domain>-core`.

2. **Core Logic** (12 crates): Pure algorithms with no I/O or async runtime.
   Depends only on Foundation Types. Naming: `tidefs-<domain>-core`.

3. **Schema / Codec** (11 crates): Binary encode/decode, framing, checksums,
   wire protocols. Naming: `tidefs-binary_schema-*`, `tidefs-schema-codec-*`.

4. **Runtime / Daemon** (38 crates): Async I/O, system services, daemon
   binaries, background workers. Naming: `tidefs-<domain>-runtime`,
   `tidefs-<domain>-daemon`.

5. **Leaf Utilities** (78 crates): Standalone crates with no tidefs
   dependencies (primitives, algorithms). Various names.

**Dependency direction rule**: Dependencies must flow upward through the
categories — Foundation ← Core ← Schema ← Runtime ← Daemon Binaries. Cyclic
dependencies are forbidden.

**Serial write surfaces**: High-fan-out crates (`tidefs-types-vfs-core`,
`tidefs-types-object-store-core`) are designated as serial write surfaces where
only one active Codex issue may edit at a time.

**Naming convention**: `tidefs-<domain>-<layer>` where `<domain>` describes
the functional area and `<layer>` is `core` (algorithms), `runtime` (async
execution), or `daemon` (binary).

## Consequences

- Every crate has a clear owner group; contributors know where to define new
  types, algorithms, and services.
- The dependency direction rule prevents architectural decay through cyclic
  dependencies.
- Serial write surfaces are now documented, reducing merge conflicts in
  parallel Codex work.
- The naming convention (`tidefs-<domain>-<layer>`) provides immediate
  navigability for all 177 crates.
- All 5 categories, 48-layer-1 leaf crates, and dependency invariants are
  documented in a single source of truth.
- Zero cyclic dependencies confirmed in the current workspace.

Design spec: `docs/design/crate-dependency-graph-ownership-boundaries.md`
Related:
  `docs/design/11-layer-architecture-dependency-matrix.md`
  `crates/README.md`
