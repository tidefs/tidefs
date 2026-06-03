# Design Overfitting Policy

## Reconciliation Note (2026-05-18, #5816)

This document was written during the May 11 cleanup era. Since then, the
production-depth workspace design has evolved. Several directives below are
now superseded or partially superseded by the workspace family layout law in
[WORKSPACE_FAMILY_LAYOUT_CRATE_SERVICE_BOUNDARIES_P1-01.md](WORKSPACE_FAMILY_LAYOUT_CRATE_SERVICE_BOUNDARIES_P1-01.md)
and the package classification in
[workspace-package-classification.md](workspace-package-classification.md).

| Section | Status | Reason |
|---|---|---|
| 1. Crate Structure (micro-crates) | Partially superseded | P1-01 types family (f0) explicitly allows small canonical type crates as lawful stratum s0 members. Still binding for adapter sub-crates under 1,000 lines. |
| 2. Scaffolding Crates (remove 20) | Partially superseded | P1-01 establishes policy_authority (f2), control_plane (f8), response_normalizer (f5), and observe (f10) as lawful workspace families. Removal of 18 of 20 packages is still correct per the classification doc, but the blanket removal policy no longer applies to all scaffold-labeled crates without P1-01 reconciliation. |
| 3. Error Types (max 12 variants) | Still binding | Not affected by P1-01. |
| 4. Feature Flags (max 8 per crate) | Still binding | Not affected by P1-01. |
| 5. Dynamic Dispatch (two impls) | Still binding | Not affected by P1-01. |
| 6. Concurrency (ownership over locking) | Still binding | Not affected by P1-01. |
| 7. Unsafe (SAFETY comments) | Still binding | Not affected by P1-01. |

Workers: consult the classification doc for per-package status before acting
on the removal directives in Section 2 below.

Maturity: **design-policy** — binding on all current and future TideFS code.

This document catalogs design patterns that have overfitted the codebase and
defines the simpler alternatives that must be used instead.

## 1. Crate Structure — No Micro-Crates

The workspace contains 181 members. Many are single-concept crates that should
be modules.

**Pattern**: 30 `tidefs-types-*` crates holding struct/enum definitions with
serde derives and no behavior. 12 `tidefs-posix-filesystem-adapter-*`
sub-crates decomposing one daemon into per-worker-family compilation units.
Sub-500-line crates. 3-line stub crates.

**Why harmful**: Each crate adds `Cargo.toml` metadata resolution, dependency
versioning, feature flag enumeration, and crate-graph node cost. A 70-line
crate has more build-system overhead than code.

**The rule**:
- A crate must provide **behavior**, not just types. Pure-data structures
  belong as modules in the crate that owns their lifecycle.
- A crate must be at least **~1,000 meaningful lines** (excluding tests,
  derives, doc comments). Smaller units are modules.
- The 30 `types-*` crates must be consolidated into the crates that consume
  those types.
- The 12 `posix-filesystem-adapter-*` sub-crates must be merged into the
  daemon crate as internal modules.
- Stub crates must be removed.

## 2. Scaffolding Crates — Remove from Workspace

**Pattern**: README key decision 5 from the cleanup era treated the
policy-authority, control-plane, response-registry, observe, truth-view, and
adjacent scaffold families as removal candidates. That old blanket list is not
current workspace authority. Some roots have since been deleted, while other
packages remain product-transitional because current workspace members still
depend on them.

The current package set and removal status must be taken from Cargo metadata,
`docs/WHOLE_REPO_REVIEW.md`, and `docs/workspace-package-classification.md`.
Do not act on the historical crate count or the old family list without
regenerating it against the current tree.

**The rule**:
- Remove crates only after current metadata and reverse-reference review prove
  they are scaffold rather than live product authority.
- Delete ambiguous live-looking directories instead of keeping them as hidden
  package roots.
- Remove all imports from active crates. Any functionality still needed must
  be moved into the product crate that owns its lifecycle or into a current
  shared type crate with explicit ownership.

## 3. Error Types — At Most 12 Variants

**Pattern**: Error enums with implausibly many variants:

| Crate | Variants |
|---|---|
| `tidefs-lock-service` | 266 |
| `tidefs-device-removal` | 143 |
| `tidefs-claim-ledger` | 101 |
| `tidefs-lease/src/types.rs` | 86 |
| `tidefs-lease/src/protocol.rs` | 70 |
| `tidefs-lease-manager/src/manager.rs` | 56 |
| `tidefs-auth/src/error.rs` | 45 |
| `tidefs-frame/src/lib.rs` | 41 |

**Why harmful**: An error type with 266 variants is impossible to handle
meaningfully. Most callers match on 1-3 variants and use a catch-all. The
remaining ~260 variants are documentation masquerading as control flow.

**The rule**:
- Error enums must have **at most 12 variants**.
- Variants must represent **semantically distinct caller-relevant outcomes**,
  not internal state enumerations.
- Internal-only errors that no caller can usefully handle must use a generic
  `Internal(String)` variant or be logged and converted to opaque errors.

## 4. Feature Flags — At Most 8 Per Crate

gating a single optional dependency with design-document-reference names like
`p5-02-capacity`, `p5-02-scheduler`.

**Why harmful**: 59 features create 2^59 theoretical compilation states, most
untested. The names encode external design doc references rather than
describing what the feature enables.

**The rule**:
- Feature flags must name **capabilities**, not document references. Good:
  `serde`, `tracing`. Bad: `p5-02-capacity`.
- At most **8 feature flags** per crate.

## 5. Dynamic Dispatch — Traits Need Two Implementations

**Pattern**: `Box<dyn Trait>` appears heavily in crates with no runtime
polymorphism need. 195 `pub trait` definitions across the codebase.

| Crate | Box<dyn> |
|---|---|
| `tidefs-dedup` | 18 |
| `tidefs-transport` | 17 |
| `tidefs-compaction` | 16 |
| `tidefs-posix-filesystem-adapter-daemon` | 12 |
| `tidefs-background-scheduler` | 11 |

**Why harmful**: Dynamic dispatch adds vtable overhead, prevents inlining,
complicates debugging. The dedup engine and background scheduler are not
plugin architectures — each trait has exactly one implementation.

**The rule**:
- Define a trait **only when there are at least two production implementations**
  (test mocks don't count — use `#[cfg(test)]` conditional compilation).
- Prefer **enum-based dispatch** for closed sets of implementations.
- Background services with one implementation must use concrete types.
- Existing single-implementation traits must be removed.

## 6. Concurrency — Ownership over Defensive Locking

**Pattern**: 194 `Arc`/`Mutex`/`RwLock`/`Atomic` in one FUSE daemon file.
60 in scrub-core. 54 in namespace.

**Why harmful**: Wrapping every field in a Mutex creates lock contention and
makes ownership unclear. High Mutex density signals that data ownership was
never designed — it's a bag of independently-locked values.

**The rule**:
- Data owned by a single task must not be behind a Mutex. Use channels or
  task-local ownership.
- A file with >20 synchronization primitives must document its concurrency
  model in a module-level comment.
- New `Arc`/`Mutex` additions require justification.

## 7. Unsafe — Every Block Must Have a SAFETY Comment

22 in ublk-control-runtime, 16 in block-volume-adapter-daemon.

**The rule**:
- Every unsafe block must have a `// SAFETY:` comment explaining why
  preconditions are satisfied (Rust stdlib convention, mandatory here).
- Unsafe blocks replaceable by safe abstractions (`bytemuck`, `MaybeUninit`
  methods) must be replaced.
- New unsafe blocks require explicit justification in the commit message.

## 8. Enforcement

New code must comply with these rules when the crate is next substantively
edited. Existing violations must be refactored via the specific issues filed
against each section.

Changes to this policy require a PR citing the design argument for the change.
