# TideFS Workspace Structure

## Authority Boundary

This document is historical review input for a prior types-core consolidation
review. It is not the current workspace-membership, package-role, or deletion
authority.

Use the current authorities instead:

- Root `Cargo.toml` or `cargo metadata --no-deps` for live workspace members.
- `docs/workspace-package-classification.md` for package roles and the
  workspace-selection authority checked by `check-workspace-policy`.
- `docs/WHOLE_REPO_REVIEW.md` for repo-review evidence about package cleanup.

Issue #276 deleted the retired scaffold type roots
`tidefs-types-control-plane-core`,
`tidefs-types-publication-pipeline-core`, and
`tidefs-types-response-registry-core`. The current package-classification
authority records those roots as deleted, not reclassified. Their surviving
control-plane, publication-pipeline, and response-registry record definitions
now live in `tidefs-types-vfs-core`.

## Current Types Package Shape

The live types package family is the set of `crates/tidefs-types-*` entries in
root `Cargo.toml` and `docs/workspace-package-classification.md`. As of the
current authority, `tidefs-types-vfs-core` is the shared VFS and record
definition root for the deleted control-plane/publication/response package
material. Other live types packages cover bounded domains such as cache
lattices, claim ledgers, dataset flags and lifecycle, deferred cleanup,
extent maps, incremental jobs, orphan indexes, package profiles, polymorphic
directory and xattr data, POSIX adapter types, pool labels, reclaim queues,
secret-key policy, space accounting, transport sessions, and VFS-owned data.

This section is a reader map only. If this prose and the package authority
disagree, treat `docs/workspace-package-classification.md` and current Cargo
metadata as authoritative.

## Historical Dependency Evidence

The prior consolidation review modeled
`tidefs-types-control-plane-core` as a hub crate and listed
`tidefs-types-publication-pipeline-core` and
`tidefs-types-response-registry-core` as dependent type roots. That material is
retained here only as evidence for why the deleted roots were reviewed; it does
not describe current workspace structure.

The same historical review found that the older archive-control, observe,
policy-authority, truth-view, and shadow-pilot split crates were deleted from
the fresh TideFS checkout after reverse-reference review. Their surviving
record surfaces live in current packages such as `tidefs-types-vfs-core` or in
product-local modules.

## Consolidation Status

For current package cleanup status, start with
`docs/workspace-package-classification.md`. It records that the prior
scaffold-transitional and archive-delete-candidate roles are retired, no
current package root uses those roles, and future archive/delete work requires
an issue-backed plan.

The older consolidation plan
([types-core-consolidation-plan.md](types-core-consolidation-plan.md)) remains
historical evidence for the review that led to package cleanup. Before using
any row from that plan for new work, re-check it against current Cargo metadata
and the package-classification authority.
