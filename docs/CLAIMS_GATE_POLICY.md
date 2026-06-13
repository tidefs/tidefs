# Claims Gate Policy

Maturity: current policy guardrail.

TideFS may describe ambition and future direction, but publishing-facing docs
must not present future capability as current product fact.

## Required command

Run this before publishing a tarball, tag, external summary, or handoff that a
reader could treat as a capability statement:

```text
cargo run -p tidefs-xtask -- check-claims-gate
```

This command checks publishing-facing capability wording. It does not validate
active work ownership. Foreground Codex work is coordinated through GitHub
issues and pull requests in `tidefs/tidefs`; use the separate worktree/claim
diagnostic commands when checking local worker ownership.

## Claims rule

Current capability wording is blocked for these claim families unless the same
line clearly frames the capability as absent today, future work, or a goal:

- must not publish an OpenZFS/Ceph successor claim;
- must not claim production-ready status;
- must not claim POSIX-complete behavior;
- must not claim distributed storage capability;
- must not claim kernelspace-ready or full-kernel operation;
- must not claim an RDMA data path.
- must not claim mounted device-level compression or mounted device-level
  encryption while the TFR-006 raw-store inventory has blocked production
  rows.
- must not claim final distributed operator UAPI status for prototype or
  development-exercise `tidefsctl` commands.

A line may mention one of those topics only when it is clearly framed as one of:

- not true today;
- future or aspirational work;
- a goal or ambition rather than current product state.

## Proof Before Stronger Claims

Stronger wording requires all of the following:

1. a tracked GitHub issue naming the claim;
2. recorded proof that covers the full claimed behavior;
3. an updated current-status or review-register row;
4. an updated claims gate rule that allows the specific stronger claim.

## Mounted Transform Authority

The mounted local-filesystem compression/encryption claim is blocked behind
`docs/MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY.md`. The lower
object-store compression and encryption wrappers may be discussed as helper
or library-tier surfaces, but publishing-facing text must not present them as
end-to-end mounted filesystem support until the transform authority records no
blocked production raw-store paths.

## Operator Command Classification

The `tidefsctl` command classification authority is
`apps/tidefsctl/src/commands/classification.rs`, marker
`tidefsctl-command-classification-v1`. Publishing-facing docs must preserve
the distinction between `public-operator`, `userspace-harness`,
`operator-diagnostic`, `prototype`, `development-diagnostic`, and
`removed-or-unsupported` command surfaces. In particular, `cluster placement
exercise`, `cluster heal exercise`, and `cluster pool create` are not final
distributed operator UAPI.

## Unreleased Authority Boundary

TideFS has not had a public release. Publishing-facing docs must not describe
old internal TideFS paths as legacy product compatibility, migration, downgrade,
or fallback promises unless a tracked GitHub issue names the released external
boundary or operator-owned data set being preserved. Current design wording
should choose current authority, retire the stale pre-release path, or mark the
material as historical input.

## Scanned surfaces

`tidefs-xtask check-claims-gate` scans the top-level README, current policy
docs, preview handoff docs that remain in the tree, the review register, and
the whole-repo review. It also verifies that the source rule table in
`xtask/tidefs-xtask/src/claims.rs` and this policy document remain present.

## Work-State Boundary

GitHub issue and pull request state is the active work-state authority for
foreground Codex development. Forgejo helper commands remain available for
historical/local diagnostics, but stale Forgejo ownership assumptions must not
block `check-claims-gate` from scanning publishing claims in a valid
GitHub/Codex worktree.
