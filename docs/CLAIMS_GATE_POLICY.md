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

## Scanned surfaces

`tidefs-xtask check-claims-gate` scans the top-level README, current policy
docs, preview handoff docs that remain in the tree, the review register, and
the whole-repo review. It also verifies that the source rule table in
`xtask/tidefs-xtask/src/claims.rs` and this policy document remain present.

## Work-State Boundary

GitHub issue and pull request state is the active work-state authority for
foreground Codex development. Legacy Forgejo helper commands remain available
for historical/local diagnostics, but stale Forgejo ownership assumptions must
not block `check-claims-gate` from scanning publishing claims in a valid
GitHub/Codex worktree.
