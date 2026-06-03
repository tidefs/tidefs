# Claims Gate Policy

Maturity: current policy guardrail.

TideFS may describe ambition and future direction, but publishing-facing docs
do not prove.

## Required command

Run this before publishing a tarball, tag, external summary, or handoff that a
reader could treat as a capability statement:

```text
cargo run -p tidefs-xtask -- check-claims-gate
```

The canonical Forgejo repository is `forgeadmin/tidefs`. Local
`TIDEFS_FORGEJO_REPO` or `git config tidefs.forgejo-repo <owner/repo>`
overrides are for temporary forks or emergency diagnostics only; the primary
`/root/tidefs` checkout should not need a tracked-source override.

The full Nix gate also runs it through:

```text
```

## Claims rule

exists. The same rule applies to these present-tense claim families:


A line may mention one of those topics only when it is clearly framed as one of:

- not true today;
- future or aspirational work;
- a goal or ambition rather than current product state.

## Scanned surfaces

`tidefs-xtask check-claims-gate` scans the top-level README, current policy
docs, preview handoff docs that remain in the tree, the review register, and
the whole-repo review. It also verifies that the source rule table in
`xtask/tidefs-xtask/src/claims.rs` and this policy document remain present.

## Forgejo Publication State

Forgejo `PC-*` issues track publication gates. No release note or handoff may
upgrade the project from prototype wording to present-tense production
intentionally.



Stronger wording requires all of the following:

1. a tracked Forgejo issue naming the claim;
3. an updated current-status or review-register row;
4. an updated claims gate rule that allows the specific stronger claim.
