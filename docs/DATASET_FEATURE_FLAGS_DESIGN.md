# Dataset Feature Flags Historical Note

Maturity: historical input.

This file is retained only as a provenance pointer while live issue #1842 owns
the remaining xtask fixture retargeting that still names this path. It is not a
current design spec, public compatibility promise, mount-behavior authority, or
production-readiness claim.

Current source authority for the dataset feature-flag data types and refusal
semantics lives in `crates/tidefs-types-dataset-feature-flags-core/src/lib.rs`
and in the callers that enforce those types. Publishing-facing capability and
successor/comparator wording remains governed by `validation/claims.toml`,
`docs/CLAIMS_GATE_POLICY.md`, and generated `docs/CLAIM_REGISTRY.md`.

Historical lineage for the removed Forgejo-era design prose remains available
through git history and GitHub issue #1800. Deleting or retargeting this path
must wait for the active xtask fixture owner to stop requiring it.

This note does not validate dataset feature negotiation, on-media upgrade
lifecycle, compatibility with older software, mounted feature behavior,
OpenZFS/ext4 parity, release readiness, performance, or production use.
