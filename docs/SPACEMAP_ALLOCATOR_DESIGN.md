# Spacemap Allocator Historical Note

Maturity: historical input.

This file is retained only as a provenance pointer while live issue #1842 owns
the remaining xtask fixture retargeting that still names this path. It is not a
current allocator spec, capacity authority, space-pressure guarantee,
production-readiness claim, or OpenZFS comparison surface.

Current source authority for allocator behavior lives in
`crates/tidefs-spacemap-allocator/src/lib.rs` and the source-owned storage and
capacity code that calls it. Current capacity, storage-intent, and product
claim boundaries remain governed by source behavior, current authority docs,
`validation/claims.toml`, `docs/CLAIMS_GATE_POLICY.md`, and generated
`docs/CLAIM_REGISTRY.md`.

Historical lineage for the removed Forgejo-era design prose remains available
through git history and GitHub issue #1800. Deleting or retargeting this path
must wait for the active xtask fixture owner to stop requiring it.

This note does not validate allocator completeness, fragmentation behavior,
space accounting, mounted capacity semantics, crash recovery, performance,
release readiness, production use, or OpenZFS/Ceph-class behavior.
