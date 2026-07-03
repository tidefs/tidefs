# Polymorphic Directory Index Historical Note

Maturity: historical input.

This file is retained only as a provenance pointer while live issue #1842 owns
the remaining xtask fixture retargeting that still names this path. It is not a
current directory-index spec, namespace authority, production-integrity claim,
performance claim, or ZFS ZAP comparison surface.

Current source authority for the directory index data types lives in
`crates/tidefs-types-polymorphic-directory-index-core/src/lib.rs` and the
callers that choose or interpret those types. Current namespace, mounted
behavior, and product-claim boundaries remain governed by source behavior,
current authority docs, `validation/claims.toml`, `docs/CLAIMS_GATE_POLICY.md`,
and generated `docs/CLAIM_REGISTRY.md`.

Historical lineage for the removed Forgejo-era design prose remains available
through git history and GitHub issue #1800. Deleting or retargeting this path
must wait for the active xtask fixture owner to stop requiring it.

This note does not validate directory indexing implementation completeness,
lookup or readdir semantics, migration thresholds, crash consistency,
performance, release readiness, production use, or OpenZFS/ZAP parity.
