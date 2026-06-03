# Module owners and invariants (PC-002)

Maturity: **implemented-source** navigation for current module ownership and
invariant boundaries.

This is a source map, not a production-completeness claim. Owner means the
names the checks that keep the owner row tied to implementation.

## Ownership Table

|---|---|---|---|---|

## Cross-Owner Rules

- Any issue that changes a subsystem invariant must name the owner path in its
- Projection adapters can narrow or render owner truth. They cannot become
  or acceleration mirrors. They cannot be used as authority for live data.
- If a future issue moves ownership, the change must update this document, the
  relevant current design/status docs, and the relevant xtask gate in the same
  branch.

## Gate

`tidefs-xtask check-module-owners` verifies that this PC-002 owner map contains
non-claims, and that the publishing-facing docs link to it.
