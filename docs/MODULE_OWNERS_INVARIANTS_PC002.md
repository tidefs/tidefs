# Module owners and invariants scaffold

Maturity: **delete-candidate scaffold**. `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`
classifies this file as a delete candidate, so it is not current module
ownership authority.

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

The active `tidefs-xtask check-module-owners` gate is tracked outside this
delete-candidate scaffold.
