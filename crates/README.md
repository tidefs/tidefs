# crates/

This directory contains reusable Rust package roots for TideFS.

The current package-role authority is `docs/workspace-package-classification.md`, and `cargo run -p tidefs-xtask -- check-workspace-policy` validates that authority against Cargo metadata, manifest discovery, and the root `workspace.exclude` list. This README is only a navigation aid, not a second package table.

## Current Inventory

- Workspace package roots under `crates/`: 139.
- Excluded crate-local fuzz package roots under `crates/`: 4.
- `crates/tidefs-fuser` is the vendored upstream `fuser` package and is tracked separately for provenance.
- The remaining excluded crate-local package roots are standalone fuzz harnesses and must stay mirrored in root `workspace.exclude`.

## Role Groups

- `product-code`: 115 crate roots. See the authority document for the full list and dispositions.
- `adapter-operator`: 8 crate roots. See the authority document for the full list and dispositions.
- `policy-tooling`: 7 crate roots. See the authority document for the full list and dispositions.
- `proof-harness`: 5 crate roots. See the authority document for the full list and dispositions.
- `vendored-third-party`: 1 crate root. See the authority document for the full list and dispositions.
- `scaffold-transitional`: 3 crate roots. See the authority document for the full list and dispositions.

Capability wording for crates remains behind implementation reality and the
review register. It must follow `docs/CLAIMS_GATE_POLICY.md` and
`cargo run -p tidefs-xtask -- check-claims-gate`. A crate appearing here is
not release proof, mounted-transform proof, distributed-storage proof, or
kernel-residency proof.
