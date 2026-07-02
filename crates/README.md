# crates/

This directory contains reusable Rust package roots for TideFS.

The current package-role authority is `docs/workspace-package-classification.md`,
and `cargo run -p tidefs-xtask -- check-workspace-policy` validates that
authority against Cargo metadata, manifest discovery, and the root
`workspace.exclude` list. This README is stable navigation only, not a package
table or count surface.

Capability wording for crates remains behind implementation reality and the
review register. It must follow `docs/CLAIMS_GATE_POLICY.md` and
`cargo run -p tidefs-xtask -- check-claims-gate`. A crate appearing here is
not release proof, mounted-transform proof, distributed-storage proof, or
kernel-residency proof.
