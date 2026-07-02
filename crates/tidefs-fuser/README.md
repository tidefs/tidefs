# TideFS vendored fuser crate

This directory is vendored third-party code. TideFS carries it as the `fuser`
package used by the in-tree FUSE adapter, validation harnesses, and demo smoke
paths.

## Provenance

The crate descends from upstream `fuser`, a Rust FUSE userspace protocol
library that itself continued the older `fuse-rs` crate lineage. TideFS keeps a
patched in-tree copy so local FUSE protocol and adapter changes can be reviewed
with the rest of the workspace.

The package manifest intentionally keeps the upstream package name, version
metadata, and license expression because this directory is not TideFS-owned
product code.

## License Boundary

The package license is MIT; see `LICENSE.md` in this directory. Some files under
`examples/` preserve GPLv2 file-local notices inherited from upstream/libfuse
example material. `docs/LICENSING.md` is the TideFS authority for those
third-party license exceptions.

Do not rewrite vendored notices to the TideFS workspace license. New TideFS
source outside this vendored package remains governed by the repository license
policy.

## Local Role

TideFS uses this package as an in-tree FUSE protocol/library dependency. This
README is only a provenance and boundary note; it is not a TideFS installation
guide, an upstream project authority, or evidence of FUSE, POSIX, production,
release, or successor/comparator readiness.

Mounted FUSE behavior and product-facing capability wording remain separately
gated by TideFS issues, pull requests, repository docs, validation workflows,
and claim checks.

## Validation Boundary

Changes in this directory should preserve the vendored provenance and license
boundary above. Documentation that describes TideFS capabilities must pass the
repo authority and claims checks selected by the owning issue or pull request
before it is treated as TideFS product authority.
