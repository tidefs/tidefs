# Online Pool Geometry Conversion

Status: source-backed pointer, not a product-readiness claim.

This file remains because `crates/tidefs-geometry-convert/src/lib.rs` cites the
design surface. The current behavior is the source code, not the removed
Forgejo-era design prose.

## Current Authority

- `crates/tidefs-geometry-convert/src/lib.rs` defines `DurabilityPolicy`,
  `ConversionScope`, `GeometryConversionProgress`, `GeometryConversionJob`, and
  the pool-backed `ExtentStore` adapter.
- `crates/tidefs-locator-table/` owns the locator-table records consumed by
  conversion.
- `crates/tidefs-types-incremental-job-core/` owns the incremental-job
  interface used by the conversion job.

## Boundary

The retained boundary is narrow: geometry conversion code may rewrite
locator-table placement for a scoped set of extents through an incremental job.
Any operator admission, live mounted conversion, background scheduling,
capacity accounting, degraded-mode behavior, or evidence publication must come
from the owning source and validation issues.

## Non-Claims

This pointer does not claim online pool conversion is product-ready, that
mirror/erasure conversion is mounted-safe, that availability or performance has
been validated, or that TideFS matches or exceeds any incumbent storage system.
Those claims remain gated by `validation/claims.toml`,
`docs/CLAIMS_GATE_POLICY.md`, runtime evidence, and live GitHub issue/PR state.
