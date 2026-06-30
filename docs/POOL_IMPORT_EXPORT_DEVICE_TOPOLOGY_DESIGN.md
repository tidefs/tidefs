# Pool Import, Export, And Device Topology Boundary

This file is the single surviving documentation surface for the pool
import/export and online device-topology family after the TFR-019 / GitHub
issue #1590 duplicate-family collapse. The deleted
`docs/design/*pool-import-export*` files were Forgejo-era lineage,
phase-planning, and sealed-design material; git history and issue history
preserve that record.

## Current Source Boundary

The current source-backed pool import/export boundary is:

- `crates/tidefs-types-pool-label-core/src/lib.rs`: `PoolLabelV1`,
  pool/device enums, label encoding, sealing, and checksum verification.
- `crates/tidefs-pool-scan/src/lib.rs`: device scan, label reading, membership
  validation, committed-root discovery, rebuild planning, and scan results.
- `crates/tidefs-pool-import/src/lib.rs`: pool activation, committed-root
  recovery, intent-log replay, and mount-readiness support.
- `crates/tidefs-local-object-store/src/pool_importer.rs`: local object-store
  pool import protocol.
- `crates/tidefs-local-object-store/src/pool_exporter.rs`: local object-store
  export state transition.
- `crates/tidefs-local-object-store/src/device_manager.rs`: add, remove, and
  replace device label updates.
- `crates/tidefs-local-object-store/src/device_health.rs`: device health state
  used by topology management.

This document does not supersede source. If source and this summary disagree,
source plus focused validation wins and this file must be corrected.

## Authority Limits

This file is not product-readiness evidence for hot spares, evacuation,
cluster-aware pool ownership, online topology conversion, hardware failure
survival, availability, operational safety, or incumbent comparison claims.
Those scopes require current source evidence, runtime validation, and claim IDs
where they become publishing-facing claims.

The current guarantee is narrow: TideFS has concrete pool-label,
pool-scan/import, local import/export, and device-manager code paths in the
crates named above. Broad operational behavior must be checked against source
and validation before it is cited.
