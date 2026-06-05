# On-Disk Format Versioning and Compatibility Policy

Maturity: **release policy** -- public compatibility contract for operators.
Issue: [#6518](http://172.16.106.12/forgejo/forgeadmin/tidefs/issues/6518).

This document is the operator-facing compatibility contract for TideFS on-disk
formats. It names every supported format family, its current version, the
upgrade rules that govern format evolution, and the refusal behavior when an
incompatible format is encountered. Implementation-level details live in the
referenced sub-documents; this document is the integration point.

## 1. Supported Format Families

TideFS on-disk state is organized into four format families. Each family is

### 1.1 Local Object Store (Segment Log)

**Authority:** `crates/tidefs-local-object-store/src/format_manifest.rs`
**Spec:** [LOCAL_OBJECT_STORE_ON_DISK_FORMAT.md](LOCAL_OBJECT_STORE_ON_DISK_FORMAT.md)

The local object store is the append-only segment log that holds all object
data, metadata records, and integrity trailers.

| Field | Current version | Meaning |
|---|---|---|
| `manifest_version` | 1 | Format manifest struct version |
| `record_format_version` | 1-3 | Record header+footer+trailer layout. v3 (current writer) adds BLAKE3-256 production-integrity trailers. v1/v2 are read-only compatibility. |
| `index_base_format_version` | 1 | Object index (B-tree root pointer) layout |
| `spacemap_base_format_version` | 1 | Spacemap checkpoint layout |
| `suspect_log_format_version` | 1 | Suspect-log record layout |
| `integrity_trailer_digest_suite_id` | 2 (BLAKE3-256) | Digest algorithm for production-integrity trailers |

A format manifest blob (20 bytes, binary) is written into every object store
source of truth for format compatibility.

### 1.2 Pool Labels

**Spec:** [POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md](POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md)

| Field | Current version | Meaning |
|---|---|---|
| `label version` | 1 | `PoolLabelV1` fixed binary struct (256 KiB per copy, 2 copies per device). BLAKE3-256 checksum. |

Pool labels carry three feature bitmasks (`features_incompat`, `features_ro_compat`,
`features_compat`) checked on import. The label version increments only when
the label struct itself changes; feature flags handle capability changes within
a version.

### 1.3 Dataset Feature Flags

**Spec:** [DATASET_FEATURE_FLAGS_DESIGN.md](DATASET_FEATURE_FLAGS_DESIGN.md)

Per-dataset feature flags stored as B-trees in the dataset record, following
the `org.tidefs:<name>` reverse-DNS naming convention. Three compatibility
classes:

| Class | Unknown feature behavior | Mount result |
|---|---|---|
| `compat` | Ignored | Read-write |
| `ro_compat` | Writes may corrupt | Read-only |
| `incompat` | Cannot interpret | Mount refused |

A freshly created dataset has empty feature B-trees. Features are enabled
explicitly as capabilities are needed.

### 1.4 Committed Roots and Intent Log

**Spec:** [TORN_COMMIT_RECOVERY_CONTRACT.md](TORN_COMMIT_RECOVERY_CONTRACT.md)

Committed-root entries and intent-log records carry their own version
discriminants. The current format is V1. Replay accepts only the exact
version written by the same TideFS release.

## 2. Versioning Discipline

### 2.1 How versions are tracked

- **Object store:** `LocalObjectStoreFormatManifest` binary blob at a fixed key
  inside the store. Compared against `CURRENT_FORMAT_MANIFEST` on every open.
- **Pool labels:** `version` field in the label struct. Feature bitmasks
  encode pool-level capability requirements.
- **Dataset features:** Per-dataset B-trees in the dataset record TLV extension
  area. Checked on dataset open, after pool import.
- **Committed roots:** Version discriminant in the root entry header.

### 2.2 When versions change

A format version is incremented only when the on-disk layout of that family
changes in a way that older code cannot safely interpret. Examples:

- Field additions that change a fixed-size prefix
- Magic number changes
- Checksum/digest algorithm changes
- B-tree key or value layout changes

Feature additions that do not change existing record layout use feature flags,
not version bumps. The format manifest version itself increments only when
the manifest struct fields change.

### 2.3 Feature flags vs. format versions

| Mechanism | Scope | When to use |
|---|---|---|
| Format version | Entire format family | Layout change that older code cannot parse |
| Feature flag | Capability within a family | New capability that older code can safely detect and refuse/restrict |

A pool label or dataset may carry feature flags unknown to the current code;
the import/open path checks the class and acts accordingly. A format version
outside the supported range is an immediate refusal -- there is no fallback.

## 3. Upgrade Rules

### 3.1 Supported upgrade paths

TideFS is pre-release. No production data migration paths exist today. The
following rules will govern upgrades when the first release ships:

- **Same-version open:** A store, pool, or dataset created by the same release
  opens read-write. This is the normal operating mode.
- **Minor version forward (U1 -- lazy re-encode on touch):** When the code
  accepts an older minor version within the same major line, it opens the store
  read-write. Existing records remain in their original format. New writes
  emit the current format. This is the intended upgrade path for record format
  evolution within a compatibility window.
- **Feature-gated forward:** A dataset with feature flags unknown to the
  current code is opened subject to the feature class: `incompat` refuses,
  `ro_compat` opens read-only, `compat` opens read-write.
- **Explicit upgrade:** Features are enabled via `tidefsctl dataset upgrade
  feature flag, and commits the change as a txg. Some features may require
  data migration (format rewrite); those requirements are listed per-feature
  in the feature registry.

### 3.2 Unsupported paths

- **Major version jump:** Moving between incompatible major versions (e.g.,
  V1 to V2 with struct layout changes) requires an explicit offline upgrade
  tool or send/receive into a new pool. It is not an online operation.
- **Downgrade:** TideFS does not support downgrade. A store written by newer
  code will refuse to open under older code. There is no "best effort"
  downgrade path.
- **Cross-pool format migration:** Moving data between pools of different
  format versions uses `tidefsctl send | receive`, not in-place conversion.

### 3.3 Pre-release note

TideFS has not shipped a public release. Internal v0.x format artifacts
(record versions 1 and 2, early pool label layouts, pre-V1 committed-root
entries) are compatibility replay inputs for development only. They are not
production format commitments. The first public release will freeze the V1
format surface; all pre-release internal formats are subject to removal or
redesign without a migration path.

## 4. Refusal Behavior

### 4.1 Object store open refusal

manifest, the store open returns an error with the first mismatched field,
the stored value, and the current expected value. Example:

```text
format manifest incompatible: field=record_format_version_max, stored=5, current=3
```

The store does not enter an undefined state. No replay or read occurs on an
incompatible store. The error is surfaced to the operator through the daemon
log and the `tidefsctl pool import` output.

### 4.2 Pool import refusal

When a pool label carries `features_incompat` bits not known to the current
code, import is refused:

```text
pool import refused: unsupported incompat feature bits 0x0004
```

When the label `version` field is outside the supported range, import is
refused:

```text
pool import refused: unsupported label version 2 (current supports 1)
```

When a pool label fails BLAKE3-256 checksum verification, import is refused:

```text
pool import refused: label checksum mismatch on device /dev/sdb
```

### 4.3 Dataset open refusal

When a dataset carries an `incompat` feature flag unknown to the current code,
the dataset open returns:

```text
dataset open refused: feature org.tidefs:future_capability (incompat) not supported
```

When a dataset carries an unknown `ro_compat` feature, the dataset opens
read-only:

```text
dataset opened read-only: feature org.tidefs:future_checksum (ro_compat) not supported
```

### 4.4 Committed-root refusal

A committed-root entry with an unknown version discriminant is quarantined
rather than replayed:

```text
committed root version 2 unsupported; replay halted at txg N
```

The pool remains importable, but the dataset state is frozen at the last
committed root with a supported version. The operator must upgrade the TideFS
binary to advance past that txg.

### 4.5 No silent fallback

Every format incompatibility is an explicit error. TideFS never silently
ignores unknown format fields, never guesses at future record layouts, and
never "best-effort" replays an incompatible artifact. Format integrity is a
hard gate.

## 5. Operator Commands

### 5.1 Inspect format versions

```sh
tidefsctl pool info <pool>     # shows pool label version and feature bits
tidefsctl dataset list <pool>  # shows per-dataset feature flags
```

### 5.2 Enable a feature

```sh
tidefsctl dataset set-strategy <pool> <dataset> --enable org.tidefs:posix_acl
```

### 5.3 Check compatibility before upgrade

```sh
```

## 6. Referenced Documents

- [FORMAT_IDENTITY_UPGRADE_REPLAY_CONTINUITY_LAW_P2-04.md](FORMAT_IDENTITY_UPGRADE_REPLAY_CONTINUITY_LAW_P2-04.md) -- design-level format identity, upgrade, and replay continuity law
- [LOCAL_OBJECT_STORE_ON_DISK_FORMAT.md](LOCAL_OBJECT_STORE_ON_DISK_FORMAT.md) -- local object store on-disk format specification
- [DATASET_FEATURE_FLAGS_DESIGN.md](DATASET_FEATURE_FLAGS_DESIGN.md) -- per-dataset feature flag architecture
- [POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md](POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md) -- pool label format and import/export design
- [TORN_COMMIT_RECOVERY_CONTRACT.md](TORN_COMMIT_RECOVERY_CONTRACT.md) -- committed-root and intent-log format contract
- [PRODUCTION_INTEGRITY_POLICY.md](PRODUCTION_INTEGRITY_POLICY.md) -- production integrity (digest, domain separation, trailer) policy
