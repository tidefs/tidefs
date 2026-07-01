# On-Disk Format Versioning and Compatibility Policy

Maturity: current pre-alpha policy boundary; not a public compatibility
contract.

TideFS is a private pre-alpha repository and has not had a public release. This
document records the current on-disk format version authorities used for
development and review. It is not an operator-facing release compatibility
contract, and it does not promise migration, downgrade, or fallback support for
unreleased internal data.

Follow [UNRELEASED_AUTHORITY_POLICY.md](UNRELEASED_AUTHORITY_POLICY.md) first:
internal formats, fixtures, design artifacts, and command sketches in this
repository are not compatibility commitments unless a current GitHub issue or
current policy document names a real external ABI, protocol, or operator-owned
data boundary. Without that named boundary, TideFS chooses the current
authority, removes or refuses stale paths, and does not add migration or
fallback debt for old pre-release data.

## 1. Supported Format Families

TideFS on-disk state is currently described through four format families. Each
family below names the current development authority and the version fields
that govern refusal behavior. A listed internal version is not a public
compatibility promise.

### 1.1 Local Object Store (Segment Log)

**Authority:** `crates/tidefs-local-object-store/src/format_manifest.rs`
**Format-family references:** `docs/design/on-media-format-strategy.md` and
`docs/PRODUCTION_INTEGRITY_POLICY.md`; the deleted local object-store format
lineage from #1612 remains historical input in git, the issue, and its PR.

The local object store is the append-only segment log that holds all object
data, metadata records, and integrity trailers.

| Field | Current version | Meaning |
|---|---|---|
| `manifest_version` | 1 | Format manifest struct version |
| `record_format_version` | 1-3 | Record header+footer+trailer layout. v3 is the current writer. v1/v2 are accepted development inputs only where the current manifest gate permits them; they are not public compatibility commitments. |
| `index_base_format_version` | 1 | Object index (B-tree root pointer) layout |
| `spacemap_base_format_version` | 1 | Spacemap checkpoint layout |
| `suspect_log_format_version` | 1 | Suspect-log record layout |
| `integrity_trailer_digest_suite_id` | 2 (BLAKE3-256) | Digest algorithm for production-integrity trailers |

A format manifest blob (20 bytes, binary) is written into every object store
source of truth and validated before replay.

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

**Authority:** source behavior plus the TFR-005/TFR-008 review-register
boundaries.

Committed-root entries and intent-log records carry their own version
discriminants. The current documented format is V1. Replay accepts only
versions explicitly handled by the current import/recovery authority; unknown
versions must fail closed rather than being guessed or silently replayed.

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

## 3. Pre-Release Upgrade Boundary

### 3.1 Current allowed paths

TideFS is pre-release. No public or production data migration paths exist
today. Current allowed paths are deliberately narrow:

- **Current-authority open:** A store, pool, or dataset created by the current
  authority opens only when its recorded versions and features are accepted by
  the current code.
- **Accepted internal range:** An older internal record version may be read
  only when the current manifest, parser, and tests explicitly support that
  range. That support is a development replay input, not a public compatibility
  promise.
- **Feature-gated forward:** A dataset with feature flags unknown to the
  current code is opened subject to the feature class: `incompat` refuses,
  `ro_compat` opens read-only, `compat` opens read-write.
- **Dataset feature upgrade:** `tidefsctl dataset upgrade <pool> <dataset>`
  enables supported dataset feature flags from the current
  `SupportedFeaturesV1` table. It is not a general on-disk migration tool.

Any future migration, downgrade, fallback, send/receive format conversion, or
offline upgrade behavior for unreleased TideFS data needs either a named
external/operator boundary or a separate prepared GitHub issue with owner,
scope, validation, and retirement or graduation criteria.

### 3.2 Unsupported or not promised paths

- **Major version jump:** There is no default online or offline major-version
  conversion path.
- **Downgrade:** TideFS does not support downgrade. A store written by newer
  code will refuse to open under older code. There is no "best effort"
  downgrade path.
- **Cross-pool format migration:** This document does not promise in-place
  conversion or send/receive conversion between incompatible format versions.
- **Fallback replay:** TideFS must not silently skip, reinterpret, or
  best-effort replay an incompatible internal artifact.

### 3.3 Pre-release note

Internal format artifacts, including old record versions, early pool label
layouts, and pre-current committed-root entries, are development evidence only.
They are subject to removal or redesign without a migration path unless a
current GitHub issue or current policy document names the real external or
operator-owned boundary being preserved.

## 4. Refusal Behavior

### 4.1 Object store open refusal

When a stored `LocalObjectStoreFormatManifest` is not compatible with
`CURRENT_FORMAT_MANIFEST`, the store open fails before replay or reads begin.
The error identifies the mismatched field, the stored value, and the current
expected value. Example:

```text
format manifest incompatible: field=record_format_version_max, stored=5, current=3
```

The store does not enter an undefined state. No replay or read occurs on an
incompatible store. A path that cannot surface an equivalent explicit refusal
must fail closed and needs implementation work before it can be documented as
operator behavior.

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

A committed-root entry with an unknown version discriminant must halt replay or
be quarantined by an explicitly documented recovery path rather than replayed:

```text
committed root version 2 unsupported; replay halted at txg N
```

If a current import path cannot safely preserve a partially imported/frozen
state, it must return an explicit error rather than claiming recovery behavior.

### 4.5 No silent fallback

Every format incompatibility is an explicit error. TideFS never silently
ignores unknown format fields, never guesses at future record layouts, and
never "best-effort" replays an incompatible artifact. Format integrity is a
hard gate.

## 5. Operator Commands

The current command surface can inspect pool and dataset state through the live
owner or explicit offline devices. It does not provide a general
format-compatibility preflight command or a data migration command.

### 5.1 Inspect pool state

```sh
tidefsctl pool scan --devices /dev/sdb /dev/sdc --json
tidefsctl pool status <pool> --json
tidefsctl pool status <pool> --devices /dev/sdb /dev/sdc --json
```

### 5.2 Inspect and change dataset feature flags

```sh
tidefsctl dataset list --pool <pool> --json
tidefsctl dataset set-strategy <pool> <dataset> --list
tidefsctl dataset set-strategy <pool> <dataset> --enable org.tidefs:posix_acl --class compat
tidefsctl dataset upgrade <pool> <dataset>
```

`dataset upgrade` enables supported dataset feature flags for the current code.
It is not a promise to rewrite old on-disk formats or to bridge incompatible
pre-release data. A future compatibility probe, offline upgrade tool,
downgrade path, fallback reader, or format migration workflow must be tracked
by a separate prepared issue unless it is tied to a named external/operator
boundary in current policy.

## 6. Referenced Documents

- [UNRELEASED_AUTHORITY_POLICY.md](UNRELEASED_AUTHORITY_POLICY.md) -- pre-release compatibility, migration, downgrade, and fallback boundary
- [FORMAT_IDENTITY_UPGRADE_REPLAY_CONTINUITY_LAW_P2-04.md](FORMAT_IDENTITY_UPGRADE_REPLAY_CONTINUITY_LAW_P2-04.md) -- design-level format identity, upgrade, and replay continuity law
- `crates/tidefs-local-object-store/src/format_manifest.rs` -- local object store manifest and record-format version authority
- [DATASET_FEATURE_FLAGS_DESIGN.md](DATASET_FEATURE_FLAGS_DESIGN.md) -- per-dataset feature flag architecture
- [POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md](POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md) -- pool label format and import/export design
- `docs/REVIEW_TODO_REGISTER.md` TFR-005/TFR-008 -- committed-root and intent-log format/recovery review boundary
- [PRODUCTION_INTEGRITY_POLICY.md](PRODUCTION_INTEGRITY_POLICY.md) -- production integrity (digest, domain separation, trailer) policy
