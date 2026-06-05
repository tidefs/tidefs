# Dataset Feature Flags Architecture Design (P1 hard-gate)

Maturity: **design-spec** for the per-dataset feature flag system with three
compatibility classes encoded as the `FeatureClass` enum (`Compat`/`RoCompat`/`Incompat`), deterministic mount
algorithm, reverse-DNS feature name registry, and 5-stage feature lifecycle.

This document closes Forgejo issue #1223.

## 1. Motivation

Storage systems evolve. On-disk format changes are inevitable as new capabilities
are added. Without a feature flag system, there are two bad choices: never change
the format (stagnation leading to competitive irrelevance) or break backward
compatibility on every change (operational nightmare for users).

OpenZFS solved this with per-pool feature flags that gate format changes and
prevent older code from damaging newer-format data. ext4 uses a similar
compat/ro_compat/incompat triplet in its superblock. These proven approaches
share a common architecture: enumerate capabilities as named flags, classify
them by compatibility impact, and check on mount.

tidefs must implement feature flags per dataset (not just per pool) because:

- Different datasets in the same pool may use different features (e.g., one
  dataset enables ACLs, another doesn't).
- Pool import (#1254) already handles pool-level compatibility through
  `features_incompat`/`features_ro_compat`/`features_compat` bitmasks.
- Dataset-level flags allow fine-grained upgrade control: enable `posix_acl` on
  production datasets while testing `compression_lz4` on a development dataset.

The feature flag architecture is a foundational dependency for:
- On-media record format evolution (#1220): feature flags gate new record families
- POSIX capability gating: ACL (#1199), extended attributes, and optional POSIX
  behaviors are enabled per-dataset via feature flags
- Pool import safety (#1254): feature incompatibility prevents data corruption
  from older code

## 2. Relationship to Existing Designs

| Design | Integration point | This design provides |
|---|---|---|
| #1220 (on-media format strategy) | Record family gating | Feature flags are the mechanism by which V1 format evolves; new record families require a named feature flag |
| #1254 (pool import/export) | Pool-level feature masks | `PoolLabelV1.features_incompat/ro_compat/compat` are pool-wide bitmasks; this design extends the same concept to per-dataset B-trees |
| #1199 (POSIX ACL) | ACL support gating | `org.tidefs:posix_acl` is a canonical feature flag name; enabling it permits ACL on-disk storage |
| #1250 (three-contract architecture) | Format contract evolution | Feature flags are the mechanism for evolving the on-media format contract without breaking the VFS semantic contract |
| #1238 (format lifecycle meta) | Define→Gate phase | Feature flags implement the "Gate" phase of the unified format lifecycle |

## 3. Three Compatibility Classes

### 3.1 Class definitions

| Class | Meaning for unknown features | Mount behavior |
|---|---|---|
| `compat` | Feature may be safely ignored | RW mount allowed |
| `ro_compat` | Writes without understanding may corrupt | RO mount only |
| `incompat` | Data cannot be interpreted without understanding | Mount refused |

### 3.2 Classification decision tree

When adding a new feature, classify it by asking:

1. Does the feature introduce a new on-disk record layout or change how existing
   records must be interpreted? → `incompat`
2. Does the feature make writes unsafe without understanding, but reads remain
   safe? → `ro_compat`
3. Is the feature purely additive (new metadata that can be silently ignored,
   new cache hint, new performance optimization)? → `compat`

**Examples:**
- New record family with different header layout: `incompat`
- Per-inode checksums that older code doesn't maintain: `ro_compat` (reads fine,
  but older code writes without checksums, breaking newer code's integrity)
- Optional `st_birthtime_ns` field in stat results: `compat`

### 3.3 Class hierarchy

```
compat < ro_compat < incompat
```

A feature classified as `incompat` has a higher barrier than `ro_compat`, which
has a higher barrier than `compat`. An implementation that doesn't know a flag
is always safe for `compat`, conditionally safe for `ro_compat` (read-only), and
never safe for `incompat`.

## 4. Feature Name Registry

### 4.1 Naming convention

Feature names follow the OpenZFS/reverse-DNS convention: `org.tidefs:<name>`.

Rules:
- ASCII lowercase alphanumeric + hyphens + underscores + dots in domain part
- Colon separates domain from feature name
- Feature name: lowercase alphanumeric + underscores
- Maximum 127 bytes (fits in a B-tree key without overflow)

**Canonical names:**

```
org.tidefs:extent_map_tristate    # V1 extent map tristate model (#1225)
org.tidefs:posix_acl              # POSIX ACL xattr codec (#1199)
org.tidefs:polymorphic_xattr      # Polymorphic xattr storage (#1290)
org.tidefs:polymorphic_dir_index  # Polymorphic directory index (#1289)
org.tidefs:compression_lz4        # LZ4 compression
org.tidefs:compression_zstd       # Zstd compression
org.tidefs:encryption_chacha20    # ChaCha20-Poly1305 AEAD encryption
org.tidefs:intent_log_log_device        # Separate intent log device (#1252)
org.tidefs:commit_group_state_machine      # Canonical commit ordering (#1267)
org.tidefs:locator_table          # Extent locator table (#1285)
org.tidefs:checksum_blake3        # BLAKE3-256 per-record checksums
org.tidefs:dedup                  # Block-level deduplication
org.tidefs:reflink                # Cross-dataset reflink
org.tidefs:userobj_accounting     # Project/user/group quota accounting
org.tidefs:device_removal         # Online device removal (#1254 §6.2)
```

### 4.2 Namespace ownership

- `org.tidefs:` — canonical tidefs features (defined in tidefs source)
- `com.example:` — vendor extensions (ignored by tidefs, interpreted by
  third-party plugins)

### 4.3 Feature deprecation

Features are never removed from the registry. If a feature is superseded, the
old name remains as an alias or is marked as `deprecated` in documentation.
This ensures that datasets created with older tidefs versions can still be

## 5. On-Media Representation

### 5.1 Per-dataset B-trees

Each dataset stores three B-trees, one per compatibility class, rooted in the
dataset record's TLV extension area:

```
DatasetFeatureFlagsV1 {
    compat_btree_root: BtreeRootPointer,     // compat features
    ro_compat_btree_root: BtreeRootPointer,  // ro_compat features
    incompat_btree_root: BtreeRootPointer,   // incompat features
}
```

**B-tree key:** feature name as raw bytes (e.g., `org.tidefs:posix_acl`)
**B-tree value:** `FeatureFlagValueV1 { state: u8 }` where state encodes:
- `0x01`: ENABLED (feature is active in this dataset)
- `0x02`: ENABLED_ACTIVE (feature is enabled AND has active on-disk state)
- `0x00`: RESERVED (invalid state for a committed flag; used only for deletion tombstones)

For V1, only the `ENABLED` state is needed. `ENABLED_ACTIVE` (refcount semantics)
is deferred to a future version.

### 5.2 Initial V1 feature set (empty)

A freshly created V1 dataset has empty feature B-trees. Features are added
explicitly via the upgrade command as capabilities are needed. This avoids
pre-enabling features that may never be used.

### 5.3 Pool label integration

The `PoolLabelV1` (#1254) already has three feature bitmasks:

```
features_incompat: u64,    // pool-level incompat flags
features_ro_compat: u64,   // pool-level ro_compat flags
features_compat: u64,      // pool-level compat flags
```

These are pool-wide bitmasks (not per dataset). They are checked on pool import.
Dataset-level feature flags are independent: a pool may support features that
individual datasets haven't enabled, and vice versa (dataset-level features are
checked on dataset open, after pool import).

Pool import checks pool-level flags first; if the pool is mountable, individual
datasets are opened with their own feature checks.

## 6. Mount Algorithm

### 6.1 Deterministic feature check

```
FeatureGate::check_dataset_features(
    engine_supported: &HashSet<FeatureName>,
    dataset_features: &DatasetFeatureFlagsV1,
) -> Result<FeatureGateResult>
```

1. Read the three B-trees from the dataset record.
2. Collect all `incompat` feature names into set `I`.
3. Collect all `ro_compat` feature names into set `R`.
4. For each feature `f` in `I`:
   - If `f` not in `engine_supported`: return `Err(MountRefused { feature: f, class: Incompat })`
5. For each feature `f` in `R`:
   - If `f` not in `engine_supported`: return `Ok(ReadOnlyRequired { feature: f })`
6. Return `Ok(ReadWrite)`

### 6.2 Pool import integration

The pool import path (#1254 §4) already includes `features_incompat` checks at
the pool level. The dataset-level check is performed during `open_dataset()`,
after the pool is imported and the dataset record is loaded.

### 6.3 Upgrade tooling

The live operator path is `tidefsctl dataset set-strategy`:

```
tidefsctl dataset set-strategy <pool> <dataset> --enable <feature>
```

The live command (implemented as of 2026-05-20):
1. Opens the dataset through the canonical pool store.
3. Auto-resolves the feature class from the canonical registry
   (compat/ro_compat/incompat) unless `--class` is explicitly given.
4. Verifies prerequisites via `enable_feature_with_prereqs`.
5. Persists the feature flags to the pool store and refreshes runtime
   policies (compression algorithm, dedup) so the change takes effect
   without remount.

The historical design spec (below) described `tidefsctl dataset upgrade-feature`,
which is the same concept under a different CLI name.

### 6.3.1 Historical design spec (tidefsctl dataset upgrade-feature)

Original design spec — the same semantics, implemented under the
`tidefsctl dataset set-strategy` surface:

The upgrade tool:
1. Opens the dataset read-only.
2. Verifies the feature is known to this tidefs version.
3. Verifies the feature is not already enabled.
4. If the feature is `incompat`: write the feature into the dataset's
   `incompat_btree` within a single commit_group commit. The dataset is now permanently
   at a higher format level.
5. If `ro_compat` or `compat`: similar, but mount behavior is less restrictive.

Upgrade is **one-way**. Once enabled, a feature cannot be disabled. This
simplifies recovery and prevents "zombie" data that references a feature that
was subsequently turned off.

## 7. Feature Lifecycle

### 7.1 Five-stage lifecycle

```
DEFINED → GATED → STAGED → ACTIVE → RETIRED
```

1. **DEFINED.** Feature name is registered in the canonical registry. B-tree
   layout is specified. Classification (compat/ro_compat/incompat) is decided.
   Implementation can begin behind a feature check.
2. **GATED.** Code paths are guarded by feature flag checks. The feature can
   be enabled on test datasets via `tidefsctl dataset upgrade-feature`. Not yet
   recommended for production.
3. **STAGED.** Feature has passed crash safety tests and xfstests gates. Opt-in
   available for production datasets. Feature is documented in release notes.
4. **ACTIVE.** Feature is enabled by default on new datasets. Existing datasets
   can upgrade explicitly. Feature is considered stable.
5. **RETIRED.** Feature has been superseded by a newer mechanism. The old flag
   remains in the registry for dataset compatibility but is not offered for new
   datasets. Datasets with the retired flag still mount correctly.

### 7.2 Current V1 initial state

All V1 features start at DEFINED. The initial V1 format (#1220) ships with an
empty feature set. Features are graduated through the lifecycle as

## 8. TLV Extension Integration

### 8.1 Feature-gated TLV payloads

When a record's TLV extension area carries a payload that requires feature
understanding, the TLV tag must correspond to a feature flag:

```
TLV tag: 0x0100 (feature-gated extension)
TLV length: variable
TLV payload:
    feature_name_len: u16,
    feature_name: [u8; feature_name_len],
    extension_data: [u8; remaining],
```

On decode:
1. Read the feature name from the TLV payload.
2. If the feature is enabled in the dataset: decode the extension data normally.
3. If the feature is NOT enabled: skip the TLV (the extension data is silently
   ignored). The decoder logs a warning for observability.

This ensures that older code (or code without the feature enabled) can still
read records that carry new-format extensions — the extensions are simply
skipped. This is the same skip-unknown-TLV rule that applies to all TLV fields.

## 9. Implementation Plan

### Phase 1: Feature name registry and types (1 issue)
- Define `FeatureFlagValueV1` enum with ENABLED/ENABLED_ACTIVE states.
- Define `DatasetFeatureFlagsV1` struct with three `BtreeRootPointer` fields.
- Canonical feature name constants for initial V1 set.

### Phase 2: Feature gate runtime (1 issue)
- `FeatureGate::check_dataset_features()` implementation.
- `MountRefused` and `ReadOnlyRequired` error types.
- Unit tests: known features pass, unknown incompat fails, unknown ro_compat
  returns read-only.

### Phase 3: Per-dataset feature B-tree storage (1 issue)
- Implement `read_features(dataset) -> DatasetFeatureFlagsV1`.
- Implement `write_feature(dataset, name, class)`.
- Integration with dataset open path: check features before returning RW access.

### Phase 4: Pool import integration (1 issue)
- Wire dataset feature check into pool import path (#1254).
- Pool-level flag checks precede dataset-level checks.
- Test: pool with unknown incompat dataset feature refuses dataset open but
  allows other datasets.

### Phase 5: Upgrade tooling (1 issue)
- `tidefsctl dataset upgrade-feature` command (now live as `tidefsctl dataset set-strategy`).
- One-way upgrade semantics with commit_group commit.
- The live implementation uses `tidefsctl dataset set-strategy --enable` with
  automatic feature-class resolution, prerequisite checking, and pool-store
  persistence through `LocalFileSystem::persist_feature_flags`.
- Test: upgrade dataset, verify feature in B-tree, verify mount still works.

### Phase 6: TLV feature-gating integration (1-2 issues)
- TLV encoder tags feature-gated extensions with feature name.
- TLV decoder skips unknown-feature extensions.
- Test: write dataset with feature A enabled, read back with feature A disabled
  (older code simulation), verify data integrity.

  semantics, TLV skip behavior.
- Integration test: full upgrade cycle with crash injection.


  upgrade enforcement, TLV feature-gating skip behavior.
- Unit tests: mount algorithm returns correct result for each combination of
  known/unknown × compat/ro_compat/incompat.
- Integration test: create dataset, enable feature, mount, verify feature in
  B-tree, unmount, verify older-code simulation handles feature correctly.

## 11. ZFS Comparison

| Aspect | OpenZFS | tidefs (this design) |
|---|---|---|
| Feature scope | Per-pool (zpool) | Per-dataset (datasets within same pool can have different features) |
| Feature naming | `org.openzfs:feature_name` | `org.tidefs:feature_name` (same convention) |
| Compatibility classes | Single pool feature list; `zpool upgrade` enables all pending | Three explicit classes: compat/ro_compat/incompat with deterministic mount decision per class |
| Enablement | `zpool upgrade` enables ALL pending features at once | `tidefsctl dataset upgrade-feature <dataset> <feature>` enables individual features per dataset |
| Disablement | Not supported (one-way) | Not supported (one-way), same constraint |
| On-media storage | Embedded in pool label (nvlist) | Per-dataset B-trees with FeatureFlagValueV1 values |
| Active refcounting | `feature_refcount` tracks in-use features for safe destroy | ENABLED_ACTIVE state deferred to future version |
| Mount check | Pool-level only | Pool-level (via PoolLabelV1 bitmasks) + dataset-level (via B-tree) |
| Upgrade dependency | No dependency tracking | Dependency relationships tracked in feature registry metadata |

## 12. Deferred Items

- **Active refcounting (ENABLED_ACTIVE).** Tracking how many objects depend on a
  feature is deferred until a use case emerges (e.g., dataset destroy with
  active feature-dependent data).
- **Feature dependency tracking.** If feature B requires feature A, the upgrade
  tool should auto-enable A when enabling B. Deferred until cross-feature
  dependencies are defined.
- **Rollback safety.** If a dataset is rolled back to a snapshot taken before a
  feature was enabled, the feature flag must be reverted. Deferred to snapshot
  rollback design.
- **Cross-dataset feature consistency.** If two datasets share data via reflink
  (#1276), features must be compatible across both. Deferred to reflink design.

## 13. Non-claims (explicit boundaries)

- This design does not implement the feature flag B-tree storage engine; it
  specifies the layout and semantics. The B-tree implementation is tracked
  separately.
- The `tidefsctl dataset upgrade-feature` CLI is now implemented as
  `tidefsctl dataset set-strategy`, which covers the specified algorithm
  plus automatic class resolution, prerequisite enforcement, and live policy refresh.
- This design does not define the complete canonical feature name registry;
  names are added as features are designed and implemented.
- Pool-level feature bitmasks in `PoolLabelV1` are specified in #1254; this
  design extends the concept to per-dataset B-trees.
