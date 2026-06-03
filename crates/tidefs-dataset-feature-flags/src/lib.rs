#![forbid(unsafe_code)]

use core::fmt;

use tidefs_btree::BPlusTree;
use tidefs_local_object_store::{DeviceIoClass, ObjectKey, Pool, Result as StoreResult};
use tidefs_types_dataset_feature_flags_core::{
    BtreeRootPointer, DatasetFeatureFlagsV1, FeatureClass, FeatureFlagValueV1, FeatureName,
    CANONICAL_V1_FEATURES,
};
use tidefs_types_dataset_lifecycle_core::DatasetOpenResult;

const FEATURE_FLAGS_PREFIX: &[u8] = b"tidefs:feature_flags:";

fn feature_flags_object_key(class: FeatureClass) -> ObjectKey {
    let suffix: &[u8] = match class {
        FeatureClass::Compat => b"compat:v1",
        FeatureClass::RoCompat => b"ro_compat:v1",
        FeatureClass::Incompat => b"incompat:v1",
    };
    let mut name = Vec::with_capacity(FEATURE_FLAGS_PREFIX.len() + suffix.len());
    name.extend_from_slice(FEATURE_FLAGS_PREFIX);
    name.extend_from_slice(suffix);
    ObjectKey::from_name(&name)
}

fn root_pointer_from_key(key: &ObjectKey) -> BtreeRootPointer {
    let bytes = key.as_bytes();
    let mut val: u64 = 0;
    for &b in bytes.iter().take(8) {
        val = (val << 8) | (b as u64);
    }
    BtreeRootPointer(val)
}

fn serialize_feature_tree(tree: &BPlusTree<FeatureName, FeatureFlagValueV1>) -> Vec<u8> {
    let entries: Vec<(FeatureName, FeatureFlagValueV1)> = tree.entries();
    let mut out = Vec::with_capacity(entries.len() * 32);
    for (name, value) in &entries {
        let name_bytes = name.as_bytes();
        out.push(name_bytes.len() as u8);
        out.extend_from_slice(name_bytes);
        out.push(value.to_u8());
    }
    out
}

fn deserialize_feature_tree(bytes: &[u8]) -> Option<BPlusTree<FeatureName, FeatureFlagValueV1>> {
    let mut tree = BPlusTree::new();
    let mut pos = 0;
    while pos < bytes.len() {
        if pos + 2 > bytes.len() {
            return None;
        }
        let name_len = bytes[pos] as usize;
        pos += 1;
        if name_len == 0 || pos + name_len + 1 > bytes.len() {
            return None;
        }
        let name_bytes = &bytes[pos..pos + name_len];
        pos += name_len;
        let value_byte = bytes[pos];
        pos += 1;
        let name = FeatureName::new(name_bytes)?;
        let value = FeatureFlagValueV1::from_u8(value_byte)?;
        tree.insert(name, value);
    }
    Some(tree)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FeatureFlagsError {
    UnknownFeature {
        name: FeatureName,
    },
    AlreadyEnabled {
        name: FeatureName,
        class: FeatureClass,
    },
    NotEnabled {
        name: FeatureName,
    },
    IncompatibleMount {
        features: Box<Vec<FeatureName>>,
    },
    MissingPrerequisite {
        name: FeatureName,
        prerequisite: FeatureName,
    },
}

impl fmt::Display for FeatureFlagsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FeatureFlagsError::UnknownFeature { name } => write!(f, "unknown feature: {name}"),
            FeatureFlagsError::AlreadyEnabled { name, class } => {
                write!(f, "feature {name} already enabled in class {class}")
            }
            FeatureFlagsError::NotEnabled { name } => write!(f, "feature {name} is not enabled"),
            FeatureFlagsError::IncompatibleMount { features } => write!(
                f,
                "mount refused: {} unknown incompat feature(s)",
                features.len()
            ),
            FeatureFlagsError::MissingPrerequisite { name, prerequisite } => {
                write!(f, "feature {name} requires prerequisite {prerequisite}")
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MountCheckResult {
    ReadWrite,
    ReadOnly { features: Box<Vec<FeatureName>> },
    Refused { features: Box<Vec<FeatureName>> },
}

impl MountCheckResult {
    #[must_use]
    pub const fn to_open_result(&self) -> DatasetOpenResult {
        match self {
            MountCheckResult::ReadWrite | MountCheckResult::ReadOnly { .. } => {
                DatasetOpenResult::ReadWrite
            }
            MountCheckResult::Refused { .. } => DatasetOpenResult::ReadOnly,
        }
    }
    #[must_use]
    pub const fn is_refused(&self) -> bool {
        matches!(self, MountCheckResult::Refused { .. })
    }
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        matches!(self, MountCheckResult::ReadOnly { .. })
    }
}

// ---------------------------------------------------------------------------
// SupportedFeaturesV1 -- the "upgrade table" for the current software version
// ---------------------------------------------------------------------------

/// The set of feature names that the current TideFS software version
/// understands. This is the "upgrade table" passed to
/// [] during mount and import.
///
/// V1 includes all 17 canonical features defined in
/// []. When V2 adds new features, this table
/// must be extended and the version marker bumped.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SupportedFeaturesV1 {
    /// Sorted list of feature names this version supports.
    features: Vec<FeatureName>,
}

impl SupportedFeaturesV1 {
    /// Return the supported feature set for the current (V1) software version.
    ///
    /// This is the canonical upgrade/compatibility table.  The mount path
    /// passes it to [] to decide whether
    /// the dataset's enabled features are compatible with this software.
    #[must_use]
    pub fn current() -> Self {
        let mut features: Vec<FeatureName> = CANONICAL_V1_FEATURES
            .iter()
            .filter_map(|s| FeatureName::from_str(s))
            .collect();
        features.sort();
        features.dedup();
        SupportedFeaturesV1 { features }
    }

    /// Return the supported features as a name slice.
    #[must_use]
    pub fn as_slice(&self) -> &[FeatureName] {
        &self.features
    }

    /// Return  if  is in the supported set.
    #[must_use]
    pub fn contains(&self, name: &FeatureName) -> bool {
        self.features.binary_search(name).is_ok()
    }

    /// Number of supported features.
    #[must_use]
    pub fn len(&self) -> usize {
        self.features.len()
    }

    /// Returns true if the supported set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.features.is_empty()
    }
}

// ---------------------------------------------------------------------------
#[derive(Clone, Debug)]
pub struct FeatureFlags {
    compat_tree: BPlusTree<FeatureName, FeatureFlagValueV1>,
    ro_compat_tree: BPlusTree<FeatureName, FeatureFlagValueV1>,
    incompat_tree: BPlusTree<FeatureName, FeatureFlagValueV1>,
}

impl FeatureFlags {
    #[must_use]
    pub fn new() -> Self {
        FeatureFlags {
            compat_tree: BPlusTree::new(),
            ro_compat_tree: BPlusTree::new(),
            incompat_tree: BPlusTree::new(),
        }
    }

    #[must_use]
    pub fn is_known_feature(name: &FeatureName) -> bool {
        CANONICAL_V1_FEATURES
            .iter()
            .any(|&canon| FeatureName::from_str(canon).is_some_and(|cn| cn == *name))
    }

    #[allow(dead_code)]
    fn tree_for(&self, class: FeatureClass) -> &BPlusTree<FeatureName, FeatureFlagValueV1> {
        match class {
            FeatureClass::Compat => &self.compat_tree,
            FeatureClass::RoCompat => &self.ro_compat_tree,
            FeatureClass::Incompat => &self.incompat_tree,
        }
    }

    fn tree_for_mut(
        &mut self,
        class: FeatureClass,
    ) -> &mut BPlusTree<FeatureName, FeatureFlagValueV1> {
        match class {
            FeatureClass::Compat => &mut self.compat_tree,
            FeatureClass::RoCompat => &mut self.ro_compat_tree,
            FeatureClass::Incompat => &mut self.incompat_tree,
        }
    }

    pub fn persist(&self, store: &mut Pool) -> StoreResult<DatasetFeatureFlagsV1> {
        let compat_key = feature_flags_object_key(FeatureClass::Compat);
        let ro_compat_key = feature_flags_object_key(FeatureClass::RoCompat);
        let incompat_key = feature_flags_object_key(FeatureClass::Incompat);
        let mut roots = DatasetFeatureFlagsV1::default();
        if !self.compat_tree.is_empty() {
            let bytes = serialize_feature_tree(&self.compat_tree);
            store.put(DeviceIoClass::Metadata, compat_key, &bytes)?;
            roots.compat_root = root_pointer_from_key(&compat_key);
        }
        if !self.ro_compat_tree.is_empty() {
            let bytes = serialize_feature_tree(&self.ro_compat_tree);
            store.put(DeviceIoClass::Metadata, ro_compat_key, &bytes)?;
            roots.ro_compat_root = root_pointer_from_key(&ro_compat_key);
        }
        if !self.incompat_tree.is_empty() {
            let bytes = serialize_feature_tree(&self.incompat_tree);
            store.put(DeviceIoClass::Metadata, incompat_key, &bytes)?;
            roots.incompat_root = root_pointer_from_key(&incompat_key);
        }
        Ok(roots)
    }

    pub fn load(store: &Pool, roots: &DatasetFeatureFlagsV1) -> StoreResult<FeatureFlags> {
        let mut ff = FeatureFlags::new();
        if !roots.compat_root.is_empty() {
            let key = feature_flags_object_key(FeatureClass::Compat);
            if let Some(bytes) = store.get(DeviceIoClass::Metadata, key)? {
                if let Some(tree) = deserialize_feature_tree(&bytes) {
                    ff.compat_tree = tree;
                }
            }
        }
        if !roots.ro_compat_root.is_empty() {
            let key = feature_flags_object_key(FeatureClass::RoCompat);
            if let Some(bytes) = store.get(DeviceIoClass::Metadata, key)? {
                if let Some(tree) = deserialize_feature_tree(&bytes) {
                    ff.ro_compat_tree = tree;
                }
            }
        }
        if !roots.incompat_root.is_empty() {
            let key = feature_flags_object_key(FeatureClass::Incompat);
            if let Some(bytes) = store.get(DeviceIoClass::Metadata, key)? {
                if let Some(tree) = deserialize_feature_tree(&bytes) {
                    ff.incompat_tree = tree;
                }
            }
        }
        Ok(ff)
    }

    #[must_use]
    pub fn check_mount(&self) -> MountCheckResult {
        let mut unknown_incompat: Vec<FeatureName> = Vec::new();
        let mut unknown_ro_compat: Vec<FeatureName> = Vec::new();
        for (name, _value) in self.incompat_tree.entries() {
            if !Self::is_known_feature(&name) {
                unknown_incompat.push(name);
            }
        }
        if !unknown_incompat.is_empty() {
            return MountCheckResult::Refused {
                features: Box::new(unknown_incompat),
            };
        }
        for (name, _value) in self.ro_compat_tree.entries() {
            if !Self::is_known_feature(&name) {
                unknown_ro_compat.push(name);
            }
        }
        if !unknown_ro_compat.is_empty() {
            return MountCheckResult::ReadOnly {
                features: Box::new(unknown_ro_compat),
            };
        }
        MountCheckResult::ReadWrite
    }

    #[allow(clippy::result_large_err)]
    pub fn check_mount_open_result(&self) -> Result<DatasetOpenResult, FeatureFlagsError> {
        match self.check_mount() {
            MountCheckResult::ReadWrite | MountCheckResult::ReadOnly { .. } => {
                Ok(DatasetOpenResult::ReadWrite)
            }
            MountCheckResult::Refused { features } => {
                Err(FeatureFlagsError::IncompatibleMount { features })
            }
        }
    }

    /// Check mount compatibility against a caller-supplied set of supported
    /// feature names (the "upgrade gate").
    ///
    /// This is the general form of `check_mount`: instead of checking against
    /// the hardcoded canonical registry, it checks against the provided
    /// `supported` slice. Returns `ReadWrite` if all enabled features are in
    /// the supported set; `ReadOnly` if any unknown `ro_compat` features exist;
    /// and `Refused` if any unknown `incompat` features exist.
    #[must_use]
    pub fn check_upgrade_gate(&self, supported: &[FeatureName]) -> MountCheckResult {
        let mut unknown_incompat: Vec<FeatureName> = Vec::new();
        let mut unknown_ro_compat: Vec<FeatureName> = Vec::new();
        for (name, _value) in self.incompat_tree.entries() {
            if !supported.contains(&name) {
                unknown_incompat.push(name);
            }
        }
        if !unknown_incompat.is_empty() {
            return MountCheckResult::Refused {
                features: Box::new(unknown_incompat),
            };
        }
        for (name, _value) in self.ro_compat_tree.entries() {
            if !supported.contains(&name) {
                unknown_ro_compat.push(name);
            }
        }
        if !unknown_ro_compat.is_empty() {
            return MountCheckResult::ReadOnly {
                features: Box::new(unknown_ro_compat),
            };
        }
        MountCheckResult::ReadWrite
    }

    /// Check the upgrade gate and convert to a `DatasetOpenResult`.
    ///
    /// Returns `Ok(ReadWrite)` if all enabled features are supported, or
    /// `Err(IncompatibleMount)` if unknown `incompat` features exist.
    #[allow(clippy::result_large_err)]
    pub fn check_upgrade_gate_open_result(
        &self,
        supported: &[FeatureName],
    ) -> Result<DatasetOpenResult, FeatureFlagsError> {
        match self.check_upgrade_gate(supported) {
            MountCheckResult::ReadWrite | MountCheckResult::ReadOnly { .. } => {
                Ok(DatasetOpenResult::ReadWrite)
            }
            MountCheckResult::Refused { features } => {
                Err(FeatureFlagsError::IncompatibleMount { features })
            }
        }
    }

    #[allow(clippy::result_large_err)]
    pub fn enable_feature(
        &mut self,
        name: FeatureName,
        class: FeatureClass,
    ) -> Result<(), FeatureFlagsError> {
        if !Self::is_known_feature(&name) {
            return Err(FeatureFlagsError::UnknownFeature { name });
        }
        if self.compat_tree.contains_key(&name)
            || self.ro_compat_tree.contains_key(&name)
            || self.incompat_tree.contains_key(&name)
        {
            return Err(FeatureFlagsError::AlreadyEnabled { name, class });
        }
        self.tree_for_mut(class)
            .insert(name, FeatureFlagValueV1::Enabled);
        Ok(())
    }

    /// Enable a feature after verifying that all prerequisites are already
    /// enabled.
    ///
    /// Returns `Err(MissingPrerequisite)` if any prerequisite is not yet
    /// enabled. Use `enable_feature` for the simpler case where
    /// prerequisites are not checked.
    #[allow(clippy::result_large_err)]
    pub fn enable_feature_with_prereqs(
        &mut self,
        name: FeatureName,
        class: FeatureClass,
    ) -> Result<(), FeatureFlagsError> {
        use tidefs_types_dataset_feature_flags_core::get_feature_prerequisites;

        // Check prerequisites first
        if let Some(prereqs) = get_feature_prerequisites(&name) {
            for prereq_str in prereqs {
                if let Some(prereq_name) = FeatureName::from_str(prereq_str) {
                    if !self.is_enabled(&prereq_name) {
                        return Err(FeatureFlagsError::MissingPrerequisite {
                            name,
                            prerequisite: prereq_name,
                        });
                    }
                }
            }
        }
        self.enable_feature(name, class)
    }

    #[allow(clippy::result_large_err)]
    pub fn disable_feature(&mut self, name: &FeatureName) -> Result<(), FeatureFlagsError> {
        let removed = self
            .compat_tree
            .delete(name)
            .or_else(|| self.ro_compat_tree.delete(name))
            .or_else(|| self.incompat_tree.delete(name));
        if removed.is_some() {
            Ok(())
        } else {
            Err(FeatureFlagsError::NotEnabled { name: name.clone() })
        }
    }
    /// Insert a feature directly into the B-tree for `class`, bypassing the
    /// `is_known_feature` check.  This is a test-only escape hatch for
    /// integration tests that must exercise the mount/upgrade gate with
    /// unknown features that would normally be rejected by `enable_feature`.
    ///
    /// **Test infrastructure only.**  Production code must use
    /// [`enable_feature`] which validates against the canonical feature
    /// registry.
    pub fn insert_unchecked_for_test(
        &mut self,
        name: FeatureName,
        class: FeatureClass,
        value: FeatureFlagValueV1,
    ) {
        self.tree_for_mut(class).insert(name, value);
    }

    #[must_use]
    pub fn is_enabled(&self, name: &FeatureName) -> bool {
        self.compat_tree.contains_key(name)
            || self.ro_compat_tree.contains_key(name)
            || self.incompat_tree.contains_key(name)
    }

    #[must_use]
    pub fn class_of(&self, name: &FeatureName) -> Option<FeatureClass> {
        if self.compat_tree.contains_key(name) {
            Some(FeatureClass::Compat)
        } else if self.ro_compat_tree.contains_key(name) {
            Some(FeatureClass::RoCompat)
        } else if self.incompat_tree.contains_key(name) {
            Some(FeatureClass::Incompat)
        } else {
            None
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.compat_tree.len() + self.ro_compat_tree.len() + self.incompat_tree.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub fn all_features(&self) -> Vec<(FeatureClass, FeatureName, FeatureFlagValueV1)> {
        let mut out = Vec::new();
        for (name, value) in self.compat_tree.entries() {
            out.push((FeatureClass::Compat, name, value));
        }
        for (name, value) in self.ro_compat_tree.entries() {
            out.push((FeatureClass::RoCompat, name, value));
        }
        for (name, value) in self.incompat_tree.entries() {
            out.push((FeatureClass::Incompat, name, value));
        }
        out
    }

    #[must_use]
    pub fn to_dataset_flags(&self) -> DatasetFeatureFlagsV1 {
        DatasetFeatureFlagsV1 {
            compat_root: BtreeRootPointer(if self.compat_tree.is_empty() { 0 } else { 1 }),
            ro_compat_root: BtreeRootPointer(if self.ro_compat_tree.is_empty() { 0 } else { 1 }),
            incompat_root: BtreeRootPointer(if self.incompat_tree.is_empty() { 0 } else { 1 }),
        }
    }

    /// Return the supported feature set for the current software version.
    ///
    /// Convenience wrapper around [`SupportedFeaturesV1::current`] so
    /// callers can access the upgrade/compatibility table without
    /// importing [`SupportedFeaturesV1`] directly.
    #[must_use]
    pub fn supported_features() -> SupportedFeaturesV1 {
        SupportedFeaturesV1::current()
    }

    /// Union of two feature-flag sets.
    ///
    /// Returns a new `FeatureFlags` containing every feature enabled in
    /// either `self` or `other`. When the same feature appears in both
    /// operands, the value from `other` takes precedence.
    #[must_use]
    pub fn union(self, other: FeatureFlags) -> FeatureFlags {
        let mut result = FeatureFlags::new();
        for (class, name, value) in self.all_features() {
            result.tree_for_mut(class).insert(name, value);
        }
        for (class, name, value) in other.all_features() {
            // Remove from any existing class so the feature appears only once.
            result.compat_tree.delete(&name);
            result.ro_compat_tree.delete(&name);
            result.incompat_tree.delete(&name);
            result.tree_for_mut(class).insert(name, value);
        }
        result
    }

    /// Intersection of two feature-flag sets.
    ///
    /// Returns a new `FeatureFlags` containing only the features that are
    /// enabled in both `self` and `other`. The class and value are taken
    /// from `self`.
    #[must_use]
    pub fn intersect(self, other: FeatureFlags) -> FeatureFlags {
        let mut result = FeatureFlags::new();
        for (class, name, value) in self.all_features() {
            if other.is_enabled(&name) {
                result.tree_for_mut(class).insert(name, value);
            }
        }
        result
    }

    /// Set difference: features in `self` but not in `other`.
    ///
    /// Returns a new `FeatureFlags` containing every feature enabled in
    /// `self` that is *not* enabled in `other`.
    #[must_use]
    pub fn diff(self, other: FeatureFlags) -> FeatureFlags {
        let mut result = FeatureFlags::new();
        for (class, name, value) in self.all_features() {
            if !other.is_enabled(&name) {
                result.tree_for_mut(class).insert(name, value);
            }
        }
        result
    }
}

impl Default for FeatureFlags {
    fn default() -> Self {
        FeatureFlags::new()
    }
}

impl fmt::Display for FeatureFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FeatureFlags(compat={} ro_compat={} incompat={})",
            self.compat_tree.len(),
            self.ro_compat_tree.len(),
            self.incompat_tree.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_types_dataset_feature_flags_core::{
        FEATURE_CHECKSUM_BLAKE3, FEATURE_COMMIT_GROUP_STATE_MACHINE, FEATURE_COMPRESSION_LZ4,
        FEATURE_COMPRESSION_ZSTD, FEATURE_ENCRYPTION_CHACHA20, FEATURE_POSIX_ACL,
        FEATURE_SEND_RECV_V2, FEATURE_SNAPSHOT_V2,
    };

    fn feature(s: &str) -> FeatureName {
        FeatureName::from_str(s).expect("valid feature name")
    }

    #[test]
    fn serialize_deserialize_empty_tree() {
        let tree: BPlusTree<FeatureName, FeatureFlagValueV1> = BPlusTree::new();
        let bytes = serialize_feature_tree(&tree);
        let restored = deserialize_feature_tree(&bytes);
        assert!(restored.is_some());
        assert!(restored.unwrap().is_empty());
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let mut tree: BPlusTree<FeatureName, FeatureFlagValueV1> = BPlusTree::new();
        let a = feature(FEATURE_POSIX_ACL);
        let b = feature(FEATURE_COMPRESSION_ZSTD);
        tree.insert(a.clone(), FeatureFlagValueV1::Enabled);
        tree.insert(b.clone(), FeatureFlagValueV1::Enabled);
        let bytes = serialize_feature_tree(&tree);
        let restored = deserialize_feature_tree(&bytes).expect("deserialize should succeed");
        assert_eq!(restored.len(), 2);
        assert!(restored.contains_key(&a));
        assert!(restored.contains_key(&b));
    }

    #[test]
    fn deserialize_corrupt_truncated() {
        let bytes = vec![5u8];
        assert!(deserialize_feature_tree(&bytes).is_none());
    }

    #[test]
    fn deserialize_corrupt_zero_length_name() {
        let bytes = vec![0u8, 1u8];
        assert!(deserialize_feature_tree(&bytes).is_none());
    }

    #[test]
    fn deserialize_corrupt_bad_value_byte() {
        let name = feature(FEATURE_POSIX_ACL);
        let name_bytes = name.as_bytes();
        let mut bytes = Vec::new();
        bytes.push(name_bytes.len() as u8);
        bytes.extend_from_slice(name_bytes);
        bytes.push(0xFF);
        assert!(deserialize_feature_tree(&bytes).is_none());
    }

    #[test]
    fn new_is_empty() {
        let ff = FeatureFlags::new();
        assert!(ff.is_empty());
        assert_eq!(ff.len(), 0);
    }

    #[test]
    fn default_is_empty() {
        let ff = FeatureFlags::default();
        assert!(ff.is_empty());
    }

    #[test]
    fn known_features_are_recognized() {
        assert!(FeatureFlags::is_known_feature(&feature(
            "org.tidefs:posix_acl"
        )));
        assert!(FeatureFlags::is_known_feature(&feature(
            "org.tidefs:compression_zstd"
        )));
        assert!(FeatureFlags::is_known_feature(&feature(
            "org.tidefs:encryption_chacha20"
        )));
    }

    #[test]
    fn unknown_features_are_rejected() {
        assert!(!FeatureFlags::is_known_feature(&feature(
            "com.example:my_feature"
        )));
        assert!(!FeatureFlags::is_known_feature(&feature(
            "org.tidefs:nonexistent"
        )));
    }

    #[test]
    fn enable_known_feature() {
        let mut ff = FeatureFlags::new();
        let name = feature(FEATURE_POSIX_ACL);
        ff.enable_feature(name.clone(), FeatureClass::Incompat)
            .unwrap();
        assert!(ff.is_enabled(&name));
        assert_eq!(ff.class_of(&name), Some(FeatureClass::Incompat));
        assert_eq!(ff.len(), 1);
    }

    #[test]
    fn enable_unknown_feature_fails() {
        let mut ff = FeatureFlags::new();
        let name = feature("com.example:custom");
        let err = ff
            .enable_feature(name.clone(), FeatureClass::Compat)
            .unwrap_err();
        assert!(matches!(err, FeatureFlagsError::UnknownFeature { .. }));
    }

    #[test]
    fn enable_duplicate_fails() {
        let mut ff = FeatureFlags::new();
        let name = feature(FEATURE_COMPRESSION_ZSTD);
        ff.enable_feature(name.clone(), FeatureClass::Compat)
            .unwrap();
        let err = ff
            .enable_feature(name.clone(), FeatureClass::RoCompat)
            .unwrap_err();
        assert!(matches!(err, FeatureFlagsError::AlreadyEnabled { .. }));
    }

    #[test]
    fn disable_enabled_feature() {
        let mut ff = FeatureFlags::new();
        let name = feature(FEATURE_ENCRYPTION_CHACHA20);
        ff.enable_feature(name.clone(), FeatureClass::Incompat)
            .unwrap();
        ff.disable_feature(&name).unwrap();
        assert!(!ff.is_enabled(&name));
        assert!(ff.is_empty());
    }

    #[test]
    fn disable_not_enabled_fails() {
        let mut ff = FeatureFlags::new();
        let name = feature(FEATURE_POSIX_ACL);
        let err = ff.disable_feature(&name).unwrap_err();
        assert!(matches!(err, FeatureFlagsError::NotEnabled { .. }));
    }

    #[test]
    fn class_of_returns_correct_class() {
        let mut ff = FeatureFlags::new();
        let a = feature(FEATURE_POSIX_ACL);
        let b = feature(FEATURE_COMPRESSION_ZSTD);
        let c = feature(FEATURE_ENCRYPTION_CHACHA20);
        ff.enable_feature(a.clone(), FeatureClass::Compat).unwrap();
        ff.enable_feature(b.clone(), FeatureClass::RoCompat)
            .unwrap();
        ff.enable_feature(c.clone(), FeatureClass::Incompat)
            .unwrap();
        assert_eq!(ff.class_of(&a), Some(FeatureClass::Compat));
        assert_eq!(ff.class_of(&b), Some(FeatureClass::RoCompat));
        assert_eq!(ff.class_of(&c), Some(FeatureClass::Incompat));
        assert_eq!(ff.class_of(&feature("org.tidefs:polymorphic_xattr")), None);
    }

    #[test]
    fn check_mount_empty_is_read_write() {
        let ff = FeatureFlags::new();
        assert_eq!(ff.check_mount(), MountCheckResult::ReadWrite);
    }

    #[test]
    fn check_mount_all_known_features_pass() {
        let mut ff = FeatureFlags::new();
        ff.enable_feature(feature(FEATURE_POSIX_ACL), FeatureClass::Compat)
            .unwrap();
        ff.enable_feature(feature(FEATURE_COMPRESSION_ZSTD), FeatureClass::RoCompat)
            .unwrap();
        ff.enable_feature(feature(FEATURE_ENCRYPTION_CHACHA20), FeatureClass::Incompat)
            .unwrap();
        assert_eq!(ff.check_mount(), MountCheckResult::ReadWrite);
    }

    #[test]
    fn check_mount_unknown_incompat_refuses() {
        let mut ff = FeatureFlags::new();
        let unknown = feature("com.example:future_feature");
        ff.incompat_tree
            .insert(unknown.clone(), FeatureFlagValueV1::Enabled);
        let result = ff.check_mount();
        assert!(result.is_refused());
        match result {
            MountCheckResult::Refused { features } => {
                assert_eq!(features.len(), 1);
                assert_eq!(features[0], unknown);
            }
            _ => panic!("expected Refused"),
        }
    }

    #[test]
    fn check_mount_unknown_ro_compat_forces_read_only() {
        let mut ff = FeatureFlags::new();
        let unknown = feature("com.example:ro_feature");
        ff.ro_compat_tree
            .insert(unknown.clone(), FeatureFlagValueV1::Enabled);
        let result = ff.check_mount();
        assert!(result.is_read_only());
        match result {
            MountCheckResult::ReadOnly { features } => {
                assert_eq!(features.len(), 1);
                assert_eq!(features[0], unknown);
            }
            _ => panic!("expected ReadOnly"),
        }
    }

    #[test]
    fn check_mount_unknown_compat_is_silently_ignored() {
        let mut ff = FeatureFlags::new();
        let unknown = feature("com.example:compat_feature");
        ff.compat_tree.insert(unknown, FeatureFlagValueV1::Enabled);
        assert_eq!(ff.check_mount(), MountCheckResult::ReadWrite);
    }

    #[test]
    fn check_mount_incompat_takes_priority_over_ro_compat() {
        let mut ff = FeatureFlags::new();
        let bad = feature("com.example:bad");
        let ro = feature("com.example:readonly");
        ff.incompat_tree
            .insert(bad.clone(), FeatureFlagValueV1::Enabled);
        ff.ro_compat_tree.insert(ro, FeatureFlagValueV1::Enabled);
        let result = ff.check_mount();
        assert!(result.is_refused());
        match result {
            MountCheckResult::Refused { features } => {
                assert_eq!(features.len(), 1);
                assert_eq!(features[0], bad);
            }
            _ => panic!("incompat should take priority"),
        }
    }

    #[test]
    fn check_mount_open_result_read_write() {
        let ff = FeatureFlags::new();
        assert_eq!(
            ff.check_mount_open_result().unwrap(),
            DatasetOpenResult::ReadWrite
        );
    }

    #[test]
    fn check_mount_open_result_refused() {
        let mut ff = FeatureFlags::new();
        let unknown = feature("com.example:future");
        ff.incompat_tree
            .insert(unknown, FeatureFlagValueV1::Enabled);
        let err = ff.check_mount_open_result().unwrap_err();
        assert!(matches!(err, FeatureFlagsError::IncompatibleMount { .. }));
    }

    #[test]
    fn to_dataset_flags_empty() {
        let ff = FeatureFlags::new();
        let flags = ff.to_dataset_flags();
        assert!(flags.is_empty());
    }

    #[test]
    fn to_dataset_flags_non_empty() {
        let mut ff = FeatureFlags::new();
        ff.enable_feature(feature(FEATURE_POSIX_ACL), FeatureClass::Compat)
            .unwrap();
        let flags = ff.to_dataset_flags();
        assert!(!flags.compat_root.is_empty());
        assert!(flags.ro_compat_root.is_empty());
        assert!(flags.incompat_root.is_empty());
    }

    #[test]
    fn all_features_returns_all_classes() {
        let mut ff = FeatureFlags::new();
        let a = feature(FEATURE_POSIX_ACL);
        let b = feature(FEATURE_COMPRESSION_ZSTD);
        let c = feature(FEATURE_ENCRYPTION_CHACHA20);
        ff.enable_feature(a.clone(), FeatureClass::Compat).unwrap();
        ff.enable_feature(b.clone(), FeatureClass::RoCompat)
            .unwrap();
        ff.enable_feature(c.clone(), FeatureClass::Incompat)
            .unwrap();
        let all = ff.all_features();
        assert_eq!(all.len(), 3);
        assert!(all.contains(&(FeatureClass::Compat, a.clone(), FeatureFlagValueV1::Enabled)));
        assert!(all.contains(&(
            FeatureClass::RoCompat,
            b.clone(),
            FeatureFlagValueV1::Enabled
        )));
        assert!(all.contains(&(
            FeatureClass::Incompat,
            c.clone(),
            FeatureFlagValueV1::Enabled
        )));
    }

    #[test]
    fn display_format() {
        let mut ff = FeatureFlags::new();
        let s = ff.to_string();
        assert!(s.contains("compat=0"));
        assert!(s.contains("ro_compat=0"));
        assert!(s.contains("incompat=0"));
        ff.enable_feature(feature(FEATURE_POSIX_ACL), FeatureClass::Compat)
            .unwrap();
        let s = ff.to_string();
        assert!(s.contains("compat=1"));
    }
    // -- check_upgrade_gate -------------------------------------------------

    #[test]
    fn check_upgrade_gate_empty() {
        let ff = FeatureFlags::new();
        let supported: Vec<FeatureName> = Vec::new();
        assert_eq!(
            ff.check_upgrade_gate(&supported),
            MountCheckResult::ReadWrite
        );
    }

    #[test]
    fn check_upgrade_gate_all_supported() {
        let mut ff = FeatureFlags::new();
        let a = feature(FEATURE_ENCRYPTION_CHACHA20);
        let b = feature(FEATURE_CHECKSUM_BLAKE3);
        ff.enable_feature(a.clone(), FeatureClass::Incompat)
            .unwrap();
        ff.enable_feature(b.clone(), FeatureClass::Compat).unwrap();
        let supported = vec![a.clone(), b.clone()];
        assert_eq!(
            ff.check_upgrade_gate(&supported),
            MountCheckResult::ReadWrite
        );
    }

    #[test]
    fn check_upgrade_gate_unknown_incompat_refused() {
        let mut ff = FeatureFlags::new();
        let feat = feature(FEATURE_ENCRYPTION_CHACHA20);
        ff.incompat_tree
            .insert(feat.clone(), FeatureFlagValueV1::Enabled);
        let supported: Vec<FeatureName> = Vec::new(); // empty supported set
        let result = ff.check_upgrade_gate(&supported);
        assert!(result.is_refused());
    }

    #[test]
    fn check_upgrade_gate_unknown_ro_compat_read_only() {
        let mut ff = FeatureFlags::new();
        let feat = feature(FEATURE_COMPRESSION_ZSTD);
        ff.ro_compat_tree
            .insert(feat.clone(), FeatureFlagValueV1::Enabled);
        let supported: Vec<FeatureName> = Vec::new(); // empty
        let result = ff.check_upgrade_gate(&supported);
        assert!(result.is_read_only());
    }

    #[test]
    fn check_upgrade_gate_partial_support() {
        let mut ff = FeatureFlags::new();
        let supported = feature(FEATURE_POSIX_ACL);
        let unsupported = feature(FEATURE_ENCRYPTION_CHACHA20);
        ff.enable_feature(supported.clone(), FeatureClass::Compat)
            .unwrap();
        ff.enable_feature(unsupported.clone(), FeatureClass::Incompat)
            .unwrap();
        // Only support posix_acl, not encryption_chacha20
        let result = ff.check_upgrade_gate(&[supported.clone()]);
        assert!(result.is_refused());
    }

    #[test]
    fn check_upgrade_gate_open_result_ok() {
        let ff = FeatureFlags::new();
        assert_eq!(
            ff.check_upgrade_gate_open_result(&[]).unwrap(),
            DatasetOpenResult::ReadWrite
        );
    }

    #[test]
    fn check_upgrade_gate_open_result_refused() {
        let mut ff = FeatureFlags::new();
        let feat = feature(FEATURE_ENCRYPTION_CHACHA20);
        ff.incompat_tree.insert(feat, FeatureFlagValueV1::Enabled);
        let err = ff.check_upgrade_gate_open_result(&[]).unwrap_err();
        assert!(matches!(err, FeatureFlagsError::IncompatibleMount { .. }));
    }

    // -- enable_feature_with_prereqs ----------------------------------------

    #[test]
    fn enable_with_prereqs_satisfied() {
        let mut ff = FeatureFlags::new();
        // encryption requires checksum_blake3
        let checksum = feature(FEATURE_CHECKSUM_BLAKE3);
        let encryption = feature(FEATURE_ENCRYPTION_CHACHA20);
        ff.enable_feature(checksum.clone(), FeatureClass::Compat)
            .unwrap();
        ff.enable_feature_with_prereqs(encryption.clone(), FeatureClass::Incompat)
            .unwrap();
        assert!(ff.is_enabled(&encryption));
    }

    #[test]
    fn enable_with_prereqs_missing() {
        let mut ff = FeatureFlags::new();
        let encryption = feature(FEATURE_ENCRYPTION_CHACHA20);
        // encryption needs checksum_blake3 but it's not enabled
        let err = ff
            .enable_feature_with_prereqs(encryption.clone(), FeatureClass::Incompat)
            .unwrap_err();
        match err {
            FeatureFlagsError::MissingPrerequisite { name, prerequisite } => {
                assert_eq!(name, encryption);
                assert_eq!(prerequisite.as_str(), "org.tidefs:checksum_blake3");
            }
            _ => panic!("expected MissingPrerequisite"),
        }
    }

    #[test]
    fn enable_with_prereqs_no_prereqs() {
        let mut ff = FeatureFlags::new();
        // posix_acl has no prerequisites
        let acl = feature(FEATURE_POSIX_ACL);
        ff.enable_feature_with_prereqs(acl.clone(), FeatureClass::Compat)
            .unwrap();
        assert!(ff.is_enabled(&acl));
    }

    #[test]
    fn enable_with_prereqs_transitive_chain() {
        let mut ff = FeatureFlags::new();
        // send_recv_v2 requires snapshot_v2 (which requires commit_group_state_machine) + checksum_blake3
        let commit_group = feature(FEATURE_COMMIT_GROUP_STATE_MACHINE);
        let snap = feature(FEATURE_SNAPSHOT_V2);
        let csum = feature(FEATURE_CHECKSUM_BLAKE3);
        let send = feature(FEATURE_SEND_RECV_V2);
        ff.enable_feature(commit_group.clone(), FeatureClass::Compat)
            .unwrap();
        ff.enable_feature_with_prereqs(snap.clone(), FeatureClass::Compat)
            .unwrap();
        ff.enable_feature(csum.clone(), FeatureClass::Compat)
            .unwrap();
        ff.enable_feature_with_prereqs(send.clone(), FeatureClass::Incompat)
            .unwrap();
        assert!(ff.is_enabled(&send));
    }

    #[test]
    fn enable_with_prereqs_snap_without_commit_group_fails() {
        let mut ff = FeatureFlags::new();
        let snap = feature(FEATURE_SNAPSHOT_V2);
        // snapshot_v2 requires commit_group_state_machine which is not enabled
        let err = ff
            .enable_feature_with_prereqs(snap.clone(), FeatureClass::Compat)
            .unwrap_err();
        assert!(matches!(err, FeatureFlagsError::MissingPrerequisite { .. }));
    }

    // -- MissingPrerequisite Display ----------------------------------------

    #[test]
    fn missing_prerequisite_display() {
        let err = FeatureFlagsError::MissingPrerequisite {
            name: feature(FEATURE_ENCRYPTION_CHACHA20),
            prerequisite: feature(FEATURE_CHECKSUM_BLAKE3),
        };
        let s = err.to_string();
        assert!(s.contains("org.tidefs:encryption_chacha20"));
        assert!(s.contains("org.tidefs:checksum_blake3"));
    }

    // -- Edge cases: all flags, max size, error Display, MountCheckResult ----

    #[test]
    fn all_sixteen_canonical_features_enabled() {
        use tidefs_types_dataset_feature_flags_core::CANONICAL_V1_FEATURES;
        let mut ff = FeatureFlags::new();
        for (i, name_str) in CANONICAL_V1_FEATURES.iter().enumerate() {
            let name = feature(name_str);
            // Scatter across the three classes
            let class = match i % 3 {
                0 => FeatureClass::Compat,
                1 => FeatureClass::RoCompat,
                _ => FeatureClass::Incompat,
            };
            ff.enable_feature(name.clone(), class).unwrap();
            assert!(ff.is_enabled(&name));
            assert_eq!(ff.class_of(&name), Some(class));
        }
        assert_eq!(ff.len(), 17);
        let all = ff.all_features();
        assert_eq!(all.len(), 17);
        // All canonical features known -> mount should succeed
        assert_eq!(ff.check_mount(), MountCheckResult::ReadWrite);
    }

    #[test]
    fn maximum_width_feature_names() {
        // Feature names at the 127-byte boundary round-trip through
        // serialization.
        let mut tree: BPlusTree<FeatureName, FeatureFlagValueV1> = BPlusTree::new();
        let long_domain = "a".repeat(118);
        let name_str = format!("{long_domain}:abcdefgh");
        assert_eq!(name_str.len(), 127);
        let name = feature(&name_str);
        tree.insert(name.clone(), FeatureFlagValueV1::EnabledActive);
        let bytes = serialize_feature_tree(&tree);
        let restored = deserialize_feature_tree(&bytes).expect("max-width name should round-trip");
        assert_eq!(restored.len(), 1);
        assert!(restored.contains_key(&name));
        assert_eq!(restored.entries()[0].1, FeatureFlagValueV1::EnabledActive);
    }

    #[test]
    fn feature_flags_error_display_all_variants() {
        let unknown = feature("com.example:unknown");
        let err = FeatureFlagsError::UnknownFeature {
            name: unknown.clone(),
        };
        assert!(err.to_string().contains("unknown feature"));
        assert!(err.to_string().contains("com.example:unknown"));

        let err = FeatureFlagsError::AlreadyEnabled {
            name: unknown.clone(),
            class: FeatureClass::Compat,
        };
        assert!(err.to_string().contains("already enabled"));
        assert!(err.to_string().contains("compat"));

        let err = FeatureFlagsError::NotEnabled {
            name: unknown.clone(),
        };
        assert!(err.to_string().contains("not enabled"));

        let err = FeatureFlagsError::IncompatibleMount {
            features: Box::new(vec![unknown.clone()]),
        };
        assert!(err.to_string().contains("mount refused"));

        let prereq = feature("org.tidefs:checksum_blake3");
        let err = FeatureFlagsError::MissingPrerequisite {
            name: unknown,
            prerequisite: prereq,
        };
        assert!(err.to_string().contains("requires prerequisite"));
    }

    #[test]
    fn mount_check_result_methods() {
        let rw = MountCheckResult::ReadWrite;
        assert_eq!(rw.to_open_result(), DatasetOpenResult::ReadWrite);
        assert!(!rw.is_refused());
        assert!(!rw.is_read_only());

        let ro = MountCheckResult::ReadOnly {
            features: Box::new(vec![]),
        };
        assert_eq!(ro.to_open_result(), DatasetOpenResult::ReadWrite);
        assert!(!ro.is_refused());
        assert!(ro.is_read_only());

        let refused = MountCheckResult::Refused {
            features: Box::new(vec![]),
        };
        assert_eq!(refused.to_open_result(), DatasetOpenResult::ReadOnly);
        assert!(refused.is_refused());
        assert!(!refused.is_read_only());
    }

    #[test]
    fn deserialize_trailing_bytes_rejected() {
        // Valid serialized data followed by garbage: the trailing bytes
        // should cause deserialization failure.
        let mut tree: BPlusTree<FeatureName, FeatureFlagValueV1> = BPlusTree::new();
        tree.insert(feature(FEATURE_POSIX_ACL), FeatureFlagValueV1::Enabled);
        let mut bytes = serialize_feature_tree(&tree);
        // Append a partial entry: name_len byte with no following data
        bytes.push(3u8);
        bytes.push(b'x');
        // Missing the third byte — this partial entry makes deserialization
        // fail.
        assert!(deserialize_feature_tree(&bytes).is_none());
    }

    #[test]
    fn deserialize_empty_bytes_roundtrips() {
        let tree: BPlusTree<FeatureName, FeatureFlagValueV1> = BPlusTree::new();
        let bytes = serialize_feature_tree(&tree);
        assert!(bytes.is_empty());
        let restored =
            deserialize_feature_tree(&bytes).expect("empty bytes should deserialize to empty tree");
        assert!(restored.is_empty());
    }

    #[test]
    fn disable_then_reenable_same_feature() {
        let mut ff = FeatureFlags::new();
        let name = feature(FEATURE_POSIX_ACL);
        ff.enable_feature(name.clone(), FeatureClass::Compat)
            .unwrap();
        assert!(ff.is_enabled(&name));
        ff.disable_feature(&name).unwrap();
        assert!(!ff.is_enabled(&name));
        // Re-enable in a different class
        ff.enable_feature(name.clone(), FeatureClass::Incompat)
            .unwrap();
        assert!(ff.is_enabled(&name));
        assert_eq!(ff.class_of(&name), Some(FeatureClass::Incompat));
    }

    #[test]
    fn check_upgrade_gate_unknown_compat_ignored() {
        let mut ff = FeatureFlags::new();
        let unknown = feature("com.example:compat_feature");
        ff.compat_tree.insert(unknown, FeatureFlagValueV1::Enabled);
        // Unknown compat features are silently ignored in upgrade gate too
        let supported: Vec<FeatureName> = Vec::new();
        assert_eq!(
            ff.check_upgrade_gate(&supported),
            MountCheckResult::ReadWrite
        );
    }

    #[test]
    fn check_upgrade_gate_multiple_incompat() {
        let mut ff = FeatureFlags::new();
        let a = feature("com.example:bad_a");
        let b = feature("com.example:bad_b");
        ff.incompat_tree
            .insert(a.clone(), FeatureFlagValueV1::Enabled);
        ff.incompat_tree
            .insert(b.clone(), FeatureFlagValueV1::Enabled);
        let result = ff.check_upgrade_gate(&[]);
        assert!(result.is_refused());
        match result {
            MountCheckResult::Refused { features } => {
                assert_eq!(features.len(), 2);
            }
            _ => panic!("expected Refused"),
        }
    }

    // -- union, intersect, diff --------------------------------------------

    #[test]
    fn union_two_empty_produces_empty() {
        let a = FeatureFlags::new();
        let b = FeatureFlags::new();
        let result = a.union(b);
        assert!(result.is_empty());
    }

    #[test]
    fn union_disjoint_sets() {
        let mut a = FeatureFlags::new();
        let mut b = FeatureFlags::new();
        let f1 = feature(FEATURE_POSIX_ACL);
        let f2 = feature(FEATURE_COMPRESSION_ZSTD);
        a.enable_feature(f1.clone(), FeatureClass::Compat).unwrap();
        b.enable_feature(f2.clone(), FeatureClass::Incompat)
            .unwrap();
        let result = a.union(b);
        assert_eq!(result.len(), 2);
        assert!(result.is_enabled(&f1));
        assert!(result.is_enabled(&f2));
        assert_eq!(result.class_of(&f1), Some(FeatureClass::Compat));
        assert_eq!(result.class_of(&f2), Some(FeatureClass::Incompat));
    }

    #[test]
    fn union_identical_sets_is_idempotent() {
        let mut a = FeatureFlags::new();
        let f1 = feature(FEATURE_ENCRYPTION_CHACHA20);
        let f2 = feature(FEATURE_CHECKSUM_BLAKE3);
        a.enable_feature(f1.clone(), FeatureClass::Incompat)
            .unwrap();
        a.enable_feature(f2.clone(), FeatureClass::Compat).unwrap();
        let result = a.clone().union(a.clone());
        assert_eq!(result.len(), 2);
        assert!(result.is_enabled(&f1));
        assert!(result.is_enabled(&f2));
    }

    #[test]
    fn union_overlapping_with_same_feature_different_class_takes_other() {
        let mut a = FeatureFlags::new();
        let mut b = FeatureFlags::new();
        let f1 = feature(FEATURE_POSIX_ACL);
        a.enable_feature(f1.clone(), FeatureClass::Compat).unwrap();
        b.enable_feature(f1.clone(), FeatureClass::Incompat)
            .unwrap();
        let result = a.union(b);
        assert_eq!(result.len(), 1);
        assert!(result.is_enabled(&f1));
        // other's class takes precedence (last inserted)
        assert_eq!(result.class_of(&f1), Some(FeatureClass::Incompat));
    }

    #[test]
    fn intersect_disjoint_produces_empty() {
        let mut a = FeatureFlags::new();
        let mut b = FeatureFlags::new();
        a.enable_feature(feature(FEATURE_POSIX_ACL), FeatureClass::Compat)
            .unwrap();
        b.enable_feature(feature(FEATURE_COMPRESSION_ZSTD), FeatureClass::Incompat)
            .unwrap();
        let result = a.intersect(b);
        assert!(result.is_empty());
    }

    #[test]
    fn intersect_overlapping_produces_common() {
        let mut a = FeatureFlags::new();
        let mut b = FeatureFlags::new();
        let common = feature(FEATURE_POSIX_ACL);
        let a_only = feature(FEATURE_COMPRESSION_ZSTD);
        let b_only = feature(FEATURE_ENCRYPTION_CHACHA20);
        a.enable_feature(common.clone(), FeatureClass::Compat)
            .unwrap();
        a.enable_feature(a_only.clone(), FeatureClass::Compat)
            .unwrap();
        b.enable_feature(common.clone(), FeatureClass::Incompat)
            .unwrap();
        b.enable_feature(b_only.clone(), FeatureClass::Incompat)
            .unwrap();
        let result = a.intersect(b);
        assert_eq!(result.len(), 1);
        assert!(result.is_enabled(&common));
        assert_eq!(result.class_of(&common), Some(FeatureClass::Compat));
    }

    #[test]
    fn diff_identical_produces_empty() {
        let mut a = FeatureFlags::new();
        a.enable_feature(feature(FEATURE_POSIX_ACL), FeatureClass::Compat)
            .unwrap();
        let result = a.clone().diff(a.clone());
        assert!(result.is_empty());
    }

    #[test]
    fn diff_superset_minus_subset() {
        let mut a = FeatureFlags::new();
        let mut b = FeatureFlags::new();
        let keep = feature(FEATURE_POSIX_ACL);
        let remove = feature(FEATURE_COMPRESSION_ZSTD);
        a.enable_feature(keep.clone(), FeatureClass::Compat)
            .unwrap();
        a.enable_feature(remove.clone(), FeatureClass::Incompat)
            .unwrap();
        b.enable_feature(remove.clone(), FeatureClass::Incompat)
            .unwrap();
        let result = a.diff(b);
        assert_eq!(result.len(), 1);
        assert!(result.is_enabled(&keep));
        assert!(!result.is_enabled(&remove));
    }

    #[test]
    fn diff_nothing_in_common_returns_all_of_self() {
        let mut a = FeatureFlags::new();
        let b = FeatureFlags::new();
        let f1 = feature(FEATURE_POSIX_ACL);
        a.enable_feature(f1.clone(), FeatureClass::Compat).unwrap();
        let result = a.diff(b);
        assert_eq!(result.len(), 1);
        assert!(result.is_enabled(&f1));
    }

    #[test]
    fn operations_preserve_class() {
        let mut a = FeatureFlags::new();
        let f1 = feature(FEATURE_POSIX_ACL);
        let f2 = feature(FEATURE_COMPRESSION_ZSTD);
        let f3 = feature(FEATURE_ENCRYPTION_CHACHA20);
        a.enable_feature(f1.clone(), FeatureClass::Compat).unwrap();
        a.enable_feature(f2.clone(), FeatureClass::RoCompat)
            .unwrap();
        a.enable_feature(f3.clone(), FeatureClass::Incompat)
            .unwrap();
        let result = a.clone().union(FeatureFlags::new());
        assert_eq!(result.class_of(&f1), Some(FeatureClass::Compat));
        assert_eq!(result.class_of(&f2), Some(FeatureClass::RoCompat));
        assert_eq!(result.class_of(&f3), Some(FeatureClass::Incompat));
    }

    #[test]
    fn roundtrip_union_diff() {
        let mut a = FeatureFlags::new();
        let mut b = FeatureFlags::new();
        let a_only = feature(FEATURE_POSIX_ACL);
        let common = feature(FEATURE_COMPRESSION_ZSTD);
        let b_only = feature(FEATURE_ENCRYPTION_CHACHA20);
        a.enable_feature(a_only.clone(), FeatureClass::Compat)
            .unwrap();
        a.enable_feature(common.clone(), FeatureClass::Compat)
            .unwrap();
        b.enable_feature(common.clone(), FeatureClass::Incompat)
            .unwrap();
        b.enable_feature(b_only.clone(), FeatureClass::Incompat)
            .unwrap();
        // (a ∪ b) \ b == a \ b
        let left = a.clone().union(b.clone()).diff(b.clone());
        let right = a.clone().diff(b);
        assert_eq!(left.len(), right.len());
        // Only a_only should remain
        assert!(left.is_enabled(&a_only));
        assert!(!left.is_enabled(&common));
        assert!(!left.is_enabled(&b_only));
    }

    #[test]
    fn roundtrip_intersect_union() {
        let mut a = FeatureFlags::new();
        let mut b = FeatureFlags::new();
        let common = feature(FEATURE_CHECKSUM_BLAKE3);
        let a_only = feature(FEATURE_POSIX_ACL);
        a.enable_feature(common.clone(), FeatureClass::Compat)
            .unwrap();
        a.enable_feature(a_only.clone(), FeatureClass::Compat)
            .unwrap();
        b.enable_feature(common.clone(), FeatureClass::Incompat)
            .unwrap();
        // (a ∩ b) ∪ a == a
        let left = a.clone().intersect(b).union(a.clone());
        assert_eq!(left.len(), a.len());
        assert!(left.is_enabled(&common));
        assert!(left.is_enabled(&a_only));
    }

    #[test]
    fn union_all_sixteen_with_itself() {
        use tidefs_types_dataset_feature_flags_core::CANONICAL_V1_FEATURES;
        let mut ff = FeatureFlags::new();
        for (i, name_str) in CANONICAL_V1_FEATURES.iter().enumerate() {
            let name = feature(name_str);
            let class = match i % 3 {
                0 => FeatureClass::Compat,
                1 => FeatureClass::RoCompat,
                _ => FeatureClass::Incompat,
            };
            ff.enable_feature(name, class).unwrap();
        }
        let result = ff.clone().union(ff.clone());
        assert_eq!(result.len(), CANONICAL_V1_FEATURES.len());
        let result2 = ff.clone().intersect(ff.clone());
        assert_eq!(result2.len(), CANONICAL_V1_FEATURES.len());
        let result3 = ff.clone().diff(ff);
        assert!(result3.is_empty());
    }

    // -- Canonical class integration: auto-resolve class via get_feature_class --

    #[test]
    fn enable_feature_with_auto_resolved_class() {
        use tidefs_types_dataset_feature_flags_core::get_feature_class;
        let mut ff = FeatureFlags::new();
        let feat = feature(FEATURE_COMPRESSION_ZSTD);
        let class = get_feature_class(&feat).expect("compression_zstd must have a class");
        assert_eq!(class, FeatureClass::RoCompat);
        ff.enable_feature_with_prereqs(feat.clone(), class).unwrap();
        assert!(ff.is_enabled(&feat));
        assert_eq!(ff.class_of(&feat), Some(FeatureClass::RoCompat));
        assert_eq!(ff.check_mount(), MountCheckResult::ReadWrite);
    }

    #[test]
    fn enable_incompat_feature_auto_class() {
        use tidefs_types_dataset_feature_flags_core::get_feature_class;
        let mut ff = FeatureFlags::new();
        let feat = feature(FEATURE_ENCRYPTION_CHACHA20);
        let class = get_feature_class(&feat).expect("encryption must have a class");
        assert_eq!(class, FeatureClass::Incompat);
        // encryption requires checksums first
        let prereq = feature(FEATURE_CHECKSUM_BLAKE3);
        let prereq_class = get_feature_class(&prereq).unwrap();
        ff.enable_feature_with_prereqs(prereq.clone(), prereq_class)
            .unwrap();
        ff.enable_feature_with_prereqs(feat.clone(), class).unwrap();
        assert!(ff.is_enabled(&feat));
        assert_eq!(ff.check_mount(), MountCheckResult::ReadWrite);
    }

    #[test]
    fn enable_all_canonical_features_auto_class_mounts() {
        use tidefs_types_dataset_feature_flags_core::{get_feature_class, CANONICAL_V1_FEATURES};
        let mut ff = FeatureFlags::new();
        // Enable prerequisites first, then all features
        for name_str in CANONICAL_V1_FEATURES {
            if let Some(name) = FeatureName::from_str(name_str) {
                if let Some(class) = get_feature_class(&name) {
                    // Use _with_prereqs to respect prerequisite ordering
                    let _ = ff.enable_feature_with_prereqs(name, class);
                }
            }
        }
        // All canonical features are known, so mount must succeed
        assert_eq!(ff.check_mount(), MountCheckResult::ReadWrite);
        // At least the features with satisfied prerequisites are enabled
        assert!(!ff.is_empty(), "at least some features should be enabled");
    }

    #[test]
    fn compression_feature_mount_is_read_write() {
        use tidefs_types_dataset_feature_flags_core::FEATURE_COMPRESSION_ZSTD;
        // Enabling a known ro_compat feature (compression_zstd) must
        // pass mount check — the feature flag → compression policy
        // chain is verified by LocalFileSystem mount-time derivation.
        let mut ff = FeatureFlags::new();
        let comp = feature(FEATURE_COMPRESSION_ZSTD);
        ff.enable_feature_with_prereqs(comp.clone(), FeatureClass::RoCompat)
            .unwrap();
        assert_eq!(ff.check_mount(), MountCheckResult::ReadWrite);
        assert!(ff.is_enabled(&comp));
    }

    #[test]
    fn compression_lz4_zstd_both_enabled_mounts() {
        use tidefs_types_dataset_feature_flags_core::{
            FEATURE_COMPRESSION_LZ4, FEATURE_COMPRESSION_ZSTD,
        };
        // Both compression features enabled: verify mount passes.
        // The mount-time derivation picks lz4 first (priority), but
        // the feature-flag layer must report both as enabled.
        let mut ff = FeatureFlags::new();
        let lz4 = feature(FEATURE_COMPRESSION_LZ4);
        let zstd = feature(FEATURE_COMPRESSION_ZSTD);
        ff.enable_feature_with_prereqs(lz4.clone(), FeatureClass::RoCompat)
            .unwrap();
        ff.enable_feature_with_prereqs(zstd.clone(), FeatureClass::RoCompat)
            .unwrap();
        assert!(ff.is_enabled(&lz4));
        assert!(ff.is_enabled(&zstd));
        assert_eq!(ff.check_mount(), MountCheckResult::ReadWrite);
    }

    #[test]
    fn unknown_feature_rejected_by_class_resolver() {
        use tidefs_types_dataset_feature_flags_core::get_feature_class;
        let unknown = feature("com.example:custom");
        assert_eq!(get_feature_class(&unknown), None);
        // The CLI should require explicit --class for this case
    }

    #[test]
    fn mount_check_enabled_compression_is_read_write() {
        // Enabling compression_zstd (a ro_compat feature that this version
        // knows) must pass mount check — the feature flag → compression
        // policy chain is verified by the mount-time derivation in
        // LocalFileSystem.
        let mut ff = FeatureFlags::new();
        let comp = feature(FEATURE_COMPRESSION_ZSTD);
        ff.enable_feature_with_prereqs(comp.clone(), FeatureClass::RoCompat)
            .unwrap();
        assert_eq!(ff.check_mount(), MountCheckResult::ReadWrite);
        assert!(ff.is_enabled(&comp));
    }

    #[test]
    fn compression_policy_priority_lz4_over_zstd() {
        // Both enabled: verify both are present in the feature set.
        // The mount-time derivation code picks lz4 first; this test
        // only confirms the feature-flag layer is correct.
        let mut ff = FeatureFlags::new();
        let lz4 = feature(FEATURE_COMPRESSION_LZ4);
        let zstd = feature(FEATURE_COMPRESSION_ZSTD);
        ff.enable_feature_with_prereqs(lz4.clone(), FeatureClass::RoCompat)
            .unwrap();
        ff.enable_feature_with_prereqs(zstd.clone(), FeatureClass::RoCompat)
            .unwrap();
        assert!(ff.is_enabled(&lz4));
        assert!(ff.is_enabled(&zstd));
        assert_eq!(ff.check_mount(), MountCheckResult::ReadWrite);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use tidefs_types_dataset_feature_flags_core::FeatureFlagValueV1;

    // -- Arbitrary FeatureName strategy ---------------------------------

    /// Valid characters for the domain part (before colon).
    fn domain_char() -> impl Strategy<Value = char> {
        prop_oneof![
            // lowercase letters: most common
            20 => proptest::char::range('a', 'z'),
            // digits
            5 => proptest::char::range('0', '9'),
            // dot
            2 => Just('.'),
            // hyphen
            1 => Just('-'),
            // underscore
            1 => Just('_'),
        ]
    }

    /// Valid characters for the feature-name part (after colon).
    fn feature_char() -> impl Strategy<Value = char> {
        prop_oneof![
            20 => proptest::char::range('a', 'z'),
            5 => proptest::char::range('0', '9'),
            1 => Just('_'),
        ]
    }

    /// Strategy that generates a valid `FeatureName`.
    ///
    /// Generates a reverse-DNS name: domain chars (1..=118) + colon +
    /// feature chars (1..=8), total ≤ 127 bytes.
    fn arb_feature_name() -> impl Strategy<Value = FeatureName> {
        (1usize..=118usize, 1usize..=8usize)
            .prop_flat_map(|(dom_len, feat_len)| {
                let dom = proptest::collection::vec(domain_char(), dom_len..=dom_len);
                let feat = proptest::collection::vec(feature_char(), feat_len..=feat_len);
                (dom, feat)
            })
            .prop_map(|(dom, feat)| {
                let mut s = String::with_capacity(dom.len() + 1 + feat.len());
                for c in &dom {
                    s.push(*c);
                }
                s.push(':');
                for c in &feat {
                    s.push(*c);
                }
                FeatureName::from_str(&s).expect("generated name must be valid")
            })
    }

    /// Strategy for `FeatureFlagValueV1`.
    fn arb_feature_value() -> impl Strategy<Value = FeatureFlagValueV1> {
        prop_oneof![
            Just(FeatureFlagValueV1::Enabled),
            Just(FeatureFlagValueV1::EnabledActive),
        ]
    }

    /// Strategy for a BPlusTree of (FeatureName, FeatureFlagValueV1).
    fn arb_feature_tree(
        max_entries: usize,
    ) -> impl Strategy<Value = BPlusTree<FeatureName, FeatureFlagValueV1>> {
        proptest::collection::vec((arb_feature_name(), arb_feature_value()), 0..=max_entries)
            .prop_map(|entries| {
                let mut tree: BPlusTree<FeatureName, FeatureFlagValueV1> = BPlusTree::new();
                for (name, value) in entries {
                    // Insert is infallible; BPlusTree handles duplicates by
                    // replacing the value, so each generated entry is
                    // independent.
                    tree.insert(name, value);
                }
                tree
            })
    }

    // -- Properties -----------------------------------------------------

    /// Round-trip: serialize then deserialize preserves all entries.
    #[test]
    fn serialize_deserialize_roundtrip_proptest() {
        let mut runner = proptest::test_runner::TestRunner::default();
        runner
            .run(&arb_feature_tree(20), |tree| {
                let expected = tree.entries();
                let bytes = serialize_feature_tree(&tree);
                let restored = deserialize_feature_tree(&bytes)
                    .expect("deserialize should succeed on valid input");
                let actual = restored.entries();
                prop_assert_eq!(
                    expected.len(),
                    actual.len(),
                    "entry count mismatch: expected {}, got {}",
                    expected.len(),
                    actual.len()
                );
                for (i, (exp_name, exp_val)) in expected.iter().enumerate() {
                    let (act_name, act_val) = &actual[i];
                    // Use assert_eq! with explicit message to avoid
                    // proptest macro hygiene issues with captures.
                    assert_eq!(exp_name, act_name, "name mismatch at index {i}");
                    assert_eq!(exp_val, act_val, "value mismatch at index {i}");
                }
                Ok(())
            })
            .unwrap();
    }

    /// Corrupt truncation: removing bytes from valid serialized data
    /// should cause deserialization to fail.
    #[test]
    fn corrupt_truncation_proptest() {
        let mut runner = proptest::test_runner::TestRunner::default();
        runner
            .run(&arb_feature_tree(10), |tree| {
                let bytes = serialize_feature_tree(&tree);
                if bytes.is_empty() {
                    return Ok(());
                }
                // Try truncating at every byte boundary
                let mut any_failure = false;
                for cut in 1..bytes.len() {
                    let truncated = &bytes[..cut];
                    if deserialize_feature_tree(truncated).is_none() {
                        any_failure = true;
                    }
                }
                // At least the final-byte truncation should fail
                // (last entry's value byte is stripped, making the entry
                //  incomplete).
                let nbytes = bytes.len();
                prop_assert!(
                    any_failure,
                    "at least one truncation point must fail for non-empty tree of {} bytes",
                    nbytes
                );
                Ok(())
            })
            .unwrap();
    }

    /// Zero-length name byte in serialized data must be rejected.
    #[test]
    fn reject_zero_length_name_proptest() {
        let mut runner = proptest::test_runner::TestRunner::default();
        runner
            .run(&arb_feature_tree(10), |tree| {
                let mut bytes = serialize_feature_tree(&tree);
                if bytes.is_empty() {
                    // For empty tree, the only valid serialization is
                    // empty; injecting bytes creates a truncated or
                    // zero-length entry that must fail.
                    bytes.push(0u8);
                    bytes.push(1u8);
                    prop_assert!(
                        deserialize_feature_tree(&bytes).is_none(),
                        "zero-length name in empty-tree injection must fail"
                    );
                } else {
                    // Insert a zero length byte at position 0: the
                    // deserializer reads name_len=0 and must reject it.
                    bytes.insert(0, 0u8);
                    prop_assert!(
                        deserialize_feature_tree(&bytes).is_none(),
                        "zero-length name injected at position 0 must fail"
                    );
                }
                Ok(())
            })
            .unwrap();
    }
}
