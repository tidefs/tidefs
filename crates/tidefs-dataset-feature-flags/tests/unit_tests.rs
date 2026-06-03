// Integration tests for tidefs-dataset-feature-flags.
//
// These tests exercise the public API surface as an external consumer
// would — create FeatureFlags, enable/disable features, check mount
// compatibility, and run set operations (union/intersect/diff). Inline
// unit tests cover edge cases and private internals; these tests
// verify the public contract.

use tidefs_dataset_feature_flags::{FeatureFlags, FeatureFlagsError, MountCheckResult};
use tidefs_types_dataset_feature_flags_core::{
    FeatureClass, FeatureName, FEATURE_CHECKSUM_BLAKE3, FEATURE_COMMIT_GROUP_STATE_MACHINE,
    FEATURE_COMPRESSION_ZSTD, FEATURE_ENCRYPTION_CHACHA20, FEATURE_POSIX_ACL, FEATURE_SEND_RECV_V2,
    FEATURE_SNAPSHOT_V2, FEATURE_XATTR_SUPPORT,
};

fn feature(s: &str) -> FeatureName {
    FeatureName::from_str(s).expect("valid feature name")
}

// ---------------------------------------------------------------------------
// Lifecycle: create → enable → check → disable → re-check
// ---------------------------------------------------------------------------

#[test]
fn full_lifecycle_single_feature() {
    let mut ff = FeatureFlags::new();
    assert!(ff.is_empty());
    assert_eq!(ff.len(), 0);

    let name = feature(FEATURE_POSIX_ACL);
    assert!(!ff.is_enabled(&name));

    // Enable
    ff.enable_feature(name.clone(), FeatureClass::Compat)
        .unwrap();
    assert!(ff.is_enabled(&name));
    assert_eq!(ff.len(), 1);
    assert_eq!(ff.class_of(&name), Some(FeatureClass::Compat));

    // Mount should pass (known feature)
    assert_eq!(ff.check_mount(), MountCheckResult::ReadWrite);

    // Disable
    ff.disable_feature(&name).unwrap();
    assert!(!ff.is_enabled(&name));
    assert!(ff.is_empty());
}

#[test]
fn lifecycle_multi_class_features() {
    let mut ff = FeatureFlags::new();

    // Enable features across all three classes
    let compat_feat = feature(FEATURE_POSIX_ACL);
    let ro_feat = feature(FEATURE_CHECKSUM_BLAKE3);
    let incompat_feat = feature(FEATURE_ENCRYPTION_CHACHA20);

    ff.enable_feature(compat_feat.clone(), FeatureClass::Compat)
        .unwrap();
    ff.enable_feature(ro_feat.clone(), FeatureClass::RoCompat)
        .unwrap();
    ff.enable_feature(incompat_feat.clone(), FeatureClass::Incompat)
        .unwrap();

    assert_eq!(ff.len(), 3);
    assert_eq!(ff.class_of(&compat_feat), Some(FeatureClass::Compat));
    assert_eq!(ff.class_of(&ro_feat), Some(FeatureClass::RoCompat));
    assert_eq!(ff.class_of(&incompat_feat), Some(FeatureClass::Incompat));

    // All known features → ReadWrite mount
    assert_eq!(ff.check_mount(), MountCheckResult::ReadWrite);

    // all_features returns all three
    let all = ff.all_features();
    assert_eq!(all.len(), 3);

    // Disable in reverse order
    ff.disable_feature(&incompat_feat).unwrap();
    ff.disable_feature(&ro_feat).unwrap();
    ff.disable_feature(&compat_feat).unwrap();
    assert!(ff.is_empty());
}

// ---------------------------------------------------------------------------
// Compatibility matrix: unknown features in each class
// ---------------------------------------------------------------------------

#[test]
fn unknown_compat_is_silently_ignored() {
    let unknown = feature("com.example:custom_compat");
    assert!(!FeatureFlags::is_known_feature(&unknown));
}

#[test]
fn unknown_incompat_refuses_mount_public_api() {
    let mut ff = FeatureFlags::new();
    let known = feature(FEATURE_POSIX_ACL);

    ff.enable_feature(known, FeatureClass::Incompat).unwrap();

    // check_upgrade_gate with empty supported set should refuse mount
    // because the known feature isn't in the supported set
    let result = ff.check_upgrade_gate(&[]);
    assert!(result.is_refused());
}

#[test]
fn check_mount_open_result_api() {
    let mut ff = FeatureFlags::new();
    let known = feature(FEATURE_POSIX_ACL);
    ff.enable_feature(known, FeatureClass::Compat).unwrap();

    let result = ff.check_mount_open_result();
    assert!(result.is_ok());
}

#[test]
fn check_upgrade_gate_open_result_api() {
    let mut ff = FeatureFlags::new();
    let known = feature(FEATURE_POSIX_ACL);
    ff.enable_feature(known.clone(), FeatureClass::Incompat)
        .unwrap();

    let supported = vec![known.clone()];
    let result = ff.check_upgrade_gate_open_result(&supported);
    assert!(result.is_ok());

    // Empty supported set should fail for incompat features
    let result = ff.check_upgrade_gate_open_result(&[]);
    assert!(result.is_err());
    match result {
        Err(FeatureFlagsError::IncompatibleMount { .. }) => {}
        _ => panic!("expected IncompatibleMount"),
    }
}

// ---------------------------------------------------------------------------
// Prerequisites: enable_feature_with_prereqs
// ---------------------------------------------------------------------------

#[test]
fn enable_with_prereqs_happy_path_integration() {
    let mut ff = FeatureFlags::new();
    let commit_group = feature(FEATURE_COMMIT_GROUP_STATE_MACHINE);
    let snap = feature(FEATURE_SNAPSHOT_V2);

    // Enable prerequisite first
    ff.enable_feature(commit_group, FeatureClass::Compat)
        .unwrap();
    // Now enable the dependent feature
    ff.enable_feature_with_prereqs(snap.clone(), FeatureClass::Incompat)
        .unwrap();
    assert!(ff.is_enabled(&snap));
}

#[test]
fn enable_with_prereqs_missing_integration() {
    let mut ff = FeatureFlags::new();
    let snap = feature(FEATURE_SNAPSHOT_V2);

    let err = ff
        .enable_feature_with_prereqs(snap.clone(), FeatureClass::Incompat)
        .unwrap_err();
    match err {
        FeatureFlagsError::MissingPrerequisite { name, prerequisite } => {
            assert_eq!(name, snap);
            assert_eq!(prerequisite.as_str(), FEATURE_COMMIT_GROUP_STATE_MACHINE);
        }
        _ => panic!("expected MissingPrerequisite, got {err:?}"),
    }
}

#[test]
fn enable_with_transitive_prereqs_integration() {
    let mut ff = FeatureFlags::new();
    // send_recv requires snapshot which requires commit_group, plus checksum
    let commit_group = feature(FEATURE_COMMIT_GROUP_STATE_MACHINE);
    let snap = feature(FEATURE_SNAPSHOT_V2);
    let blake3 = feature(FEATURE_CHECKSUM_BLAKE3);
    let send = feature(FEATURE_SEND_RECV_V2);

    ff.enable_feature(commit_group, FeatureClass::Compat)
        .unwrap();
    ff.enable_feature(blake3, FeatureClass::Compat).unwrap();
    ff.enable_feature_with_prereqs(snap, FeatureClass::RoCompat)
        .unwrap();
    ff.enable_feature_with_prereqs(send.clone(), FeatureClass::Incompat)
        .unwrap();

    assert!(ff.is_enabled(&send));
    assert_eq!(ff.len(), 4);
}

// ---------------------------------------------------------------------------
// Set operations: union, intersect, diff (end-to-end)
// ---------------------------------------------------------------------------

#[test]
fn union_integration() {
    let mut a = FeatureFlags::new();
    let mut b = FeatureFlags::new();
    let posix = feature(FEATURE_POSIX_ACL);
    let zstd = feature(FEATURE_COMPRESSION_ZSTD);
    let xattr = feature(FEATURE_XATTR_SUPPORT);

    a.enable_feature(posix.clone(), FeatureClass::Compat)
        .unwrap();
    a.enable_feature(zstd.clone(), FeatureClass::RoCompat)
        .unwrap();
    b.enable_feature(zstd.clone(), FeatureClass::Incompat)
        .unwrap();
    b.enable_feature(xattr.clone(), FeatureClass::Compat)
        .unwrap();

    let union = a.union(b);
    assert_eq!(union.len(), 3);
    assert!(union.is_enabled(&posix));
    assert!(union.is_enabled(&zstd));
    assert!(union.is_enabled(&xattr));
    // zstd class taken from b (last insert wins)
    assert_eq!(union.class_of(&zstd), Some(FeatureClass::Incompat));
}

#[test]
fn intersect_integration() {
    let mut a = FeatureFlags::new();
    let mut b = FeatureFlags::new();
    let posix = feature(FEATURE_POSIX_ACL);
    let zstd = feature(FEATURE_COMPRESSION_ZSTD);
    let xattr = feature(FEATURE_XATTR_SUPPORT);

    a.enable_feature(posix, FeatureClass::Compat).unwrap();
    a.enable_feature(zstd.clone(), FeatureClass::Compat)
        .unwrap();
    b.enable_feature(zstd.clone(), FeatureClass::Incompat)
        .unwrap();
    b.enable_feature(xattr, FeatureClass::Compat).unwrap();

    let intersect = a.intersect(b);
    assert_eq!(intersect.len(), 1);
    assert!(intersect.is_enabled(&zstd));
    // Class from self (a)
    assert_eq!(intersect.class_of(&zstd), Some(FeatureClass::Compat));
}

#[test]
fn diff_integration() {
    let mut a = FeatureFlags::new();
    let mut b = FeatureFlags::new();
    let posix = feature(FEATURE_POSIX_ACL);
    let zstd = feature(FEATURE_COMPRESSION_ZSTD);

    a.enable_feature(posix.clone(), FeatureClass::Compat)
        .unwrap();
    a.enable_feature(zstd.clone(), FeatureClass::Incompat)
        .unwrap();
    b.enable_feature(zstd, FeatureClass::Incompat).unwrap();

    let diff = a.diff(b);
    assert_eq!(diff.len(), 1);
    assert!(diff.is_enabled(&posix));
}

#[test]
fn set_ops_idempotent_identity() {
    let mut a = FeatureFlags::new();
    let f = feature(FEATURE_POSIX_ACL);
    a.enable_feature(f.clone(), FeatureClass::Compat).unwrap();

    // a ∪ a == a
    let union_self = a.clone().union(a.clone());
    assert_eq!(union_self.len(), 1);
    assert!(union_self.is_enabled(&f));

    // a ∩ a == a
    let intersect_self = a.clone().intersect(a.clone());
    assert_eq!(intersect_self.len(), 1);
    assert!(intersect_self.is_enabled(&f));

    // a \ a == ∅
    let diff_self = a.clone().diff(a);
    assert!(diff_self.is_empty());
}

// ---------------------------------------------------------------------------
// to_dataset_flags and Display
// ---------------------------------------------------------------------------

#[test]
fn to_dataset_flags_integration() {
    let mut ff = FeatureFlags::new();

    // Empty → all roots are empty
    let empty = ff.to_dataset_flags();
    assert!(empty.is_empty());

    // Enable some features
    ff.enable_feature(feature(FEATURE_POSIX_ACL), FeatureClass::Compat)
        .unwrap();
    ff.enable_feature(feature(FEATURE_CHECKSUM_BLAKE3), FeatureClass::RoCompat)
        .unwrap();
    ff.enable_feature(feature(FEATURE_ENCRYPTION_CHACHA20), FeatureClass::Incompat)
        .unwrap();

    let flags = ff.to_dataset_flags();
    // Non-empty trees → roots point to non-zero
    assert!(!flags.compat_root.is_empty());
    assert!(!flags.ro_compat_root.is_empty());
    assert!(!flags.incompat_root.is_empty());
}

#[test]
fn display_format_integration() {
    let mut ff = FeatureFlags::new();

    let s = ff.to_string();
    assert!(s.contains("compat=0"));
    assert!(s.contains("ro_compat=0"));
    assert!(s.contains("incompat=0"));

    ff.enable_feature(feature(FEATURE_POSIX_ACL), FeatureClass::Compat)
        .unwrap();
    ff.enable_feature(feature(FEATURE_COMPRESSION_ZSTD), FeatureClass::Incompat)
        .unwrap();

    let s = ff.to_string();
    assert!(s.contains("compat=1"));
    assert!(s.contains("incompat=1"));
}

// ---------------------------------------------------------------------------
// Default and zero-state
// ---------------------------------------------------------------------------

#[test]
fn default_is_new_is_empty() {
    let a = FeatureFlags::new();
    let b = FeatureFlags::default();
    assert_eq!(a.len(), 0);
    assert_eq!(b.len(), 0);
    assert!(a.is_empty());
    assert!(b.is_empty());
}

// ---------------------------------------------------------------------------
// all_features: verifies class assignment
// ---------------------------------------------------------------------------

#[test]
fn all_features_class_assignment_integration() {
    let mut ff = FeatureFlags::new();
    let c = feature(FEATURE_POSIX_ACL);
    let r = feature(FEATURE_CHECKSUM_BLAKE3);
    let i = feature(FEATURE_ENCRYPTION_CHACHA20);

    ff.enable_feature(c.clone(), FeatureClass::Compat).unwrap();
    ff.enable_feature(r.clone(), FeatureClass::RoCompat)
        .unwrap();
    ff.enable_feature(i.clone(), FeatureClass::Incompat)
        .unwrap();

    let all = ff.all_features();
    assert_eq!(all.len(), 3);

    let compat: Vec<_> = all
        .iter()
        .filter(|(cls, _, _)| *cls == FeatureClass::Compat)
        .collect();
    let ro: Vec<_> = all
        .iter()
        .filter(|(cls, _, _)| *cls == FeatureClass::RoCompat)
        .collect();
    let incompat: Vec<_> = all
        .iter()
        .filter(|(cls, _, _)| *cls == FeatureClass::Incompat)
        .collect();

    assert_eq!(compat.len(), 1);
    assert_eq!(compat[0].1, c);
    assert_eq!(ro.len(), 1);
    assert_eq!(ro[0].1, r);
    assert_eq!(incompat.len(), 1);
    assert_eq!(incompat[0].1, i);
}

// ---------------------------------------------------------------------------
// Error type display
// ---------------------------------------------------------------------------

#[test]
fn error_display_public_api() {
    let name = feature("com.example:error_test");

    let e = FeatureFlagsError::UnknownFeature { name: name.clone() };
    assert!(e.to_string().contains("unknown feature"));

    let e = FeatureFlagsError::AlreadyEnabled {
        name: name.clone(),
        class: FeatureClass::Incompat,
    };
    assert!(e.to_string().contains("already enabled"));

    let e = FeatureFlagsError::NotEnabled { name: name.clone() };
    assert!(e.to_string().contains("not enabled"));

    let e = FeatureFlagsError::IncompatibleMount {
        features: Box::new(vec![name.clone()]),
    };
    assert!(e.to_string().contains("mount refused"));

    let prereq = feature("org.tidefs:checksum_blake3");
    let e = FeatureFlagsError::MissingPrerequisite {
        name,
        prerequisite: prereq,
    };
    assert!(e.to_string().contains("requires prerequisite"));
}

// ---------------------------------------------------------------------------
// is_known_feature
// ---------------------------------------------------------------------------

#[test]
fn is_known_feature_public_api() {
    let known = feature(FEATURE_POSIX_ACL);
    let unknown = feature("com.example:nonexistent");

    assert!(FeatureFlags::is_known_feature(&known));
    assert!(!FeatureFlags::is_known_feature(&unknown));
}
