#![no_std]
#![forbid(unsafe_code)]

//! Human-readable build profile, capability, bundle, and service-surface manifests.
//!
//! The `package_profile_catalog` package name is a stable internal-locator package identifier. New
//! operator-facing code should use the human names returned by `human_name()` and
//! keep the stable internal-locator strings from `as_str()` only as stable IDs.

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum BuildProfile {
    CorePortable,
    AllocPortable,
    UserspaceLibrary,
    UserspaceApp,
    TestXtaskStd,
}

impl BuildProfile {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CorePortable => "profile.environment_boundary.core_portable.p0",
            Self::AllocPortable => "profile.environment_boundary.alloc_portable.p1",
            Self::UserspaceLibrary => "profile.environment_boundary.userspace_library.p2",
            Self::UserspaceApp => "profile.environment_boundary.userspace_app.p3",
            Self::TestXtaskStd => "profile.environment_boundary.test_xtask.p6",
        }
    }

    #[must_use]
    pub const fn stable_id(self) -> &'static str {
        self.as_str()
    }

    #[must_use]
    pub const fn human_name(self) -> &'static str {
        match self {
            Self::CorePortable => "Core portable",
            Self::AllocPortable => "Alloc portable",
            Self::UserspaceLibrary => "Userspace library",
            Self::UserspaceApp => "Userspace application",
            Self::TestXtaskStd => "Workspace test/xtask",
        }
    }

    #[must_use]
    pub const fn rust_hint(self) -> &'static str {
        match self {
            Self::CorePortable => "core_portable",
            Self::AllocPortable => "alloc_portable",
            Self::UserspaceLibrary => "userspace_library",
            Self::UserspaceApp => "userspace_application",
            Self::TestXtaskStd => "workspace_test_xtask",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CapabilityClass {
    CanonShared,
    AuthorityUserspace,
    PosixUserspace,
    BlockVolumeUserspace,
    ControlSurface,
    ObserveGate,
}

impl CapabilityClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CanonShared => "cap.package_profile_catalog.canon_shared.c0",
            Self::AuthorityUserspace => "cap.package_profile_catalog.authority_userspace.c1",
            Self::PosixUserspace => "cap.package_profile_catalog.posix_userspace.c2",
            Self::BlockVolumeUserspace => "cap.package_profile_catalog.block_volume_userspace.c3",
            Self::ControlSurface => "cap.package_profile_catalog.control_surface.c4",
            Self::ObserveGate => "cap.package_profile_catalog.observe_gate.c6",
        }
    }

    #[must_use]
    pub const fn stable_id(self) -> &'static str {
        self.as_str()
    }

    #[must_use]
    pub const fn human_name(self) -> &'static str {
        match self {
            Self::CanonShared => "Canonical shared records",
            Self::AuthorityUserspace => "Policy-authority userspace",
            Self::PosixUserspace => "POSIX-adapter userspace",
            Self::BlockVolumeUserspace => "Block-volume-adapter userspace",
            Self::ControlSurface => "Control/query surface",
            Self::ObserveGate => "Observation/validation gate",
        }
    }

    #[must_use]
    pub const fn rust_hint(self) -> &'static str {
        match self {
            Self::CanonShared => "canonical_shared_records",
            Self::AuthorityUserspace => "policy_authority_userspace",
            Self::PosixUserspace => "posix_adapter_userspace",
            Self::BlockVolumeUserspace => "block_volume_adapter_userspace",
            Self::ControlSurface => "control_query_surface",
            Self::ObserveGate => "observation_validation_gate",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum BundleClass {
    DevWorkspace,
    RuntimeAuthorityUserspace,
    RuntimePosixUserspace,
    RuntimeBlockVolumeUserspace,
    RuntimeControlQuery,
    ObserveTestGate,
}

impl BundleClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DevWorkspace => "bundle.package_profile_catalog.dev_workspace.b0",
            Self::RuntimeAuthorityUserspace => {
                "bundle.package_profile_catalog.runtime.authority_userspace.b2"
            }
            Self::RuntimePosixUserspace => {
                "bundle.package_profile_catalog.runtime.posix_userspace.b3"
            }
            Self::RuntimeBlockVolumeUserspace => {
                "bundle.package_profile_catalog.runtime.block_volume_userspace.b4"
            }
            Self::RuntimeControlQuery => "bundle.package_profile_catalog.runtime.control_query.b5",
            Self::ObserveTestGate => "bundle.package_profile_catalog.observe_test_gate.b6",
        }
    }

    #[must_use]
    pub const fn stable_id(self) -> &'static str {
        self.as_str()
    }

    #[must_use]
    pub const fn human_name(self) -> &'static str {
        match self {
            Self::DevWorkspace => "Development workspace",
            Self::RuntimeAuthorityUserspace => "Runtime policy-authority userspace",
            Self::RuntimePosixUserspace => "Runtime POSIX-adapter userspace",
            Self::RuntimeBlockVolumeUserspace => "Runtime block-volume-adapter userspace",
            Self::RuntimeControlQuery => "Runtime control/query service",
            Self::ObserveTestGate => "Observation test gate",
        }
    }

    #[must_use]
    pub const fn rust_hint(self) -> &'static str {
        match self {
            Self::DevWorkspace => "development_workspace",
            Self::RuntimeAuthorityUserspace => "runtime_policy_authority_userspace",
            Self::RuntimePosixUserspace => "runtime_posix_adapter_userspace",
            Self::RuntimeBlockVolumeUserspace => "runtime_block_volume_adapter_userspace",
            Self::RuntimeControlQuery => "runtime_control_query_service",
            Self::ObserveTestGate => "observation_test_gate",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ServiceFamily {
    PolicyAuthority,
    PosixFilesystemAdapter,
    BlockVolumeAdapter,
    ControlPlane,
    Xtask,
}

impl ServiceFamily {
    pub const POLICY_AUTHORITY: Self = Self::PolicyAuthority;
    pub const POSIX_FILESYSTEM_ADAPTER: Self = Self::PosixFilesystemAdapter;
    pub const BLOCK_VOLUME_ADAPTER: Self = Self::BlockVolumeAdapter;
    pub const CONTROL_PLANE: Self = Self::ControlPlane;
    pub const WORKSPACE_TOOLING: Self = Self::Xtask;

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PolicyAuthority => "family.workspace_layout.policy_authority.f2",
            Self::PosixFilesystemAdapter => "family.workspace_layout.posix_filesystem_adapter.f6",
            Self::BlockVolumeAdapter => "family.workspace_layout.block_volume_adapter.f7",
            Self::ControlPlane => "family.workspace_layout.control_plane.f8",
            Self::Xtask => "class.workspace_layout.test_or_xtask.c9",
        }
    }

    #[must_use]
    pub const fn stable_id(self) -> &'static str {
        self.as_str()
    }

    #[must_use]
    pub const fn stable_locator(self) -> &'static str {
        match self {
            Self::PolicyAuthority => "policy_authority",
            Self::PosixFilesystemAdapter => "posix_filesystem_adapter",
            Self::BlockVolumeAdapter => "block_volume_adapter",
            Self::ControlPlane => "control_plane",
            Self::Xtask => "xtask",
        }
    }

    #[must_use]
    pub const fn human_name(self) -> &'static str {
        match self {
            Self::PolicyAuthority => "Policy Authority",
            Self::PosixFilesystemAdapter => "POSIX Filesystem Adapter",
            Self::BlockVolumeAdapter => "Block Volume Adapter",
            Self::ControlPlane => "Control Plane",
            Self::Xtask => "Workspace Tooling",
        }
    }

    #[must_use]
    pub const fn rust_hint(self) -> &'static str {
        match self {
            Self::PolicyAuthority => "policy_authority",
            Self::PosixFilesystemAdapter => "posix_filesystem_adapter",
            Self::BlockVolumeAdapter => "block_volume_adapter",
            Self::ControlPlane => "control_plane",
            Self::Xtask => "workspace_tooling",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SurfaceManifest {
    pub binary_name: &'static str,
    pub family: ServiceFamily,
    pub profile: BuildProfile,
    pub bundle: BundleClass,
    pub capabilities: &'static [CapabilityClass],
    pub stage: &'static str,
}

impl SurfaceManifest {
    #[must_use]
    pub const fn human_family_name(self) -> &'static str {
        self.family.human_name()
    }

    #[must_use]
    pub const fn family_locator(self) -> &'static str {
        self.family.stable_locator()
    }
}

impl SurfaceManifest {
    #[must_use]
    pub const fn human_name(self) -> &'static str {
        self.family.human_name()
    }

    #[must_use]
    pub const fn rust_hint(self) -> &'static str {
        self.family.rust_hint()
    }

    #[must_use]
    pub const fn stable_locator(self) -> &'static str {
        self.family.stable_locator()
    }

    #[must_use]
    pub const fn stable_family_id(self) -> &'static str {
        self.family.stable_id()
    }

    #[must_use]
    pub const fn profile_name(self) -> &'static str {
        self.profile.human_name()
    }

    #[must_use]
    pub const fn bundle_name(self) -> &'static str {
        self.bundle.human_name()
    }

    #[must_use]
    pub fn has_capability(self, capability: CapabilityClass) -> bool {
        self.capabilities.contains(&capability)
    }
}

/// Capability set for the policy-authority daemon profile.
const POLICY_AUTHORITY_DAEMON_CAPS: &[CapabilityClass] = &[
    CapabilityClass::CanonShared,
    CapabilityClass::AuthorityUserspace,
    CapabilityClass::ObserveGate,
];

/// Capability set for the posix-filesystem-adapter daemon profile.
const POSIX_FILESYSTEM_ADAPTER_DAEMON_CAPS: &[CapabilityClass] = &[
    CapabilityClass::CanonShared,
    CapabilityClass::PosixUserspace,
    CapabilityClass::ObserveGate,
];

/// Capability set for the block-volume-adapter daemon profile.
const BLOCK_VOLUME_ADAPTER_DAEMON_CAPS: &[CapabilityClass] = &[
    CapabilityClass::CanonShared,
    CapabilityClass::BlockVolumeUserspace,
    CapabilityClass::ObserveGate,
];

/// Capability set for the control-plane daemon profile.
const CONTROL_PLANE_DAEMON_CAPS: &[CapabilityClass] = &[
    CapabilityClass::CanonShared,
    CapabilityClass::ControlSurface,
    CapabilityClass::ObserveGate,
];

/// Capability set for the xtask profile.
const XTASK_CAPS: &[CapabilityClass] = &[
    CapabilityClass::CanonShared,
    CapabilityClass::ControlSurface,
];

pub const POLICY_AUTHORITY_DAEMON_SURFACE: SurfaceManifest = SurfaceManifest {
    binary_name: "tidefs-policy-authority-daemon",
    family: ServiceFamily::POLICY_AUTHORITY,
    profile: BuildProfile::UserspaceApp,
    bundle: BundleClass::RuntimeAuthorityUserspace,
    capabilities: POLICY_AUTHORITY_DAEMON_CAPS,
    stage: "stage.userspace.shared_canon_portability.s0",
};

pub const POSIX_FILESYSTEM_ADAPTER_DAEMON_SURFACE: SurfaceManifest = SurfaceManifest {
    binary_name: "tidefs-posix-filesystem-adapter-daemon",
    family: ServiceFamily::POSIX_FILESYSTEM_ADAPTER,
    profile: BuildProfile::UserspaceApp,
    bundle: BundleClass::RuntimePosixUserspace,
    capabilities: POSIX_FILESYSTEM_ADAPTER_DAEMON_CAPS,
    stage: "stage.userspace.shared_canon_portability.s0",
};

pub const BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE: SurfaceManifest = SurfaceManifest {
    binary_name: "tidefs-block-volume-adapter-daemon",
    family: ServiceFamily::BLOCK_VOLUME_ADAPTER,
    profile: BuildProfile::UserspaceApp,
    bundle: BundleClass::RuntimeBlockVolumeUserspace,
    capabilities: BLOCK_VOLUME_ADAPTER_DAEMON_CAPS,
    stage: "stage.userspace.shared_canon_portability.s0",
};

pub const CONTROL_PLANE_DAEMON_SURFACE: SurfaceManifest = SurfaceManifest {
    binary_name: "tidefs-control-plane-daemon",
    family: ServiceFamily::CONTROL_PLANE,
    profile: BuildProfile::UserspaceApp,
    bundle: BundleClass::RuntimeControlQuery,
    capabilities: CONTROL_PLANE_DAEMON_CAPS,
    stage: "stage.userspace.shared_canon_portability.s0",
};

pub const XTASK_SURFACE: SurfaceManifest = SurfaceManifest {
    binary_name: "tidefs-xtask",
    family: ServiceFamily::WORKSPACE_TOOLING,
    profile: BuildProfile::TestXtaskStd,
    bundle: BundleClass::DevWorkspace,
    capabilities: XTASK_CAPS,
    stage: "stage.userspace.shared_canon_portability.s0",
};

pub const SURFACES: &[SurfaceManifest] = &[
    POLICY_AUTHORITY_DAEMON_SURFACE,
    POSIX_FILESYSTEM_ADAPTER_DAEMON_SURFACE,
    BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE,
    CONTROL_PLANE_DAEMON_SURFACE,
    XTASK_SURFACE,
];

#[must_use]
pub fn find_surface_by_binary_name(binary_name: &str) -> Option<SurfaceManifest> {
    SURFACES
        .iter()
        .copied()
        .find(|surface| surface.binary_name == binary_name)
}

#[must_use]
pub fn find_surface_by_family(family: ServiceFamily) -> Option<SurfaceManifest> {
    SURFACES
        .iter()
        .copied()
        .find(|surface| surface.family == family)
}

// TURN3_HUMAN_PACKAGE_PROFILE_CATALOG_ALIASES
/// Human-named module for the Package Profile Catalog family.
pub mod package_profile_catalog {
    pub const FAMILY_NAME: &str = "Package Profile Catalog";
    pub const STABLE_SOURCE_LOCATOR: &str = "package_profile_catalog";
    pub const ROLE: &str = "build profile, capability, bundle, and service-surface manifests";

    pub use super::{
        find_surface_by_binary_name, find_surface_by_family, BuildProfile as Profile,
        BundleClass as Bundle, CapabilityClass as Capability, ServiceFamily as Service,
        SurfaceManifest, BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE as BLOCK_VOLUME_ADAPTER_SURFACE,
        CONTROL_PLANE_DAEMON_SURFACE as CONTROL_PLANE_SURFACE,
        POLICY_AUTHORITY_DAEMON_SURFACE as POLICY_AUTHORITY_SURFACE,
        POSIX_FILESYSTEM_ADAPTER_DAEMON_SURFACE as POSIX_FILESYSTEM_ADAPTER_SURFACE, SURFACES,
        XTASK_SURFACE as WORKSPACE_TOOLING_SURFACE,
    };
}

/// Human alias namespace. Prefer `human::package_profile_catalog::*` in new examples.
pub mod human {
    pub mod package_profile_catalog {
        pub use crate::package_profile_catalog::*;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn surfaces_are_stage_bound_to_wave_zero_a() {
        for surface in SURFACES {
            assert_eq!(surface.stage, "stage.userspace.shared_canon_portability.s0");
        }
    }

    #[test]
    fn control_plane_surface_binds_control_query_bundle() {
        assert_eq!(
            CONTROL_PLANE_DAEMON_SURFACE.bundle,
            BundleClass::RuntimeControlQuery
        );
        assert_eq!(
            CONTROL_PLANE_DAEMON_SURFACE.family,
            ServiceFamily::ControlPlane
        );
        assert_eq!(CONTROL_PLANE_DAEMON_SURFACE.human_name(), "Control Plane");
        assert_eq!(CONTROL_PLANE_DAEMON_SURFACE.rust_hint(), "control_plane");
    }

    #[test]
    fn service_family_keeps_internal_ids_and_exposes_human_names() {
        assert_eq!(
            ServiceFamily::POLICY_AUTHORITY,
            ServiceFamily::PolicyAuthority
        );
        assert_eq!(
            ServiceFamily::PolicyAuthority.stable_locator(),
            "policy_authority"
        );
        assert_eq!(
            ServiceFamily::PolicyAuthority.human_name(),
            "Policy Authority"
        );
        assert_eq!(
            ServiceFamily::PosixFilesystemAdapter.human_name(),
            "POSIX Filesystem Adapter"
        );
        assert_eq!(
            ServiceFamily::BlockVolumeAdapter.human_name(),
            "Block Volume Adapter"
        );
        assert_eq!(ServiceFamily::ControlPlane.human_name(), "Control Plane");
    }

    #[test]
    fn block_volume_adapter_surface_binds_userspace_smoke_bundle() {
        assert_eq!(
            BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE.binary_name,
            "tidefs-block-volume-adapter-daemon"
        );
        assert_eq!(
            BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE.bundle,
            BundleClass::RuntimeBlockVolumeUserspace
        );
        assert_eq!(
            BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE.family,
            ServiceFamily::BlockVolumeAdapter
        );
        assert!(BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE
            .capabilities
            .contains(&CapabilityClass::BlockVolumeUserspace));
    }

    #[test]
    fn surface_lookup_finds_exact_binary_names() {
        assert_eq!(
            find_surface_by_binary_name("tidefs-policy-authority-daemon"),
            Some(POLICY_AUTHORITY_DAEMON_SURFACE)
        );
        assert_eq!(
            find_surface_by_binary_name("tidefs-control-plane-daemon"),
            Some(CONTROL_PLANE_DAEMON_SURFACE)
        );
        assert_eq!(find_surface_by_binary_name("tidefs-missing-daemon"), None);
    }

    #[test]
    fn surface_lookup_finds_service_families() {
        assert_eq!(
            find_surface_by_family(ServiceFamily::BlockVolumeAdapter),
            Some(BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE)
        );
        assert_eq!(
            find_surface_by_family(ServiceFamily::WORKSPACE_TOOLING),
            Some(XTASK_SURFACE)
        );
    }

    #[test]
    fn surface_manifest_reports_capability_membership() {
        assert!(POLICY_AUTHORITY_DAEMON_SURFACE.has_capability(CapabilityClass::AuthorityUserspace));
        assert!(
            !POLICY_AUTHORITY_DAEMON_SURFACE.has_capability(CapabilityClass::BlockVolumeUserspace)
        );
    }
}

// ── profile enumeration ──────────────────────────────────────────────

#[test]
fn build_profile_variants_are_exhaustive() {
    let variants = [
        BuildProfile::CorePortable,
        BuildProfile::AllocPortable,
        BuildProfile::UserspaceLibrary,
        BuildProfile::UserspaceApp,
        BuildProfile::TestXtaskStd,
    ];
    let mut seen: &[&str] = &[];
    for v in &variants {
        let id = v.as_str();
        assert!(!id.is_empty(), "empty as_str for {v:?}");
        assert!(!seen.contains(&id), "duplicate as_str for {v:?}");
        seen = &[];
    }
}

#[test]
fn capability_class_variants_are_exhaustive() {
    let variants = [
        CapabilityClass::CanonShared,
        CapabilityClass::AuthorityUserspace,
        CapabilityClass::PosixUserspace,
        CapabilityClass::BlockVolumeUserspace,
        CapabilityClass::ControlSurface,
        CapabilityClass::ObserveGate,
    ];
    for v in &variants {
        assert!(!v.as_str().is_empty());
        assert!(!v.human_name().is_empty());
    }
}

#[test]
fn bundle_class_variants_are_exhaustive() {
    let variants = [
        BundleClass::DevWorkspace,
        BundleClass::RuntimeAuthorityUserspace,
        BundleClass::RuntimePosixUserspace,
        BundleClass::RuntimeBlockVolumeUserspace,
        BundleClass::RuntimeControlQuery,
        BundleClass::ObserveTestGate,
    ];
    for v in &variants {
        assert!(!v.as_str().is_empty());
        assert!(!v.human_name().is_empty());
    }
}

#[test]
fn service_family_variants_are_exhaustive() {
    let variants = [
        ServiceFamily::PolicyAuthority,
        ServiceFamily::PosixFilesystemAdapter,
        ServiceFamily::BlockVolumeAdapter,
        ServiceFamily::ControlPlane,
        ServiceFamily::Xtask,
    ];
    for v in &variants {
        assert!(!v.as_str().is_empty());
        assert!(!v.stable_locator().is_empty());
        assert!(!v.human_name().is_empty());
    }
}

// ── variant-to-profile binding ───────────────────────────────────────

#[test]
fn each_daemon_surface_binds_userspace_app_profile() {
    let daemon_surfaces = [
        POLICY_AUTHORITY_DAEMON_SURFACE,
        POSIX_FILESYSTEM_ADAPTER_DAEMON_SURFACE,
        BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE,
        CONTROL_PLANE_DAEMON_SURFACE,
    ];
    for s in &daemon_surfaces {
        assert_eq!(s.profile, BuildProfile::UserspaceApp);
    }
}

#[test]
fn xtask_surface_binds_test_profile() {
    assert_eq!(XTASK_SURFACE.profile, BuildProfile::TestXtaskStd);
}

// ── bundle activation records ────────────────────────────────────────

#[test]
fn each_surface_binds_correct_bundle() {
    assert_eq!(
        POLICY_AUTHORITY_DAEMON_SURFACE.bundle,
        BundleClass::RuntimeAuthorityUserspace
    );
    assert_eq!(
        POSIX_FILESYSTEM_ADAPTER_DAEMON_SURFACE.bundle,
        BundleClass::RuntimePosixUserspace
    );
    assert_eq!(
        BLOCK_VOLUME_ADAPTER_DAEMON_SURFACE.bundle,
        BundleClass::RuntimeBlockVolumeUserspace
    );
    assert_eq!(
        CONTROL_PLANE_DAEMON_SURFACE.bundle,
        BundleClass::RuntimeControlQuery
    );
    assert_eq!(XTASK_SURFACE.bundle, BundleClass::DevWorkspace);
}

// ── profile identity comparisons ─────────────────────────────────────

#[test]
fn all_enums_support_eq_and_copy() {
    fn assert_eq_copy<T: Eq + Copy>(_: T) {}
    assert_eq_copy(BuildProfile::CorePortable);
    assert_eq_copy(CapabilityClass::CanonShared);
    assert_eq_copy(BundleClass::DevWorkspace);
    assert_eq_copy(ServiceFamily::PolicyAuthority);
}

// ── as_str roundtrip stability ───────────────────────────────────────

#[test]
fn build_profile_as_str_is_stable() {
    assert_eq!(
        BuildProfile::CorePortable.as_str(),
        "profile.environment_boundary.core_portable.p0"
    );
    assert_eq!(
        BuildProfile::AllocPortable.as_str(),
        "profile.environment_boundary.alloc_portable.p1"
    );
    assert_eq!(
        BuildProfile::UserspaceLibrary.as_str(),
        "profile.environment_boundary.userspace_library.p2"
    );
    assert_eq!(
        BuildProfile::UserspaceApp.as_str(),
        "profile.environment_boundary.userspace_app.p3"
    );
    assert_eq!(
        BuildProfile::TestXtaskStd.as_str(),
        "profile.environment_boundary.test_xtask.p6"
    );
}

#[test]
fn capability_class_as_str_is_stable() {
    assert_eq!(
        CapabilityClass::CanonShared.as_str(),
        "cap.package_profile_catalog.canon_shared.c0"
    );
    assert_eq!(
        CapabilityClass::AuthorityUserspace.as_str(),
        "cap.package_profile_catalog.authority_userspace.c1"
    );
    assert_eq!(
        CapabilityClass::PosixUserspace.as_str(),
        "cap.package_profile_catalog.posix_userspace.c2"
    );
    assert_eq!(
        CapabilityClass::BlockVolumeUserspace.as_str(),
        "cap.package_profile_catalog.block_volume_userspace.c3"
    );
    assert_eq!(
        CapabilityClass::ControlSurface.as_str(),
        "cap.package_profile_catalog.control_surface.c4"
    );
    assert_eq!(
        CapabilityClass::ObserveGate.as_str(),
        "cap.package_profile_catalog.observe_gate.c6"
    );
}

#[test]
fn bundle_class_as_str_is_stable() {
    assert_eq!(
        BundleClass::DevWorkspace.as_str(),
        "bundle.package_profile_catalog.dev_workspace.b0"
    );
    assert_eq!(
        BundleClass::RuntimeAuthorityUserspace.as_str(),
        "bundle.package_profile_catalog.runtime.authority_userspace.b2"
    );
    assert_eq!(
        BundleClass::RuntimePosixUserspace.as_str(),
        "bundle.package_profile_catalog.runtime.posix_userspace.b3"
    );
    assert_eq!(
        BundleClass::RuntimeBlockVolumeUserspace.as_str(),
        "bundle.package_profile_catalog.runtime.block_volume_userspace.b4"
    );
    assert_eq!(
        BundleClass::RuntimeControlQuery.as_str(),
        "bundle.package_profile_catalog.runtime.control_query.b5"
    );
    assert_eq!(
        BundleClass::ObserveTestGate.as_str(),
        "bundle.package_profile_catalog.observe_test_gate.b6"
    );
}

// ── catalog query operations ─────────────────────────────────────────

#[test]
fn find_surface_by_binary_name_exhaustive() {
    for expected in SURFACES {
        let found = find_surface_by_binary_name(expected.binary_name);
        assert_eq!(found, Some(*expected));
    }
}

#[test]
fn find_surface_by_binary_name_rejects_unknown() {
    assert_eq!(find_surface_by_binary_name(""), None);
    assert_eq!(find_surface_by_binary_name("unknown-daemon"), None);
    assert_eq!(find_surface_by_binary_name("tidefs-"), None);
}

#[test]
fn find_surface_by_family_exhaustive() {
    for expected in SURFACES {
        let found = find_surface_by_family(expected.family);
        assert_eq!(found, Some(*expected));
    }
}

#[test]
fn surfaces_array_matches_expected_cardinality() {
    assert_eq!(SURFACES.len(), 5);
}

#[test]
fn human_module_exports_all_surfaces() {
    use human::package_profile_catalog::*;
    let _: SurfaceManifest = POLICY_AUTHORITY_SURFACE;
    let _: SurfaceManifest = POSIX_FILESYSTEM_ADAPTER_SURFACE;
    let _: SurfaceManifest = BLOCK_VOLUME_ADAPTER_SURFACE;
    let _: SurfaceManifest = CONTROL_PLANE_SURFACE;
    let _: SurfaceManifest = WORKSPACE_TOOLING_SURFACE;
}

#[test]
fn surface_manifest_fields_expose_human_names() {
    assert_eq!(
        POLICY_AUTHORITY_DAEMON_SURFACE.profile_name(),
        "Userspace application"
    );
    assert_eq!(
        POLICY_AUTHORITY_DAEMON_SURFACE.bundle_name(),
        "Runtime policy-authority userspace"
    );
    assert_eq!(XTASK_SURFACE.bundle_name(), "Development workspace");
}
