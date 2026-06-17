// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use serde::{Deserialize, Serialize};
use tidefs_permission::MountIdentity;

use crate::principal::{PrincipalId, ScopeSelector};

// ---------------------------------------------------------------------------
// Capability grant: fine-grained permission tokens
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct CapabilityGrantId(pub u64);

impl CapabilityGrantId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CapabilityGrantUse {
    pub grant_id: CapabilityGrantId,
    pub principal_id: PrincipalId,
    pub capability: String,
    pub scope: ScopeSelector,
    pub use_count: u32,
    pub max_uses: Option<u32>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CapabilityGrantDenial {
    pub grant_id: CapabilityGrantId,
    pub principal_id: PrincipalId,
    pub requested_capability: String,
    pub requested_scope: ScopeSelector,
    pub reason: CapabilityGrantDenialReason,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum CapabilityGrantDenialReason {
    PrincipalMismatch {
        grant_principal_id: PrincipalId,
        requested_principal_id: PrincipalId,
    },
    ScopeMismatch {
        grant_scope: ScopeSelector,
        requested_scope: ScopeSelector,
    },
    CapabilityMismatch {
        grant_capability: String,
        requested_capability: String,
    },
    Expired {
        expired_at_millis: u64,
        now_millis: u64,
    },
    Exhausted {
        max_uses: u32,
        use_count: u32,
    },
    UseCountOverflow {
        use_count: u32,
    },
    MissingMountIdentity {
        grant_mount_identity: MountIdentity,
    },
    InvalidMountIdentity {
        presented_mount_identity: MountIdentity,
    },
    MountIdentityMismatch {
        grant_mount_identity: MountIdentity,
        presented_mount_identity: MountIdentity,
    },
}

pub type CapabilityGrantConsumeResult = Result<CapabilityGrantUse, CapabilityGrantDenial>;

impl std::fmt::Display for CapabilityGrantDenialReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrincipalMismatch {
                grant_principal_id,
                requested_principal_id,
            } => write!(
                f,
                "principal {requested_principal_id:?} does not match grant principal {grant_principal_id:?}"
            ),
            Self::ScopeMismatch {
                grant_scope,
                requested_scope,
            } => write!(
                f,
                "scope {requested_scope:?} is not covered by grant scope {grant_scope:?}"
            ),
            Self::CapabilityMismatch {
                grant_capability,
                requested_capability,
            } => write!(
                f,
                "capability '{requested_capability}' does not match grant capability '{grant_capability}'"
            ),
            Self::Expired {
                expired_at_millis,
                now_millis,
            } => write!(
                f,
                "capability grant expired at {expired_at_millis} (now {now_millis})"
            ),
            Self::Exhausted {
                max_uses,
                use_count,
            } => write!(
                f,
                "capability grant exhausted after {use_count} of {max_uses} uses"
            ),
            Self::UseCountOverflow { use_count } => {
                write!(f, "capability grant use count overflow at {use_count}")
            }
            Self::MissingMountIdentity {
                grant_mount_identity,
            } => write!(
                f,
                "capability grant requires mount identity {grant_mount_identity:?}"
            ),
            Self::InvalidMountIdentity {
                presented_mount_identity,
            } => write!(
                f,
                "capability grant was presented with invalid mount identity {presented_mount_identity:?}"
            ),
            Self::MountIdentityMismatch {
                grant_mount_identity,
                presented_mount_identity,
            } => write!(
                f,
                "capability grant mount identity {grant_mount_identity:?} does not match presented mount identity {presented_mount_identity:?}"
            ),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CapabilityGrant {
    pub grant_id: CapabilityGrantId,
    pub principal_id: PrincipalId,
    pub capability: String,
    pub scope: ScopeSelector,
    pub issued_at_millis: u64,
    pub expires_at_millis: Option<u64>,
    pub max_uses: Option<u32>,
    pub use_count: u32,
    pub mount_identity: Option<MountIdentity>,
}

impl CapabilityGrant {
    pub fn new(
        grant_id: CapabilityGrantId,
        principal_id: PrincipalId,
        capability: String,
        scope: ScopeSelector,
    ) -> Self {
        let now = crate::identity::current_time_utils();
        Self {
            grant_id,
            principal_id,
            capability,
            scope,
            issued_at_millis: now,
            expires_at_millis: None,
            max_uses: None,
            use_count: 0,
            mount_identity: None,
        }
    }

    pub fn with_ttl(mut self, ttl_millis: u64) -> Self {
        self.expires_at_millis = Some(self.issued_at_millis + ttl_millis);
        self
    }

    pub fn with_max_uses(mut self, max: u32) -> Self {
        self.max_uses = Some(max);
        self
    }

    pub fn with_mount_identity(mut self, mount_identity: MountIdentity) -> Self {
        self.mount_identity = Some(mount_identity);
        self
    }

    pub fn is_valid(&self) -> bool {
        let now_millis = crate::identity::current_time_utils();
        if self
            .expires_at_millis
            .is_some_and(|expired_at_millis| now_millis >= expired_at_millis)
        {
            return false;
        }

        if self
            .max_uses
            .is_some_and(|max_uses| self.use_count >= max_uses)
        {
            return false;
        }

        true
    }

    pub fn is_valid_for_mount(&self, mount_identity: &MountIdentity) -> bool {
        if !mount_identity.is_valid() {
            return false;
        }

        match self.mount_identity {
            Some(bound) => bound.is_valid() && bound == *mount_identity,
            None => true,
        }
    }

    pub fn is_valid_with_mount(&self, mount_identity: &MountIdentity) -> bool {
        self.is_valid() && self.is_valid_for_mount(mount_identity)
    }

    pub fn consume(
        &mut self,
        principal_id: PrincipalId,
        requested_scope: &ScopeSelector,
        requested_capability: &str,
    ) -> CapabilityGrantConsumeResult {
        if let Some(grant_mount_identity) = self.mount_identity {
            return Err(self.denial(
                principal_id,
                requested_scope,
                requested_capability,
                CapabilityGrantDenialReason::MissingMountIdentity {
                    grant_mount_identity,
                },
            ));
        }

        self.consume_unbound(principal_id, requested_scope, requested_capability)
    }

    pub fn consume_for_mount(
        &mut self,
        principal_id: PrincipalId,
        requested_scope: &ScopeSelector,
        requested_capability: &str,
        mount_identity: &MountIdentity,
    ) -> CapabilityGrantConsumeResult {
        if !mount_identity.is_valid() {
            return Err(self.denial(
                principal_id,
                requested_scope,
                requested_capability,
                CapabilityGrantDenialReason::InvalidMountIdentity {
                    presented_mount_identity: *mount_identity,
                },
            ));
        }

        if let Some(grant_mount_identity) = self.mount_identity {
            if !grant_mount_identity.is_valid() || grant_mount_identity != *mount_identity {
                return Err(self.denial(
                    principal_id,
                    requested_scope,
                    requested_capability,
                    CapabilityGrantDenialReason::MountIdentityMismatch {
                        grant_mount_identity,
                        presented_mount_identity: *mount_identity,
                    },
                ));
            }
        }

        self.consume_unbound(principal_id, requested_scope, requested_capability)
    }

    fn consume_unbound(
        &mut self,
        principal_id: PrincipalId,
        requested_scope: &ScopeSelector,
        requested_capability: &str,
    ) -> CapabilityGrantConsumeResult {
        if self.principal_id != principal_id {
            return Err(self.denial(
                principal_id,
                requested_scope,
                requested_capability,
                CapabilityGrantDenialReason::PrincipalMismatch {
                    grant_principal_id: self.principal_id,
                    requested_principal_id: principal_id,
                },
            ));
        }

        if !grant_scope_covers(&self.scope, requested_scope) {
            return Err(self.denial(
                principal_id,
                requested_scope,
                requested_capability,
                CapabilityGrantDenialReason::ScopeMismatch {
                    grant_scope: self.scope.clone(),
                    requested_scope: requested_scope.clone(),
                },
            ));
        }

        if self.capability != requested_capability {
            return Err(self.denial(
                principal_id,
                requested_scope,
                requested_capability,
                CapabilityGrantDenialReason::CapabilityMismatch {
                    grant_capability: self.capability.clone(),
                    requested_capability: requested_capability.to_string(),
                },
            ));
        }

        let now_millis = crate::identity::current_time_utils();
        if let Some(expired_at_millis) = self.expires_at_millis {
            if now_millis >= expired_at_millis {
                return Err(self.denial(
                    principal_id,
                    requested_scope,
                    requested_capability,
                    CapabilityGrantDenialReason::Expired {
                        expired_at_millis,
                        now_millis,
                    },
                ));
            }
        }

        if let Some(max_uses) = self.max_uses {
            if self.use_count >= max_uses {
                return Err(self.denial(
                    principal_id,
                    requested_scope,
                    requested_capability,
                    CapabilityGrantDenialReason::Exhausted {
                        max_uses,
                        use_count: self.use_count,
                    },
                ));
            }
        }

        let use_count = self.use_count.checked_add(1).ok_or_else(|| {
            self.denial(
                principal_id,
                requested_scope,
                requested_capability,
                CapabilityGrantDenialReason::UseCountOverflow {
                    use_count: self.use_count,
                },
            )
        })?;
        self.use_count = use_count;

        Ok(CapabilityGrantUse {
            grant_id: self.grant_id,
            principal_id,
            capability: self.capability.clone(),
            scope: requested_scope.clone(),
            use_count,
            max_uses: self.max_uses,
        })
    }

    fn denial(
        &self,
        principal_id: PrincipalId,
        requested_scope: &ScopeSelector,
        requested_capability: &str,
        reason: CapabilityGrantDenialReason,
    ) -> CapabilityGrantDenial {
        CapabilityGrantDenial {
            grant_id: self.grant_id,
            principal_id,
            requested_capability: requested_capability.to_string(),
            requested_scope: requested_scope.clone(),
            reason,
        }
    }
}

fn grant_scope_covers(grant_scope: &ScopeSelector, requested_scope: &ScopeSelector) -> bool {
    match grant_scope {
        ScopeSelector::All => true,
        ScopeSelector::Path(prefix) => match requested_scope {
            ScopeSelector::Path(path) => path.starts_with(prefix.as_str()),
            _ => false,
        },
        _ => grant_scope == requested_scope,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mount_a() -> MountIdentity {
        MountIdentity::new(
            [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10,
            ],
            1,
        )
    }

    fn make_mount_b() -> MountIdentity {
        MountIdentity::new(
            [
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
                0x1f, 0x20,
            ],
            2,
        )
    }

    #[test]
    fn grant_id_new_roundtrip() {
        let id = CapabilityGrantId::new(42);
        assert_eq!(id.0, 42);
    }

    #[test]
    fn grant_consume_increments_once() {
        let mut grant = CapabilityGrant::new(
            CapabilityGrantId::new(1),
            PrincipalId::new(100),
            "read".into(),
            ScopeSelector::All,
        );
        assert_eq!(grant.use_count, 0);
        let use_record = grant
            .consume(PrincipalId::new(100), &ScopeSelector::All, "read")
            .expect("grant should consume");
        assert_eq!(use_record.use_count, 1);
        assert_eq!(grant.use_count, 1);
    }

    #[test]
    fn grant_with_ttl_sets_expiration() {
        let grant = CapabilityGrant::new(
            CapabilityGrantId::new(1),
            PrincipalId::new(100),
            "write".into(),
            ScopeSelector::Cluster { cluster_id: 1 },
        )
        .with_ttl(60_000);
        assert!(grant.expires_at_millis.is_some());
        assert_eq!(
            grant.expires_at_millis.unwrap(),
            grant.issued_at_millis + 60_000
        );
    }

    #[test]
    fn grant_with_max_uses_sets_limit() {
        let grant = CapabilityGrant::new(
            CapabilityGrantId::new(2),
            PrincipalId::new(200),
            "admin".into(),
            ScopeSelector::All,
        )
        .with_max_uses(5);
        assert_eq!(grant.max_uses, Some(5));
    }

    #[test]
    fn grant_consume_allows_unlimited_uses_when_no_max() {
        let mut grant = CapabilityGrant::new(
            CapabilityGrantId::new(1),
            PrincipalId::new(100),
            "read".into(),
            ScopeSelector::All,
        );
        assert!(grant
            .consume(PrincipalId::new(100), &ScopeSelector::All, "read")
            .is_ok());
        assert!(grant
            .consume(PrincipalId::new(100), &ScopeSelector::All, "read")
            .is_ok());
        assert_eq!(grant.use_count, 2);
    }

    #[test]
    fn grant_consume_final_use_succeeds_once() {
        let mut grant = CapabilityGrant::new(
            CapabilityGrantId::new(1),
            PrincipalId::new(100),
            "read".into(),
            ScopeSelector::All,
        )
        .with_max_uses(2);
        assert_eq!(
            grant
                .consume(PrincipalId::new(100), &ScopeSelector::All, "read")
                .expect("first use should succeed")
                .use_count,
            1
        );
        assert_eq!(
            grant
                .consume(PrincipalId::new(100), &ScopeSelector::All, "read")
                .expect("last allowed use should succeed")
                .use_count,
            2
        );
        let denial = grant
            .consume(PrincipalId::new(100), &ScopeSelector::All, "read")
            .expect_err("next use should be denied");
        assert!(matches!(
            denial.reason,
            CapabilityGrantDenialReason::Exhausted {
                max_uses: 2,
                use_count: 2
            }
        ));
        assert_eq!(grant.use_count, 2);
    }

    #[test]
    fn grant_consume_denies_expired_without_increment() {
        let mut grant = CapabilityGrant::new(
            CapabilityGrantId::new(1),
            PrincipalId::new(100),
            "read".into(),
            ScopeSelector::All,
        );
        grant.expires_at_millis = Some(1);
        let denial = grant
            .consume(PrincipalId::new(100), &ScopeSelector::All, "read")
            .expect_err("expired grant should be denied");
        assert!(matches!(
            denial.reason,
            CapabilityGrantDenialReason::Expired { .. }
        ));
        assert_eq!(grant.use_count, 0);
    }

    #[test]
    fn grant_consume_denies_principal_mismatch_without_increment() {
        let mut grant = CapabilityGrant::new(
            CapabilityGrantId::new(1),
            PrincipalId::new(100),
            "read".into(),
            ScopeSelector::All,
        );
        let denial = grant
            .consume(PrincipalId::new(101), &ScopeSelector::All, "read")
            .expect_err("wrong principal should be denied");
        assert!(matches!(
            denial.reason,
            CapabilityGrantDenialReason::PrincipalMismatch {
                grant_principal_id: PrincipalId(100),
                requested_principal_id: PrincipalId(101)
            }
        ));
        assert_eq!(grant.use_count, 0);
    }

    #[test]
    fn grant_consume_denies_scope_mismatch_without_increment() {
        let mut grant = CapabilityGrant::new(
            CapabilityGrantId::new(1),
            PrincipalId::new(100),
            "read".into(),
            ScopeSelector::Cluster { cluster_id: 1 },
        );
        let denial = grant
            .consume(
                PrincipalId::new(100),
                &ScopeSelector::Cluster { cluster_id: 2 },
                "read",
            )
            .expect_err("wrong scope should be denied");
        assert!(matches!(
            denial.reason,
            CapabilityGrantDenialReason::ScopeMismatch { .. }
        ));
        assert_eq!(grant.use_count, 0);
    }

    #[test]
    fn grant_consume_denies_capability_mismatch_without_increment() {
        let mut grant = CapabilityGrant::new(
            CapabilityGrantId::new(1),
            PrincipalId::new(100),
            "read".into(),
            ScopeSelector::All,
        );
        let denial = grant
            .consume(PrincipalId::new(100), &ScopeSelector::All, "write")
            .expect_err("wrong capability should be denied");
        assert!(matches!(
            denial.reason,
            CapabilityGrantDenialReason::CapabilityMismatch { .. }
        ));
        assert_eq!(grant.use_count, 0);
    }

    #[test]
    fn grant_consume_all_scope_covers_requested_scope() {
        let mut grant = CapabilityGrant::new(
            CapabilityGrantId::new(1),
            PrincipalId::new(100),
            "read".into(),
            ScopeSelector::All,
        );
        assert!(grant
            .consume(
                PrincipalId::new(100),
                &ScopeSelector::Volume { volume_id: 7 },
                "read"
            )
            .is_ok());
    }

    #[test]
    fn grant_with_mount_identity_stores_binding() {
        let mount = make_mount_a();
        let grant = CapabilityGrant::new(
            CapabilityGrantId::new(1),
            PrincipalId::new(100),
            "read".into(),
            ScopeSelector::All,
        )
        .with_mount_identity(mount);

        assert_eq!(grant.mount_identity, Some(mount));
    }

    #[test]
    fn grant_unbound_valid_for_any_valid_mount() {
        let grant = CapabilityGrant::new(
            CapabilityGrantId::new(1),
            PrincipalId::new(100),
            "read".into(),
            ScopeSelector::All,
        );

        assert!(grant.is_valid_for_mount(&make_mount_a()));
        assert!(grant.is_valid_for_mount(&make_mount_b()));
        assert!(!grant.is_valid_for_mount(&MountIdentity::default()));
    }

    #[test]
    fn grant_bound_to_mount_rejects_different_mount() {
        let mount_a = make_mount_a();
        let mount_b = make_mount_b();
        let grant = CapabilityGrant::new(
            CapabilityGrantId::new(1),
            PrincipalId::new(100),
            "read".into(),
            ScopeSelector::All,
        )
        .with_mount_identity(mount_a);

        assert!(grant.is_valid_for_mount(&mount_a));
        assert!(!grant.is_valid_for_mount(&mount_b));
    }

    #[test]
    fn grant_is_valid_with_mount_checks_both_time_and_mount() {
        let mount_a = make_mount_a();
        let mount_b = make_mount_b();
        let mut grant = CapabilityGrant::new(
            CapabilityGrantId::new(1),
            PrincipalId::new(100),
            "read".into(),
            ScopeSelector::All,
        )
        .with_max_uses(1)
        .with_mount_identity(mount_a);

        assert!(grant.is_valid_with_mount(&mount_a));
        assert!(!grant.is_valid_with_mount(&mount_b));
        assert!(grant
            .consume_for_mount(PrincipalId::new(100), &ScopeSelector::All, "read", &mount_a)
            .is_ok());
        assert!(!grant.is_valid_with_mount(&mount_a));
    }

    #[test]
    fn grant_consume_without_mount_rejects_bound_grant() {
        let mount = make_mount_a();
        let mut grant = CapabilityGrant::new(
            CapabilityGrantId::new(1),
            PrincipalId::new(100),
            "read".into(),
            ScopeSelector::All,
        )
        .with_mount_identity(mount);

        let denial = grant
            .consume(PrincipalId::new(100), &ScopeSelector::All, "read")
            .expect_err("mount-bound grant must fail closed without a mount identity");
        assert!(matches!(
            denial.reason,
            CapabilityGrantDenialReason::MissingMountIdentity {
                grant_mount_identity
            } if grant_mount_identity == mount
        ));
        assert_eq!(grant.use_count, 0);
    }

    #[test]
    fn grant_consume_for_mount_accepts_matching_bound_grant() {
        let mount = make_mount_a();
        let mut grant = CapabilityGrant::new(
            CapabilityGrantId::new(1),
            PrincipalId::new(100),
            "read".into(),
            ScopeSelector::All,
        )
        .with_mount_identity(mount);

        let use_record = grant
            .consume_for_mount(PrincipalId::new(100), &ScopeSelector::All, "read", &mount)
            .expect("matching mount identity should consume");
        assert_eq!(use_record.use_count, 1);
        assert_eq!(grant.use_count, 1);
    }

    #[test]
    fn grant_consume_for_mount_rejects_different_mount() {
        let mount_a = make_mount_a();
        let mount_b = make_mount_b();
        let mut grant = CapabilityGrant::new(
            CapabilityGrantId::new(1),
            PrincipalId::new(100),
            "read".into(),
            ScopeSelector::All,
        )
        .with_mount_identity(mount_a);

        let denial = grant
            .consume_for_mount(PrincipalId::new(100), &ScopeSelector::All, "read", &mount_b)
            .expect_err("different mount identity should be denied");
        assert!(matches!(
            denial.reason,
            CapabilityGrantDenialReason::MountIdentityMismatch {
                grant_mount_identity,
                presented_mount_identity,
            } if grant_mount_identity == mount_a && presented_mount_identity == mount_b
        ));
        assert_eq!(grant.use_count, 0);
    }

    #[test]
    fn grant_consume_for_mount_rejects_invalid_mount() {
        let invalid_mount = MountIdentity::default();
        let mut grant = CapabilityGrant::new(
            CapabilityGrantId::new(1),
            PrincipalId::new(100),
            "read".into(),
            ScopeSelector::All,
        );

        let denial = grant
            .consume_for_mount(
                PrincipalId::new(100),
                &ScopeSelector::All,
                "read",
                &invalid_mount,
            )
            .expect_err("invalid mount identity should be denied");
        assert!(matches!(
            denial.reason,
            CapabilityGrantDenialReason::InvalidMountIdentity {
                presented_mount_identity
            } if presented_mount_identity == invalid_mount
        ));
        assert_eq!(grant.use_count, 0);
    }
}
