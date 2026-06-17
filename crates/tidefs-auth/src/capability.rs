use serde::{Deserialize, Serialize};

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

    pub fn consume(
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
}
