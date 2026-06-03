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

    /// Whether this grant is still valid.
    pub fn is_valid(&self) -> bool {
        // Check expiration
        if let Some(exp) = self.expires_at_millis {
            if crate::identity::current_time_utils() > exp {
                return false;
            }
        }

        // Check use count
        if let Some(max) = self.max_uses {
            if self.use_count >= max {
                return false;
            }
        }

        true
    }

    /// Record a use of this grant.
    pub fn record_use(&mut self) {
        self.use_count += 1;
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
    fn grant_record_use_increments() {
        let mut grant = CapabilityGrant::new(
            CapabilityGrantId::new(1),
            PrincipalId::new(100),
            "read".into(),
            ScopeSelector::All,
        );
        assert_eq!(grant.use_count, 0);
        grant.record_use();
        assert_eq!(grant.use_count, 1);
        grant.record_use();
        assert_eq!(grant.use_count, 2);
        grant.record_use();
        assert_eq!(grant.use_count, 3);
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
    fn grant_is_valid_when_no_expiry_and_under_max_uses() {
        let mut grant = CapabilityGrant::new(
            CapabilityGrantId::new(1),
            PrincipalId::new(100),
            "read".into(),
            ScopeSelector::All,
        );
        assert!(grant.is_valid());
        grant.record_use();
        assert!(grant.is_valid());
    }

    #[test]
    fn grant_is_valid_respects_max_uses() {
        let mut grant = CapabilityGrant::new(
            CapabilityGrantId::new(1),
            PrincipalId::new(100),
            "read".into(),
            ScopeSelector::All,
        )
        .with_max_uses(2);
        assert!(grant.is_valid());
        grant.record_use();
        assert!(grant.is_valid());
        grant.record_use();
        assert!(!grant.is_valid());
    }
}
