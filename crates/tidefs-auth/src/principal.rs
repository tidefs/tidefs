use ed25519_dalek::{Keypair, Signer};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Principal model: who can do what
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PrincipalClass {
    /// Person identity — observe, stage, publish, override
    HumanOperator,
    /// Daemon identity — bounded by service family and scope
    Service,
    /// Node identity — proves membership but not policy authority
    ClusterNode,
    /// Read-mostly — inspect receipts, decisions, audit chains
    Auditor,
    /// Emergency — short-lived, dual-controlled, heavily audited
    Breakglass,
}

impl std::fmt::Display for PrincipalClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HumanOperator => write!(f, "human_operator"),
            Self::Service => write!(f, "service"),
            Self::ClusterNode => write!(f, "cluster_node"),
            Self::Auditor => write!(f, "auditor"),
            Self::Breakglass => write!(f, "breakglass"),
        }
    }
}

#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord,
)]
pub struct PrincipalId(pub u64);

impl PrincipalId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord,
)]
pub struct RoleBindingId(pub u64);

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    pub principal_id: PrincipalId,
    pub class: PrincipalClass,
    pub node_id: u64,
    pub roles: Vec<RoleBinding>,
    pub created_at_millis: u64,
}

impl Principal {
    pub fn new(
        principal_id: PrincipalId,
        class: PrincipalClass,
        node_id: u64,
        roles: Vec<RoleBinding>,
    ) -> Self {
        let now = crate::identity::current_time_utils();
        Self {
            principal_id,
            class,
            node_id,
            roles,
            created_at_millis: now,
        }
    }

    /// Whether this principal has a role granting the given capability.
    pub fn has_capability(&self, capability: &str) -> bool {
        self.roles
            .iter()
            .any(|role| role.capabilities.iter().any(|cap| cap == capability))
    }

    /// Whether this principal matches the required class.
    pub fn has_class(&self, class: PrincipalClass) -> bool {
        self.class == class
    }

    /// Whether this principal's roles grant all of the given capabilities.
    pub fn has_all_capabilities(&self, capabilities: &[&str]) -> bool {
        capabilities.iter().all(|cap| self.has_capability(cap))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RoleBinding {
    pub binding_id: RoleBindingId,
    pub role_name: String,
    pub capabilities: Vec<String>,
    pub scope: ScopeSelector,
    pub granted_at_millis: u64,
    pub expires_at_millis: Option<u64>,
    /// Signature by the authority that granted this role
    pub grant_signature: Vec<u8>,
}

impl RoleBinding {
    pub fn new(
        binding_id: RoleBindingId,
        role_name: String,
        capabilities: Vec<String>,
        scope: ScopeSelector,
        signing_key: &Keypair,
    ) -> Self {
        let now = crate::identity::current_time_utils();
        let mut binding = Self {
            binding_id,
            role_name,
            capabilities,
            scope,
            granted_at_millis: now,
            expires_at_millis: None,
            grant_signature: Vec::new(),
        };

        // Sign the role binding
        let preimage = binding.preimage_for_signing();
        binding.grant_signature = signing_key.sign(&preimage).to_bytes().to_vec();

        binding
    }

    pub fn with_ttl(mut self, ttl_millis: u64) -> Self {
        self.expires_at_millis = Some(self.granted_at_millis + ttl_millis);
        self
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_at_millis {
            crate::identity::current_time_utils() > expires
        } else {
            false
        }
    }

    fn preimage_for_signing(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.binding_id.0.to_le_bytes());
        buf.extend_from_slice(self.role_name.as_bytes());
        for cap in &self.capabilities {
            buf.extend_from_slice(cap.as_bytes());
            buf.push(0);
        }
        buf.extend_from_slice(self.scope.to_string().as_bytes());
        buf.extend_from_slice(&self.granted_at_millis.to_le_bytes());
        if let Some(exp) = self.expires_at_millis {
            buf.extend_from_slice(&exp.to_le_bytes());
        }
        buf
    }
}

// ---------------------------------------------------------------------------
// Scope selector: what resource(s) the role applies to
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ScopeSelector {
    /// Unrestricted — applies to all resources
    All,
    /// Cluster-scoped: /cluster/{cluster_id}
    Cluster { cluster_id: u64 },
    /// Node-scoped: /node/{node_id}
    Node { node_id: u64 },
    /// Volume-scoped: /volume/{volume_id}
    Volume { volume_id: u64 },
    /// Snapshot-scoped: /snapshot/{snapshot_id}
    Snapshot { snapshot_id: u64 },
    /// Custom path: e.g. "/policy/retention/" or "/observe/validation/"
    Path(String),
}

impl std::fmt::Display for ScopeSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::All => write!(f, "*"),
            Self::Cluster { cluster_id } => write!(f, "/cluster/{cluster_id}"),
            Self::Node { node_id } => write!(f, "/node/{node_id}"),
            Self::Volume { volume_id } => write!(f, "/volume/{volume_id}"),
            Self::Snapshot { snapshot_id } => write!(f, "/snapshot/{snapshot_id}"),
            Self::Path(p) => write!(f, "{p}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Principal predicates ---

    fn make_principal(roles: Vec<RoleBinding>) -> Principal {
        Principal {
            principal_id: PrincipalId::new(1),
            class: PrincipalClass::Service,
            node_id: 10,
            roles,
            created_at_millis: 1000,
        }
    }

    fn make_role_binding(name: &str, capabilities: Vec<String>) -> RoleBinding {
        RoleBinding {
            binding_id: RoleBindingId(1),
            role_name: name.into(),
            capabilities,
            scope: ScopeSelector::All,
            granted_at_millis: 1000,
            expires_at_millis: None,
            grant_signature: vec![],
        }
    }

    #[test]
    fn principal_has_capability_direct_match() {
        let binding = make_role_binding("reader", vec!["read".into()]);
        let p = make_principal(vec![binding]);
        assert!(p.has_capability("read"));
        assert!(!p.has_capability("write"));
    }

    #[test]
    fn principal_has_capability_multiple_roles() {
        let r1 = make_role_binding("reader", vec!["read".into()]);
        let r2 = make_role_binding("writer", vec!["write".into(), "append".into()]);
        let p = make_principal(vec![r1, r2]);
        assert!(p.has_capability("read"));
        assert!(p.has_capability("write"));
        assert!(p.has_capability("append"));
        assert!(!p.has_capability("admin"));
    }

    #[test]
    fn principal_has_capability_no_roles() {
        let p = make_principal(vec![]);
        assert!(!p.has_capability("read"));
    }

    #[test]
    fn principal_has_class_match() {
        let p = make_principal(vec![]);
        assert!(p.has_class(PrincipalClass::Service));
        assert!(!p.has_class(PrincipalClass::HumanOperator));
    }

    #[test]
    fn principal_has_all_capabilities_all_present() {
        let binding = make_role_binding(
            "admin",
            vec!["read".into(), "write".into(), "delete".into()],
        );
        let p = make_principal(vec![binding]);
        assert!(p.has_all_capabilities(&["read", "write"]));
        assert!(p.has_all_capabilities(&["read", "write", "delete"]));
    }

    #[test]
    fn principal_has_all_capabilities_partial() {
        let binding = make_role_binding("reader", vec!["read".into()]);
        let p = make_principal(vec![binding]);
        assert!(!p.has_all_capabilities(&["read", "write"]));
    }

    #[test]
    fn principal_has_all_capabilities_empty_list() {
        let binding = make_role_binding("reader", vec!["read".into()]);
        let p = make_principal(vec![binding]);
        assert!(p.has_all_capabilities(&[]));
    }

    // --- Display impls ---

    #[test]
    fn principal_class_display() {
        assert_eq!(PrincipalClass::HumanOperator.to_string(), "human_operator");
        assert_eq!(PrincipalClass::Service.to_string(), "service");
        assert_eq!(PrincipalClass::ClusterNode.to_string(), "cluster_node");
        assert_eq!(PrincipalClass::Auditor.to_string(), "auditor");
        assert_eq!(PrincipalClass::Breakglass.to_string(), "breakglass");
    }

    #[test]
    fn scope_selector_display() {
        assert_eq!(ScopeSelector::All.to_string(), "*");
        assert_eq!(
            ScopeSelector::Cluster { cluster_id: 42 }.to_string(),
            "/cluster/42"
        );
        assert_eq!(ScopeSelector::Node { node_id: 7 }.to_string(), "/node/7");
        assert_eq!(
            ScopeSelector::Volume { volume_id: 100 }.to_string(),
            "/volume/100"
        );
        assert_eq!(
            ScopeSelector::Snapshot { snapshot_id: 3 }.to_string(),
            "/snapshot/3"
        );
        assert_eq!(
            ScopeSelector::Path("/observe/validation".into()).to_string(),
            "/observe/validation"
        );
    }

    #[test]
    fn principal_id_new_roundtrip() {
        let id = PrincipalId::new(99);
        assert_eq!(id.0, 99);
    }

    #[test]
    fn role_binding_id_default() {
        let id = RoleBindingId::default();
        assert_eq!(id.0, 0);
    }
}
