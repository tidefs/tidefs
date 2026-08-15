// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Runtime authority spine: single source of truth for the active transport
//! backend, wired through membership, placement, and replication.
//!
//! The [`RuntimeAuthority`] struct holds the [`BackendDisclosure`] that every
//! subsystem consults. It eliminates separate deterministic-only and
//! live-only truth paths by establishing one coherent configuration surface
//! at storage-node startup.
//!
//! This spine is daemon-internal backend disclosure. It is not final
//! distributed operator UAPI, does not authorize cluster pool prototype
//! commands, and does not turn placement/heal exercises into operator status
//! or repair authority. Public `cluster status` must still route through a
//! reachable live owner and fail closed when no owner can provide evidence.

use std::net::SocketAddr;
use std::sync::Arc;

use tidefs_auth::{NodeKeyStore, NodePrivateCredential, NodePublicIdentity};
use tidefs_membership_epoch::MemberClass;
use tidefs_membership_live::BackendDisclosure;
use tidefs_transport::{
    config::{TransportConfig, TransportConfigBuilder},
    TransportAddr,
};

/// Single authority spine constructed at storage-node startup.
///
/// Holds the disclosed backend, a derived transport configuration, and
/// initialization parameters shared by membership, placement, and
/// replication. This type is storage-node runtime evidence only; it is not a
/// final distributed operator surface.
#[derive(Clone, Debug)]
pub struct RuntimeAuthority {
    disclosure: BackendDisclosure,
    transport_config: TransportConfig,
    node_id: u64,
    member_class: Option<MemberClass>,
    failure_domain: Option<u64>,
    replication_factor: u8,
    transport_identity: Option<ProvisionedTransportIdentity>,
}

/// Exact provisioned identity and trust set for the live storage-node
/// transport. Private credential bytes remain host-local and are redacted by
/// [`NodePrivateCredential`].
#[derive(Clone, Debug)]
pub struct ProvisionedTransportIdentity {
    local_credential: Arc<NodePrivateCredential>,
    trusted_peers: Vec<NodePublicIdentity>,
}

impl ProvisionedTransportIdentity {
    fn new(
        local_credential: NodePrivateCredential,
        trusted_peers: Vec<NodePublicIdentity>,
    ) -> Result<Self, String> {
        let local_identity = local_credential.public_identity().into_identity();
        let mut exact_trust = NodeKeyStore::new();
        exact_trust
            .register(local_identity)
            .map_err(|error| format!("register local transport identity: {error}"))?;
        for identity in &trusted_peers {
            if let Some(existing) = exact_trust.identities.get(&identity.node_id()) {
                if existing != identity.identity() {
                    return Err(format!(
                        "transport trust contains conflicting identities for node {}",
                        identity.node_id()
                    ));
                }
                continue;
            }
            exact_trust
                .register(identity.identity().clone())
                .map_err(|error| format!("register trusted transport identity: {error}"))?;
        }
        Ok(Self {
            local_credential: Arc::new(local_credential),
            trusted_peers,
        })
    }

    #[must_use]
    pub fn local_credential(&self) -> Arc<NodePrivateCredential> {
        Arc::clone(&self.local_credential)
    }

    #[must_use]
    pub fn trusted_peers(&self) -> &[NodePublicIdentity] {
        &self.trusted_peers
    }
}

impl RuntimeAuthority {
    /// Build the authority spine from a backend disclosure and node
    /// parameters.  Derives a [`TransportConfig`] from the disclosure
    /// so every subsystem sees the same transport settings.
    pub fn build(
        disclosure: BackendDisclosure,
        node_id: u64,
        member_class: Option<MemberClass>,
        failure_domain: Option<u64>,
        replication_factor: u8,
    ) -> Result<Self, String> {
        let transport_config = derive_transport_config(&disclosure, node_id)?;
        Ok(Self {
            disclosure,
            transport_config,
            node_id,
            member_class,
            failure_domain,
            replication_factor,
            transport_identity: None,
        })
    }

    /// Bind this live authority to one exact local credential and an explicit
    /// peer trust set. Numeric node identity is derived from the credential.
    pub fn with_transport_identity(
        mut self,
        local_credential: NodePrivateCredential,
        trusted_peers: Vec<NodePublicIdentity>,
    ) -> Result<Self, String> {
        if local_credential.node_id() != self.node_id {
            return Err(format!(
                "transport credential names node {}, expected configured storage node {}",
                local_credential.node_id(),
                self.node_id
            ));
        }
        if trusted_peers.is_empty() {
            return Err("provisioned transport trust set must not be empty".to_string());
        }
        self.transport_identity = Some(ProvisionedTransportIdentity::new(
            local_credential,
            trusted_peers,
        )?);
        Ok(self)
    }

    /// The disclosed active backend.
    #[must_use]
    pub fn backend(&self) -> &BackendDisclosure {
        &self.disclosure
    }

    /// Transport configuration derived from the backend choice.
    #[must_use]
    pub fn transport_config(&self) -> &TransportConfig {
        &self.transport_config
    }

    /// Node identifier for this storage node.
    #[must_use]
    pub fn node_id(&self) -> u64 {
        self.node_id
    }

    /// Member class (Voter, Learner, DataOnly, etc.), if configured.
    #[must_use]
    pub fn member_class(&self) -> Option<MemberClass> {
        self.member_class
    }

    /// Failure domain identifier, if configured.
    #[must_use]
    pub fn failure_domain(&self) -> Option<u64> {
        self.failure_domain
    }

    /// Configured replication factor.
    #[must_use]
    pub fn replication_factor(&self) -> u8 {
        self.replication_factor
    }

    #[must_use]
    pub fn transport_identity(&self) -> Option<&ProvisionedTransportIdentity> {
        self.transport_identity.as_ref()
    }

    /// Returns `true` when the backend uses a real network transport.
    /// Delegates to [`BackendDisclosure::is_live`]. This is backend
    /// disclosure only, not cluster status or repair authority.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.disclosure.is_live()
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

fn default_endpoint_for_disclosure(
    disclosure: &BackendDisclosure,
) -> Result<TransportAddr, String> {
    match disclosure {
        BackendDisclosure::Tcp(addr) => Ok(TransportAddr::Tcp(*addr)),
        BackendDisclosure::Rdma(addr) => {
            if let Ok(endpoint) = addr.parse::<TransportAddr>() {
                return match endpoint {
                    TransportAddr::Rdma { .. } | TransportAddr::Tcp(_) => Ok(endpoint),
                    TransportAddr::Unix(_) => Err(format!(
                        "RDMA disclosure cannot use a Unix transport endpoint `{addr}`"
                    )),
                };
            }

            if let Ok(tcp_fallback) = addr.parse::<SocketAddr>() {
                return Ok(TransportAddr::Tcp(tcp_fallback));
            }

            Err(format!(
                "RDMA disclosure must use an rdma:// TransportAddr or TCP fallback socket address, got `{addr}`"
            ))
        }
        BackendDisclosure::Loopback | BackendDisclosure::DeterministicInMemory => {
            // Use a localhost address as a reasonable non-network endpoint
            // for in-process / deterministic modes.
            let local: SocketAddr = "127.0.0.1:0".parse().map_err(|e| format!("{e}"))?;
            Ok(TransportAddr::Tcp(local))
        }
        BackendDisclosure::NotRun => {
            Err("cannot derive transport endpoint for NotRun backend".into())
        }
    }
}

fn derive_transport_config(
    disclosure: &BackendDisclosure,
    _node_id: u64,
) -> Result<TransportConfig, String> {
    let endpoint = default_endpoint_for_disclosure(disclosure)?;
    TransportConfigBuilder::default()
        .endpoint(endpoint)
        .build()
        .map_err(|e| format!("transport config build failed: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rdma_endpoint_uri() -> &'static str {
        "rdma://fe80:0000:0000:0000:0000:0000:0000:0001:42:1"
    }

    // ── Build succeeds for every live variant ─────────────────────────

    #[test]
    fn build_tcp() {
        let addr: SocketAddr = "10.0.0.1:9090".parse().unwrap();
        let d = BackendDisclosure::Tcp(addr);
        let a = RuntimeAuthority::build(d, 1, Some(MemberClass::Voter), Some(1), 3).expect("build");
        assert_eq!(a.node_id(), 1);
        assert!(a.is_live());
        assert_eq!(a.replication_factor(), 3);
        assert_eq!(a.member_class(), Some(MemberClass::Voter));
    }

    #[test]
    fn build_rdma() {
        let d = BackendDisclosure::Rdma("127.0.0.1:9100".into());
        let a = RuntimeAuthority::build(d, 7, None, None, 1).expect("build");
        assert!(a.is_live());
        assert_eq!(a.node_id(), 7);
    }

    #[test]
    fn build_loopback() {
        let d = BackendDisclosure::Loopback;
        let a = RuntimeAuthority::build(d, 42, None, None, 1).expect("build");
        assert!(!a.is_live());
        assert_eq!(a.backend(), &BackendDisclosure::Loopback);
    }

    #[test]
    fn build_deterministic_in_memory() {
        let d = BackendDisclosure::DeterministicInMemory;
        let a = RuntimeAuthority::build(d, 99, None, None, 2).expect("build");
        assert!(!a.is_live());
        assert_eq!(a.replication_factor(), 2);
    }

    #[test]
    fn build_not_run_errors() {
        let d = BackendDisclosure::NotRun;
        let result = RuntimeAuthority::build(d, 1, None, None, 1);
        assert!(result.is_err());
    }

    // ── Accessor consistency ──────────────────────────────────────────

    #[test]
    fn backend_round_trip() {
        let addr: SocketAddr = "192.168.0.1:7777".parse().unwrap();
        let d = BackendDisclosure::Tcp(addr);
        let a = RuntimeAuthority::build(d.clone(), 5, None, None, 1).expect("build");
        assert_eq!(a.backend(), &d);
    }

    #[test]
    fn transport_config_derived_from_backend() {
        let addr: SocketAddr = "10.0.0.55:9000".parse().unwrap();
        let d = BackendDisclosure::Tcp(addr);
        let a = RuntimeAuthority::build(d, 5, None, None, 1).expect("build");
        let tc = a.transport_config();
        // The endpoint should match the TCP address.
        assert_eq!(tc.endpoint(), &TransportAddr::Tcp(addr));
    }

    #[test]
    fn rdma_transport_config_uses_tcp_fallback_endpoint() {
        let addr: SocketAddr = "127.0.0.1:9100".parse().unwrap();
        let d = BackendDisclosure::Rdma(addr.to_string());
        let a = RuntimeAuthority::build(d, 5, None, None, 1).expect("build");
        assert_eq!(a.transport_config().endpoint(), &TransportAddr::Tcp(addr));
    }

    #[test]
    fn rdma_transport_config_accepts_canonical_rdma_endpoint() {
        let expected: TransportAddr = rdma_endpoint_uri().parse().unwrap();
        let d = BackendDisclosure::Rdma(rdma_endpoint_uri().into());
        let a = RuntimeAuthority::build(d, 5, None, None, 1).expect("build");
        assert_eq!(a.transport_config().endpoint(), &expected);
    }

    #[test]
    fn rdma_disclosure_requires_canonical_endpoint() {
        let d = BackendDisclosure::Rdma("rxe0".into());
        let err = RuntimeAuthority::build(d, 5, None, None, 1).unwrap_err();
        assert!(err.contains("RDMA disclosure must use"));
    }

    #[test]
    fn loopback_derives_localhost_endpoint() {
        let d = BackendDisclosure::Loopback;
        let a = RuntimeAuthority::build(d, 1, None, None, 1).expect("build");
        // Loopback/DeterministicInMemory derive a local TCP endpoint
        // for in-process use.
        assert!(matches!(
            a.transport_config().endpoint(),
            TransportAddr::Tcp(_)
        ));
    }

    #[test]
    fn replication_factor_preserved() {
        for rf in [1u8, 3u8, 7u8, 255u8] {
            let d = BackendDisclosure::Loopback;
            let a = RuntimeAuthority::build(d, 1, None, None, rf).expect("build");
            assert_eq!(a.replication_factor(), rf, "rf={rf}");
        }
    }

    #[test]
    fn provisioned_transport_identity_derives_exact_node_and_trust() {
        let local = NodePrivateCredential::generate(7).unwrap();
        let peer = NodePrivateCredential::generate(9)
            .unwrap()
            .public_identity();
        let authority = RuntimeAuthority::build(BackendDisclosure::Loopback, 7, None, None, 1)
            .unwrap()
            .with_transport_identity(local, vec![peer.clone()])
            .unwrap();
        let identity = authority.transport_identity().unwrap();
        assert_eq!(identity.local_credential().node_id(), 7);
        assert_eq!(identity.trusted_peers(), &[peer]);
    }

    #[test]
    fn provisioned_transport_identity_rejects_node_mismatch_and_empty_trust() {
        let mismatch = RuntimeAuthority::build(BackendDisclosure::Loopback, 7, None, None, 1)
            .unwrap()
            .with_transport_identity(NodePrivateCredential::generate(8).unwrap(), Vec::new())
            .unwrap_err();
        assert!(mismatch.contains("credential names node 8"));

        let empty = RuntimeAuthority::build(BackendDisclosure::Loopback, 7, None, None, 1)
            .unwrap()
            .with_transport_identity(NodePrivateCredential::generate(7).unwrap(), Vec::new())
            .unwrap_err();
        assert!(empty.contains("trust set must not be empty"));
    }

    #[test]
    fn provisioned_transport_identity_rejects_conflicting_node_keys() {
        let local = NodePrivateCredential::generate(7).unwrap();
        let conflicting_local = NodePrivateCredential::generate(7)
            .unwrap()
            .public_identity();
        let error = RuntimeAuthority::build(BackendDisclosure::Loopback, 7, None, None, 1)
            .unwrap()
            .with_transport_identity(local, vec![conflicting_local])
            .unwrap_err();
        assert!(error.contains("conflicting identities for node 7"));
    }
}
