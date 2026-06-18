// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Runtime authority spine: single source of truth for the active transport
//! backend, wired through membership, placement, and replication.
//!
//! The [`RuntimeAuthority`] struct holds the [`BackendDisclosure`] that every
//! subsystem consults. It eliminates separate deterministic-only and
//! live-only truth paths by establishing one coherent configuration surface
//! at storage-node startup.

use std::net::SocketAddr;

use tidefs_membership_epoch::MemberClass;
use tidefs_membership_live::BackendDisclosure;
use tidefs_transport::config::{TransportConfig, TransportConfigBuilder, TransportEndpoint};

/// Single authority spine constructed at storage-node startup.
///
/// Holds the disclosed backend, a derived transport configuration, and
/// initialization parameters shared by membership, placement, and
/// replication.
#[derive(Clone, Debug)]
pub struct RuntimeAuthority {
    disclosure: BackendDisclosure,
    transport_config: TransportConfig,
    node_id: u64,
    member_class: Option<MemberClass>,
    failure_domain: Option<u64>,
    replication_factor: u8,
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
        })
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

    /// Returns `true` when the backend uses a real network transport.
    /// Delegates to [`BackendDisclosure::is_live`].
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.disclosure.is_live()
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

fn default_endpoint_for_disclosure(
    disclosure: &BackendDisclosure,
) -> Result<TransportEndpoint, String> {
    match disclosure {
        BackendDisclosure::Tcp(addr) => Ok(TransportEndpoint::Tcp(*addr)),
        BackendDisclosure::Rdma(addr) => Ok(TransportEndpoint::Rdma(addr.clone())),
        BackendDisclosure::Loopback | BackendDisclosure::DeterministicInMemory => {
            // Use a localhost address as a reasonable non-network endpoint
            // for in-process / deterministic modes.
            let local: SocketAddr = "127.0.0.1:0".parse().map_err(|e| format!("{e}"))?;
            Ok(TransportEndpoint::Tcp(local))
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
        let d = BackendDisclosure::Rdma("mlx5_0".into());
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
        assert_eq!(tc.endpoint(), &TransportEndpoint::Tcp(addr));
    }

    #[test]
    fn rdma_transport_config_has_rdma_endpoint() {
        let d = BackendDisclosure::Rdma("rxe0".into());
        let a = RuntimeAuthority::build(d, 5, None, None, 1).expect("build");
        assert_eq!(
            a.transport_config().endpoint(),
            &TransportEndpoint::Rdma("rxe0".into())
        );
    }

    #[test]
    fn loopback_derives_localhost_endpoint() {
        let d = BackendDisclosure::Loopback;
        let a = RuntimeAuthority::build(d, 1, None, None, 1).expect("build");
        // Loopback/DeterministicInMemory derive a local TCP endpoint
        // for in-process use.
        assert!(matches!(
            a.transport_config().endpoint(),
            TransportEndpoint::Tcp(_)
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
}
