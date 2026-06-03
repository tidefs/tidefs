//! Seed-peer discovery for cold-start cluster bootstrap.
//!
//! Provides [`SeedDiscovery`] which accepts a configured list of seed
//! addresses, resolves DNS for each, tries transport connections in order
//! with per-seed timeouts, and returns the first successful connection
//! for handoff to [`crate::join_initiator::JoinInitiator`].
//!
//! ## Lifecycle
//!
//! 1. Create a [`SeedDiscovery`] with a seed list, transport, and address
//!    registry.
//! 2. Call [`discover`](SeedDiscovery::discover) to probe seeds in order.
//! 3. On success, the returned [`DiscoveredSeed`] carries the transport
//!    session handle and resolved address. The caller feeds the session
//!    into `JoinInitiator` for the join handshake.
//! 4. On failure, [`SeedDiscoveryError`] carries per-seed failure detail
//!    for operator diagnosis.
//!
//! ## Thread safety
//!
//! `SeedDiscovery` is `Send + Sync`. Transport access goes through the
//! shared `Arc<Mutex<Transport>>`; the address registry is read-only
//! during discovery.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tidefs_transport::addr::TransportAddr;
use tidefs_transport::connect_lifecycle::ConnectConfig;
use tidefs_transport::session_cohort::NodeInfo;
use tidefs_transport::{SessionCloseReason, SessionId, Transport};

use crate::peer_address_registry::PeerAddressRegistry;

// ---------------------------------------------------------------------------
// SeedDiscoveryConfig
// ---------------------------------------------------------------------------

/// Configuration for seed discovery.
#[derive(Clone, Debug)]
pub struct SeedDiscoveryConfig {
    /// Seed addresses in `"host:port"` or `"ip:port"` format.
    ///
    /// Each entry is resolved via DNS before a connection is attempted.
    /// The first successfully connected seed wins; remaining seeds are
    /// not tried.
    pub seeds: Vec<String>,

    /// Per-seed connection timeout applied as the transport
    /// `ConnectConfig::connect_timeout`.
    ///
    /// When the deadline is exceeded for a seed, the connection is
    /// closed and the next seed is tried.
    pub per_seed_connect_timeout: Duration,
}

impl Default for SeedDiscoveryConfig {
    fn default() -> Self {
        Self {
            seeds: Vec::new(),
            per_seed_connect_timeout: Duration::from_secs(10),
        }
    }
}

// ---------------------------------------------------------------------------
// SeedFailureReason
// ---------------------------------------------------------------------------

/// Why a single seed-address probe failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SeedFailureReason {
    /// DNS resolution failed for the seed host:port string.
    DnsResolution(String),
    /// The transport connect call returned an error.
    ConnectionFailed(String),
    /// The session handshake timed out or returned an error.
    HandshakeFailed(String),
}

// ---------------------------------------------------------------------------
// SeedDiscoveryError
// ---------------------------------------------------------------------------

/// Error returned when seed discovery fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SeedDiscoveryError {
    /// The seed list is empty.
    EmptySeedList,
    /// All seeds were exhausted without a successful connection.
    AllSeedsExhausted {
        /// Per-seed failure detail: `(seed_string, failure_reason)`.
        failures: Vec<(String, SeedFailureReason)>,
    },
}

// ---------------------------------------------------------------------------
// DiscoveredSeed
// ---------------------------------------------------------------------------

/// Result of a successful seed discovery.
#[derive(Clone, Debug)]
pub struct DiscoveredSeed {
    /// The temporary node ID assigned to this seed peer in the transport
    /// cohort graph. Callers should use this ID when feeding the session
    /// into `JoinInitiator`.
    pub temporary_peer_id: u64,

    /// The established transport session handle.
    pub session_id: SessionId,

    /// The resolved and successfully connected address.
    pub resolved_addr: TransportAddr,
}

// ---------------------------------------------------------------------------
// SeedDiscovery
// ---------------------------------------------------------------------------

/// Cold-start seed-peer discovery engine.
///
/// Wraps a shared transport and probes a configured seed list in order,
/// stopping at the first successful connection. On success the resolved
/// address is registered in the [`PeerAddressRegistry`] with a temporary
/// [`tidefs_membership_epoch::MemberId`] so downstream join logic can
/// resolve the peer.
///
/// # Temporary node IDs
///
/// Because the real [`tidefs_membership_epoch::MemberId`] of a seed peer
/// is not known until the join handshake completes, each seed probe
/// registers the peer under a temporary ID drawn from a high range
/// (`u64::MAX - probe_index`). After the join handshake delivers the
/// real identity, callers should update the address registry and cohort
/// graph accordingly.
pub struct SeedDiscovery {
    /// Shared transport for outbound connections.
    transport: Arc<Mutex<Transport>>,

    /// Seed list and timeout configuration.
    config: SeedDiscoveryConfig,

    /// Shared peer address registry for recording discovered peers.
    address_registry: Arc<PeerAddressRegistry>,

    /// Monotonically-increasing probe index for temporary node-ID
    /// assignment.  Temporary IDs are `u64::MAX - probe_index`.
    probe_index: u64,
}

impl SeedDiscovery {
    /// Create a new seed discovery engine.
    #[must_use]
    pub fn new(
        transport: Arc<Mutex<Transport>>,
        config: SeedDiscoveryConfig,
        address_registry: Arc<PeerAddressRegistry>,
    ) -> Self {
        Self {
            transport,
            config,
            address_registry,
            probe_index: 0,
        }
    }

    /// Return the seed configuration.
    #[must_use]
    pub fn config(&self) -> &SeedDiscoveryConfig {
        &self.config
    }

    /// Probe seeds in order and return the first successful connection.
    ///
    /// # Algorithm
    ///
    /// 1. Validate that the seed list is non-empty.
    /// 2. For each seed string: resolve DNS, try each resolved address.
    /// 3. On first success: register the address and return.
    /// 4. On all-exhausted: return error with per-seed detail.
    pub fn discover(&mut self) -> Result<DiscoveredSeed, SeedDiscoveryError> {
        if self.config.seeds.is_empty() {
            return Err(SeedDiscoveryError::EmptySeedList);
        }

        let mut failures: Vec<(String, SeedFailureReason)> = Vec::new();
        let seeds: Vec<String> = self.config.seeds.clone();

        for seed_str in &seeds {
            let sock_addrs = match resolve_seed(seed_str) {
                Ok(addrs) => addrs,
                Err(e) => {
                    failures.push((seed_str.clone(), SeedFailureReason::DnsResolution(e)));
                    continue;
                }
            };

            for sock_addr in &sock_addrs {
                let resolved_addr = TransportAddr::Tcp(*sock_addr);
                let temporary_id = self.next_temporary_id();

                match self.probe_one_seed(temporary_id, &resolved_addr) {
                    Ok(session_id) => {
                        let temp_member = tidefs_membership_epoch::MemberId::new(temporary_id);
                        self.address_registry
                            .register(temp_member, vec![resolved_addr.clone()]);

                        return Ok(DiscoveredSeed {
                            temporary_peer_id: temporary_id,
                            session_id,
                            resolved_addr,
                        });
                    }
                    Err(failure) => {
                        failures.push((seed_str.clone(), failure));
                    }
                }
            }
        }

        Err(SeedDiscoveryError::AllSeedsExhausted { failures })
    }

    // ── private helpers ──────────────────────────────────────────────

    fn next_temporary_id(&mut self) -> u64 {
        let id = u64::MAX.saturating_sub(self.probe_index);
        self.probe_index = self.probe_index.saturating_add(1);
        id
    }

    fn probe_one_seed(
        &self,
        temporary_id: u64,
        resolved_addr: &TransportAddr,
    ) -> Result<SessionId, SeedFailureReason> {
        let mut transport = self.transport.lock().unwrap();

        transport.add_node(NodeInfo::new(temporary_id, vec![resolved_addr.clone()], 0));

        transport.set_connect_config(ConnectConfig::new(Some(
            self.config.per_seed_connect_timeout,
        )));

        let session_id = match transport.connect(temporary_id) {
            Ok(sid) => sid,
            Err(e) => {
                return Err(SeedFailureReason::ConnectionFailed(e.to_string()));
            }
        };

        if let Err(e) = transport.perform_handshake(session_id) {
            let _ = transport.close_session(session_id, SessionCloseReason::TransportError);
            return Err(SeedFailureReason::HandshakeFailed(e.to_string()));
        }

        Ok(session_id)
    }
}

// ---------------------------------------------------------------------------
// DNS resolution helper
// ---------------------------------------------------------------------------

/// Resolve a `"host:port"` or `"ip:port"` string to [`SocketAddr`]s.
fn resolve_seed(seed: &str) -> Result<Vec<SocketAddr>, String> {
    seed.to_socket_addrs()
        .map(|iter| iter.collect())
        .map_err(|e| format!("DNS resolution failed for '{seed}': {e}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tidefs_transport::Transport;

    fn make_config(seeds: Vec<String>) -> SeedDiscoveryConfig {
        SeedDiscoveryConfig {
            seeds,
            per_seed_connect_timeout: Duration::from_secs(5),
        }
    }

    fn make_discovery(
        seeds: Vec<String>,
    ) -> (
        SeedDiscovery,
        Arc<Mutex<Transport>>,
        Arc<PeerAddressRegistry>,
    ) {
        let transport = Arc::new(Mutex::new(Transport::new(1)));
        let registry = Arc::new(PeerAddressRegistry::new());
        let discovery = SeedDiscovery::new(
            Arc::clone(&transport),
            make_config(seeds),
            Arc::clone(&registry),
        );
        (discovery, transport, registry)
    }

    #[test]
    fn new_creates_with_zero_probe_index() {
        let (discovery, _t, _r) = make_discovery(vec!["127.0.0.1:9100".into()]);
        assert_eq!(discovery.config().seeds.len(), 1);
        assert_eq!(discovery.probe_index, 0);
    }

    #[test]
    fn default_config_is_empty() {
        let cfg = SeedDiscoveryConfig::default();
        assert!(cfg.seeds.is_empty());
        assert_eq!(cfg.per_seed_connect_timeout, Duration::from_secs(10));
    }

    #[test]
    fn resolve_seed_valid_ip() {
        let addrs = resolve_seed("127.0.0.1:9100").unwrap();
        assert!(!addrs.is_empty());
        assert_eq!(
            addrs[0],
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 9100))
        );
    }

    #[test]
    fn resolve_seed_localhost() {
        let addrs = resolve_seed("localhost:9100").unwrap();
        assert!(!addrs.is_empty());
        let has_loopback = addrs.iter().any(|a| a.ip().is_loopback());
        assert!(has_loopback);
    }

    #[test]
    fn resolve_seed_invalid_dns() {
        let result = resolve_seed("invalid-host-that-does-not-exist.invalid:9100");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("DNS resolution failed"));
    }

    #[test]
    fn resolve_seed_empty_string() {
        assert!(resolve_seed("").is_err());
    }

    #[test]
    fn resolve_seed_missing_port() {
        assert!(resolve_seed("127.0.0.1").is_err());
    }

    #[test]
    fn empty_seed_list_returns_error() {
        let (mut discovery, _t, _r) = make_discovery(vec![]);
        assert!(matches!(
            discovery.discover(),
            Err(SeedDiscoveryError::EmptySeedList)
        ));
    }

    #[test]
    fn temporary_ids_descend_from_max() {
        let (mut discovery, _t, _r) = make_discovery(vec!["127.0.0.1:9100".into()]);
        assert_eq!(discovery.next_temporary_id(), u64::MAX);
        assert_eq!(discovery.next_temporary_id(), u64::MAX - 1);
        assert_eq!(discovery.next_temporary_id(), u64::MAX - 2);
    }

    #[test]
    fn temporary_ids_saturate_at_zero() {
        let (mut discovery, _t, _r) = make_discovery(vec!["127.0.0.1:9100".into()]);
        discovery.probe_index = u64::MAX;
        assert_eq!(discovery.next_temporary_id(), 0);
    }

    #[test]
    fn dns_failure_is_recorded() {
        let (mut discovery, _t, _r) = make_discovery(vec!["invalid-host.invalid:9100".into()]);
        match discovery.discover() {
            Err(SeedDiscoveryError::AllSeedsExhausted { failures }) => {
                assert_eq!(failures.len(), 1);
                assert!(matches!(failures[0].1, SeedFailureReason::DnsResolution(_)));
            }
            other => panic!("expected AllSeedsExhausted, got {other:?}"),
        }
    }

    #[test]
    fn seed_discovery_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SeedDiscovery>();
    }

    #[test]
    fn seed_failure_reason_debug() {
        let r = SeedFailureReason::DnsResolution("bad".into());
        assert!(format!("{r:?}").contains("bad"));
        let r = SeedFailureReason::ConnectionFailed("refused".into());
        assert!(format!("{r:?}").contains("refused"));
        let r = SeedFailureReason::HandshakeFailed("timeout".into());
        assert!(format!("{r:?}").contains("timeout"));
    }

    #[test]
    fn seed_discovery_error_debug() {
        let err = SeedDiscoveryError::EmptySeedList;
        assert!(format!("{err:?}").contains("EmptySeedList"));
        let err = SeedDiscoveryError::AllSeedsExhausted {
            failures: vec![(
                "bad:1".into(),
                SeedFailureReason::DnsResolution("no".into()),
            )],
        };
        assert!(format!("{err:?}").contains("AllSeedsExhausted"));
    }

    #[test]
    fn discovered_seed_clone_and_debug() {
        let seed = DiscoveredSeed {
            temporary_peer_id: u64::MAX,
            session_id: SessionId(42),
            resolved_addr: TransportAddr::Tcp("127.0.0.1:9100".parse().unwrap()),
        };
        let seed2 = seed.clone();
        assert_eq!(seed2.temporary_peer_id, u64::MAX);
        assert!(format!("{seed:?}").contains("127.0.0.1"));
    }

    #[test]
    fn config_accessor_returns_config() {
        let (discovery, _t, _r) = make_discovery(vec!["a:1".into(), "b:2".into()]);
        assert_eq!(discovery.config().seeds.len(), 2);
    }
}
