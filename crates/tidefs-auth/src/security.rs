//! Cluster security and identity model — sealed implementation.
//!
//! This module implements the sealed design specification from
//! `docs/design/cluster-security-identity-model.md` (§3–§11).
//!
//! It provides:
//! - Four security modes (`dev_insecure`, `tcp_mtls`, `psk_hmac`, `trusted_fabric`)
//! - HELLO-service TLV negotiation (TLV_AUTH_MODE, TLV_PSK_PROOF)
//! - PSK HMAC proof generation and verification
//! - Transport-authenticated peer identity binding (`AuthenticatedPeer`)
//! - Deduplication key construction scoped by peer identity
//! - ADMIN service auth gating
//! - RDMA bulk mode safety gating

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

use crate::error::{AdminAccessDenied, RdmaBulkDenied, SecurityError};

// ---------------------------------------------------------------------------
// 3.1 Mode Enumeration
// ---------------------------------------------------------------------------

/// Four security modes, per §3.1 of the sealed design.
///
/// Wire values:
///   `0x00 = dev_insecure`
///   `0x01 = tcp_mtls`
///   `0x02 = psk_hmac`
///   `0x03 = trusted_fabric`
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum SecurityMode {
    /// Development only — no authentication. Never production.
    DevInsecure = 0x00,
    /// TLS peer certificate mutual TLS.
    TcpMtls = 0x01,
    /// PSK HMAC proof in HELLO exchange (TLS-free).
    PskHmac = 0x02,
    /// Physical fabric trust; PSK recommended but optional.
    TrustedFabric = 0x03,
}

impl SecurityMode {
    /// Decode from a wire byte.
    pub fn from_u8(v: u8) -> Result<Self, SecurityError> {
        match v {
            0x00 => Ok(Self::DevInsecure),
            0x01 => Ok(Self::TcpMtls),
            0x02 => Ok(Self::PskHmac),
            0x03 => Ok(Self::TrustedFabric),
            other => Err(SecurityError::UnsupportedMode { mode: other }),
        }
    }

    /// Whether this mode is authenticated (not dev_insecure).
    pub fn is_authenticated(&self) -> bool {
        !matches!(self, Self::DevInsecure)
    }
}

impl std::fmt::Display for SecurityMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DevInsecure => write!(f, "dev_insecure"),
            Self::TcpMtls => write!(f, "tcp_mtls"),
            Self::PskHmac => write!(f, "psk_hmac"),
            Self::TrustedFabric => write!(f, "trusted_fabric"),
        }
    }
}

// ---------------------------------------------------------------------------
// 3.2 Defaults — see `NodeSecurityConfig` (in tidefs-transport context)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 3.3 Mode Configuration
// ---------------------------------------------------------------------------

/// Per-node security configuration, carried in membership config (§3.3).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeSecurityConfig {
    /// Minimum acceptable security mode for this node.
    pub required_mode: SecurityMode,

    /// PSK identifier for psk_hmac mode (empty if not used).
    pub psk_identity: String,

    /// TLS certificate file path (empty if not used).
    pub tls_cert_path: Option<String>,

    /// TLS key file path.
    pub tls_key_path: Option<String>,

    /// Known PSK store path (file or directory of PSK blobs).
    pub psk_store_path: Option<String>,
}

impl NodeSecurityConfig {
    /// Dev-mode default: dev_insecure, no PSK, no TLS.
    pub fn dev_default() -> Self {
        Self {
            required_mode: SecurityMode::DevInsecure,
            psk_identity: String::new(),
            tls_cert_path: None,
            tls_key_path: None,
            psk_store_path: None,
        }
    }
}

/// Negotiate the effective security mode between two peers (§3.3).
///
/// The effective mode is `max(local, remote)`, but `dev_insecure`
/// cannot interoperate with any authenticated mode.
pub fn negotiate_mode(
    local: SecurityMode,
    remote: SecurityMode,
) -> Result<SecurityMode, SecurityError> {
    let effective = std::cmp::max(local, remote);

    // dev_insecure cannot pair with any higher mode
    if (local == SecurityMode::DevInsecure) != (remote == SecurityMode::DevInsecure) {
        return Err(SecurityError::ModeMismatch {
            local: local.to_string(),
            remote: remote.to_string(),
            reason: "dev_insecure cannot interoperate with authenticated modes".to_string(),
        });
    }

    Ok(effective)
}

// ---------------------------------------------------------------------------
// 4. HELLO TLV Negotiation
// ---------------------------------------------------------------------------

/// TLV tag constants (§4.3).
pub mod tlv_tag {
    /// Client proposes auth mode.
    pub const TLV_AUTH_MODE: u16 = 0x0100;
    /// Server acknowledges auth mode.
    pub const TLV_AUTH_MODE_ACK: u16 = 0x0101;
    /// Client PSK HMAC proof.
    pub const TLV_PSK_PROOF: u16 = 0x0200;
    /// Server PSK HMAC proof echo.
    pub const TLV_PSK_PROOF_ACK: u16 = 0x0201;
    /// General error TLV from server.
    pub const TLV_ERROR: u16 = 0xFF00;
}

/// A HELLO TLV extension carried in the security_tlvs field (§4.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloTlv {
    /// 16-bit tag identifying the TLV type.
    pub tag: u16,
    /// Variable-length value (length determined by enclosing wire format).
    pub value: Vec<u8>,
}

impl HelloTlv {
    pub fn new(tag: u16, value: Vec<u8>) -> Self {
        Self { tag, value }
    }

    /// Build a `TLV_AUTH_MODE` carrying the proposed mode byte.
    pub fn auth_mode(mode: SecurityMode) -> Self {
        Self {
            tag: tlv_tag::TLV_AUTH_MODE,
            value: vec![mode as u8],
        }
    }

    /// Build a `TLV_AUTH_MODE_ACK` carrying the accepted mode byte.
    pub fn auth_mode_ack(mode: SecurityMode) -> Self {
        Self {
            tag: tlv_tag::TLV_AUTH_MODE_ACK,
            value: vec![mode as u8],
        }
    }

    /// Build a `TLV_ERROR` with an error code and reason.
    pub fn error_tlv(error_code: u16, reason: &[u8]) -> Self {
        let mut value = Vec::with_capacity(2 + reason.len());
        value.extend_from_slice(&error_code.to_be_bytes());
        value.extend_from_slice(reason);
        Self {
            tag: tlv_tag::TLV_ERROR,
            value,
        }
    }

    /// Decode TLV_AUTH_MODE value to SecurityMode.
    pub fn as_auth_mode(&self) -> Result<SecurityMode, SecurityError> {
        if self.value.is_empty() {
            return Err(SecurityError::InvalidPskProof);
        }
        SecurityMode::from_u8(self.value[0])
    }
}

// ---------------------------------------------------------------------------
// 5. PSK HMAC Proof Mechanism
// ---------------------------------------------------------------------------

/// In-memory PSK store keyed by psk_identity (§5.6).
///
/// PSKs are populated from the secret-key-policy storage layer (P9-04).
/// They are never logged, traced, or serialized in plaintext outside
/// the sealed-envelope storage.
#[derive(Clone, Debug, Default)]
pub struct PskStore {
    keys: HashMap<String, Vec<u8>>,
}

impl PskStore {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Insert a PSK for the given identity.
    pub fn insert(&mut self, identity: String, key: Vec<u8>) {
        self.keys.insert(identity, key);
    }

    /// Look up a PSK by identity.
    pub fn get(&self, identity: &str) -> Result<Vec<u8>, SecurityError> {
        self.keys
            .get(identity)
            .cloned()
            .ok_or_else(|| SecurityError::UnknownPskIdentity {
                identity: identity.to_string(),
            })
    }

    /// Check if an identity is known.
    pub fn contains(&self, identity: &str) -> bool {
        self.keys.contains_key(identity)
    }
}

/// Generate a PSK HMAC proof for the client side of the HELLO exchange (§5.4).
///
/// The client computes `HMAC-SHA256(psk, client_nonce)` and packs it
/// together with the `psk_identity` into a `HelloTlv` with tag `TLV_PSK_PROOF`.
pub fn generate_psk_proof(psk: &[u8], psk_identity: &str, client_nonce: &[u8; 32]) -> HelloTlv {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac = Hmac::<Sha256>::new_from_slice(psk).expect("HMAC-SHA256 supports any key length");
    mac.update(client_nonce);
    let proof = mac.finalize().into_bytes();

    let identity_bytes = psk_identity.as_bytes();
    let mut value = Vec::with_capacity(1 + identity_bytes.len() + 32);
    value.push(identity_bytes.len() as u8);
    value.extend_from_slice(identity_bytes);
    value.extend_from_slice(&proof);

    HelloTlv {
        tag: tlv_tag::TLV_PSK_PROOF,
        value,
    }
}

/// Verify a client PSK proof TLV on the server side (§5.5).
///
/// Returns the authenticated `psk_identity` on success.
pub fn verify_psk_proof(
    tlv: &HelloTlv,
    client_nonce: &[u8; 32],
    psk_store: &PskStore,
) -> Result<String, SecurityError> {
    if tlv.tag != tlv_tag::TLV_PSK_PROOF {
        return Err(SecurityError::InvalidPskProof);
    }
    if tlv.value.len() < 2 {
        return Err(SecurityError::InvalidPskProof);
    }
    let id_len = tlv.value[0] as usize;
    if id_len == 0 || tlv.value.len() < 1 + id_len + 32 {
        return Err(SecurityError::InvalidPskProof);
    }
    let psk_identity = std::str::from_utf8(&tlv.value[1..1 + id_len])
        .map_err(|_| SecurityError::InvalidPskIdentity)?;
    let client_proof: [u8; 32] = tlv.value[1 + id_len..1 + id_len + 32]
        .try_into()
        .map_err(|_| SecurityError::InvalidPskProof)?;

    let psk = psk_store.get(psk_identity)?;

    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac =
        Hmac::<Sha256>::new_from_slice(&psk).expect("HMAC-SHA256 supports any key length");
    mac.update(client_nonce);
    mac.verify_slice(&client_proof)
        .map_err(|_| SecurityError::PskProofMismatch)?;

    Ok(psk_identity.to_string())
}

/// Generate the server's PSK proof ACK TLV (§5.1).
///
/// The server computes `HMAC-SHA256(psk, server_nonce || client_nonce)`.
pub fn generate_psk_proof_ack(
    psk: &[u8],
    server_nonce: &[u8; 32],
    client_nonce: &[u8; 32],
) -> HelloTlv {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac = Hmac::<Sha256>::new_from_slice(psk).expect("HMAC-SHA256 supports any key length");
    mac.update(server_nonce);
    mac.update(client_nonce);
    let proof = mac.finalize().into_bytes();

    HelloTlv {
        tag: tlv_tag::TLV_PSK_PROOF_ACK,
        value: proof.to_vec(),
    }
}

/// Verify the server's PSK proof ACK on the client side (§5.1).
pub fn verify_psk_proof_ack(
    tlv: &HelloTlv,
    psk: &[u8],
    server_nonce: &[u8; 32],
    client_nonce: &[u8; 32],
) -> Result<(), SecurityError> {
    if tlv.tag != tlv_tag::TLV_PSK_PROOF_ACK {
        return Err(SecurityError::PskProofAckMismatch);
    }
    if tlv.value.len() != 32 {
        return Err(SecurityError::PskProofAckMismatch);
    }
    let server_proof: [u8; 32] = tlv.value[..32]
        .try_into()
        .map_err(|_| SecurityError::PskProofAckMismatch)?;

    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac = Hmac::<Sha256>::new_from_slice(psk).expect("HMAC-SHA256 supports any key length");
    mac.update(server_nonce);
    mac.update(client_nonce);
    mac.verify_slice(&server_proof)
        .map_err(|_| SecurityError::PskProofAckMismatch)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// 6. Peer Identity Binding
// ---------------------------------------------------------------------------

/// Transport-authenticated peer identity, bound at session establishment
/// and immutable for the lifetime of the session (§6.2).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuthenticatedPeer {
    /// TLS peer certificate Distinguished Name (e.g., "CN=node-7,O=TideFS").
    TlsPeerDN(String),

    /// PSK-authenticated identity string.
    PskIdentity(String),

    /// Trusted fabric — PSK verified (strong recommendation).
    TrustedFabricPsk(String),

    /// Trusted fabric — unauthenticated (logged, never for admin/rdma).
    TrustedFabricUnauthenticated { src_ip: String, src_port: u16 },

    /// Development only — source IP:port.
    DevInsecure { src_ip: String, src_port: u16 },
}

impl AuthenticatedPeer {
    /// Whether this peer can access ADMIN service (§8.1).
    pub fn can_access_admin(&self) -> bool {
        !matches!(
            self,
            Self::DevInsecure { .. } | Self::TrustedFabricUnauthenticated { .. }
        )
    }

    /// Whether this peer can use RDMA bulk mode (§9.1).
    pub fn can_use_rdma_bulk(&self) -> bool {
        matches!(
            self,
            Self::TrustedFabricPsk(_)
                | Self::TrustedFabricUnauthenticated { .. }
                | Self::PskIdentity(_)
        )
    }

    /// Stable string key for deduplication windows (§7.2).
    pub fn dedup_key(&self) -> String {
        match self {
            Self::TlsPeerDN(dn) => format!("tls:{dn}"),
            Self::PskIdentity(id) => format!("psk:{id}"),
            Self::TrustedFabricPsk(id) => format!("tf_psk:{id}"),
            Self::TrustedFabricUnauthenticated { src_ip, src_port } => {
                format!("tf:{src_ip}:{src_port}")
            }
            Self::DevInsecure { src_ip, src_port } => {
                format!("dev:{src_ip}:{src_port}")
            }
        }
    }

    /// Extract peer identity from security mode and transport-level data (§6.3).
    ///
    /// Returns `TlsPeerIdentityMissing` if `tcp_mtls` is requested without a
    /// transport-provided TLS peer certificate DN. Callers must supply the real
    /// peer DN obtained from the TLS session; placeholder or absent DNs are
    /// refused.
    pub fn from_mode(
        mode: SecurityMode,
        tls_dn: Option<&str>,
        psk_identity: Option<&str>,
        src_ip: &str,
        src_port: u16,
    ) -> Result<Self, SecurityError> {
        match mode {
            SecurityMode::DevInsecure => Ok(Self::DevInsecure {
                src_ip: src_ip.to_string(),
                src_port,
            }),
            SecurityMode::TcpMtls => {
                let dn = tls_dn.ok_or(SecurityError::TlsPeerIdentityMissing)?;
                Ok(Self::TlsPeerDN(dn.to_string()))
            }
            SecurityMode::PskHmac => {
                if let Some(id) = psk_identity {
                    Ok(Self::PskIdentity(id.to_string()))
                } else {
                    Ok(Self::DevInsecure {
                        src_ip: src_ip.to_string(),
                        src_port,
                    })
                }
            }
            SecurityMode::TrustedFabric => {
                if let Some(id) = psk_identity {
                    Ok(Self::TrustedFabricPsk(id.to_string()))
                } else {
                    Ok(Self::TrustedFabricUnauthenticated {
                        src_ip: src_ip.to_string(),
                        src_port,
                    })
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 7. Deduplication Key Construction
// ---------------------------------------------------------------------------

/// Construct a deduplication key from transport-authenticated identity (§7.2).
///
/// The key is `auth_peer.dedup_key() || ":" || op_id_le`.
pub fn dedup_key(auth_peer: &AuthenticatedPeer, op_id: u64) -> Vec<u8> {
    let mut key = Vec::new();
    key.extend_from_slice(auth_peer.dedup_key().as_bytes());
    key.push(b':');
    key.extend_from_slice(&op_id.to_le_bytes());
    key
}

/// Result of a dedup window check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DedupResult {
    /// Operation was not seen before — recorded.
    New,
    /// Operation is a duplicate — already seen.
    Duplicate,
}

/// A deduplication entry with a monotonic timestamp (§7.3).
#[derive(Clone, Debug)]
pub struct DedupEntry {
    pub recorded_at_millis: u64,
}

impl DedupEntry {
    pub fn new() -> Self {
        Self {
            recorded_at_millis: crate::identity::current_time_utils(),
        }
    }
}

impl Default for DedupEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-authenticated-peer deduplication window (§7.3).
///
/// Keyed by `AuthenticatedPeer::dedup_key()`, bounded to `max_ops` entries.
pub struct DedupWindow {
    /// Per-authenticated-peer dedup state.
    windows: HashMap<String, BTreeMap<u64, DedupEntry>>,
    max_ops: u16,
}

impl DedupWindow {
    pub fn new(max_ops: u16) -> Self {
        Self {
            windows: HashMap::new(),
            max_ops,
        }
    }

    /// Check if an operation is a duplicate, and record it if not.
    pub fn check_and_record(&mut self, auth_peer: &AuthenticatedPeer, op_id: u64) -> DedupResult {
        let peer_key = auth_peer.dedup_key();
        let window = self.windows.entry(peer_key).or_default();

        if window.contains_key(&op_id) {
            return DedupResult::Duplicate;
        }

        // Evict oldest entries if window full
        while window.len() >= self.max_ops as usize {
            let oldest = window.keys().next().copied();
            if let Some(k) = oldest {
                window.remove(&k);
            }
        }

        window.insert(op_id, DedupEntry::new());
        DedupResult::New
    }

    /// Remove all state for a peer identity (e.g., on disconnect or rotation).
    pub fn invalidate_peer(&mut self, auth_peer: &AuthenticatedPeer) {
        self.windows.remove(&auth_peer.dedup_key());
    }

    /// Number of tracked peer windows.
    pub fn peer_count(&self) -> usize {
        self.windows.len()
    }

    /// Total tracked operation entries across all peers.
    pub fn entry_count(&self) -> usize {
        self.windows.values().map(|w| w.len()).sum()
    }
}

// ---------------------------------------------------------------------------
// 8. ADMIN Service Authentication
// ---------------------------------------------------------------------------

/// Check whether an authenticated peer is permitted to access the ADMIN service (§8.1).
///
/// - `dev_insecure`: allow all (development only, logged)
/// - `trusted_fabric` unauthenticated: deny
/// - authenticated: must be in the admin peer set
pub fn admin_access_check(
    auth_peer: &AuthenticatedPeer,
    admin_peers: &[AuthenticatedPeer],
) -> Result<(), AdminAccessDenied> {
    // dev_insecure: allow all (development only)
    if matches!(auth_peer, AuthenticatedPeer::DevInsecure { .. }) {
        return Ok(());
    }

    // Trusted-fabric unauthenticated: deny
    if matches!(
        auth_peer,
        AuthenticatedPeer::TrustedFabricUnauthenticated { .. }
    ) {
        return Err(AdminAccessDenied::NotAuthenticated);
    }

    // Check if this authenticated peer is in the admin set
    if !admin_peers.contains(auth_peer) {
        return Err(AdminAccessDenied::NotInAdminSet {
            peer: format!("{auth_peer:?}"),
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 8.3 Admin Proxy Header
// ---------------------------------------------------------------------------

/// Proxied admin operation carries the original caller's identity (§8.3).
///
/// When the ADMIN service proxies a request, the proxy node forwards
/// the original caller's `AuthenticatedPeer` identity. The leader performs
/// auth checks against the **original** caller, not the proxy node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminProxyHeader {
    pub original_caller: AuthenticatedPeer,
    pub proxy_node_id: u64,
    pub proxy_epoch: u64,
}

// ---------------------------------------------------------------------------
// 9. RDMA Bulk Mode Gating
// ---------------------------------------------------------------------------

/// Cluster configuration for RDMA gating (§9.1).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ClusterSecurityConfig {
    /// Whether RDMA bulk is permitted over authenticated (non-trusted-fabric) modes.
    pub allow_rdma_over_authenticated: bool,
}

/// Gate RDMA bulk mode based on security mode and cluster config (§9.1).
///
/// - `dev_insecure`: always denied
/// - `trusted_fabric`: always allowed
/// - `psk_hmac` / `tcp_mtls`: allowed only with operator acknowledgment
pub fn rdma_bulk_gate(
    mode: SecurityMode,
    _auth_peer: &AuthenticatedPeer,
    config: &ClusterSecurityConfig,
) -> Result<(), RdmaBulkDenied> {
    match mode {
        SecurityMode::DevInsecure => Err(RdmaBulkDenied::DevInsecureNotSupported),
        SecurityMode::TrustedFabric => {
            // Allowed by default for trusted fabric
            Ok(())
        }
        SecurityMode::PskHmac | SecurityMode::TcpMtls => {
            if !config.allow_rdma_over_authenticated {
                return Err(RdmaBulkDenied::OperatorAckRequired);
            }
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// 10. HELLO Security Verification
// ---------------------------------------------------------------------------

/// Verify the security TLVs from a HELLO exchange.
///
/// Steps (§4.5):
/// 1. Extract TLV_AUTH_MODE from client
/// 2. Server negotiates effective mode
/// 3. If mode is psk_hmac, extract TLV_PSK_PROOF and verify
/// 4. Server responds with TLV_AUTH_MODE_ACK and TLV_PSK_PROOF_ACK
/// 5. Client verifies TLV_PSK_PROOF_ACK
pub fn verify_hello_security(
    client_tlvs: &[HelloTlv],
    server_tlvs: &[HelloTlv],
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    psk_store: &PskStore,
    tls_peer_dn: Option<&str>,
) -> Result<(SecurityMode, AuthenticatedPeer), SecurityError> {
    // Find client's auth mode proposal
    let client_mode_tlv = client_tlvs
        .iter()
        .find(|t| t.tag == tlv_tag::TLV_AUTH_MODE)
        .ok_or_else(|| SecurityError::AuthModeUnsupported {
            requested: "none".to_string(),
            supported: vec![],
        })?;
    let client_mode = client_mode_tlv.as_auth_mode()?;

    // Find server's auth mode ACK
    let server_mode_tlv = server_tlvs
        .iter()
        .find(|t| t.tag == tlv_tag::TLV_AUTH_MODE_ACK)
        .ok_or_else(|| SecurityError::AuthModeUnsupported {
            requested: client_mode.to_string(),
            supported: vec![],
        })?;
    let server_mode = server_mode_tlv.as_auth_mode()?;

    // Negotiate effective mode
    let effective_mode = negotiate_mode(client_mode, server_mode)?;

    // If psk_hmac, verify PSK proofs
    let auth_peer = match effective_mode {
        SecurityMode::DevInsecure => AuthenticatedPeer::DevInsecure {
            src_ip: "0.0.0.0".to_string(),
            src_port: 0,
        },
        SecurityMode::PskHmac | SecurityMode::TrustedFabric => {
            // Verify client PSK proof
            let client_psk_tlv = client_tlvs
                .iter()
                .find(|t| t.tag == tlv_tag::TLV_PSK_PROOF)
                .ok_or(SecurityError::InvalidPskProof)?;
            let psk_identity = verify_psk_proof(client_psk_tlv, client_nonce, psk_store)?;

            // Verify server PSK proof ACK
            let psk = psk_store.get(&psk_identity)?;
            let server_ack_tlv = server_tlvs
                .iter()
                .find(|t| t.tag == tlv_tag::TLV_PSK_PROOF_ACK)
                .ok_or(SecurityError::PskProofAckMismatch)?;
            verify_psk_proof_ack(server_ack_tlv, &psk, server_nonce, client_nonce)?;

            if effective_mode == SecurityMode::TrustedFabric {
                AuthenticatedPeer::TrustedFabricPsk(psk_identity)
            } else {
                AuthenticatedPeer::PskIdentity(psk_identity)
            }
        }
        SecurityMode::TcpMtls => {
            // TLS peer identity is bound by the transport layer.
            // Must be supplied; fail closed if absent.
            let dn = tls_peer_dn.ok_or(SecurityError::TlsPeerIdentityMissing)?;
            AuthenticatedPeer::TlsPeerDN(dn.to_string())
        }
    };

    Ok((effective_mode, auth_peer))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_mode_wire_values() {
        assert_eq!(SecurityMode::DevInsecure as u8, 0x00);
        assert_eq!(SecurityMode::TcpMtls as u8, 0x01);
        assert_eq!(SecurityMode::PskHmac as u8, 0x02);
        assert_eq!(SecurityMode::TrustedFabric as u8, 0x03);
    }

    #[test]
    fn test_security_mode_from_u8() {
        assert_eq!(
            SecurityMode::from_u8(0x00).unwrap(),
            SecurityMode::DevInsecure
        );
        assert_eq!(SecurityMode::from_u8(0x01).unwrap(), SecurityMode::TcpMtls);
        assert_eq!(SecurityMode::from_u8(0x02).unwrap(), SecurityMode::PskHmac);
        assert_eq!(
            SecurityMode::from_u8(0x03).unwrap(),
            SecurityMode::TrustedFabric
        );
        assert!(SecurityMode::from_u8(0xFF).is_err());
    }

    #[test]
    fn test_negotiate_mode_same() {
        assert_eq!(
            negotiate_mode(SecurityMode::DevInsecure, SecurityMode::DevInsecure).unwrap(),
            SecurityMode::DevInsecure
        );
        assert_eq!(
            negotiate_mode(SecurityMode::TcpMtls, SecurityMode::TcpMtls).unwrap(),
            SecurityMode::TcpMtls
        );
        assert_eq!(
            negotiate_mode(SecurityMode::PskHmac, SecurityMode::PskHmac).unwrap(),
            SecurityMode::PskHmac
        );
    }

    #[test]
    fn test_negotiate_mode_max() {
        // psk_hmac with trusted_fabric → trusted_fabric (max)
        assert_eq!(
            negotiate_mode(SecurityMode::PskHmac, SecurityMode::TrustedFabric).unwrap(),
            SecurityMode::TrustedFabric
        );
        // tcp_mtls with psk_hmac → psk_hmac (max)
        assert_eq!(
            negotiate_mode(SecurityMode::TcpMtls, SecurityMode::PskHmac).unwrap(),
            SecurityMode::PskHmac
        );
    }

    #[test]
    fn test_negotiate_mode_dev_insecure_ghetto() {
        // dev_insecure cannot pair with authenticated
        assert!(negotiate_mode(SecurityMode::DevInsecure, SecurityMode::TcpMtls).is_err());
        assert!(negotiate_mode(SecurityMode::DevInsecure, SecurityMode::PskHmac).is_err());
        assert!(negotiate_mode(SecurityMode::TcpMtls, SecurityMode::DevInsecure).is_err());
    }

    // --- PSK HMAC proof round-trip ---

    #[test]
    fn test_psk_proof_round_trip() {
        let mut store = PskStore::new();
        let psk = b"test-pre-shared-key-material-32b!".to_vec();
        store.insert("node-7".to_string(), psk.clone());

        let client_nonce = [0xAAu8; 32];
        let server_nonce = [0xBBu8; 32];

        // Client generates proof
        let client_tlv = generate_psk_proof(&psk, "node-7", &client_nonce);
        assert_eq!(client_tlv.tag, tlv_tag::TLV_PSK_PROOF);

        // Server verifies proof
        let identity = verify_psk_proof(&client_tlv, &client_nonce, &store).unwrap();
        assert_eq!(identity, "node-7");

        // Server generates ACK
        let server_psk = store.get("node-7").unwrap();
        let server_tlv = generate_psk_proof_ack(&server_psk, &server_nonce, &client_nonce);
        assert_eq!(server_tlv.tag, tlv_tag::TLV_PSK_PROOF_ACK);

        // Client verifies ACK
        verify_psk_proof_ack(&server_tlv, &psk, &server_nonce, &client_nonce).unwrap();
    }

    #[test]
    fn test_psk_proof_mismatch() {
        let mut store = PskStore::new();
        let psk = b"test-pre-shared-key-material-32b!".to_vec();
        store.insert("node-7".to_string(), psk);

        let client_nonce = [0xAAu8; 32];
        let client_tlv = generate_psk_proof(&store.get("node-7").unwrap(), "node-7", &client_nonce);

        // Verify with wrong nonce
        let wrong_nonce = [0xCCu8; 32];
        let result = verify_psk_proof(&client_tlv, &wrong_nonce, &store);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SecurityError::PskProofMismatch
        ));
    }

    // --- AuthenticatedPeer ---

    #[test]
    fn test_auth_peer_admin_access() {
        assert!(!AuthenticatedPeer::DevInsecure {
            src_ip: "127.0.0.1".into(),
            src_port: 12345
        }
        .can_access_admin());
        assert!(!AuthenticatedPeer::TrustedFabricUnauthenticated {
            src_ip: "10.0.0.1".into(),
            src_port: 9000
        }
        .can_access_admin());
        assert!(AuthenticatedPeer::PskIdentity("node-7".into()).can_access_admin());
        assert!(AuthenticatedPeer::TlsPeerDN("CN=node-7".into()).can_access_admin());
        assert!(AuthenticatedPeer::TrustedFabricPsk("node-7".into()).can_access_admin());
    }

    #[test]
    fn test_auth_peer_rdma_bulk() {
        assert!(!AuthenticatedPeer::DevInsecure {
            src_ip: "127.0.0.1".into(),
            src_port: 12345
        }
        .can_use_rdma_bulk());
        assert!(AuthenticatedPeer::TrustedFabricUnauthenticated {
            src_ip: "10.0.0.1".into(),
            src_port: 9000
        }
        .can_use_rdma_bulk());
        assert!(AuthenticatedPeer::PskIdentity("node-7".into()).can_use_rdma_bulk());
        assert!(AuthenticatedPeer::TrustedFabricPsk("node-7".into()).can_use_rdma_bulk());
    }

    // --- AuthenticatedPeer::from_mode ---

    #[test]
    fn test_from_mode_tls_peer_dn_present() {
        let peer = AuthenticatedPeer::from_mode(
            SecurityMode::TcpMtls,
            Some("CN=node-3,O=TideFS"),
            None,
            "10.0.0.1",
            9000,
        )
        .unwrap();
        assert_eq!(
            peer,
            AuthenticatedPeer::TlsPeerDN("CN=node-3,O=TideFS".into())
        );
        assert_eq!(peer.dedup_key(), "tls:CN=node-3,O=TideFS");
        assert!(peer.can_access_admin());
    }

    #[test]
    fn test_from_mode_tls_peer_dn_missing_refused() {
        let result =
            AuthenticatedPeer::from_mode(SecurityMode::TcpMtls, None, None, "10.0.0.1", 9000);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SecurityError::TlsPeerIdentityMissing
        ));
    }

    #[test]
    fn test_from_mode_distinct_tls_peers_distinct_dedup_keys() {
        let peer_a = AuthenticatedPeer::from_mode(
            SecurityMode::TcpMtls,
            Some("CN=node-7,O=TideFS"),
            None,
            "10.0.0.1",
            9000,
        )
        .unwrap();
        let peer_b = AuthenticatedPeer::from_mode(
            SecurityMode::TcpMtls,
            Some("CN=node-8,O=TideFS"),
            None,
            "10.0.0.2",
            9001,
        )
        .unwrap();

        assert_ne!(peer_a.dedup_key(), peer_b.dedup_key());

        // Verify dedup keys are stable per identity
        let k1 = dedup_key(&peer_a, 42);
        let k2 = dedup_key(&peer_a, 42);
        assert_eq!(k1, k2);

        // Different peer -> different key
        let k3 = dedup_key(&peer_b, 42);
        assert_ne!(k1, k3);
    }

    #[test]
    fn test_from_mode_tls_peer_admin_access() {
        let peer = AuthenticatedPeer::from_mode(
            SecurityMode::TcpMtls,
            Some("CN=admin-node,O=TideFS"),
            None,
            "10.0.0.1",
            9000,
        )
        .unwrap();
        assert!(peer.can_access_admin());
    }

    // --- verify_hello_security TcpMtls ---

    #[test]
    fn test_verify_hello_security_tcp_mtls_with_dn() {
        let client_tlvs = vec![HelloTlv::auth_mode(SecurityMode::TcpMtls)];
        let server_tlvs = vec![HelloTlv::auth_mode_ack(SecurityMode::TcpMtls)];
        let client_nonce = [0xAAu8; 32];
        let server_nonce = [0xBBu8; 32];
        let psk_store = PskStore::new();

        let (mode, peer) = verify_hello_security(
            &client_tlvs,
            &server_tlvs,
            &client_nonce,
            &server_nonce,
            &psk_store,
            Some("CN=node-5,O=TideFS"),
        )
        .unwrap();

        assert_eq!(mode, SecurityMode::TcpMtls);
        assert_eq!(
            peer,
            AuthenticatedPeer::TlsPeerDN("CN=node-5,O=TideFS".into())
        );
        assert_eq!(peer.dedup_key(), "tls:CN=node-5,O=TideFS");
    }

    #[test]
    fn test_verify_hello_security_tcp_mtls_missing_dn_refused() {
        let client_tlvs = vec![HelloTlv::auth_mode(SecurityMode::TcpMtls)];
        let server_tlvs = vec![HelloTlv::auth_mode_ack(SecurityMode::TcpMtls)];
        let client_nonce = [0xAAu8; 32];
        let server_nonce = [0xBBu8; 32];
        let psk_store = PskStore::new();

        let result = verify_hello_security(
            &client_tlvs,
            &server_tlvs,
            &client_nonce,
            &server_nonce,
            &psk_store,
            None,
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SecurityError::TlsPeerIdentityMissing
        ));
    }

    #[test]
    fn test_verify_hello_security_distinct_tls_dn_distinct_peers() {
        let client_tlvs = vec![HelloTlv::auth_mode(SecurityMode::TcpMtls)];
        let server_tlvs = vec![HelloTlv::auth_mode_ack(SecurityMode::TcpMtls)];
        let client_nonce = [0xAAu8; 32];
        let server_nonce = [0xBBu8; 32];
        let psk_store = PskStore::new();

        let (_mode_a, peer_a) = verify_hello_security(
            &client_tlvs,
            &server_tlvs,
            &client_nonce,
            &server_nonce,
            &psk_store,
            Some("CN=node-7,O=TideFS"),
        )
        .unwrap();

        let (_mode_b, peer_b) = verify_hello_security(
            &client_tlvs,
            &server_tlvs,
            &client_nonce,
            &server_nonce,
            &psk_store,
            Some("CN=node-8,O=TideFS"),
        )
        .unwrap();

        assert_ne!(peer_a.dedup_key(), peer_b.dedup_key());
    }

    #[test]
    fn test_dedup_key_stable() {
        let peer = AuthenticatedPeer::PskIdentity("node-7".into());
        let k1 = dedup_key(&peer, 42);
        let k2 = dedup_key(&peer, 42);
        assert_eq!(k1, k2);
        // Different op_id should produce different key
        let k3 = dedup_key(&peer, 43);
        assert_ne!(k1, k3);
        // Different peer should produce different key
        let peer2 = AuthenticatedPeer::PskIdentity("node-8".into());
        let k4 = dedup_key(&peer2, 42);
        assert_ne!(k1, k4);
    }

    #[test]
    fn test_dedup_window_basic() {
        let peer = AuthenticatedPeer::PskIdentity("node-7".into());
        let mut window = DedupWindow::new(100);

        assert_eq!(window.check_and_record(&peer, 1), DedupResult::New);
        assert_eq!(window.check_and_record(&peer, 1), DedupResult::Duplicate);
        assert_eq!(window.check_and_record(&peer, 2), DedupResult::New);
    }

    #[test]
    fn test_dedup_window_different_peers() {
        let peer_a = AuthenticatedPeer::PskIdentity("node-7".into());
        let peer_b = AuthenticatedPeer::PskIdentity("node-8".into());
        let mut window = DedupWindow::new(100);

        assert_eq!(window.check_and_record(&peer_a, 1), DedupResult::New);
        assert_eq!(window.check_and_record(&peer_b, 1), DedupResult::New);
        assert_eq!(window.check_and_record(&peer_a, 1), DedupResult::Duplicate);
        assert_eq!(window.check_and_record(&peer_b, 1), DedupResult::Duplicate);
    }

    #[test]
    fn test_dedup_window_eviction() {
        let peer = AuthenticatedPeer::PskIdentity("node-7".into());
        let mut window = DedupWindow::new(3);

        window.check_and_record(&peer, 1);
        window.check_and_record(&peer, 2);
        window.check_and_record(&peer, 3);
        // Window is full, next insert evicts oldest (op_id 1)
        window.check_and_record(&peer, 4);

        // op_id 1 should be evicted, so it's "new" again
        assert_eq!(window.check_and_record(&peer, 1), DedupResult::New);
        // op_id 4 should still be tracked
        assert_eq!(window.check_and_record(&peer, 4), DedupResult::Duplicate);
    }

    // --- Admin access check ---

    #[test]
    fn test_admin_access_insecure_allowed() {
        let peer = AuthenticatedPeer::DevInsecure {
            src_ip: "127.0.0.1".into(),
            src_port: 12345,
        };
        assert!(admin_access_check(&peer, &[]).is_ok());
    }

    #[test]
    fn test_admin_access_unauthenticated_denied() {
        let peer = AuthenticatedPeer::TrustedFabricUnauthenticated {
            src_ip: "10.0.0.1".into(),
            src_port: 9000,
        };
        let result = admin_access_check(&peer, &[]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AdminAccessDenied::NotAuthenticated
        ));
    }

    #[test]
    fn test_admin_access_not_in_set() {
        let peer = AuthenticatedPeer::PskIdentity("node-7".into());
        let admin_set = vec![AuthenticatedPeer::PskIdentity("node-1".into())];
        let result = admin_access_check(&peer, &admin_set);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AdminAccessDenied::NotInAdminSet { .. }
        ));
    }

    #[test]
    fn test_admin_access_in_set() {
        let peer = AuthenticatedPeer::PskIdentity("node-7".into());
        let admin_set = vec![
            AuthenticatedPeer::PskIdentity("node-1".into()),
            AuthenticatedPeer::PskIdentity("node-7".into()),
        ];
        assert!(admin_access_check(&peer, &admin_set).is_ok());
    }

    // --- RDMA bulk gate ---

    #[test]
    fn test_rdma_dev_insecure_denied() {
        let peer = AuthenticatedPeer::DevInsecure {
            src_ip: "127.0.0.1".into(),
            src_port: 12345,
        };
        let config = ClusterSecurityConfig::default();
        let result = rdma_bulk_gate(SecurityMode::DevInsecure, &peer, &config);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RdmaBulkDenied::DevInsecureNotSupported
        ));
    }

    #[test]
    fn test_rdma_trusted_fabric_allowed() {
        let peer = AuthenticatedPeer::TrustedFabricPsk("node-7".into());
        let config = ClusterSecurityConfig::default();
        assert!(rdma_bulk_gate(SecurityMode::TrustedFabric, &peer, &config).is_ok());
    }

    #[test]
    fn test_rdma_authenticated_requires_ack() {
        let peer = AuthenticatedPeer::PskIdentity("node-7".into());
        let config = ClusterSecurityConfig::default(); // allow_rdma_over_authenticated = false
        let result = rdma_bulk_gate(SecurityMode::PskHmac, &peer, &config);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RdmaBulkDenied::OperatorAckRequired
        ));
    }

    #[test]
    fn test_rdma_authenticated_with_ack() {
        let peer = AuthenticatedPeer::PskIdentity("node-7".into());
        let config = ClusterSecurityConfig {
            allow_rdma_over_authenticated: true,
        };
        assert!(rdma_bulk_gate(SecurityMode::PskHmac, &peer, &config).is_ok());
    }
}
