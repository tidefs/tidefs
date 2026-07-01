// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use ed25519_dalek::{Keypair, Signature, Signer, Verifier};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::error::AttestationError;
use crate::identity::{NodeIdentity, NodeKeyStore};
use crate::security::HelloTlv;

// ---------------------------------------------------------------------------
// Session token (short-lived, bound to a session)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SessionToken {
    pub session_id: u64,
    pub token_bytes: [u8; 32],
    pub issued_at_millis: u64,
    pub expires_at_millis: u64,
}

impl SessionToken {
    pub fn generate(session_id: u64, ttl_millis: u64) -> Self {
        let mut rng = rand::thread_rng();
        let mut token_bytes = [0u8; 32];
        rng.fill(&mut token_bytes);

        let now = crate::identity::current_time_utils();
        Self {
            session_id,
            token_bytes,
            issued_at_millis: now,
            expires_at_millis: now + ttl_millis,
        }
    }

    pub fn is_expired(&self) -> bool {
        crate::identity::current_time_utils() > self.expires_at_millis
    }
}

// ---------------------------------------------------------------------------
// Session class for negotiation
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionClass {
    FullMesh,
    DomainAware,
    Ring,
    Dedicated,
}

impl std::fmt::Display for SessionClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FullMesh => write!(f, "full_mesh"),
            Self::DomainAware => write!(f, "domain_aware"),
            Self::Ring => write!(f, "ring"),
            Self::Dedicated => write!(f, "dedicated"),
        }
    }
}

// ---------------------------------------------------------------------------
// HelloMessage: initial client→server attestation request
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct HelloMessage {
    pub client_identity: NodeIdentity,
    pub client_nonce: [u8; 32],
    pub supported_protocol_versions: Vec<u16>,
    pub proposed_session_class: SessionClass,
    pub proposed_epoch: u64,
    /// Signature over all above fields, signed by client's private key
    pub signature: Vec<u8>,
    /// Security TLV extensions (HELLO auth negotiation) — not covered by Ed25519 sig
    pub security_tlvs: Vec<HelloTlv>,
}

impl HelloMessage {
    /// Create a signed HelloMessage.
    pub fn new(
        client_identity: NodeIdentity,
        signing_key: &Keypair,
        supported_versions: Vec<u16>,
        session_class: SessionClass,
        epoch: u64,
    ) -> Self {
        let mut rng = rand::thread_rng();
        let mut nonce = [0u8; 32];
        rng.fill(&mut nonce);

        let mut msg = Self {
            client_identity,
            client_nonce: nonce,
            supported_protocol_versions: supported_versions,
            proposed_session_class: session_class,
            proposed_epoch: epoch,
            signature: Vec::new(),
            security_tlvs: Vec::new(),
        };

        // Sign all fields except the signature itself
        let preimage = msg.preimage_for_signing();
        msg.signature = signing_key.sign(&preimage).to_bytes().to_vec();

        msg
    }

    /// Verify the client's signature on this message.
    pub fn verify(&self) -> Result<(), AttestationError> {
        let verifying_key = self.client_identity.verifying_key().map_err(|e| {
            AttestationError::SignatureVerificationFailed {
                node_id: self.client_identity.node_id,
                reason: e.to_string(),
            }
        })?;

        let preimage = self.preimage_for_signing();
        let signature = Signature::from_bytes(&self.signature).map_err(|e| {
            AttestationError::SignatureVerificationFailed {
                node_id: self.client_identity.node_id,
                reason: format!("invalid signature bytes: {e}"),
            }
        })?;

        verifying_key.verify(&preimage, &signature).map_err(|e| {
            AttestationError::SignatureVerificationFailed {
                node_id: self.client_identity.node_id,
                reason: format!("signature mismatch: {e}"),
            }
        })?;

        Ok(())
    }

    fn preimage_for_signing(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.client_identity.node_id.to_le_bytes());
        buf.extend_from_slice(&self.client_identity.verifying_key_bytes);
        buf.extend_from_slice(&self.client_identity.attested_at_millis.to_le_bytes());
        buf.extend_from_slice(&self.client_identity.identity_version.to_le_bytes());
        buf.extend_from_slice(&self.client_nonce);
        for v in &self.supported_protocol_versions {
            buf.extend_from_slice(&v.to_le_bytes());
        }
        buf.extend_from_slice(self.proposed_session_class.to_string().as_bytes());
        buf.extend_from_slice(&self.proposed_epoch.to_le_bytes());
        buf
    }

    /// Attach security TLVs from the transport layer for HELLO auth negotiation (§10.2).
    ///
    /// The security TLVs are not covered by the Ed25519 signature — they are
    /// independently authenticated via their own mechanisms (PSK HMAC, TLS binding).
    pub fn with_security_tlvs(mut self, tlvs: Vec<HelloTlv>) -> Self {
        self.security_tlvs = tlvs;
        self
    }
}

// ---------------------------------------------------------------------------
// HelloResponse: server→client attestation response
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct HelloResponse {
    pub server_identity: NodeIdentity,
    pub server_nonce: [u8; 32],
    pub client_nonce_echo: [u8; 32],
    /// Server signs (client_nonce || server_nonce) as a challenge
    pub signed_challenge: Vec<u8>,
    pub accepted_protocol_version: u16,
    pub accepted_session_class: SessionClass,
    pub session_token: SessionToken,
    pub server_epoch: u64,
    /// Signature over all above fields
    pub signature: Vec<u8>,
    /// Security TLV extensions (HELLO auth response) — not covered by Ed25519 sig
    pub security_tlvs: Vec<HelloTlv>,
}

impl HelloResponse {
    /// Create a signed HelloResponse.
    pub fn new(
        server_identity: NodeIdentity,
        signing_key: &Keypair,
        client_nonce: [u8; 32],
        accepted_version: u16,
        accepted_session_class: SessionClass,
        session_id: u64,
        epoch: u64,
    ) -> Self {
        let mut rng = rand::thread_rng();
        let mut server_nonce = [0u8; 32];
        rng.fill(&mut server_nonce);

        // Challenge: server signs (client_nonce || server_nonce)
        let mut challenge = Vec::new();
        challenge.extend_from_slice(&client_nonce);
        challenge.extend_from_slice(&server_nonce);
        let signed_challenge = signing_key.sign(&challenge).to_bytes().to_vec();

        let session_token = SessionToken::generate(session_id, 3_600_000); // 1 hour default

        let mut resp = Self {
            server_identity,
            server_nonce,
            client_nonce_echo: client_nonce,
            signed_challenge,
            accepted_protocol_version: accepted_version,
            accepted_session_class,
            session_token,
            server_epoch: epoch,
            signature: Vec::new(),
            security_tlvs: Vec::new(),
        };

        let preimage = resp.preimage_for_signing();
        resp.signature = signing_key.sign(&preimage).to_bytes().to_vec();

        resp
    }

    /// Verify the server's signature on this response.
    pub fn verify(&self) -> Result<(), AttestationError> {
        let verifying_key = self.server_identity.verifying_key().map_err(|e| {
            AttestationError::SignatureVerificationFailed {
                node_id: self.server_identity.node_id,
                reason: e.to_string(),
            }
        })?;

        let preimage = self.preimage_for_signing();
        let signature = Signature::from_bytes(&self.signature).map_err(|e| {
            AttestationError::SignatureVerificationFailed {
                node_id: self.server_identity.node_id,
                reason: format!("invalid response signature: {e}"),
            }
        })?;

        verifying_key.verify(&preimage, &signature).map_err(|e| {
            AttestationError::SignatureVerificationFailed {
                node_id: self.server_identity.node_id,
                reason: format!("response signature mismatch: {e}"),
            }
        })?;

        Ok(())
    }

    fn preimage_for_signing(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.server_identity.node_id.to_le_bytes());
        buf.extend_from_slice(&self.server_identity.verifying_key_bytes);
        buf.extend_from_slice(&self.server_identity.attested_at_millis.to_le_bytes());
        buf.extend_from_slice(&self.server_identity.identity_version.to_le_bytes());
        buf.extend_from_slice(&self.server_nonce);
        buf.extend_from_slice(&self.client_nonce_echo);
        buf.extend_from_slice(&self.accepted_protocol_version.to_le_bytes());
        buf.extend_from_slice(self.accepted_session_class.to_string().as_bytes());
        buf.extend_from_slice(&self.server_epoch.to_le_bytes());
        buf
    }

    /// Attach security TLVs from the transport layer for HELLO auth response (§10.2).
    pub fn with_security_tlvs(mut self, tlvs: Vec<HelloTlv>) -> Self {
        self.security_tlvs = tlvs;
        self
    }
}

// ---------------------------------------------------------------------------
// Mutual attestation verifier
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationResult {
    pub session_token: SessionToken,
    pub peer_identity: NodeIdentity,
    pub session_class: SessionClass,
    pub epoch: u64,
    pub verified: bool,
}

/// Verify the full mutual attestation handshake.
///
/// Steps:
/// 1. Verify client self-signature on identity
/// 2. Verify server self-signature on identity
/// 3. Verify client signature on HelloMessage
/// 4. Verify server signature on HelloResponse
/// 5. Verify server's signed challenge (client_nonce || server_nonce)
/// 6. Verify client nonce echo
/// 7. Verify both identities are known to the key store
pub fn verify_mutual_attestation(
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    client_msg: &HelloMessage,
    server_msg: &HelloResponse,
    known_keys: &NodeKeyStore,
) -> Result<AttestationResult, AttestationError> {
    // 1. Verify client self-signature
    client_msg
        .client_identity
        .verify_self_signature()
        .map_err(|e| AttestationError::SignatureVerificationFailed {
            node_id: client_msg.client_identity.node_id,
            reason: e.to_string(),
        })?;

    // 2. Verify server self-signature
    server_msg
        .server_identity
        .verify_self_signature()
        .map_err(|e| AttestationError::SignatureVerificationFailed {
            node_id: server_msg.server_identity.node_id,
            reason: e.to_string(),
        })?;

    // 3. Verify client HelloMessage signature
    client_msg.verify()?;

    // 4. Verify server HelloResponse signature
    server_msg.verify()?;

    // 5. Verify server's signed challenge: server signed (client_nonce || server_nonce)
    let server_vk = server_msg.server_identity.verifying_key().map_err(|e| {
        AttestationError::SignatureVerificationFailed {
            node_id: server_msg.server_identity.node_id,
            reason: e.to_string(),
        }
    })?;

    let mut challenge = Vec::new();
    challenge.extend_from_slice(client_nonce);
    challenge.extend_from_slice(server_nonce);

    let challenge_sig = Signature::from_bytes(&server_msg.signed_challenge).map_err(|e| {
        AttestationError::ChallengeFailed {
            reason: format!("invalid challenge signature bytes: {e}"),
        }
    })?;

    server_vk.verify(&challenge, &challenge_sig).map_err(|e| {
        AttestationError::ChallengeFailed {
            reason: format!("challenge verification failed: {e}"),
        }
    })?;

    // 6. Verify client nonce echo
    if server_msg.client_nonce_echo != *client_nonce {
        return Err(AttestationError::NonceMismatch);
    }

    // 7. Verify identities against known keys
    if !known_keys.contains(client_msg.client_identity.node_id) {
        return Err(AttestationError::IdentityNotInEpoch {
            node_id: client_msg.client_identity.node_id,
        });
    }

    if !known_keys.contains(server_msg.server_identity.node_id) {
        return Err(AttestationError::IdentityNotInEpoch {
            node_id: server_msg.server_identity.node_id,
        });
    }

    if client_msg.proposed_epoch != server_msg.server_epoch {
        return Err(AttestationError::EpochMismatch {
            client_epoch: client_msg.proposed_epoch,
            server_epoch: server_msg.server_epoch,
        });
    }

    Ok(AttestationResult {
        session_token: server_msg.session_token.clone(),
        peer_identity: server_msg.server_identity.clone(),
        session_class: server_msg.accepted_session_class,
        epoch: server_msg.server_epoch,
        verified: true,
    })
}

// ---------------------------------------------------------------------------
// Algorithm: mint_session_grant_for_authenticated_subject.
// ---------------------------------------------------------------------------

use crate::principal::{Principal, ScopeSelector};
use crate::records::{AssuranceClass, SessionGrantId, SessionGrantRecord};

/// Mint a session grant for an authenticated principal after successful
/// attestation handshake.
///
/// Produces a `SessionGrantRecord` with audience, assurance
/// class, scope ceiling, and revocation epoch.
#[allow(clippy::too_many_arguments)]
pub fn mint_session_grant_for_authenticated_subject(
    grant_id: SessionGrantId,
    session_id: u64,
    principal: &Principal,
    token_bytes: [u8; 32],
    ttl_millis: u64,
    audience: Vec<u64>,
    assurance_class: AssuranceClass,
    scope_ceiling: ScopeSelector,
    revocation_epoch: u64,
    signing_key: &ed25519_dalek::Keypair,
) -> crate::records::SessionGrantRecord {
    SessionGrantRecord::new(
        grant_id,
        session_id,
        principal.principal_id,
        token_bytes,
        ttl_millis,
        audience,
        assurance_class,
        scope_ceiling,
        revocation_epoch,
        signing_key,
    )
}

// ---------------------------------------------------------------------------
// Algorithm: check_nonce_replay — design §4.2, §11.2
// ---------------------------------------------------------------------------

/// Per-listener nonce deduplication cache (1024-entry LRU).
///
/// Capacity: 1024 recent nonces. When full, the oldest entry is evicted.
/// This prevents replay of a captured `HelloMessage` with the same nonce.
#[derive(Clone, Debug)]
pub struct NonceCache {
    entries: std::collections::VecDeque<[u8; 32]>,
    capacity: usize,
}

impl NonceCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: std::collections::VecDeque::new(),
            capacity,
        }
    }

    /// Record a nonce as seen. Evicts oldest if at capacity.
    pub fn record(&mut self, nonce: [u8; 32]) {
        if self.entries.len() >= self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back(nonce);
    }

    /// Check if a nonce has been seen.
    pub fn contains(&self, nonce: &[u8; 32]) -> bool {
        self.entries.contains(nonce)
    }
}

impl Default for NonceCache {
    fn default() -> Self {
        Self::new(1024)
    }
}

/// Check whether a nonce has been replayed.
///
/// If the nonce is new, it is inserted into the cache and `Ok(())` is returned.
/// If the nonce is already in the cache, `Err(AttestationError::NonceReplay)` is returned.
pub fn check_nonce_replay(
    cache: &mut NonceCache,
    nonce: &[u8; 32],
    node_id: u64,
) -> Result<(), crate::error::AttestationError> {
    if cache.contains(nonce) {
        return Err(crate::error::AttestationError::NonceReplay { node_id });
    }
    cache.record(*nonce);
    Ok(())
}
