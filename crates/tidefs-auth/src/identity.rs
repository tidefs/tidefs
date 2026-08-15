// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroize;

use crate::error::IdentityError;

// ---------------------------------------------------------------------------
// NodeIdentity: Ed25519-based node identity with self-signed attestation
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct NodeIdentity {
    pub node_id: u64,
    pub verifying_key_bytes: [u8; 32],
    pub attested_at_millis: u64,
    pub identity_version: u64,
    /// Self-signed signature over (node_id || verifying_key || attested_at || version)
    pub self_signature: Vec<u8>,
}

impl NodeIdentity {
    /// Generate a new node identity with a fresh Ed25519 key pair.
    pub fn generate(node_id: u64) -> Result<(Self, Keypair), IdentityError> {
        let mut csprng = OsRng;
        let signing_key = Keypair::generate(&mut csprng);
        let verifying_key = signing_key.public;

        let attested_at_millis = current_time_utils();
        let identity_version: u64 = 1;

        // Self-sign: sign(node_id || verifying_key || attested_at || version)
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&node_id.to_le_bytes());
        preimage.extend_from_slice(verifying_key.as_bytes());
        preimage.extend_from_slice(&attested_at_millis.to_le_bytes());
        preimage.extend_from_slice(&identity_version.to_le_bytes());

        let self_signature = signing_key.sign(&preimage).to_bytes().to_vec();

        Ok((
            Self {
                node_id,
                verifying_key_bytes: verifying_key.to_bytes(),
                attested_at_millis,
                identity_version,
                self_signature,
            },
            signing_key,
        ))
    }

    /// Verify the self-signature on this identity.
    pub fn verify_self_signature(&self) -> Result<(), IdentityError> {
        let verifying_key = PublicKey::from_bytes(&self.verifying_key_bytes).map_err(|e| {
            IdentityError::KeyGenerationFailed {
                reason: format!("invalid verifying key: {e}"),
            }
        })?;

        let mut preimage = Vec::new();
        preimage.extend_from_slice(&self.node_id.to_le_bytes());
        preimage.extend_from_slice(self.verifying_key_bytes.as_slice());
        preimage.extend_from_slice(&self.attested_at_millis.to_le_bytes());
        preimage.extend_from_slice(&self.identity_version.to_le_bytes());

        let signature = Signature::from_bytes(&self.self_signature).map_err(|e| {
            IdentityError::KeyGenerationFailed {
                reason: format!("invalid self-signature bytes: {e}"),
            }
        })?;

        verifying_key
            .verify(&preimage, &signature)
            .map_err(|e| IdentityError::Revoked {
                reason: format!("self-signature verification failed: {e}"),
            })?;

        Ok(())
    }

    /// Rotate to a new key pair. Returns the new identity, new signing key,
    /// and a KeyRotationRecord with the old-key rotation proof.
    /// The old key signs the rotation payload (proving continuity of identity),
    /// and the new key self-signs the new identity.
    pub fn rotate(
        &self,
        signing_key: &Keypair,
    ) -> Result<(Self, Keypair, KeyRotationRecord), IdentityError> {
        let new_version = self.identity_version + 1;
        let mut csprng = OsRng;
        let new_signing_key = Keypair::generate(&mut csprng);
        let new_verifying_key = new_signing_key.public;

        let rotated_at_millis = current_time_utils();

        let mut preimage = Vec::new();
        preimage.extend_from_slice(&self.node_id.to_le_bytes());
        preimage.extend_from_slice(new_verifying_key.as_bytes());
        preimage.extend_from_slice(&rotated_at_millis.to_le_bytes());
        preimage.extend_from_slice(&new_version.to_le_bytes());

        // Sign the rotation payload with the OLD key (proves continuity of identity)
        let rotation_proof = signing_key.sign(&preimage).to_bytes().to_vec();

        // Self-sign the new identity with the NEW key
        let self_signature = new_signing_key.sign(&preimage).to_bytes().to_vec();

        let new_identity = Self {
            node_id: self.node_id,
            verifying_key_bytes: new_verifying_key.to_bytes(),
            attested_at_millis: rotated_at_millis,
            identity_version: new_version,
            self_signature,
        };

        let rotation_record = KeyRotationRecord {
            node_id: self.node_id,
            old_identity_version: self.identity_version,
            new_identity_version: new_version,
            new_verifying_key_bytes: new_verifying_key.to_bytes(),
            rotated_at_millis,
            rotation_proof,
        };

        Ok((new_identity, new_signing_key, rotation_record))
    }

    /// Get the verifying key for signature verification.
    pub fn verifying_key(&self) -> Result<PublicKey, IdentityError> {
        PublicKey::from_bytes(&self.verifying_key_bytes).map_err(|e| {
            IdentityError::KeyGenerationFailed {
                reason: format!("invalid verifying key: {e}"),
            }
        })
    }

    /// Emergency rotation after a confirmed compromise. Returns a
    /// CompromiseRecoveryRecord with epoch fencing metadata.
    ///
    /// Differs from regular rotation: the old key is NOT used to sign the
    /// rotation — we cannot trust a compromised key. Instead, the new key
    /// self-signs and the caller (operator or quorum) must publish the
    /// CompromiseRecoveryRecord to fence the compromised identity from the
    /// current epoch.
    pub fn compromise_rotate(
        &self,
    ) -> Result<(Self, Keypair, CompromiseRecoveryRecord), IdentityError> {
        let new_version = self.identity_version + 1;
        let mut csprng = OsRng;
        let new_signing_key = Keypair::generate(&mut csprng);
        let new_verifying_key = new_signing_key.public;

        let recovered_at_millis = current_time_utils();

        let mut preimage = Vec::new();
        preimage.extend_from_slice(&self.node_id.to_le_bytes());
        preimage.extend_from_slice(new_verifying_key.as_bytes());
        preimage.extend_from_slice(&recovered_at_millis.to_le_bytes());
        preimage.extend_from_slice(&new_version.to_le_bytes());

        // ONLY self-sign with the new key — the old key is untrusted
        let self_signature = new_signing_key.sign(&preimage).to_bytes().to_vec();

        let new_identity = Self {
            node_id: self.node_id,
            verifying_key_bytes: new_verifying_key.to_bytes(),
            attested_at_millis: recovered_at_millis,
            identity_version: new_version,
            self_signature: self_signature.clone(),
        };

        let recovery_record = CompromiseRecoveryRecord {
            node_id: self.node_id,
            compromised_identity_version: self.identity_version,
            new_identity_version: new_version,
            new_verifying_key_bytes: new_verifying_key.to_bytes(),
            recovered_at_millis,
            new_self_signature: self_signature,
        };

        Ok((new_identity, new_signing_key, recovery_record))
    }
}

// ---------------------------------------------------------------------------
// Operator-provisioned node credential records
// ---------------------------------------------------------------------------

const NODE_RECORD_HEADER_SIZE: usize = 16;
const NODE_IDENTITY_PAYLOAD_SIZE: usize = 120;
const NODE_IDENTITY_PAYLOAD_OFFSET: usize = NODE_RECORD_HEADER_SIZE;
const NODE_KEYPAIR_SIZE: usize = 64;
const NODE_CREDENTIAL_MAGIC: [u8; 8] = *b"TIDENCR1";
const NODE_PUBLIC_IDENTITY_MAGIC: [u8; 8] = *b"TIDENID1";
const NODE_RECORD_VERSION: u16 = 1;

/// Exact size of a version-1 private node credential record.
pub const NODE_PRIVATE_CREDENTIAL_WIRE_SIZE: usize =
    NODE_RECORD_HEADER_SIZE + NODE_IDENTITY_PAYLOAD_SIZE + NODE_KEYPAIR_SIZE;

/// Exact size of a version-1 shareable public node identity record.
pub const NODE_PUBLIC_IDENTITY_WIRE_SIZE: usize =
    NODE_RECORD_HEADER_SIZE + NODE_IDENTITY_PAYLOAD_SIZE;

/// Strict decode/validation error for provisioned node identity records.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum NodeCredentialError {
    #[error("{record} record length is {actual} bytes; expected {expected}")]
    InvalidLength {
        record: &'static str,
        actual: usize,
        expected: usize,
    },
    #[error("invalid {record} record magic")]
    InvalidMagic { record: &'static str },
    #[error("unsupported {record} record version {version}")]
    UnsupportedVersion { record: &'static str, version: u16 },
    #[error("invalid {record} record header")]
    InvalidHeader { record: &'static str },
    #[error("node credential identity must be nonzero")]
    ZeroNodeId,
    #[error("invalid node identity: {reason}")]
    InvalidIdentity { reason: String },
    #[error("invalid Ed25519 private credential: {reason}")]
    InvalidKeypair { reason: String },
    #[error("private credential does not match its public node identity")]
    PublicKeyMismatch,
}

/// Host-local Ed25519 node credential.
///
/// The keypair bytes are never exposed directly and are redacted from debug
/// output. Callers can reconstruct a validated keypair for transport setup.
pub struct NodePrivateCredential {
    identity: NodeIdentity,
    keypair_bytes: [u8; NODE_KEYPAIR_SIZE],
}

impl std::fmt::Debug for NodePrivateCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NodePrivateCredential")
            .field("identity", &self.identity)
            .field("keypair", &"<redacted>")
            .finish()
    }
}

impl Drop for NodePrivateCredential {
    fn drop(&mut self) {
        self.keypair_bytes.zeroize();
    }
}

impl NodePrivateCredential {
    /// Generate an operator-provisionable identity using the operating system RNG.
    pub fn generate(node_id: u64) -> Result<Self, NodeCredentialError> {
        if node_id == 0 {
            return Err(NodeCredentialError::ZeroNodeId);
        }
        let (identity, keypair) = NodeIdentity::generate(node_id).map_err(|error| {
            NodeCredentialError::InvalidKeypair {
                reason: error.to_string(),
            }
        })?;
        Self::from_parts(identity, keypair)
    }

    /// Bind an existing identity to its exact Ed25519 keypair.
    pub fn from_parts(
        identity: NodeIdentity,
        keypair: Keypair,
    ) -> Result<Self, NodeCredentialError> {
        validate_public_identity(&identity)?;
        validate_keypair_matches_identity(&keypair, &identity)?;
        Ok(Self {
            identity,
            keypair_bytes: keypair.to_bytes(),
        })
    }

    #[must_use]
    pub const fn node_id(&self) -> u64 {
        self.identity.node_id
    }

    #[must_use]
    pub fn identity(&self) -> &NodeIdentity {
        &self.identity
    }

    /// Return the separately shareable public record for this credential.
    #[must_use]
    pub fn public_identity(&self) -> NodePublicIdentity {
        NodePublicIdentity {
            identity: self.identity.clone(),
        }
    }

    /// Reconstruct the validated signing key without exposing raw secret bytes.
    pub fn keypair(&self) -> Result<Keypair, NodeCredentialError> {
        let keypair = Keypair::from_bytes(&self.keypair_bytes).map_err(|error| {
            NodeCredentialError::InvalidKeypair {
                reason: error.to_string(),
            }
        })?;
        validate_keypair_matches_identity(&keypair, &self.identity)?;
        Ok(keypair)
    }

    /// Encode the credential as the sole accepted fixed-binary format.
    #[must_use]
    pub fn encode_fixed(&self) -> [u8; NODE_PRIVATE_CREDENTIAL_WIRE_SIZE] {
        let mut out = [0_u8; NODE_PRIVATE_CREDENTIAL_WIRE_SIZE];
        encode_record_header(&mut out, NODE_CREDENTIAL_MAGIC);
        encode_identity_payload(&mut out, &self.identity);
        out[NODE_PUBLIC_IDENTITY_WIRE_SIZE..].copy_from_slice(&self.keypair_bytes);
        out
    }

    /// Decode and fully validate one fixed-binary private credential record.
    pub fn decode_fixed(bytes: &[u8]) -> Result<Self, NodeCredentialError> {
        validate_record_header(
            bytes,
            "private credential",
            NODE_CREDENTIAL_MAGIC,
            NODE_PRIVATE_CREDENTIAL_WIRE_SIZE,
        )?;
        let identity = decode_identity_payload(bytes)?;
        let mut keypair_bytes = [0_u8; NODE_KEYPAIR_SIZE];
        keypair_bytes.copy_from_slice(&bytes[NODE_PUBLIC_IDENTITY_WIRE_SIZE..]);
        let keypair = match Keypair::from_bytes(&keypair_bytes) {
            Ok(keypair) => keypair,
            Err(error) => {
                keypair_bytes.zeroize();
                return Err(NodeCredentialError::InvalidKeypair {
                    reason: error.to_string(),
                });
            }
        };
        if let Err(error) = validate_keypair_matches_identity(&keypair, &identity) {
            keypair_bytes.zeroize();
            return Err(error);
        }
        Ok(Self {
            identity,
            keypair_bytes,
        })
    }
}

/// Shareable, self-signed public node identity record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodePublicIdentity {
    identity: NodeIdentity,
}

impl NodePublicIdentity {
    pub fn from_identity(identity: NodeIdentity) -> Result<Self, NodeCredentialError> {
        validate_public_identity(&identity)?;
        Ok(Self { identity })
    }

    #[must_use]
    pub const fn node_id(&self) -> u64 {
        self.identity.node_id
    }

    #[must_use]
    pub fn identity(&self) -> &NodeIdentity {
        &self.identity
    }

    #[must_use]
    pub fn into_identity(self) -> NodeIdentity {
        self.identity
    }

    /// Encode the public identity as the sole accepted fixed-binary format.
    #[must_use]
    pub fn encode_fixed(&self) -> [u8; NODE_PUBLIC_IDENTITY_WIRE_SIZE] {
        let mut out = [0_u8; NODE_PUBLIC_IDENTITY_WIRE_SIZE];
        encode_record_header(&mut out, NODE_PUBLIC_IDENTITY_MAGIC);
        encode_identity_payload(&mut out, &self.identity);
        out
    }

    /// Decode and fully validate one fixed-binary public identity record.
    pub fn decode_fixed(bytes: &[u8]) -> Result<Self, NodeCredentialError> {
        validate_record_header(
            bytes,
            "public identity",
            NODE_PUBLIC_IDENTITY_MAGIC,
            NODE_PUBLIC_IDENTITY_WIRE_SIZE,
        )?;
        Self::from_identity(decode_identity_payload(bytes)?)
    }
}

fn encode_record_header<const N: usize>(out: &mut [u8; N], magic: [u8; 8]) {
    out[..8].copy_from_slice(&magic);
    out[8..10].copy_from_slice(&NODE_RECORD_VERSION.to_le_bytes());
    out[10..12].copy_from_slice(&0_u16.to_le_bytes());
    out[12..16].copy_from_slice(&(N as u32).to_le_bytes());
}

fn validate_record_header(
    bytes: &[u8],
    record: &'static str,
    magic: [u8; 8],
    expected_len: usize,
) -> Result<(), NodeCredentialError> {
    if bytes.len() != expected_len {
        return Err(NodeCredentialError::InvalidLength {
            record,
            actual: bytes.len(),
            expected: expected_len,
        });
    }
    if bytes[..8] != magic {
        return Err(NodeCredentialError::InvalidMagic { record });
    }
    let version = u16::from_le_bytes(bytes[8..10].try_into().expect("fixed header slice"));
    if version != NODE_RECORD_VERSION {
        return Err(NodeCredentialError::UnsupportedVersion { record, version });
    }
    let reserved = u16::from_le_bytes(bytes[10..12].try_into().expect("fixed header slice"));
    let declared_len =
        u32::from_le_bytes(bytes[12..16].try_into().expect("fixed header slice")) as usize;
    if reserved != 0 || declared_len != expected_len {
        return Err(NodeCredentialError::InvalidHeader { record });
    }
    Ok(())
}

fn encode_identity_payload<const N: usize>(out: &mut [u8; N], identity: &NodeIdentity) {
    let mut offset = NODE_IDENTITY_PAYLOAD_OFFSET;
    out[offset..offset + 8].copy_from_slice(&identity.node_id.to_le_bytes());
    offset += 8;
    out[offset..offset + 32].copy_from_slice(&identity.verifying_key_bytes);
    offset += 32;
    out[offset..offset + 8].copy_from_slice(&identity.attested_at_millis.to_le_bytes());
    offset += 8;
    out[offset..offset + 8].copy_from_slice(&identity.identity_version.to_le_bytes());
    offset += 8;
    debug_assert_eq!(identity.self_signature.len(), 64);
    out[offset..offset + 64].copy_from_slice(&identity.self_signature);
}

fn decode_identity_payload(bytes: &[u8]) -> Result<NodeIdentity, NodeCredentialError> {
    let mut offset = NODE_IDENTITY_PAYLOAD_OFFSET;
    let node_id = u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("fixed payload"));
    offset += 8;
    let mut verifying_key_bytes = [0_u8; 32];
    verifying_key_bytes.copy_from_slice(&bytes[offset..offset + 32]);
    offset += 32;
    let attested_at_millis =
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("fixed payload"));
    offset += 8;
    let identity_version =
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("fixed payload"));
    offset += 8;
    let self_signature = bytes[offset..offset + 64].to_vec();
    let identity = NodeIdentity {
        node_id,
        verifying_key_bytes,
        attested_at_millis,
        identity_version,
        self_signature,
    };
    validate_public_identity(&identity)?;
    Ok(identity)
}

fn validate_public_identity(identity: &NodeIdentity) -> Result<(), NodeCredentialError> {
    if identity.node_id == 0 {
        return Err(NodeCredentialError::ZeroNodeId);
    }
    identity
        .verify_self_signature()
        .map_err(|error| NodeCredentialError::InvalidIdentity {
            reason: error.to_string(),
        })
}

fn validate_keypair_matches_identity(
    keypair: &Keypair,
    identity: &NodeIdentity,
) -> Result<(), NodeCredentialError> {
    let derived_public = PublicKey::from(&keypair.secret);
    if keypair.public.to_bytes() != identity.verifying_key_bytes
        || derived_public.to_bytes() != identity.verifying_key_bytes
    {
        return Err(NodeCredentialError::PublicKeyMismatch);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Well-known node key store
// ---------------------------------------------------------------------------

/// Registry of known node identities, keyed by node_id.
/// This is the bootstrap trust anchor — populated from config or initial seed.
pub struct NodeKeyStore {
    pub identities: BTreeMap<u64, NodeIdentity>,
}

impl NodeKeyStore {
    pub fn new() -> Self {
        Self {
            identities: BTreeMap::new(),
        }
    }

    /// Register a known node identity (from bootstrap config or previous epoch).
    pub fn register(&mut self, identity: NodeIdentity) -> Result<(), IdentityError> {
        identity.verify_self_signature()?;
        self.identities.insert(identity.node_id, identity);
        Ok(())
    }

    /// Look up a node's verifying key.
    pub fn get_verifying_key(&self, node_id: u64) -> Option<PublicKey> {
        self.identities
            .get(&node_id)
            .and_then(|id| id.verifying_key().ok())
    }

    /// Check if a node is known.
    pub fn contains(&self, node_id: u64) -> bool {
        self.identities.contains_key(&node_id)
    }
}

impl Default for NodeKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helper: approximate current time in milliseconds
// ---------------------------------------------------------------------------

pub fn current_time_utils() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ---------------------------------------------------------------------------
// Algorithm: resolve_principal_from_presented_credential_chain.
// ---------------------------------------------------------------------------

use crate::principal::Principal;
use crate::records::{CredentialBindingId, CredentialBindingRecord};

/// Resolve a principal from a credential binding record.
///
/// Looks up the binding by hash of the presented credential material,
/// verifies it is not expired, and returns the bound principal.
pub fn resolve_principal_from_presented_credential_chain(
    bindings: &BTreeMap<CredentialBindingId, CredentialBindingRecord>,
    credential_hash: &[u8; 32],
    principals: &BTreeMap<crate::principal::PrincipalId, Principal>,
) -> Result<Principal, crate::error::IdentityError> {
    // Find the binding for this credential hash
    let binding = bindings
        .values()
        .find(|b| &b.credential_hash == credential_hash)
        .ok_or(crate::error::IdentityError::CredentialBindingNotFound {
            hash: *credential_hash,
        })?;

    if binding.is_expired() {
        return Err(crate::error::IdentityError::CredentialBindingExpired {
            principal_id: format!("{:?}", binding.principal_id),
        });
    }

    principals.get(&binding.principal_id).cloned().ok_or(
        crate::error::IdentityError::CredentialBindingNotFound {
            hash: *credential_hash,
        },
    )
}

// ---------------------------------------------------------------------------
// Algorithm: validate_credential_binding_and_time_health.
// ---------------------------------------------------------------------------

/// Validate credential binding is healthy and within time bounds.
///
/// Checks:
/// 1. Binding is not expired
/// 2. Time skew is within acceptable threshold
pub fn validate_credential_binding_and_time_health(
    binding: &CredentialBindingRecord,
    observed_time_millis: u64,
    max_skew_millis: i64,
) -> Result<(), crate::error::AuthorizationError> {
    // Check binding expiration
    if binding.is_expired() {
        return Err(crate::error::AuthorizationError::SessionExpired {
            session_id: 0,
            expired_at: "credential binding expired".to_string(),
        });
    }

    // Check time skew: the binding's bound_at time vs observed time
    let bound_at = binding.bound_at_millis as i64;
    let observed = observed_time_millis as i64;
    let skew = (observed - bound_at).abs();

    if skew > max_skew_millis {
        return Err(crate::error::AuthorizationError::TimeHealthFailed {
            skew_ms: skew,
            threshold_ms: max_skew_millis,
        });
    }

    Ok(())
}
// ---------------------------------------------------------------------------
// Revocation structures — design §10.4
// ---------------------------------------------------------------------------

/// Reason a node identity was revoked (§10.4).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RevocationReason {
    ScheduledRotation,
    SuspectedCompromise,
    ConfirmedCompromise,
    OperatorInitiated,
    NodeDecommissioned,
}

impl std::fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ScheduledRotation => write!(f, "scheduled_rotation"),
            Self::SuspectedCompromise => write!(f, "suspected_compromise"),
            Self::ConfirmedCompromise => write!(f, "confirmed_compromise"),
            Self::OperatorInitiated => write!(f, "operator_initiated"),
            Self::NodeDecommissioned => write!(f, "node_decommissioned"),
        }
    }
}

/// Record that revokes a specific version of a node identity (§10.4).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct IdentityRevocationRecord {
    pub node_id: u64,
    pub identity_version: u64,
    pub revoked_at_millis: u64,
    pub revoked_by: crate::principal::PrincipalId,
    pub reason: RevocationReason,
    /// Signature by `revoked_by` over (node_id || identity_version || revoked_at_millis || reason).
    pub revocation_signature: Vec<u8>,
}

impl IdentityRevocationRecord {
    /// Create a signed revocation record.
    pub fn new(
        node_id: u64,
        identity_version: u64,
        revoked_by: crate::principal::PrincipalId,
        reason: RevocationReason,
        signing_key: &ed25519_dalek::Keypair,
    ) -> Self {
        let revoked_at_millis = current_time_utils();
        let preimage = Self::build_preimage(node_id, identity_version, revoked_at_millis, &reason);
        let revocation_signature = signing_key.sign(&preimage).to_bytes().to_vec();
        Self {
            node_id,
            identity_version,
            revoked_at_millis,
            revoked_by,
            reason,
            revocation_signature,
        }
    }

    /// Verify the revocation signature.
    pub fn verify(
        &self,
        verifying_key: &ed25519_dalek::PublicKey,
    ) -> Result<(), crate::error::IdentityError> {
        use ed25519_dalek::Verifier;
        let preimage = Self::build_preimage(
            self.node_id,
            self.identity_version,
            self.revoked_at_millis,
            &self.reason,
        );
        let signature =
            ed25519_dalek::Signature::from_bytes(&self.revocation_signature).map_err(|e| {
                crate::error::IdentityError::KeyGenerationFailed {
                    reason: format!("invalid revocation signature bytes: {e}"),
                }
            })?;
        verifying_key.verify(&preimage, &signature).map_err(|e| {
            crate::error::IdentityError::Revoked {
                reason: format!("revocation signature verification failed: {e}"),
            }
        })
    }

    fn build_preimage(
        node_id: u64,
        identity_version: u64,
        revoked_at_millis: u64,
        reason: &RevocationReason,
    ) -> Vec<u8> {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&node_id.to_le_bytes());
        preimage.extend_from_slice(&identity_version.to_le_bytes());
        preimage.extend_from_slice(&revoked_at_millis.to_le_bytes());
        preimage.extend_from_slice(reason.to_string().as_bytes());
        preimage
    }
}

// ---------------------------------------------------------------------------
// Algorithm: check_revocation_status — design §11.4
// ---------------------------------------------------------------------------

/// Local revocation set: maps (node_id, identity_version) pairs to their
/// revocation records. In production this would be a persistent, gossip-replicated
/// store. For now it is an in-memory set.
pub type RevocationSet = std::collections::BTreeMap<(u64, u64), IdentityRevocationRecord>;

/// Check whether a (node_id, identity_version) pair is revoked.
///
/// Returns `Ok(())` if not revoked, or `Err(IdentityError::Revoked)` if the
/// identity is present in the revocation set.
pub fn check_revocation_status(
    revocation_set: &RevocationSet,
    node_id: u64,
    identity_version: u64,
) -> Result<(), crate::error::IdentityError> {
    if revocation_set.contains_key(&(node_id, identity_version)) {
        return Err(crate::error::IdentityError::Revoked {
            reason: format!("identity (node={node_id}, version={identity_version}) is revoked"),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// KeyRotationRecord — §10.5 key rotation lifecycle
// ---------------------------------------------------------------------------

/// Record of a key rotation published in the membership epoch.
///
/// The `rotation_proof` is a signature by the old key over
/// (node_id || new_verifying_key || rotated_at_millis || new_version),
/// proving continuity of the node identity across the rotation.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct KeyRotationRecord {
    pub node_id: u64,
    pub old_identity_version: u64,
    pub new_identity_version: u64,
    pub new_verifying_key_bytes: [u8; 32],
    pub rotated_at_millis: u64,
    /// Signature by the old key proving continuity across the rotation.
    pub rotation_proof: Vec<u8>,
}

impl KeyRotationRecord {
    /// Verify the rotation proof using the old verifying key.
    ///
    /// Returns `Ok(())` if the old key signed the rotation payload,
    /// proving the rotation was authorized by the key holder.
    pub fn verify(&self, old_verifying_key: &PublicKey) -> Result<(), IdentityError> {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&self.node_id.to_le_bytes());
        preimage.extend_from_slice(&self.new_verifying_key_bytes);
        preimage.extend_from_slice(&self.rotated_at_millis.to_le_bytes());
        preimage.extend_from_slice(&self.new_identity_version.to_le_bytes());

        let signature = Signature::from_bytes(&self.rotation_proof).map_err(|e| {
            IdentityError::KeyRotationFailed {
                reason: format!("invalid rotation proof bytes: {e}"),
            }
        })?;

        old_verifying_key
            .verify(&preimage, &signature)
            .map_err(|e| IdentityError::KeyRotationFailed {
                reason: format!("rotation proof verification failed: {e}"),
            })
    }
}

// ---------------------------------------------------------------------------
// CompromiseRecoveryRecord — §10.6 emergency rotation with epoch fencing
// ---------------------------------------------------------------------------

/// Emergency rotation record for compromise recovery.
///
/// Unlike a normal `KeyRotationRecord`, the old key is NOT trusted to sign.
/// Instead, the node generates a new identity and self-signs. The record is
/// published with a `fence_epoch` that tells all peers to exclude the
/// compromised identity version from the membership view starting at that
/// epoch. The compromised node must then re-join with the new identity
/// (or be re-admitted by an operator).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CompromiseRecoveryRecord {
    pub node_id: u64,
    pub compromised_identity_version: u64,
    pub new_identity_version: u64,
    pub new_verifying_key_bytes: [u8; 32],
    pub recovered_at_millis: u64,
    /// Self-signature by the new key over the recovery payload.
    pub new_self_signature: Vec<u8>,
}

impl CompromiseRecoveryRecord {
    /// Verify the recovery record using the new verifying key.
    ///
    /// This proves the new key was freshly generated post-compromise.
    /// The caller must separately verify that the record was published
    /// by an authorized operator or quorum-approved epoch transition.
    pub fn verify_new_key_self_signature(&self) -> Result<(), IdentityError> {
        let new_verifying_key =
            PublicKey::from_bytes(&self.new_verifying_key_bytes).map_err(|e| {
                IdentityError::CompromiseRecoveryFailed {
                    reason: format!("invalid new verifying key: {e}"),
                }
            })?;

        let mut preimage = Vec::new();
        preimage.extend_from_slice(&self.node_id.to_le_bytes());
        preimage.extend_from_slice(&self.new_verifying_key_bytes);
        preimage.extend_from_slice(&self.recovered_at_millis.to_le_bytes());
        preimage.extend_from_slice(&self.new_identity_version.to_le_bytes());

        let signature = Signature::from_bytes(&self.new_self_signature).map_err(|e| {
            IdentityError::CompromiseRecoveryFailed {
                reason: format!("invalid recovery signature bytes: {e}"),
            }
        })?;

        new_verifying_key
            .verify(&preimage, &signature)
            .map_err(|e| IdentityError::CompromiseRecoveryFailed {
                reason: format!("recovery self-signature verification failed: {e}"),
            })
    }

    /// The fence epoch: all peers begin rejecting the compromised identity
    /// version at this epoch. Set by the quorum/operator when the record
    /// is published.
    pub fn fence_epoch(&self) -> u64 {
        // For now, fence immediately — the record IS the fence.
        // Future: a membership transition sets the actual fence epoch.
        self.recovered_at_millis
    }
}

// ---------------------------------------------------------------------------
// Grace-period revocation — §10.4.1
// ---------------------------------------------------------------------------

const DEFAULT_GRACE_PERIOD_MILLIS: u64 = 300_000; // 5 minutes

/// Extended revocation record including a grace period.
///
/// During the grace period (from `revoked_at_millis` to
/// `grace_period_until_millis`), messages signed by the revoked key are
/// still accepted with a warning logged. After the grace period expires,
/// the key is fully rejected.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GracePeriodRevocationRecord {
    pub revocation: IdentityRevocationRecord,
    /// Inclusive deadline: after this timestamp, messages are rejected.
    pub grace_period_until_millis: u64,
}

impl GracePeriodRevocationRecord {
    pub fn new(
        node_id: u64,
        identity_version: u64,
        revoked_by: crate::principal::PrincipalId,
        reason: RevocationReason,
        signing_key: &Keypair,
        grace_period_millis: u64,
    ) -> Self {
        let revocation = IdentityRevocationRecord::new(
            node_id,
            identity_version,
            revoked_by,
            reason,
            signing_key,
        );
        let grace_period_until_millis = revocation
            .revoked_at_millis
            .saturating_add(grace_period_millis);
        Self {
            revocation,
            grace_period_until_millis,
        }
    }

    /// Whether the grace period has expired.
    pub fn grace_period_expired(&self) -> bool {
        current_time_utils() >= self.grace_period_until_millis
    }

    /// Whether messages from this identity are still accepted (within grace).
    pub fn within_grace_period(&self) -> bool {
        !self.grace_period_expired()
    }
}

/// Revocation set with grace-period support: maps
/// `(node_id, identity_version)` to `GracePeriodRevocationRecord`.
pub type GracePeriodRevocationSet =
    std::collections::BTreeMap<(u64, u64), GracePeriodRevocationRecord>;

/// Check revocation status with grace-period semantics.
///
/// - If the identity is NOT in the revocation set, returns `Ok(())`.
/// - If the identity IS in the revocation set AND within the grace period,
///   returns `Err(IdentityError::RevocationGracePeriod)` — caller may choose
///   to accept with a warning.
/// - If the identity IS in the revocation set AND the grace period has
///   expired, returns `Err(IdentityError::Revoked)` — caller MUST reject.
pub fn check_revocation_status_with_grace(
    revocation_set: &GracePeriodRevocationSet,
    node_id: u64,
    identity_version: u64,
) -> Result<(), IdentityError> {
    if let Some(record) = revocation_set.get(&(node_id, identity_version)) {
        if record.grace_period_expired() {
            return Err(IdentityError::Revoked {
                reason: format!("identity (node={node_id}, version={identity_version}) is revoked"),
            });
        }
        return Err(IdentityError::RevocationGracePeriod {
            reason: format!(
                "identity (node={node_id}, version={identity_version}) revoked but within grace period"
            ),
        });
    }
    Ok(())
}

/// Insert a revocation into the grace-period set with the default 5-minute
/// grace period.
pub fn revoke_identity_with_grace(
    revocation_set: &mut GracePeriodRevocationSet,
    node_id: u64,
    identity_version: u64,
    revoked_by: crate::principal::PrincipalId,
    reason: RevocationReason,
    signing_key: &Keypair,
) {
    let record = GracePeriodRevocationRecord::new(
        node_id,
        identity_version,
        revoked_by,
        reason,
        signing_key,
        DEFAULT_GRACE_PERIOD_MILLIS,
    );
    revocation_set.insert((node_id, identity_version), record);
}

// ---------------------------------------------------------------------------
// KeyLifecycleStats — §10.7 key lifecycle metrics
// ---------------------------------------------------------------------------

/// Aggregate statistics for key lifecycle events on a node.
///
/// Tracks rotations, revocations, compromises, and current key age
/// for monitoring and alerting.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyLifecycleStats {
    pub total_rotations: u64,
    pub total_revocations: u64,
    pub total_compromises: u64,
    /// Time in milliseconds since the last rotation or initial generation.
    pub current_key_created_at_millis: u64,
    /// The current identity version.
    pub current_identity_version: u64,
}

impl KeyLifecycleStats {
    pub fn new(current_identity_version: u64, key_created_at_millis: u64) -> Self {
        Self {
            total_rotations: 0,
            total_revocations: 0,
            total_compromises: 0,
            current_key_created_at_millis: key_created_at_millis,
            current_identity_version,
        }
    }

    /// Record a completed key rotation.
    pub fn record_rotation(&mut self, new_version: u64) {
        self.total_rotations += 1;
        self.current_identity_version = new_version;
        self.current_key_created_at_millis = current_time_utils();
    }

    /// Record a completed compromise recovery.
    pub fn record_compromise(&mut self, new_version: u64) {
        self.total_compromises += 1;
        self.total_rotations += 1; // compromise recovery is also a rotation
        self.current_identity_version = new_version;
        self.current_key_created_at_millis = current_time_utils();
    }

    /// Record a revocation event (does not change current key info).
    pub fn record_revocation(&mut self) {
        self.total_revocations += 1;
    }

    /// Current key age in milliseconds.
    pub fn current_key_age_millis(&self) -> u64 {
        current_time_utils().saturating_sub(self.current_key_created_at_millis)
    }
}
