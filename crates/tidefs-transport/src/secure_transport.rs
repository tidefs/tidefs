// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! SecureTransport: upgrades an unauthenticated transport session after HELLO.
//!
//! After the HELLO handshake establishes session keys, `SecureTransport`
//! wraps two [`SessionSecurity`] instances (one per direction) and provides
//! per-frame HMAC authentication with optional ChaCha20-Poly1305 encryption.
//!
//! ## Design
//!
//! - **Outbound**: compute HMAC-SHA256 of header+payload, optionally encrypt
//!   the header+payload+HMAC blob with ChaCha20-Poly1305.
//! - **Inbound**: verify HMAC tag, reject on mismatch; decrypt if encrypted.
//! - **Key derivation**: HKDF-SHA256 with domain-separated info strings
//!   ensures independent HMAC and encryption keys per direction.
//! - **Nonce replay**: monotonic nonce counters; replayed or reordered
//!   frames are rejected.
//!
//! ## Usage
//!
//! ```ignore
//! let session_key: [u8; 32] = /* from HELLO handshake */;
//! let mut transport = SecureTransport::new(&session_key, true);
//!
//! // Outbound
//! let wire = transport.seal_frame(b"header", b"payload")?;
//!
//! // Inbound
//! let (header, payload) = transport.open_frame(&wire)?;
//! ```

use tidefs_auth::{SessionSecurity, SessionSecurityError, SessionSecurityStats};
use tidefs_storage_intent_core::{StorageIntentEvidenceKind, StorageIntentEvidenceRef};
use tidefs_storage_intent_remote_media_capability::RemoteTrustFacts;

/// Wraps a post-HELLO transport session with HMAC per-frame authentication
/// and optional ChaCha20-Poly1305 encryption.
///
/// Two [`SessionSecurity`] instances are created from the session key:
/// one for outbound (sealing) and one for inbound (opening). Each direction
/// maintains independent nonce counters and statistics.
pub struct SecureTransport {
    /// Outbound session security for sealing frames.
    outbound: SessionSecurity,
    /// Inbound session security for opening frames.
    inbound: SessionSecurity,
    /// Whether encryption is enabled (set at construction time).
    encryption_enabled: bool,
}

impl SecureTransport {
    /// Create a new `SecureTransport` from a 32-byte session key established
    /// during the HELLO handshake.
    ///
    /// `encryption_enabled`: if `true`, encrypts frames with ChaCha20-Poly1305
    /// in addition to HMAC-SHA256 authentication. If `false`, uses HMAC only.
    #[must_use]
    pub fn new(session_key: &[u8; 32], encryption_enabled: bool) -> Self {
        let outbound = SessionSecurity::new(session_key, encryption_enabled);
        let inbound = SessionSecurity::new(session_key, encryption_enabled);
        Self {
            outbound,
            inbound,
            encryption_enabled,
        }
    }

    /// Seal an outbound frame: compute HMAC over `header || payload`,
    /// optionally encrypt, and return the wire-format bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SessionSecurityError`] on nonce exhaustion.
    pub fn seal_frame(
        &mut self,
        header: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, SessionSecurityError> {
        self.outbound.seal(header, payload)
    }

    /// Open an inbound frame: verify HMAC tag, optionally decrypt, and
    /// return the `(header, payload)` pair.
    ///
    /// # Errors
    ///
    /// Returns [`SessionSecurityError`] on HMAC mismatch, decryption failure,
    /// nonce replay, truncation, or unknown frame flags.
    pub fn open_frame(
        &mut self,
        wire_bytes: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), SessionSecurityError> {
        self.inbound.open(wire_bytes)
    }

    /// Whether encryption is enabled for this transport.
    #[must_use]
    pub fn encryption_enabled(&self) -> bool {
        self.encryption_enabled
    }

    /// Aggregate statistics from both directions.
    #[must_use]
    pub fn stats(&self) -> SecureTransportStats {
        SecureTransportStats {
            outbound: self.outbound.stats.clone(),
            inbound: self.inbound.stats.clone(),
        }
    }

    /// Consume the transport and return the underlying [`SessionSecurity`]
    /// instances for outbound and inbound directions.
    #[must_use]
    pub fn into_inner(self) -> (SessionSecurity, SessionSecurity) {
        (self.outbound, self.inbound)
    }
}

impl std::fmt::Debug for SecureTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureTransport")
            .field("encryption_enabled", &self.encryption_enabled)
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// SecureTransportStats
// ---------------------------------------------------------------------------

/// Combined statistics for a [`SecureTransport`] (both directions).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecureTransportStats {
    /// Statistics for the outbound direction (sealing).
    pub outbound: SessionSecurityStats,
    /// Statistics for the inbound direction (opening).
    pub inbound: SessionSecurityStats,
}

impl SecureTransportStats {
    /// Total frames sent (outbound).
    #[must_use]
    pub fn total_frames_sent(&self) -> u64 {
        self.outbound.frames_sent
    }

    /// Total frames received (inbound).
    #[must_use]
    pub fn total_frames_received(&self) -> u64 {
        self.inbound.frames_received
    }

    /// Total failures across both directions.
    #[must_use]
    pub fn total_failures(&self) -> u64 {
        self.outbound
            .total_failures()
            .saturating_add(self.inbound.total_failures())
    }

    /// Project observed secure-frame evidence into the authentication portion
    /// of #961 remote trust facts.
    ///
    /// This deliberately leaves domain compatibility, authorization, audit,
    /// and residency unset; encrypted transport is evidence input, not a
    /// complete #897 trust-domain authority decision.
    #[must_use]
    pub fn remote_media_authenticated_frame_facts(
        &self,
        encrypted: bool,
        mutually_authenticated: bool,
        trust_ref: StorageIntentEvidenceRef,
    ) -> RemoteTrustFacts {
        let trust_ref_is_bound = trust_ref.is_bound()
            && trust_ref.kind as u16 == StorageIntentEvidenceKind::TrustDomainEvidence as u16;
        let observed_authenticated_frames = self.total_frames_sent() > 0
            && self.total_frames_received() > 0
            && self.total_failures() == 0;

        if !trust_ref_is_bound
            || !encrypted
            || !mutually_authenticated
            || !observed_authenticated_frames
        {
            return RemoteTrustFacts::default();
        }

        RemoteTrustFacts {
            authenticated_principal: true,
            domain_compatible: false,
            key_epoch_fresh: true,
            authorization_present: false,
            audit_present: false,
            residency_compatible: false,
            trust_ref,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_storage_intent_core::StorageIntentEvidenceId;

    fn session_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0..16].copy_from_slice(b"test-session-key");
        k
    }

    fn trust_ref(seed: u8) -> StorageIntentEvidenceRef {
        StorageIntentEvidenceRef::new(
            StorageIntentEvidenceKind::TrustDomainEvidence,
            StorageIntentEvidenceId([seed; 32]),
            u64::from(seed),
            1,
        )
    }

    // ── Plaintext round-trip ────────────────────────────────────────

    #[test]
    fn plaintext_roundtrip_bidirectional() {
        let key = session_key();
        let mut t = SecureTransport::new(&key, false);

        let wire = t.seal_frame(b"hdr", b"body").unwrap();
        let (hdr, body) = t.open_frame(&wire).unwrap();
        assert_eq!(hdr, b"hdr");
        assert_eq!(body, b"body");
    }

    #[test]
    fn plaintext_empty_header_and_payload() {
        let key = session_key();
        let mut t = SecureTransport::new(&key, false);

        let wire = t.seal_frame(b"", b"").unwrap();
        let (hdr, body) = t.open_frame(&wire).unwrap();
        assert!(hdr.is_empty());
        assert!(body.is_empty());
    }

    // ── Encrypted round-trip ────────────────────────────────────────

    #[test]
    fn encrypted_roundtrip_bidirectional() {
        let key = session_key();
        let mut t = SecureTransport::new(&key, true);

        let wire = t.seal_frame(b"hdr", b"body").unwrap();
        let (hdr, body) = t.open_frame(&wire).unwrap();
        assert_eq!(hdr, b"hdr");
        assert_eq!(body, b"body");
    }

    #[test]
    fn encrypted_empty_payload() {
        let key = session_key();
        let mut t = SecureTransport::new(&key, true);

        let wire = t.seal_frame(b"", b"").unwrap();
        let (hdr, body) = t.open_frame(&wire).unwrap();
        assert!(hdr.is_empty());
        assert!(body.is_empty());
    }

    // ── Tampering detection ─────────────────────────────────────────

    #[test]
    fn tampering_detected_plaintext() {
        let key = session_key();
        let mut t = SecureTransport::new(&key, false);

        let mut wire = t.seal_frame(b"hdr", b"payload").unwrap();
        wire[8] ^= 0x01;
        let result = t.open_frame(&wire);
        assert!(matches!(
            result,
            Err(SessionSecurityError::HmacVerificationFailed)
        ));
    }

    #[test]
    fn tampering_detected_encrypted() {
        let key = session_key();
        let mut t = SecureTransport::new(&key, true);

        let mut wire = t.seal_frame(b"hdr", b"payload").unwrap();
        wire[20] ^= 0x01;
        let result = t.open_frame(&wire);
        assert!(matches!(
            result,
            Err(SessionSecurityError::DecryptionFailed)
        ));
    }

    // ── Cross-mode rejection ───────────────────────────────────────

    #[test]
    fn encrypted_frame_rejected_by_plaintext_transport() {
        let key = session_key();
        let mut seal_t = SecureTransport::new(&key, true);
        let mut open_t = SecureTransport::new(&key, false);

        let wire = seal_t.seal_frame(b"hdr", b"body").unwrap();
        let result = open_t.open_frame(&wire);
        assert!(matches!(
            result,
            Err(SessionSecurityError::UnknownFlags { flags: 0x01 })
        ));
    }

    // ── Wrong key rejection ─────────────────────────────────────────

    #[test]
    fn wrong_session_key_rejected() {
        let k1 = {
            let mut k = [0u8; 32];
            k[0] = 0xAA;
            k
        };
        let k2 = {
            let mut k = [0u8; 32];
            k[0] = 0xBB;
            k
        };

        let mut seal_t = SecureTransport::new(&k1, false);
        let mut open_t = SecureTransport::new(&k2, false);

        let wire = seal_t.seal_frame(b"hdr", b"body").unwrap();
        let result = open_t.open_frame(&wire);
        assert!(matches!(
            result,
            Err(SessionSecurityError::HmacVerificationFailed)
        ));
    }

    // ── Nonce replay protection ────────────────────────────────────

    #[test]
    fn nonce_replay_rejected() {
        let key = session_key();
        let mut t = SecureTransport::new(&key, true);

        let wire = t.seal_frame(b"msg", b"1").unwrap();
        t.open_frame(&wire).unwrap();

        let result = t.open_frame(&wire);
        assert!(matches!(
            result,
            Err(SessionSecurityError::NonceReuse { .. })
        ));
    }

    // ── Truncated frame ─────────────────────────────────────────────

    #[test]
    fn truncated_frame_rejected() {
        let key = session_key();
        let mut seal_t = SecureTransport::new(&key, false);
        let mut open_t = SecureTransport::new(&key, false);

        let wire = seal_t.seal_frame(b"hdr", b"body").unwrap();
        let result = open_t.open_frame(&wire[..1]);
        assert!(matches!(
            result,
            Err(SessionSecurityError::TruncatedFrame { .. })
        ));
    }

    // ── Encryption enabled flag ─────────────────────────────────────

    #[test]
    fn encryption_enabled_flag() {
        let key = session_key();
        assert!(SecureTransport::new(&key, true).encryption_enabled());
        assert!(!SecureTransport::new(&key, false).encryption_enabled());
    }

    // ── Statistics ──────────────────────────────────────────────────

    #[test]
    fn stats_count_frames() {
        let key = session_key();
        let mut t = SecureTransport::new(&key, false);

        let w1 = t.seal_frame(b"h1", b"p1").unwrap();
        let w2 = t.seal_frame(b"h2", b"p2").unwrap();
        t.open_frame(&w1).unwrap();
        t.open_frame(&w2).unwrap();

        let s = t.stats();
        assert_eq!(s.total_frames_sent(), 2);
        assert_eq!(s.total_frames_received(), 2);
        assert_eq!(s.total_failures(), 0);
    }

    #[test]
    fn stats_count_failures() {
        let key = session_key();
        let mut seal_t = SecureTransport::new(&key, false);
        let mut open_t = SecureTransport::new(&key, false);

        let wire = seal_t.seal_frame(b"hdr", b"body").unwrap();

        let mut bad_wire = wire.clone();
        bad_wire[8] ^= 0x01;
        let _ = open_t.open_frame(&bad_wire);

        let s = open_t.stats();
        assert!(s.total_failures() > 0);
        assert_eq!(s.inbound.hmac_failures, 1);
    }

    #[test]
    fn authenticated_frame_stats_project_partial_remote_trust() {
        let stats = SecureTransportStats {
            outbound: SessionSecurityStats {
                frames_sent: 3,
                ..SessionSecurityStats::default()
            },
            inbound: SessionSecurityStats {
                frames_received: 2,
                ..SessionSecurityStats::default()
            },
        };
        let trust_ref = trust_ref(21);
        let facts = stats.remote_media_authenticated_frame_facts(true, true, trust_ref);

        assert!(facts.authenticated_principal);
        assert!(facts.key_epoch_fresh);
        assert!(!facts.domain_compatible);
        assert!(!facts.authorization_present);
        assert!(!facts.audit_present);
        assert!(!facts.residency_compatible);
        assert_eq!(facts.trust_ref, trust_ref);
    }

    #[test]
    fn failed_secure_frame_stats_do_not_project_remote_trust() {
        let stats = SecureTransportStats {
            outbound: SessionSecurityStats {
                frames_sent: 3,
                ..SessionSecurityStats::default()
            },
            inbound: SessionSecurityStats {
                frames_received: 2,
                hmac_failures: 1,
                ..SessionSecurityStats::default()
            },
        };
        let facts = stats.remote_media_authenticated_frame_facts(true, true, trust_ref(22));

        assert_eq!(facts, RemoteTrustFacts::default());
    }

    // ── Concurrent independent sessions ─────────────────────────────

    #[test]
    fn concurrent_sessions_independent() {
        let k1 = {
            let mut k = [0u8; 32];
            k[0] = 1;
            k
        };
        let k2 = {
            let mut k = [0u8; 32];
            k[0] = 2;
            k
        };

        let mut t1 = SecureTransport::new(&k1, true);
        let mut t2 = SecureTransport::new(&k2, true);

        let w1 = t1.seal_frame(b"s1", b"d1").unwrap();
        let w2 = t2.seal_frame(b"s2", b"d2").unwrap();

        let (h1, p1) = t1.open_frame(&w1).unwrap();
        assert_eq!(h1, b"s1");
        assert_eq!(p1, b"d1");

        let (h2, p2) = t2.open_frame(&w2).unwrap();
        assert_eq!(h2, b"s2");
        assert_eq!(p2, b"d2");

        let result = t1.open_frame(&w2);
        assert!(result.is_err());
    }

    // ── into_inner ──────────────────────────────────────────────────

    #[test]
    fn into_inner_returns_session_security_instances() {
        let key = session_key();
        let t = SecureTransport::new(&key, true);
        let (outbound, inbound) = t.into_inner();
        assert!(outbound.encryption_enabled());
        assert!(inbound.encryption_enabled());
    }

    // ── Debug formatting ────────────────────────────────────────────

    #[test]
    fn debug_format() {
        let key = session_key();
        let t = SecureTransport::new(&key, true);
        let dbg = format!("{t:?}");
        assert!(dbg.contains("SecureTransport"));
        assert!(dbg.contains("encryption_enabled"));
    }

    // ── Large payload round-trip ───────────────────────────────────

    #[test]
    fn large_payload_roundtrip() {
        let key = session_key();
        let mut t = SecureTransport::new(&key, true);

        let header = vec![0xAAu8; 256];
        let payload = vec![0xBBu8; 65536];
        let wire = t.seal_frame(&header, &payload).unwrap();
        let (hdr, body) = t.open_frame(&wire).unwrap();
        assert_eq!(hdr, header);
        assert_eq!(body, payload);
    }
}
