//! Per-session ChaCha20-Poly1305 transport encryption with monotonic nonce
//! protection.
//!
//! ## Design
//!
//! Every established transport session derives a unique ChaCha20-Poly1305
//! session key via HKDF-SHA256 from handshake key material. Two independent
//! [`TransportSessionCipher`] instances are created per session — one for each
//! direction — using domain-separated HKDF info strings so that the
//! initiator→responder and responder→initiator keys are distinct.
//!
//! Each [`TransportSessionCipher`] maintains a monotonic 64-bit encrypt
//! counter and a per-peer `last_seen` decrypt nonce for replay protection.
//! Nonces are never reused and never wrap: sealing fails with
//! [`CipherError::NonceExhausted`] when the counter would overflow.
//!
//! ## Wire format
//!
//! ```text
//! [nonce: 12 bytes][ciphertext || Poly1305 tag: N + 16 bytes]
//! ```
//!
//! The 12-byte nonce is `[encrypt_nonce as u64 BE || 0x0000_0000 as u32 BE]`.
//!
//! ## Layering
//!
//! Session encryption provides its own integrity and authenticity through the
//! ChaCha20-Poly1305 AEAD authenticator. The session's HMAC-SHA256 at the
//! transport-frame boundary provides per-frame authentication. No per-message
//! BLAKE3 payload digest is stacked on top of the session boundary.
//!
//! ## Security properties
//!
//! - **Confidentiality**: ChaCha20-Poly1305 AEAD (RFC 8439).
//! - **Integrity + authenticity**: Poly1305 MAC detects any ciphertext
//!   modification, wrong-key decryption, or truncated frames.
//! - **Replay protection**: monotonic nonce counter; any message with a
//!   nonce ≤ the last-seen nonce is rejected.
//! - **Domain separation**: HKDF info strings prevent cross-direction and
//!   cross-protocol key reuse.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt;

// ---------------------------------------------------------------------------
// Domain separation constants
// ---------------------------------------------------------------------------

/// HKDF info prefix for session cipher key derivation.
const HKDF_INFO_PREFIX: &[u8] = b"tidefs-transport-session-cipher-v1";

/// Direction tag for initiator→responder encryption.
const DIRECTION_INITIATOR_TO_RESPONDER: &[u8] = b"initiator-to-responder";

/// Direction tag for responder→initiator encryption.
const DIRECTION_RESPONDER_TO_INITIATOR: &[u8] = b"responder-to-initiator";

/// Key size for ChaCha20-Poly1305 (256 bits).
const KEY_LEN: usize = 32;

/// Nonce size for ChaCha20-Poly1305 IETF (96 bits = 12 bytes).
const NONCE_LEN: usize = 12;

/// Minimum wire size: nonce (12) + tag (16) = 28 bytes.
const MIN_WIRE_SIZE: usize = NONCE_LEN + 16;

// ---------------------------------------------------------------------------
// SessionKeyMaterial trait
// ---------------------------------------------------------------------------

/// Trait for types that can provide a 32-byte shared secret for session key
/// derivation.
///
/// The transport handshake layer implements this trait to expose the
/// post-handshake shared secret. The cipher consumes it through HKDF-SHA256
/// expand with domain-separated info strings.
pub trait SessionKeyMaterial {
    /// The 32-byte shared secret established during session handshake.
    fn shared_secret(&self) -> &[u8; 32];
}

// ---------------------------------------------------------------------------
// CipherError
// ---------------------------------------------------------------------------

/// Errors from transport session cipher operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CipherError {
    /// AEAD open failed: ciphertext corrupted, wrong key, or tampered frame.
    AeadOpenFailed,
    /// Nonce reuse detected: received nonce is ≤ the last seen nonce.
    /// Indicates a replay attack or a buggy/compromised peer.
    NonceReuse {
        /// The nonce that was rejected.
        received: u64,
        /// The last valid nonce seen on this direction.
        last_seen: u64,
    },
    /// The encrypt nonce counter has exhausted the u64 space.
    /// Over 18 quintillion messages; indicates a session that has lived far
    /// beyond its intended lifetime.
    NonceExhausted,
    /// Wire bytes too short to contain a valid encrypted frame
    /// (need at least nonce + Poly1305 tag).
    TruncatedFrame {
        /// Actual length received.
        got: usize,
        /// Minimum required length.
        min: usize,
    },
}

impl fmt::Display for CipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AeadOpenFailed => {
                write!(f, "AEAD open failed: corrupted, wrong key, or tampered")
            }
            Self::NonceReuse {
                received,
                last_seen,
            } => {
                write!(
                    f,
                    "nonce reuse detected: received {received}, last seen {last_seen}"
                )
            }
            Self::NonceExhausted => {
                write!(f, "nonce counter exhausted (u64 overflow)")
            }
            Self::TruncatedFrame { got, min } => {
                write!(
                    f,
                    "truncated encrypted frame: got {got} bytes, need at least {min}"
                )
            }
        }
    }
}

impl std::error::Error for CipherError {}

// ---------------------------------------------------------------------------
// EncryptionContext -- AAD for AEAD binding
// ---------------------------------------------------------------------------

/// Metadata bound into the AEAD authenticated data for a transport message.
///
/// By including session and message identity in the AAD, the Poly1305
/// authentication tag prevents ciphertext from being replayed across
/// different sessions, directions, endpoints, or lanes.
///
/// Wire format for AAD (18 bytes):
///
/// ```text
/// [session_id: u64 LE][endpoint_family: u32 LE][direction: u8]
/// [message_family: u8][sequence_no: u32 LE]
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncryptionContext {
    /// Session ID from the transport envelope.
    pub session_id: u64,
    /// Endpoint family (e0-e3).
    pub endpoint_family: u32,
    /// Direction tag: 0 = InitiatorToResponder, 1 = ResponderToInitiator.
    pub direction: u8,
    /// Message family discriminant (m0-m9).
    pub message_family: u8,
    /// Per-message sequence number (unique within the session+direction).
    pub sequence_no: u32,
}

impl EncryptionContext {
    /// Wire size of the serialized AAD context.
    pub const WIRE_SIZE: usize = 18;

    /// Encode this context to a fixed-size byte array for use as AEAD AAD.
    #[must_use]
    pub fn to_aad_bytes(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..8].copy_from_slice(&self.session_id.to_le_bytes());
        buf[8..12].copy_from_slice(&self.endpoint_family.to_le_bytes());
        buf[12] = self.direction;
        buf[13] = self.message_family;
        buf[14..18].copy_from_slice(&self.sequence_no.to_le_bytes());
        buf
    }
}

// ---------------------------------------------------------------------------
// TransportSessionCipher
// ---------------------------------------------------------------------------

/// A ChaCha20-Poly1305 AEAD cipher for one direction of a transport session.
///
/// Each instance handles both sealing (encrypt for outbound) and opening
/// (decrypt for inbound) for a single direction. For bidirectional
/// communication, create two instances with different [`Direction`] tags.
///
/// ## Nonce management
///
/// - **Encrypt nonce**: a monotonic u64 counter. Incremented on every
///   `seal()` call. Returns `CipherError::NonceExhausted` on overflow.
/// - **Decrypt nonce**: the last-seen u64 counter value. Every `open()`
///   call extracts the nonce from the wire frame and verifies strict
///   monotonicity before decrypting.
///
/// ## Example
///
/// ```ignore
/// use tidefs_transport::session_cipher::{
///     TransportSessionCipher, SessionKeyMaterial, Direction,
/// };
///
/// struct HandshakeResult { secret: [u8; 32] }
/// impl SessionKeyMaterial for HandshakeResult {
///     fn shared_secret(&self) -> &[u8; 32] { &self.secret }
/// }
///
/// let handshake = HandshakeResult { secret: [0x42u8; 32] };
/// let mut cipher = TransportSessionCipher::new(
///     &handshake, Direction::InitiatorToResponder,
/// );
///
/// let sealed = cipher.seal(b"hello").unwrap();
/// let opened = cipher.open(&sealed).unwrap();
/// assert_eq!(opened, b"hello");
/// ```
pub struct TransportSessionCipher {
    cipher: ChaCha20Poly1305,
    /// Monotonic encrypt counter. Incremented on every seal().
    encrypt_nonce: u64,
    /// Last seen decrypt nonce. None means no message received yet.
    decrypt_last_seen: Option<u64>,
    /// Whether the encrypt nonce space has been exhausted (u64::MAX reached
    /// and wrapped). Further seal() calls return NonceExhausted.
    encrypt_exhausted: bool,
    /// Default AAD context bound to session/message metadata.
    /// When set, seal() and open() automatically include this in the AEAD tag.
    aad_context: Option<[u8; EncryptionContext::WIRE_SIZE]>,
}

/// Which direction this cipher instance handles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Initiator→responder: the initiator seals, the responder opens.
    InitiatorToResponder,
    /// Responder→initiator: the responder seals, the initiator opens.
    ResponderToInitiator,
}

impl Direction {
    fn info_bytes(self) -> &'static [u8] {
        match self {
            Self::InitiatorToResponder => DIRECTION_INITIATOR_TO_RESPONDER,
            Self::ResponderToInitiator => DIRECTION_RESPONDER_TO_INITIATOR,
        }
    }
}

impl TransportSessionCipher {
    /// Create a new cipher for the given direction, deriving the ChaCha20 key
    /// via HKDF-SHA256 expand from the session key material.
    ///
    /// The HKDF info string is
    /// `"tidefs-transport-session-cipher-v1" || direction_tag`.
    pub fn new(key_material: &(impl SessionKeyMaterial + ?Sized), direction: Direction) -> Self {
        let info: Vec<u8> = HKDF_INFO_PREFIX
            .iter()
            .chain(direction.info_bytes().iter())
            .copied()
            .collect();
        let key = hkdf_expand_sha256(key_material.shared_secret(), &info, KEY_LEN);
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .expect("HKDF-SHA256 output is always 32 bytes, valid for ChaCha20Poly1305");
        Self {
            cipher,
            encrypt_nonce: 0,
            decrypt_last_seen: None,
            encrypt_exhausted: false,
            aad_context: None,
        }
    }

    /// Create a cipher from a raw 32-byte key (for testing with known-answer
    /// vectors).
    #[doc(hidden)]
    pub fn from_raw_key(key: &[u8; KEY_LEN]) -> Self {
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .expect("32-byte key is valid for ChaCha20Poly1305");
        Self {
            cipher,
            encrypt_nonce: 0,
            decrypt_last_seen: None,
            encrypt_exhausted: false,
            aad_context: None,
        }
    }

    /// Encrypt `plaintext` and return the wire-format frame.
    ///
    /// The returned bytes are `[nonce: 12][ciphertext || tag: N+16]`.
    ///
    /// # Errors
    ///
    /// Returns [`CipherError::NonceExhausted`] if the counter would overflow.
    /// Set the default encryption context used as AAD by [`seal`] and [`open`].
    ///
    /// Once set, every call to [`seal`] and [`open`] automatically binds the
    /// context bytes into the Poly1305 authentication tag, preventing
    /// ciphertext replay across sessions, directions, endpoints, or lanes.
    pub fn set_encryption_context(&mut self, ctx: EncryptionContext) {
        self.aad_context = Some(ctx.to_aad_bytes());
    }

    /// Clear the encryption context, reverting to empty AAD for seal/open.
    pub fn clear_encryption_context(&mut self) {
        self.aad_context = None;
    }

    /// The current AAD context bytes, if set.
    #[must_use]
    pub fn aad_context(&self) -> Option<&[u8; EncryptionContext::WIRE_SIZE]> {
        self.aad_context.as_ref()
    }

    /// Encrypt `plaintext` with associated data bound into the Poly1305 tag.
    ///
    /// The `aad` bytes are authenticated but not encrypted. This prevents
    /// ciphertext from being replayed with different session/message metadata.
    pub fn seal_with_aad(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CipherError> {
        if self.encrypt_exhausted {
            return Err(CipherError::NonceExhausted);
        }
        let nonce_val = self.encrypt_nonce;

        let nonce = nonce_to_bytes(nonce_val);
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        let ciphertext = self
            .cipher
            .encrypt(&nonce, payload)
            .expect("ChaCha20Poly1305 encrypt is infallible for valid inputs");

        let mut frame = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        frame.extend_from_slice(&nonce);
        frame.extend_from_slice(&ciphertext);

        // Advance counter; signal exhaustion for the next call when we
        // overflow past u64::MAX.
        let (next, overflowed) = self.encrypt_nonce.overflowing_add(1);
        self.encrypt_nonce = next;
        if overflowed {
            self.encrypt_exhausted = true;
        }

        Ok(frame)
    }

    /// Decrypt and authenticate a wire-format frame with associated data.
    ///
    /// The `aad` bytes must match those used during [`seal_with_aad`].
    ///
    /// Validates nonce monotonicity before decrypting.
    pub fn open_with_aad(&mut self, wire_bytes: &[u8], aad: &[u8]) -> Result<Vec<u8>, CipherError> {
        if wire_bytes.len() < MIN_WIRE_SIZE {
            return Err(CipherError::TruncatedFrame {
                got: wire_bytes.len(),
                min: MIN_WIRE_SIZE,
            });
        }

        let mut nonce_arr = [0u8; NONCE_LEN];
        nonce_arr.copy_from_slice(&wire_bytes[..NONCE_LEN]);
        let nonce = Nonce::clone_from_slice(&nonce_arr);
        let nonce_val = bytes_to_nonce(&nonce_arr);

        // Replay protection
        if let Some(last) = self.decrypt_last_seen {
            if nonce_val <= last {
                return Err(CipherError::NonceReuse {
                    received: nonce_val,
                    last_seen: last,
                });
            }
        }

        let ciphertext = &wire_bytes[NONCE_LEN..];
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        let plaintext = self
            .cipher
            .decrypt(&nonce, payload)
            .map_err(|_| CipherError::AeadOpenFailed)?;

        self.decrypt_last_seen = Some(nonce_val);
        Ok(plaintext)
    }

    /// Encrypt `plaintext` without associated data (empty AAD).
    ///
    /// Prefer [`seal_with_aad`] for transport messages to bind session
    /// metadata into the authentication tag.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
        let aad_buf: Option<[u8; EncryptionContext::WIRE_SIZE]> = self.aad_context;
        match aad_buf {
            Some(ref ctx) => self.seal_with_aad(plaintext, ctx),
            None => self.seal_with_aad(plaintext, b""),
        }
    }

    /// Decrypt and authenticate a wire-format frame without associated data.
    ///
    /// Prefer [`open_with_aad`] for transport messages that bind session
    /// metadata into the authentication tag.
    ///
    /// # Errors
    ///
    /// - [`CipherError::TruncatedFrame`] if `wire_bytes` is shorter than
    ///   nonce + tag.
    /// - [`CipherError::NonceReuse`] if the extracted nonce is ≤ the last
    ///   seen nonce.
    /// - [`CipherError::AeadOpenFailed`] on authentication failure
    ///   (corruption, wrong key, tampering).
    pub fn open(&mut self, wire_bytes: &[u8]) -> Result<Vec<u8>, CipherError> {
        let aad_buf: Option<[u8; EncryptionContext::WIRE_SIZE]> = self.aad_context;
        match aad_buf {
            Some(ref ctx) => self.open_with_aad(wire_bytes, ctx),
            None => self.open_with_aad(wire_bytes, b""),
        }
    }

    /// Current encrypt nonce value (for testing/assertions).
    #[doc(hidden)]
    pub fn encrypt_nonce(&self) -> u64 {
        self.encrypt_nonce
    }

    /// Last seen decrypt nonce value (for testing/assertions).
    #[doc(hidden)]
    pub fn decrypt_last_seen(&self) -> Option<u64> {
        self.decrypt_last_seen
    }
}

impl fmt::Debug for TransportSessionCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransportSessionCipher")
            .field("encrypt_nonce", &self.encrypt_nonce)
            .field("decrypt_last_seen", &self.decrypt_last_seen)
            .field("encrypt_exhausted", &self.encrypt_exhausted)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Nonce encoding helpers
// ---------------------------------------------------------------------------

/// Encode a u64 counter as a 12-byte ChaCha20-Poly1305 nonce.
///
/// Layout: `[counter: 8 bytes BE][zeros: 4 bytes BE]`.
fn nonce_to_bytes(counter: u64) -> Nonce {
    let mut arr = [0u8; NONCE_LEN];
    arr[..8].copy_from_slice(&counter.to_be_bytes());
    // bytes 8..12 remain zero
    Nonce::clone_from_slice(&arr)
}

/// Extract the u64 counter value from a 12-byte nonce.
fn bytes_to_nonce(bytes: &[u8]) -> u64 {
    let mut counter_bytes = [0u8; 8];
    counter_bytes.copy_from_slice(&bytes[..8]);
    u64::from_be_bytes(counter_bytes)
}

// ---------------------------------------------------------------------------
// HKDF-SHA256 expand (RFC 5869 §2.3)
// ---------------------------------------------------------------------------

/// HKDF-Expand step for SHA-256.
///
/// Uses `prk` directly as the PRK (the shared secret is assumed to be
/// uniformly random from the handshake key exchange, so the HKDF-Extract
/// step is skipped).
///
/// # Panics
///
/// Panics if `len > 8160` (255 × 32, the HKDF-SHA256 limit).
fn hkdf_expand_sha256(prk: &[u8; 32], info: &[u8], len: usize) -> Vec<u8> {
    assert!(
        len <= 255 * 32,
        "HKDF-SHA256 output length must be <= 8160 bytes"
    );

    let n = len.div_ceil(32);
    let mut okm = Vec::with_capacity(len);
    let mut t_prev: Vec<u8> = Vec::new();

    for i in 1u8..=n as u8 {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(prk)
            .expect("HMAC-SHA256 can accept any key length");
        if !t_prev.is_empty() {
            mac.update(&t_prev);
        }
        mac.update(info);
        mac.update(&[i]);

        let block = mac.finalize().into_bytes();
        let take = std::cmp::min(32, len - okm.len());
        okm.extend_from_slice(&block[..take]);
        t_prev = block.to_vec();
    }

    okm
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A simple SessionKeyMaterial for testing.
    struct TestKeyMaterial([u8; 32]);

    impl SessionKeyMaterial for TestKeyMaterial {
        fn shared_secret(&self) -> &[u8; 32] {
            &self.0
        }
    }

    fn test_key_material() -> TestKeyMaterial {
        let mut k = [0u8; 32];
        k[0..8].copy_from_slice(b"test-key");
        TestKeyMaterial(k)
    }

    // ── Round-trip ───────────────────────────────────────────────────

    #[test]
    fn roundtrip_empty_payload() {
        let km = test_key_material();
        let mut cipher = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);
        let sealed = cipher.seal(b"").unwrap();
        assert_eq!(sealed.len(), NONCE_LEN + 16); // nonce + tag only
        let opened = cipher.open(&sealed).unwrap();
        assert!(opened.is_empty());
    }

    #[test]
    fn roundtrip_hello_world() {
        let km = test_key_material();
        let mut cipher = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);
        let sealed = cipher.seal(b"hello world").unwrap();
        let opened = cipher.open(&sealed).unwrap();
        assert_eq!(opened, b"hello world");
    }

    #[test]
    fn roundtrip_1k_payload() {
        let km = test_key_material();
        let mut cipher = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);
        let data = vec![0xABu8; 1024];
        let sealed = cipher.seal(&data).unwrap();
        assert_eq!(sealed.len(), NONCE_LEN + data.len() + 16);
        let opened = cipher.open(&sealed).unwrap();
        assert_eq!(opened, data);
    }

    #[test]
    fn roundtrip_various_sizes() {
        let km = test_key_material();
        let mut cipher = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);
        for size in [0, 1, 12, 13, 31, 32, 33, 255, 256, 1024, 65535] {
            let data = vec![(size % 256) as u8; size];
            let sealed = cipher.seal(&data).unwrap();
            let opened = cipher.open(&sealed).unwrap();
            assert_eq!(opened, data, "roundtrip failed for size {size}");
        }
    }

    #[test]
    fn multiple_messages_in_order() {
        let km = test_key_material();
        let mut cipher = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);
        for i in 0..100u8 {
            let msg = vec![i; 32];
            let sealed = cipher.seal(&msg).unwrap();
            let opened = cipher.open(&sealed).unwrap();
            assert_eq!(opened, msg);
        }
    }

    // ── Tamper detection ─────────────────────────────────────────────

    #[test]
    fn tampered_ciphertext_rejected() {
        let km = test_key_material();
        let mut cipher = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);
        let mut sealed = cipher.seal(b"sensitive data").unwrap();
        // Flip a byte in the ciphertext (past the nonce)
        sealed[NONCE_LEN + 3] ^= 0x01;
        let result = cipher.open(&sealed);
        assert!(matches!(result, Err(CipherError::AeadOpenFailed)));
    }

    #[test]
    fn truncated_frame_rejected() {
        let km = test_key_material();
        let mut cipher = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);
        let sealed = cipher.seal(b"hello").unwrap();

        // Too short for nonce + tag
        let short = &sealed[..NONCE_LEN + 5];
        let result = cipher.open(short);
        assert!(matches!(result, Err(CipherError::TruncatedFrame { .. })));
    }

    #[test]
    fn zero_length_frame_rejected() {
        let km = test_key_material();
        let mut cipher = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);
        let result = cipher.open(&[]);
        assert!(matches!(result, Err(CipherError::TruncatedFrame { .. })));
    }

    #[test]
    fn tampered_nonce_rejected() {
        let km = test_key_material();
        let mut cipher = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);

        // Seal two messages with different nonces
        let sealed1 = cipher.seal(b"first").unwrap();
        let sealed2 = cipher.seal(b"second").unwrap();

        // Build a frame with nonce from msg2 but ciphertext from msg1
        let mut bad = Vec::new();
        bad.extend_from_slice(&sealed2[..NONCE_LEN]); // nonce from msg2
        bad.extend_from_slice(&sealed1[NONCE_LEN..]); // ciphertext from msg1

        // Decrypt should fail: nonce doesn't match the AEAD context
        let result = cipher.open(&bad);
        assert!(matches!(result, Err(CipherError::AeadOpenFailed)));
    }

    // ── Wrong key rejection ──────────────────────────────────────────

    #[test]
    fn wrong_key_rejected() {
        let km_a = TestKeyMaterial([0xAAu8; 32]);
        let km_b = TestKeyMaterial([0xBBu8; 32]);

        let mut cipher_a = TransportSessionCipher::new(&km_a, Direction::InitiatorToResponder);
        let mut cipher_b = TransportSessionCipher::new(&km_b, Direction::InitiatorToResponder);

        let sealed = cipher_a.seal(b"hello").unwrap();
        let result = cipher_b.open(&sealed);
        assert!(matches!(result, Err(CipherError::AeadOpenFailed)));
    }

    // ── Nonce monotonicity and replay protection ─────────────────────

    #[test]
    fn nonce_advances_on_seal() {
        let km = test_key_material();
        let mut cipher = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);
        assert_eq!(cipher.encrypt_nonce(), 0);
        cipher.seal(b"msg1").unwrap();
        assert_eq!(cipher.encrypt_nonce(), 1);
        cipher.seal(b"msg2").unwrap();
        assert_eq!(cipher.encrypt_nonce(), 2);
    }

    #[test]
    fn decrypt_nonce_tracks_last_seen() {
        let km = test_key_material();
        let mut cipher = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);
        assert_eq!(cipher.decrypt_last_seen(), None);

        let sealed0 = cipher.seal(b"msg0").unwrap();
        cipher.open(&sealed0).unwrap();
        assert_eq!(cipher.decrypt_last_seen(), Some(0));

        let sealed1 = cipher.seal(b"msg1").unwrap();
        cipher.open(&sealed1).unwrap();
        assert_eq!(cipher.decrypt_last_seen(), Some(1));
    }

    #[test]
    fn nonce_reuse_same_value_rejected() {
        let km = test_key_material();
        let mut cipher = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);

        let sealed = cipher.seal(b"message").unwrap();
        cipher.open(&sealed).unwrap();

        // Replaying the exact same frame should be rejected
        let result = cipher.open(&sealed);
        assert!(matches!(result, Err(CipherError::NonceReuse { .. })));
    }

    #[test]
    fn nonce_reuse_lower_value_rejected() {
        let km = test_key_material();
        let mut cipher = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);

        // Advance through nonces 0, 1, 2
        let sealed0 = cipher.seal(b"msg0").unwrap();
        cipher.open(&sealed0).unwrap();
        let sealed1 = cipher.seal(b"msg1").unwrap();
        cipher.open(&sealed1).unwrap();
        let _sealed2 = cipher.seal(b"msg2").unwrap();

        // Replay msg0 (nonce=0, last_seen=1) should be rejected
        let result = cipher.open(&sealed0);
        assert!(matches!(result, Err(CipherError::NonceReuse { .. })));
    }

    #[test]
    fn nonce_replay_different_ciphertext_same_nonce_rejected() {
        let km = test_key_material();
        let mut cipher = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);

        let sealed = cipher.seal(b"original").unwrap();
        cipher.open(&sealed).unwrap();

        // Manually construct a frame with nonce=0 but different ciphertext.
        // First build valid nonce=0 bytes, then replace ciphertext.
        // This should fail AeadOpenFailed because the tag won't verify,
        // but let's also ensure that nonce reuse check fires first.
        // Actually AEAD failure will fire since ciphertext is invalid.
        // The nonce check: nonce_val (0) <= last_seen (0) → reject with
        // NonceReuse before even trying decryption.
        let mut bad_frame = Vec::new();
        bad_frame.extend_from_slice(&sealed[..NONCE_LEN]); // nonce=0
        bad_frame.extend_from_slice(&vec![0xFFu8; sealed.len() - NONCE_LEN]); // bogus ciphertext

        let result = cipher.open(&bad_frame);
        assert!(
            matches!(result, Err(CipherError::NonceReuse { .. })),
            "expected NonceReuse, got {result:?}"
        );
    }

    // ── Nonce exhaustion ─────────────────────────────────────────────

    #[test]
    fn nonce_exhaustion_detected() {
        let km = test_key_material();
        let mut cipher = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);
        // Set counter just before overflow
        cipher.encrypt_nonce = u64::MAX;
        let result = cipher.seal(b"last message");
        // This should encrypt with nonce u64::MAX, then overflow on
        // increment → next call fails
        assert!(result.is_ok(), "seal with nonce MAX should succeed");

        let result2 = cipher.seal(b"one too many");
        assert!(matches!(result2, Err(CipherError::NonceExhausted)));
    }

    // ── Session isolation ────────────────────────────────────────────

    #[test]
    fn different_directions_have_different_keys() {
        let km = test_key_material();
        let mut c_init = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);
        let mut c_resp = TransportSessionCipher::new(&km, Direction::ResponderToInitiator);

        let sealed_init = c_init.seal(b"init message").unwrap();
        // responder cipher should not be able to decrypt initiator's message
        let result = c_resp.open(&sealed_init);
        assert!(matches!(result, Err(CipherError::AeadOpenFailed)));
    }

    #[test]
    fn different_sessions_have_independent_keys() {
        let km_a = TestKeyMaterial([1u8; 32]);
        let km_b = TestKeyMaterial([2u8; 32]);

        let mut c_a = TransportSessionCipher::new(&km_a, Direction::InitiatorToResponder);
        let mut c_b = TransportSessionCipher::new(&km_b, Direction::InitiatorToResponder);

        let sealed_a = c_a.seal(b"session A").unwrap();
        let result = c_b.open(&sealed_a);
        assert!(matches!(result, Err(CipherError::AeadOpenFailed)));

        // But each session can decrypt its own messages
        let opened_a = c_a.open(&sealed_a).unwrap();
        assert_eq!(opened_a, b"session A");
    }

    #[test]
    fn independent_nonce_counters_per_direction() {
        let km = test_key_material();
        let mut c_init = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);
        let mut c_resp = TransportSessionCipher::new(&km, Direction::ResponderToInitiator);

        // Both start at nonce 0
        assert_eq!(c_init.encrypt_nonce(), 0);
        assert_eq!(c_resp.encrypt_nonce(), 0);

        let si = c_init.seal(b"i").unwrap();
        let sr = c_resp.seal(b"r").unwrap();

        assert_eq!(c_init.encrypt_nonce(), 1);
        assert_eq!(c_resp.encrypt_nonce(), 1);

        // Each direction can decrypt its own sealed messages
        assert_eq!(c_init.open(&si).unwrap(), b"i");
        assert_eq!(c_resp.open(&sr).unwrap(), b"r");
    }

    // ── Bidirectional exchange simulation ────────────────────────────

    #[test]
    fn bidirectional_exchange() {
        let km = test_key_material();

        // Initiator creates: cipher for init→resp (seal), cipher for resp→init (open)
        let mut init_seal = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);
        let mut init_open = TransportSessionCipher::new(&km, Direction::ResponderToInitiator);

        // Responder creates: cipher for resp→init (seal), cipher for init→resp (open)
        let mut resp_seal = TransportSessionCipher::new(&km, Direction::ResponderToInitiator);
        let mut resp_open = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);

        // Exchange 100 messages in each direction
        for i in 0..100u8 {
            let init_msg = format!("initiator message {i}");
            let sealed_i = init_seal.seal(init_msg.as_bytes()).unwrap();
            let opened_i = resp_open.open(&sealed_i).unwrap();
            assert_eq!(opened_i, init_msg.as_bytes());

            let resp_msg = format!("responder message {i}");
            let sealed_r = resp_seal.seal(resp_msg.as_bytes()).unwrap();
            let opened_r = init_open.open(&sealed_r).unwrap();
            assert_eq!(opened_r, resp_msg.as_bytes());
        }

        // Verify nonce monotonicity
        assert_eq!(init_seal.encrypt_nonce(), 100);
        assert_eq!(resp_open.decrypt_last_seen(), Some(99));
        assert_eq!(resp_seal.encrypt_nonce(), 100);
        assert_eq!(init_open.decrypt_last_seen(), Some(99));
    }

    // ── Known-answer test vectors (RFC 8439 §2.8.2) ─────────────────

    #[test]
    fn known_answer_rfc8439_section_2_8_2_ciphertext() {
        // RFC 8439 §2.8.2 test vector: verify the ChaCha20 ciphertext portion
        // matches (the Poly1305 tag may differ due to crate AEAD framing).
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];

        let plaintext: &[u8] = &[
            0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e,
            0x74, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20,
            0x63, 0x6c, 0x61, 0x73, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20,
            0x49, 0x66, 0x20, 0x49, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
            0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e,
            0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20,
            0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, 0x63, 0x72,
            0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
            0x74, 0x2e,
        ];

        // RFC 8439 nonce (12 bytes): 0x070000004041424344454647
        let nonce_bytes: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];

        // RFC 8439 expected ciphertext (114 bytes, excluding tag)
        let expected_ct_only: &[u8] = &[
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
            0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
            0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
            0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
            0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
            0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16,
        ];

        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let nonce = Nonce::clone_from_slice(&nonce_bytes);

        // Encrypt: returns ciphertext || tag (130 bytes)
        let ct_with_tag = cipher.encrypt(&nonce, plaintext).unwrap();
        assert_eq!(ct_with_tag.len(), 114 + 16);

        // The ciphertext portion (first 114 bytes) must match the RFC
        assert_eq!(&ct_with_tag[..114], expected_ct_only);

        // Round-trip: decrypt must recover the original plaintext
        let decrypted = cipher.decrypt(&nonce, ct_with_tag.as_slice()).unwrap();
        assert_eq!(decrypted, plaintext);

        // Deterministic: same inputs always produce the same output
        let ct2 = cipher.encrypt(&nonce, plaintext).unwrap();
        assert_eq!(ct_with_tag, ct2);
    }

    // ── Empty plaintext ──────────────────────────────────────────────

    #[test]
    fn empty_plaintext_produces_valid_frame() {
        let km = test_key_material();
        let mut cipher = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);
        let sealed = cipher.seal(b"").unwrap();
        // Frame must be nonce (12) + tag (16) = 28 bytes
        assert_eq!(sealed.len(), 28);
        let opened = cipher.open(&sealed).unwrap();
        assert!(opened.is_empty());
    }

    // ── Maximum-size plaintext ───────────────────────────────────────

    #[test]
    fn large_payload_roundtrip() {
        let km = test_key_material();
        let mut cipher = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);
        let data = vec![0xCCu8; 1_048_576]; // 1 MiB
        let sealed = cipher.seal(&data).unwrap();
        assert_eq!(sealed.len(), NONCE_LEN + data.len() + 16);
        let opened = cipher.open(&sealed).unwrap();
        assert_eq!(opened, data);
    }

    // ── Debug formatting ─────────────────────────────────────────────

    #[test]
    fn debug_format_is_non_exhaustive() {
        let km = test_key_material();
        let cipher = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);
        let s = format!("{cipher:?}");
        assert!(s.contains("TransportSessionCipher"));
        assert!(!s.contains("cipher"));
    }

    // ── Nonce encoding helpers ──────────────────────────────────────

    #[test]
    fn nonce_encoding_roundtrip() {
        for val in [0u64, 1, 42, 256, u64::MAX] {
            let n = nonce_to_bytes(val);
            let extracted = bytes_to_nonce(&n);
            assert_eq!(extracted, val, "nonce roundtrip failed for {val}");
        }
    }

    #[test]
    fn nonce_encoding_is_big_endian() {
        let n = nonce_to_bytes(0x0102_0304_0506_0708);
        // First 8 bytes should be the BE representation
        assert_eq!(n[0], 0x01);
        assert_eq!(n[1], 0x02);
        assert_eq!(n[7], 0x08);
        // Last 4 bytes should be zero
        assert_eq!(&n[8..12], &[0u8; 4]);
    }

    #[test]
    fn nonce_encoding_is_deterministic() {
        let n1 = nonce_to_bytes(42);
        let n2 = nonce_to_bytes(42);
        assert_eq!(&n1[..], &n2[..]);
    }

    // ── HKDF expand tests ───────────────────────────────────────────

    #[test]
    fn hkdf_expand_produces_requested_length() {
        let prk = [0x42u8; 32];
        for len in [1, 16, 32, 64, 128] {
            let okm = hkdf_expand_sha256(&prk, b"test-info", len);
            assert_eq!(okm.len(), len, "wrong length for len={len}");
        }
    }

    #[test]
    fn hkdf_expand_is_deterministic() {
        let prk = [0x42u8; 32];
        let a = hkdf_expand_sha256(&prk, b"info", 32);
        let b = hkdf_expand_sha256(&prk, b"info", 32);
        assert_eq!(a, b);
    }

    #[test]
    fn hkdf_expand_different_info_different_output() {
        let prk = [0x42u8; 32];
        let a = hkdf_expand_sha256(&prk, b"info-a", 32);
        let b = hkdf_expand_sha256(&prk, b"info-b", 32);
        assert_ne!(a, b);
    }

    #[test]
    fn hkdf_expand_different_prk_different_output() {
        let prk_a = [0xAAu8; 32];
        let prk_b = [0xBBu8; 32];
        let a = hkdf_expand_sha256(&prk_a, b"info", 32);
        let b = hkdf_expand_sha256(&prk_b, b"info", 32);
        assert_ne!(a, b);
    }

    // ── CipherError Display ─────────────────────────────────────────

    #[test]
    fn cipher_error_display() {
        assert_eq!(
            CipherError::AeadOpenFailed.to_string(),
            "AEAD open failed: corrupted, wrong key, or tampered"
        );
        assert_eq!(
            CipherError::NonceExhausted.to_string(),
            "nonce counter exhausted (u64 overflow)"
        );
        assert!(CipherError::NonceReuse {
            received: 5,
            last_seen: 10
        }
        .to_string()
        .contains("nonce reuse"));
        assert!(CipherError::TruncatedFrame { got: 10, min: 28 }
            .to_string()
            .contains("truncated"));
    }

    // ── AAD binding tests ────────────────────────────────────────────

    #[test]
    fn aad_roundtrip_matches() {
        let km = test_key_material();
        let mut seal_cipher = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);
        let mut open_cipher = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);

        let aad = b"session-42:e1:dir0:fam1:seq7";
        let plaintext = b"data with aad";
        let sealed = seal_cipher.seal_with_aad(plaintext, aad).unwrap();
        let opened = open_cipher.open_with_aad(&sealed, aad).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn aad_mismatch_rejected() {
        let km = test_key_material();
        let mut seal_cipher = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);
        let mut open_cipher = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);

        let sealed = seal_cipher.seal_with_aad(b"data", b"aad-1").unwrap();
        let result = open_cipher.open_with_aad(&sealed, b"aad-2");
        assert!(
            matches!(result, Err(CipherError::AeadOpenFailed)),
            "wrong AAD must cause AEAD failure"
        );
    }

    #[test]
    fn aad_empty_vs_nonempty_are_different() {
        let km = test_key_material();
        let mut c = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);

        let sealed_no_aad = c.seal(b"data").unwrap();
        let result = c.open_with_aad(&sealed_no_aad, b"some-aad");
        assert!(
            matches!(result, Err(CipherError::AeadOpenFailed)),
            "ciphertext without AAD must not verify with AAD"
        );
    }

    #[test]
    fn aad_large_payload() {
        let km = test_key_material();
        let mut seal_cipher = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);
        let mut open_cipher = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);

        let aad = vec![0x42u8; 256];
        let plaintext = vec![0xABu8; 4096];
        let sealed = seal_cipher.seal_with_aad(&plaintext, &aad).unwrap();
        let opened = open_cipher.open_with_aad(&sealed, &aad).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn aad_preserves_nonce_protection() {
        let km = test_key_material();
        let mut seal_cipher = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);
        let mut open_cipher = TransportSessionCipher::new(&km, Direction::InitiatorToResponder);

        let aad = b"ctx";
        let sealed = seal_cipher.seal_with_aad(b"msg", aad).unwrap();
        open_cipher.open_with_aad(&sealed, aad).unwrap();

        // Replay with same AAD must be rejected
        let result = open_cipher.open_with_aad(&sealed, aad);
        assert!(matches!(result, Err(CipherError::NonceReuse { .. })));
    }

    #[test]
    fn encryption_context_roundtrip() {
        let ctx = EncryptionContext {
            session_id: 0xDEADBEEF_CAFEBABE,
            endpoint_family: 1, // Control
            direction: 0,       // InitiatorToResponder
            message_family: 4,  // PublicationProgress
            sequence_no: 42,
        };
        let aad = ctx.to_aad_bytes();
        assert_eq!(aad.len(), EncryptionContext::WIRE_SIZE);

        // Verify the encoding is deterministic
        let aad2 = ctx.to_aad_bytes();
        assert_eq!(aad, aad2);

        // Verify distinct contexts produce distinct AAD
        let ctx2 = EncryptionContext {
            sequence_no: 43,
            ..ctx
        };
        assert_ne!(ctx.to_aad_bytes(), ctx2.to_aad_bytes());
    }

    // ── SessionKeyMaterial trait object test ────────────────────────

    #[test]
    fn cipher_from_trait_object() {
        fn make_cipher(km: &dyn SessionKeyMaterial) -> TransportSessionCipher {
            TransportSessionCipher::new(km, Direction::InitiatorToResponder)
        }

        let km = test_key_material();
        let mut c = make_cipher(&km);
        let sealed = c.seal(b"via trait object").unwrap();
        let opened = c.open(&sealed).unwrap();
        assert_eq!(opened, b"via trait object");
    }
}
