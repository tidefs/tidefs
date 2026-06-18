// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Session-bound transport security with HMAC-SHA256 per-frame
//! authentication and optional ChaCha20-Poly1305 encryption.
//!
//! ## Design
//!
//! After the HELLO handshake establishes session keys, every transport
//! frame is protected by `SessionSecurity`:
//!
//! - **HMAC-SHA256** authentication covers the frame header and payload.
//!   The 32-byte tag is appended to every frame.
//! - **ChaCha20-Poly1305** encryption (optional) encrypts the
//!   `header || payload || hmac_tag` blob, providing both confidentiality
//!   and a second layer of ciphertext authentication.
//!
//! Keys are derived from the session key material via HKDF-SHA256 with
//! domain-separated info strings, ensuring the HMAC key and encryption
//! key are cryptographically independent.
//!
//! ## Wire format
//!
//! ```text
//! Plaintext (encryption disabled):
//!   [flags: u8 = 0x00]
//!   [header_len: u16 LE]
//!   [payload_len: u32 LE]
//!   [header: header_len bytes]
//!   [payload: payload_len bytes]
//!   [hmac_tag: 32 bytes]
//!
//! Encrypted (encryption enabled):
//!   [flags: u8 = 0x01]
//!   [nonce: 12 bytes]
//!   [ciphertext || poly1305_tag]
//!   Decrypted plaintext:
//!     [header_len: u16 LE]
//!     [header: header_len bytes]
//!     [payload: variable]
//!     [hmac_tag: 32 bytes]
//! ```
//!
//! HMAC covers `header || payload` (excluding the length prefixes).
//! Nonces are monotonic u64 counters encoded as 12-byte IETF nonces.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt;

// ---------------------------------------------------------------------------
// Domain separation constants for HKDF key derivation
// ---------------------------------------------------------------------------

const HKDF_INFO_PREFIX: &[u8] = b"tidefs-session-security-v1";
const HMAC_KEY_INFO: &[u8] = b"hmac-key";
const ENCRYPTION_KEY_INFO: &[u8] = b"encryption-key";
const KEY_LEN: usize = 32;
const HMAC_TAG_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const MIN_ENCRYPTED_WIRE: usize = 1 + NONCE_LEN + 16;
const MIN_PLAINTEXT_WIRE: usize = 1 + 2 + 4 + HMAC_TAG_LEN;

// ---------------------------------------------------------------------------
// SessionSecurityStats
// ---------------------------------------------------------------------------

/// Per-session security statistics counters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionSecurityStats {
    pub frames_sent: u64,
    pub frames_received: u64,
    pub hmac_failures: u64,
    pub decrypt_failures: u64,
}

impl SessionSecurityStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn total_failures(&self) -> u64 {
        self.hmac_failures.saturating_add(self.decrypt_failures)
    }
}

// ---------------------------------------------------------------------------
// SessionSecurityError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionSecurityError {
    HmacVerificationFailed,
    DecryptionFailed,
    NonceReuse { received: u64, last_seen: u64 },
    NonceExhausted,
    TruncatedFrame { got: usize, min: usize },
    UnknownFlags { flags: u8 },
    InvalidHeaderLength { declared: u16, available: usize },
    InvalidPayloadLength { declared: u32, available: usize },
}

impl fmt::Display for SessionSecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HmacVerificationFailed => {
                write!(f, "HMAC verification failed: frame tampered or wrong key")
            }
            Self::DecryptionFailed => {
                write!(
                    f,
                    "AEAD decryption failed: corrupted, wrong key, or tampered"
                )
            }
            Self::NonceReuse {
                received,
                last_seen,
            } => {
                write!(f, "nonce reuse: received {received}, last seen {last_seen}")
            }
            Self::NonceExhausted => {
                write!(f, "encrypt nonce counter exhausted (u64 overflow)")
            }
            Self::TruncatedFrame { got, min } => {
                write!(f, "truncated frame: got {got} bytes, need at least {min}")
            }
            Self::UnknownFlags { flags } => {
                write!(f, "unknown frame flags byte: 0x{flags:02x}")
            }
            Self::InvalidHeaderLength {
                declared,
                available,
            } => {
                write!(
                    f,
                    "invalid header length: declared {declared}, available {available}"
                )
            }
            Self::InvalidPayloadLength {
                declared,
                available,
            } => {
                write!(
                    f,
                    "invalid payload length: declared {declared}, available {available}"
                )
            }
        }
    }
}

impl std::error::Error for SessionSecurityError {}

// ---------------------------------------------------------------------------
// SessionSecurity
// ---------------------------------------------------------------------------

/// Session-bound transport security wrapping one direction of a session.
///
/// Each instance protects frames in one direction. For bidirectional
/// communication, create two instances with independent nonce counters.
pub struct SessionSecurity {
    hmac_key: [u8; KEY_LEN],
    cipher: Option<ChaCha20Poly1305>,
    encrypt_nonce: u64,
    decrypt_last_nonce: Option<u64>,
    encrypt_exhausted: bool,
    pub stats: SessionSecurityStats,
}

impl SessionSecurity {
    /// Create a new `SessionSecurity` from a 32-byte session key.
    ///
    /// `encryption_enabled`: if true, encrypts frames with ChaCha20-Poly1305
    /// in addition to HMAC authentication. If false, uses HMAC only.
    ///
    /// HMAC and encryption keys are derived independently via HKDF-SHA256.
    pub fn new(session_key: &[u8; KEY_LEN], encryption_enabled: bool) -> Self {
        let hmac_key_arr: [u8; KEY_LEN] = {
            let mut info = Vec::from(HKDF_INFO_PREFIX);
            info.extend_from_slice(HMAC_KEY_INFO);
            let derived = hkdf_expand_sha256(session_key, &info, KEY_LEN);
            let mut arr = [0u8; KEY_LEN];
            arr.copy_from_slice(&derived);
            arr
        };

        let cipher = if encryption_enabled {
            let mut info = Vec::from(HKDF_INFO_PREFIX);
            info.extend_from_slice(ENCRYPTION_KEY_INFO);
            let derived = hkdf_expand_sha256(session_key, &info, KEY_LEN);
            let mut enc_key = [0u8; KEY_LEN];
            enc_key.copy_from_slice(&derived);
            Some(
                ChaCha20Poly1305::new_from_slice(&enc_key)
                    .expect("32-byte key is valid for ChaCha20Poly1305"),
            )
        } else {
            None
        };

        Self {
            hmac_key: hmac_key_arr,
            cipher,
            encrypt_nonce: 0,
            decrypt_last_nonce: None,
            encrypt_exhausted: false,
            stats: SessionSecurityStats::new(),
        }
    }

    /// Create a `SessionSecurity` with raw keys (bypasses HKDF, for testing).
    #[doc(hidden)]
    pub fn from_raw_keys(hmac_key: &[u8; KEY_LEN], encryption_key: Option<&[u8; KEY_LEN]>) -> Self {
        let cipher = encryption_key.map(|k| {
            ChaCha20Poly1305::new_from_slice(k).expect("32-byte key is valid for ChaCha20Poly1305")
        });
        Self {
            hmac_key: *hmac_key,
            cipher,
            encrypt_nonce: 0,
            decrypt_last_nonce: None,
            encrypt_exhausted: false,
            stats: SessionSecurityStats::new(),
        }
    }

    /// Whether encryption is enabled for this instance.
    pub fn encryption_enabled(&self) -> bool {
        self.cipher.is_some()
    }

    // ── Seal (outbound) ────────────────────────────────────────────

    /// Protect a frame: compute HMAC, optionally encrypt, return wire bytes.
    ///
    /// HMAC covers `header || payload`. If encryption is enabled, the
    /// `header || payload || hmac_tag` blob is encrypted with ChaCha20-Poly1305.
    pub fn seal(&mut self, header: &[u8], payload: &[u8]) -> Result<Vec<u8>, SessionSecurityError> {
        let hmac_tag = self.compute_hmac(header, payload);

        if let Some(ref cipher) = self.cipher {
            if self.encrypt_exhausted {
                return Err(SessionSecurityError::NonceExhausted);
            }

            let header_len = header.len() as u16;
            let mut plaintext = Vec::with_capacity(2 + header.len() + payload.len() + HMAC_TAG_LEN);
            plaintext.extend_from_slice(&header_len.to_le_bytes());
            plaintext.extend_from_slice(header);
            plaintext.extend_from_slice(payload);
            plaintext.extend_from_slice(&hmac_tag);

            let nonce_val = self.encrypt_nonce;
            let nonce = nonce_to_bytes(nonce_val);
            let ciphertext = cipher
                .encrypt(
                    &nonce,
                    Payload {
                        msg: &plaintext,
                        aad: b"",
                    },
                )
                .expect("ChaCha20Poly1305 encrypt is infallible for valid inputs");

            let mut frame = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
            frame.push(0x01u8);
            frame.extend_from_slice(&nonce);
            frame.extend_from_slice(&ciphertext);

            let (next, overflowed) = self.encrypt_nonce.overflowing_add(1);
            self.encrypt_nonce = next;
            if overflowed {
                self.encrypt_exhausted = true;
            }

            self.stats.frames_sent = self.stats.frames_sent.saturating_add(1);
            return Ok(frame);
        }

        // Plaintext path
        let header_len = header.len() as u16;
        let payload_len = payload.len() as u32;
        let mut frame = Vec::with_capacity(1 + 2 + 4 + header.len() + payload.len() + HMAC_TAG_LEN);
        frame.push(0x00u8);
        frame.extend_from_slice(&header_len.to_le_bytes());
        frame.extend_from_slice(&payload_len.to_le_bytes());
        frame.extend_from_slice(header);
        frame.extend_from_slice(payload);
        frame.extend_from_slice(&hmac_tag);

        self.stats.frames_sent = self.stats.frames_sent.saturating_add(1);
        Ok(frame)
    }

    // ── Open (inbound) ─────────────────────────────────────────────

    /// Authenticate and decrypt (if needed) an inbound frame.
    ///
    /// Returns `(header, payload)` on success.
    pub fn open(&mut self, wire_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SessionSecurityError> {
        if wire_bytes.is_empty() {
            return Err(SessionSecurityError::TruncatedFrame { got: 0, min: 1 });
        }

        let flags = wire_bytes[0];

        match flags {
            0x00 => self.open_plaintext(wire_bytes),
            0x01 => self.open_encrypted(wire_bytes),
            other => Err(SessionSecurityError::UnknownFlags { flags: other }),
        }
    }

    fn open_plaintext(
        &mut self,
        wire_bytes: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), SessionSecurityError> {
        if wire_bytes.len() < MIN_PLAINTEXT_WIRE {
            return Err(SessionSecurityError::TruncatedFrame {
                got: wire_bytes.len(),
                min: MIN_PLAINTEXT_WIRE,
            });
        }

        let header_len = u16::from_le_bytes(wire_bytes[1..3].try_into().unwrap()) as usize;
        let payload_len = u32::from_le_bytes(wire_bytes[3..7].try_into().unwrap()) as usize;

        let header_start = 7;
        let header_end = header_start + header_len;
        let payload_end = header_end + payload_len;
        let hmac_start = payload_end;
        let hmac_end = hmac_start + HMAC_TAG_LEN;

        if wire_bytes.len() < hmac_end {
            return Err(SessionSecurityError::TruncatedFrame {
                got: wire_bytes.len(),
                min: hmac_end,
            });
        }

        let header = wire_bytes[header_start..header_end].to_vec();
        let payload = wire_bytes[header_end..payload_end].to_vec();
        let received_hmac: [u8; HMAC_TAG_LEN] =
            wire_bytes[hmac_start..hmac_end].try_into().unwrap();

        self.verify_hmac(&header, &payload, &received_hmac)?;

        self.stats.frames_received = self.stats.frames_received.saturating_add(1);
        Ok((header, payload))
    }

    fn open_encrypted(
        &mut self,
        wire_bytes: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), SessionSecurityError> {
        if wire_bytes.len() < MIN_ENCRYPTED_WIRE {
            return Err(SessionSecurityError::TruncatedFrame {
                got: wire_bytes.len(),
                min: MIN_ENCRYPTED_WIRE,
            });
        }

        let cipher = self
            .cipher
            .as_ref()
            .ok_or(SessionSecurityError::UnknownFlags { flags: 0x01 })?;

        let mut nonce_arr = [0u8; NONCE_LEN];
        nonce_arr.copy_from_slice(&wire_bytes[1..1 + NONCE_LEN]);
        let nonce = Nonce::clone_from_slice(&nonce_arr);
        let nonce_val = bytes_to_nonce(&nonce_arr);

        if let Some(last) = self.decrypt_last_nonce {
            if nonce_val <= last {
                self.stats.decrypt_failures = self.stats.decrypt_failures.saturating_add(1);
                return Err(SessionSecurityError::NonceReuse {
                    received: nonce_val,
                    last_seen: last,
                });
            }
        }

        let ciphertext = &wire_bytes[1 + NONCE_LEN..];
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: b"",
                },
            )
            .map_err(|_| {
                self.stats.decrypt_failures = self.stats.decrypt_failures.saturating_add(1);
                SessionSecurityError::DecryptionFailed
            })?;

        self.decrypt_last_nonce = Some(nonce_val);

        if plaintext.len() < 2 + HMAC_TAG_LEN {
            return Err(SessionSecurityError::TruncatedFrame {
                got: plaintext.len(),
                min: 2 + HMAC_TAG_LEN,
            });
        }

        let header_len = u16::from_le_bytes(plaintext[0..2].try_into().unwrap()) as usize;
        let payload_and_hmac = &plaintext[2..];

        if payload_and_hmac.len() < header_len + HMAC_TAG_LEN {
            return Err(SessionSecurityError::InvalidHeaderLength {
                declared: header_len as u16,
                available: payload_and_hmac.len(),
            });
        }

        let header = payload_and_hmac[..header_len].to_vec();
        let payload = payload_and_hmac[header_len..payload_and_hmac.len() - HMAC_TAG_LEN].to_vec();
        let received_hmac: [u8; HMAC_TAG_LEN] = payload_and_hmac
            [payload_and_hmac.len() - HMAC_TAG_LEN..]
            .try_into()
            .unwrap();

        self.verify_hmac(&header, &payload, &received_hmac)?;

        self.stats.frames_received = self.stats.frames_received.saturating_add(1);
        Ok((header, payload))
    }

    // ── Internal helpers ───────────────────────────────────────────

    fn compute_hmac(&self, header: &[u8], payload: &[u8]) -> [u8; HMAC_TAG_LEN] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.hmac_key)
            .expect("HMAC-SHA256 supports any key length");
        mac.update(header);
        mac.update(payload);
        mac.finalize().into_bytes().into()
    }

    fn verify_hmac(
        &mut self,
        header: &[u8],
        payload: &[u8],
        tag: &[u8; HMAC_TAG_LEN],
    ) -> Result<(), SessionSecurityError> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.hmac_key)
            .expect("HMAC-SHA256 supports any key length");
        mac.update(header);
        mac.update(payload);
        if mac.verify_slice(tag).is_err() {
            self.stats.hmac_failures = self.stats.hmac_failures.saturating_add(1);
            return Err(SessionSecurityError::HmacVerificationFailed);
        }
        Ok(())
    }

    // ── Accessors for testing ──────────────────────────────────────

    #[doc(hidden)]
    pub fn encrypt_nonce(&self) -> u64 {
        self.encrypt_nonce
    }

    #[doc(hidden)]
    pub fn decrypt_last_nonce(&self) -> Option<u64> {
        self.decrypt_last_nonce
    }
}

impl fmt::Debug for SessionSecurity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionSecurity")
            .field("encryption_enabled", &self.cipher.is_some())
            .field("encrypt_nonce", &self.encrypt_nonce)
            .field("decrypt_last_nonce", &self.decrypt_last_nonce)
            .field("encrypt_exhausted", &self.encrypt_exhausted)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Nonce encoding helpers
// ---------------------------------------------------------------------------

fn nonce_to_bytes(counter: u64) -> Nonce {
    let mut arr = [0u8; NONCE_LEN];
    arr[..8].copy_from_slice(&counter.to_be_bytes());
    Nonce::clone_from_slice(&arr)
}

fn bytes_to_nonce(bytes: &[u8]) -> u64 {
    let mut counter_bytes = [0u8; 8];
    counter_bytes.copy_from_slice(&bytes[..8]);
    u64::from_be_bytes(counter_bytes)
}

// ---------------------------------------------------------------------------
// HKDF-SHA256 expand (RFC 5869 S2.3)
// ---------------------------------------------------------------------------

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

    fn session_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0..16].copy_from_slice(b"test-session-key");
        k
    }

    // ── Plaintext round-trip ───────────────────────────────────────

    #[test]
    fn plaintext_roundtrip() {
        let key = session_key();
        let mut seal = SessionSecurity::new(&key, false);
        let mut open = SessionSecurity::new(&key, false);

        let frame = seal.seal(b"hdr", b"body").unwrap();
        let (hdr, body) = open.open(&frame).unwrap();
        assert_eq!(hdr, b"hdr");
        assert_eq!(body, b"body");
        assert_eq!(seal.stats.frames_sent, 1);
        assert_eq!(open.stats.frames_received, 1);
    }

    #[test]
    fn plaintext_empty_header_and_payload() {
        let key = session_key();
        let mut seal = SessionSecurity::new(&key, false);
        let mut open = SessionSecurity::new(&key, false);

        let frame = seal.seal(b"", b"").unwrap();
        let (hdr, body) = open.open(&frame).unwrap();
        assert!(hdr.is_empty());
        assert!(body.is_empty());
    }

    #[test]
    fn plaintext_large_payload() {
        let key = session_key();
        let mut seal = SessionSecurity::new(&key, false);
        let mut open = SessionSecurity::new(&key, false);

        let header = vec![0xAAu8; 256];
        let payload = vec![0xBBu8; 65536];
        let frame = seal.seal(&header, &payload).unwrap();
        let (hdr, body) = open.open(&frame).unwrap();
        assert_eq!(hdr, header);
        assert_eq!(body, payload);
    }

    // ── Encrypted round-trip ───────────────────────────────────────

    #[test]
    fn encrypted_roundtrip() {
        let key = session_key();
        let mut seal = SessionSecurity::new(&key, true);
        let mut open = SessionSecurity::new(&key, true);

        let frame = seal.seal(b"hdr", b"body").unwrap();
        assert_eq!(frame[0], 0x01);
        let (hdr, body) = open.open(&frame).unwrap();
        assert_eq!(hdr, b"hdr");
        assert_eq!(body, b"body");
    }

    #[test]
    fn encrypted_empty_payload() {
        let key = session_key();
        let mut seal = SessionSecurity::new(&key, true);
        let mut open = SessionSecurity::new(&key, true);

        let frame = seal.seal(b"", b"").unwrap();
        let (hdr, body) = open.open(&frame).unwrap();
        assert!(hdr.is_empty());
        assert!(body.is_empty());
    }

    // ── HMAC tampering detection ───────────────────────────────────

    #[test]
    fn hmac_tampering_detected_plaintext() {
        let key = session_key();
        let mut seal = SessionSecurity::new(&key, false);
        let mut open = SessionSecurity::new(&key, false);

        let mut frame = seal.seal(b"hdr", b"payload").unwrap();
        frame[8] ^= 0x01;

        let result = open.open(&frame);
        assert!(matches!(
            result,
            Err(SessionSecurityError::HmacVerificationFailed)
        ));
        assert_eq!(open.stats.hmac_failures, 1);
    }

    #[test]
    fn hmac_tampering_detected_encrypted() {
        let key = session_key();
        let mut seal = SessionSecurity::new(&key, true);
        let mut open = SessionSecurity::new(&key, true);

        let mut frame = seal.seal(b"hdr", b"payload").unwrap();
        frame[20] ^= 0x01;

        let result = open.open(&frame);
        assert!(matches!(
            result,
            Err(SessionSecurityError::DecryptionFailed)
        ));
        assert_eq!(open.stats.decrypt_failures, 1);
    }

    #[test]
    fn hmac_tampering_header_plaintext() {
        let key = session_key();
        let mut seal = SessionSecurity::new(&key, false);
        let mut open = SessionSecurity::new(&key, false);

        let mut frame = seal.seal(b"important", b"data").unwrap();
        frame[7] ^= 0x01;

        let result = open.open(&frame);
        assert!(matches!(
            result,
            Err(SessionSecurityError::HmacVerificationFailed)
        ));
    }

    // ── Cross-mode handling ────────────────────────────────────────

    #[test]
    fn encrypted_frame_rejected_by_plaintext_receiver() {
        let key = session_key();
        let mut seal = SessionSecurity::new(&key, true);
        let mut open = SessionSecurity::new(&key, false);

        let frame = seal.seal(b"hdr", b"body").unwrap();
        let result = open.open(&frame);
        assert!(matches!(
            result,
            Err(SessionSecurityError::UnknownFlags { flags: 0x01 })
        ));
    }

    // ── Wrong key rejection ────────────────────────────────────────

    #[test]
    fn wrong_session_key_rejected_plaintext() {
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

        let mut seal = SessionSecurity::new(&k1, false);
        let mut open = SessionSecurity::new(&k2, false);

        let frame = seal.seal(b"hdr", b"body").unwrap();
        let result = open.open(&frame);
        assert!(matches!(
            result,
            Err(SessionSecurityError::HmacVerificationFailed)
        ));
    }

    #[test]
    fn wrong_session_key_rejected_encrypted() {
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

        let mut seal = SessionSecurity::new(&k1, true);
        let mut open = SessionSecurity::new(&k2, true);

        let frame = seal.seal(b"hdr", b"body").unwrap();
        let result = open.open(&frame);
        assert!(matches!(
            result,
            Err(SessionSecurityError::DecryptionFailed)
        ));
    }

    // ── Nonce replay protection ────────────────────────────────────

    #[test]
    fn nonce_replay_rejected_encrypted() {
        let key = session_key();
        let mut seal = SessionSecurity::new(&key, true);
        let mut open = SessionSecurity::new(&key, true);

        let frame = seal.seal(b"msg", b"1").unwrap();
        open.open(&frame).unwrap();

        let result = open.open(&frame);
        assert!(matches!(
            result,
            Err(SessionSecurityError::NonceReuse { .. })
        ));
    }

    #[test]
    fn nonce_replay_older_value_rejected() {
        let key = session_key();
        let mut seal = SessionSecurity::new(&key, true);
        let mut open = SessionSecurity::new(&key, true);

        let f0 = seal.seal(b"m", b"0").unwrap();
        let f1 = seal.seal(b"m", b"1").unwrap();

        open.open(&f0).unwrap();
        open.open(&f1).unwrap();

        let result = open.open(&f0);
        assert!(matches!(
            result,
            Err(SessionSecurityError::NonceReuse { .. })
        ));
    }

    // ── Nonce exhaustion ───────────────────────────────────────────

    #[test]
    fn nonce_exhaustion_detected() {
        let key = session_key();
        let mut seal = SessionSecurity::new(&key, true);
        seal.encrypt_nonce = u64::MAX;
        assert!(seal.seal(b"last", b"msg").is_ok());
        assert!(matches!(
            seal.seal(b"too", b"many"),
            Err(SessionSecurityError::NonceExhausted)
        ));
    }

    // ── Truncated frames ───────────────────────────────────────────

    #[test]
    fn truncated_plaintext_frame() {
        let key = session_key();
        let mut seal = SessionSecurity::new(&key, false);
        let mut open = SessionSecurity::new(&key, false);
        let frame = seal.seal(b"hdr", b"body").unwrap();
        let result = open.open(&frame[..1]);
        assert!(matches!(
            result,
            Err(SessionSecurityError::TruncatedFrame { .. })
        ));
    }

    #[test]
    fn truncated_encrypted_frame() {
        let key = session_key();
        let mut seal = SessionSecurity::new(&key, true);
        let mut open = SessionSecurity::new(&key, true);
        let frame = seal.seal(b"hdr", b"body").unwrap();
        let result = open.open(&frame[..5]);
        assert!(matches!(
            result,
            Err(SessionSecurityError::TruncatedFrame { .. })
        ));
    }

    #[test]
    fn empty_frame_rejected() {
        let key = session_key();
        let mut open = SessionSecurity::new(&key, false);
        let result = open.open(&[]);
        assert!(matches!(
            result,
            Err(SessionSecurityError::TruncatedFrame { .. })
        ));
    }

    // ── Unknown flags ──────────────────────────────────────────────

    #[test]
    fn unknown_flags_rejected() {
        let key = session_key();
        let mut open = SessionSecurity::new(&key, false);
        let mut frame = vec![0xFFu8];
        frame.extend_from_slice(&[0u8; 64]);
        let result = open.open(&frame);
        assert!(matches!(
            result,
            Err(SessionSecurityError::UnknownFlags { flags: 0xFF })
        ));
    }

    // ── Concurrent sessions ────────────────────────────────────────

    #[test]
    fn concurrent_secure_sessions_independent() {
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

        let mut s1_seal = SessionSecurity::new(&k1, true);
        let mut s1_open = SessionSecurity::new(&k1, true);
        let mut s2_seal = SessionSecurity::new(&k2, true);
        let mut s2_open = SessionSecurity::new(&k2, true);

        let f1 = s1_seal.seal(b"s1", b"data1").unwrap();
        let f2 = s2_seal.seal(b"s2", b"data2").unwrap();

        let (h1, p1) = s1_open.open(&f1).unwrap();
        let (h2, p2) = s2_open.open(&f2).unwrap();

        assert_eq!(h1, b"s1");
        assert_eq!(p1, b"data1");
        assert_eq!(h2, b"s2");
        assert_eq!(p2, b"data2");

        let result = s1_open.open(&f2);
        assert!(result.is_err());
    }

    // ── SessionSecurityStats ───────────────────────────────────────

    #[test]
    fn stats_total_failures() {
        let mut stats = SessionSecurityStats::new();
        assert_eq!(stats.total_failures(), 0);
        stats.hmac_failures = 3;
        stats.decrypt_failures = 2;
        assert_eq!(stats.total_failures(), 5);
    }

    // ── Error Display ──────────────────────────────────────────────

    #[test]
    fn error_display_variants() {
        assert!(SessionSecurityError::HmacVerificationFailed
            .to_string()
            .contains("HMAC"));
        assert!(SessionSecurityError::DecryptionFailed
            .to_string()
            .contains("decryption"));
        let e = SessionSecurityError::NonceReuse {
            received: 5,
            last_seen: 10,
        };
        assert!(e.to_string().contains("nonce reuse"));
        let e = SessionSecurityError::TruncatedFrame { got: 5, min: 39 };
        assert!(e.to_string().contains("truncated"));
    }

    // ── Debug formatting ───────────────────────────────────────────

    #[test]
    fn debug_format_non_exhaustive() {
        let key = session_key();
        let s = SessionSecurity::new(&key, true);
        let dbg = format!("{s:?}");
        assert!(dbg.contains("SessionSecurity"));
        assert!(!dbg.contains("hmac_key"));
    }

    // ── Nonce encoding roundtrip ───────────────────────────────────

    #[test]
    fn nonce_encoding_roundtrip() {
        for val in [0u64, 1, 42, 256, u64::MAX] {
            let n = nonce_to_bytes(val);
            assert_eq!(bytes_to_nonce(&n), val);
        }
    }

    // ── HKDF expand tests ──────────────────────────────────────────

    #[test]
    fn hkdf_expand_deterministic() {
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
    fn hkdf_expand_produces_requested_length() {
        let prk = [0x42u8; 32];
        for len in [1, 16, 32, 64, 128] {
            assert_eq!(hkdf_expand_sha256(&prk, b"test", len).len(), len);
        }
    }

    // ── Encryption enabled flag ────────────────────────────────────

    #[test]
    fn encryption_enabled_flag() {
        let key = session_key();
        assert!(SessionSecurity::new(&key, true).encryption_enabled());
        assert!(!SessionSecurity::new(&key, false).encryption_enabled());
    }
}
