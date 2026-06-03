//! Transport wire message codec: bridges [`MessageFamily`]-tagged payloads
//! to length-delimited byte frames and back.
//!
//! ## Wire format
//!
//! ```text
//! [0..4)   payload_len    u32 LE (length of payload only)
//! [4]      family         u8  (MessageFamily discriminant)
//! [5..]    payload        payload_len bytes
//! ```
//!
//! Total frame size = 5 + payload_len.
//!
//! ## Decoding tolerance
//!
//! Decode ignores trailing bytes beyond the declared payload length, enabling
//! the receive path to extract frames from a stream that may include
//! subsequent frames without knowing boundaries a priori.

use std::fmt;

use crate::envelope::MessageFamily;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Header size in bytes: 4 (payload_len) + 1 (discriminant).
pub const CODEC_FRAME_HEADER_SIZE: usize = 5;

/// Default maximum frame size: 16 MiB.
pub const DEFAULT_MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// CodecError
// ---------------------------------------------------------------------------

/// Errors that can occur during wire message encoding or decoding.
#[derive(Debug)]
pub enum CodecError {
    /// The payload is larger than the configured maximum frame size.
    PayloadTooLarge {
        /// Actual payload size in bytes.
        actual: usize,
        /// Configured maximum payload size in bytes.
        max: usize,
    },
    /// The input buffer is too short to contain a complete frame header.
    TruncatedHeader,
    /// The input buffer declares a payload length but does not contain
    /// enough bytes to satisfy it.
    TruncatedPayload {
        /// Declared payload length from the frame header.
        declared: usize,
        /// Actual bytes available after the header.
        available: usize,
    },
    /// The family discriminant byte does not map to any known [`MessageFamily`].
    InvalidDiscriminant(u8),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge { actual, max } => {
                write!(f, "payload size {actual} exceeds maximum frame size {max}")
            }
            Self::TruncatedHeader => f.write_str("frame too short: truncated header"),
            Self::TruncatedPayload {
                declared,
                available,
            } => {
                write!(
                    f,
                    "truncated payload: declared {declared} bytes but only {available} available"
                )
            }
            Self::InvalidDiscriminant(d) => {
                write!(f, "invalid message family discriminant: {d}")
            }
        }
    }
}

impl std::error::Error for CodecError {}

// ---------------------------------------------------------------------------
// MessageCodec
// ---------------------------------------------------------------------------

/// Configurable codec for encoding/decoding transport wire messages.
///
/// Produces and consumes length-delimited frames carrying a
/// [`MessageFamily`] discriminant and an opaque payload.
///
/// # Examples
///
/// ```
/// use tidefs_transport::codec::MessageCodec;
/// use tidefs_transport::envelope::MessageFamily;
///
/// let codec = MessageCodec::default();
/// let payload = b"hello";
/// let frame = codec.encode(MessageFamily::HelloClose, payload).unwrap();
/// let (family, decoded) = codec.decode(&frame).unwrap();
/// assert_eq!(family, MessageFamily::HelloClose);
/// assert_eq!(decoded, payload);
/// ```
#[derive(Clone, Debug)]
pub struct MessageCodec {
    /// Maximum payload size in bytes accepted during encoding.
    max_frame_size: usize,
}

impl Default for MessageCodec {
    fn default() -> Self {
        Self {
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
        }
    }
}

impl MessageCodec {
    /// Create a codec with a custom maximum frame size.
    ///
    /// Encoding a payload larger than `max_frame_size` returns
    /// [`CodecError::PayloadTooLarge`].
    #[must_use]
    pub fn with_max_frame_size(max_frame_size: usize) -> Self {
        Self { max_frame_size }
    }

    /// Return the configured maximum payload size.
    #[must_use]
    pub fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }

    /// Encode a [`MessageFamily`] and payload into a wire frame.
    ///
    /// Produces a byte vector in the wire format:
    /// `[payload_len LE u32][family u8][payload ...]`.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::PayloadTooLarge`] if `payload.len()` exceeds
    /// the configured `max_frame_size`.
    pub fn encode(&self, family: MessageFamily, payload: &[u8]) -> Result<Vec<u8>, CodecError> {
        let payload_len = payload.len();
        if payload_len > self.max_frame_size {
            return Err(CodecError::PayloadTooLarge {
                actual: payload_len,
                max: self.max_frame_size,
            });
        }

        let frame_len = CODEC_FRAME_HEADER_SIZE + payload_len;
        let mut frame = Vec::with_capacity(frame_len);

        // Payload length as 4-byte little-endian.
        frame.extend_from_slice(&(payload_len as u32).to_le_bytes());
        // MessageFamily discriminant as a single byte.
        frame.push(family as u8);
        // Variable-length payload.
        frame.extend_from_slice(payload);

        Ok(frame)
    }

    /// Decode a wire frame into a [`MessageFamily`] and payload bytes.
    ///
    /// Trailing bytes beyond the declared payload length are ignored.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] variants for truncated frames, invalid
    /// discriminants, or payload length mismatches.
    pub fn decode(&self, frame: &[u8]) -> Result<(MessageFamily, Vec<u8>), CodecError> {
        // Decode payload length.
        let payload_len = read_u32_le(frame).ok_or(CodecError::TruncatedHeader)? as usize;

        // Decode discriminant.
        let disc_byte = frame.get(4).copied().ok_or(CodecError::TruncatedHeader)?;
        let family = MessageFamily::try_from(disc_byte)
            .map_err(|_| CodecError::InvalidDiscriminant(disc_byte))?;

        // Decode payload.
        let payload_start = CODEC_FRAME_HEADER_SIZE;
        let payload_end =
            payload_start
                .checked_add(payload_len)
                .ok_or(CodecError::TruncatedPayload {
                    declared: payload_len,
                    available: frame.len().saturating_sub(payload_start),
                })?;
        if payload_end > frame.len() {
            return Err(CodecError::TruncatedPayload {
                declared: payload_len,
                available: frame.len().saturating_sub(payload_start),
            });
        }

        let payload = frame[payload_start..payload_end].to_vec();
        Ok((family, payload))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read a little-endian u32 from the first 4 bytes of a slice.
///
/// Returns `None` if the slice has fewer than 4 bytes.
fn read_u32_le(buf: &[u8]) -> Option<u32> {
    let arr: [u8; 4] = buf.get(..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(arr))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn codec() -> MessageCodec {
        MessageCodec::default()
    }

    // ---- Round-trip for every MessageFamily variant ----

    #[test]
    fn roundtrip_all_variants() {
        let codec = codec();
        for family in MessageFamily::all() {
            let payload = b"roundtrip payload";
            let frame = codec.encode(family, payload).unwrap();
            let (decoded_family, decoded_payload) = codec.decode(&frame).unwrap();
            assert_eq!(decoded_family, family, "family mismatch for {family}");
            assert_eq!(decoded_payload, payload, "payload mismatch for {family}");
        }
    }

    // ---- Empty payload ----

    #[test]
    fn roundtrip_empty_payload() {
        let codec = codec();
        let frame = codec.encode(MessageFamily::HelloClose, &[]).unwrap();
        assert_eq!(frame.len(), CODEC_FRAME_HEADER_SIZE);
        let (family, payload) = codec.decode(&frame).unwrap();
        assert_eq!(family, MessageFamily::HelloClose);
        assert!(payload.is_empty());
    }

    // ---- Exact max size frame ----

    #[test]
    fn roundtrip_exact_max_size() {
        let max = 1024;
        let codec = MessageCodec::with_max_frame_size(max);
        let payload = vec![0xABu8; max];
        let frame = codec
            .encode(MessageFamily::StateTransfer, &payload)
            .unwrap();
        assert_eq!(frame.len(), CODEC_FRAME_HEADER_SIZE + max);
        let (family, decoded) = codec.decode(&frame).unwrap();
        assert_eq!(family, MessageFamily::StateTransfer);
        assert_eq!(decoded, payload);
    }

    // ---- Max size + 1 rejection ----

    #[test]
    fn reject_oversize_payload() {
        let codec = MessageCodec::with_max_frame_size(256);
        let payload = vec![0u8; 257];
        let err = codec
            .encode(MessageFamily::HelloClose, &payload)
            .unwrap_err();
        match err {
            CodecError::PayloadTooLarge { actual, max } => {
                assert_eq!(actual, 257);
                assert_eq!(max, 256);
            }
            _ => panic!("expected PayloadTooLarge, got {err:?}"),
        }
    }

    // ---- Truncated header (fewer than 5 bytes) ----

    #[test]
    fn reject_truncated_header() {
        let codec = codec();
        for len in 0..CODEC_FRAME_HEADER_SIZE {
            let buf = vec![0u8; len];
            let err = codec.decode(&buf).unwrap_err();
            assert!(
                matches!(err, CodecError::TruncatedHeader),
                "expected TruncatedHeader for len={len}, got {err:?}"
            );
        }
    }

    // ---- Truncated payload ----

    #[test]
    fn reject_truncated_payload() {
        let codec = codec();
        // Declare 10 bytes of payload but provide only 3.
        let mut buf = Vec::new();
        buf.extend_from_slice(&10u32.to_le_bytes()); // payload_len = 10
        buf.push(MessageFamily::HelloClose as u8); // valid discriminant
        buf.extend_from_slice(b"123"); // only 3 bytes of payload
        let err = codec.decode(&buf).unwrap_err();
        match err {
            CodecError::TruncatedPayload {
                declared,
                available,
            } => {
                assert_eq!(declared, 10);
                assert_eq!(available, 3);
            }
            _ => panic!("expected TruncatedPayload, got {err:?}"),
        }
    }

    // ---- Invalid discriminant ----

    #[test]
    fn reject_invalid_discriminant() {
        let codec = codec();
        let mut buf = Vec::new();
        buf.extend_from_slice(&4u32.to_le_bytes()); // payload_len = 4
        buf.push(255u8); // invalid discriminant (max valid is 9)
        buf.extend_from_slice(b"data");
        let err = codec.decode(&buf).unwrap_err();
        assert!(matches!(err, CodecError::InvalidDiscriminant(255)));
    }

    // ---- Trailing bytes are ignored ----

    #[test]
    fn ignore_trailing_bytes() {
        let codec = codec();
        let payload = b"core";
        let frame = codec.encode(MessageFamily::HeartbeatAck, payload).unwrap();
        // Append extra garbage bytes.
        let mut with_trailing = frame.clone();
        with_trailing.extend_from_slice(b"trailing garbage");
        let (family, decoded) = codec.decode(&with_trailing).unwrap();
        assert_eq!(family, MessageFamily::HeartbeatAck);
        assert_eq!(decoded, payload);
    }

    // ---- Decode returns exactly declared payload, not whole input ----

    #[test]
    fn decode_returns_declared_length_only() {
        let codec = codec();
        let frame = codec
            .encode(MessageFamily::PublicationProgress, b"abc")
            .unwrap();
        assert_eq!(frame.len(), CODEC_FRAME_HEADER_SIZE + 3);
        let (_, payload) = codec.decode(&frame).unwrap();
        assert_eq!(payload.len(), 3);
        assert_eq!(payload, b"abc");
    }

    // ---- Frame size matches formula ----

    #[test]
    fn frame_size_is_header_plus_payload() {
        let codec = codec();
        for payload_len in [0, 1, 7, 256, 1024] {
            let payload = vec![0xCCu8; payload_len];
            let frame = codec
                .encode(MessageFamily::ElectionControl, &payload)
                .unwrap();
            assert_eq!(frame.len(), CODEC_FRAME_HEADER_SIZE + payload_len);
        }
    }

    // ---- Default max_frame_size is 16 MiB ----

    #[test]
    fn default_max_frame_size_is_16_mib() {
        let codec = MessageCodec::default();
        assert_eq!(codec.max_frame_size(), 16 * 1024 * 1024);
    }

    // ---- Custom max_frame_size ----

    #[test]
    fn custom_max_frame_size() {
        let codec = MessageCodec::with_max_frame_size(42);
        assert_eq!(codec.max_frame_size(), 42);
    }

    // ---- Length prefix round-trip for boundary values ----

    #[test]
    fn length_prefix_boundary_values() {
        let codec = codec();
        for plen in [0u32, 1, 0xFF, 0xFFFF, 0x00FF_FFFF] {
            let payload = vec![0x5Au8; plen as usize];
            let frame = codec
                .encode(MessageFamily::LeaseFenceDeadline, &payload)
                .unwrap();
            let len_bytes = &frame[..4];
            let parsed_len = u32::from_le_bytes(len_bytes.try_into().unwrap());
            assert_eq!(parsed_len, plen);
        }
    }
}
