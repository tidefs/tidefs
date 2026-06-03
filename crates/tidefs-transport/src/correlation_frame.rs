//! Correlation framing for request-response tracking over transport sessions.
//!
//! Provides lightweight framing that wraps an arbitrary payload with a
//! correlation ID and a direction flag so the transport layer can
//! automatically register outgoing requests and deliver incoming responses
//! through the per-session [`RequestResponseHandle`].
//!
//! ## Wire format
//!
//! ```text
//! [0..8)   correlation_id   u64 LE
//! [8]      flags            u8 (bit 0: 0=response, 1=request; bits 1-7: reserved)
//! [9..]    payload          variable length
//! ```
//!
//! ## Usage
//!
//! - Sender calls [`encode_correlation_request`] to register a new in-flight
//!   request and frame the payload before calling `send_message`.
//! - Receiver calls [`decode_correlation_frame`] on the inbound payload; if
//!   the frame carries a response, it delivers the payload through
//!   `Session::deliver_response`.

/// Length of the correlation frame header (8 bytes id + 1 byte flags).
pub const CORRELATION_HEADER_LEN: usize = 9;

/// Bit 0 of the flags byte: set for requests, clear for responses.
const FLAG_IS_REQUEST: u8 = 0x01;

/// Errors returned by correlation-frame decoding.
#[derive(Clone, Debug, thiserror::Error)]
pub enum CorrelationFrameError {
    /// The payload is too short to contain a correlation header.
    #[error("payload too short for correlation header: {0} bytes")]
    TooShort(usize),

    /// Reserved flag bits are set (bits 1-7 must be zero).
    #[error("reserved flag bits set: {0:#04x}")]
    ReservedBitsSet(u8),
}

/// Build a correlation-framed request payload.
///
/// Returns the framed bytes suitable for passing to `send_message`.
/// The caller must store the returned correlation ID so the receiving side
/// can call [`decode_correlation_frame`] and deliver the response.
pub fn encode_correlation_request(correlation_id: u64, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(CORRELATION_HEADER_LEN + payload.len());
    frame.extend_from_slice(&correlation_id.to_le_bytes());
    frame.push(FLAG_IS_REQUEST);
    frame.extend_from_slice(payload);
    frame
}

/// Build a correlation-framed response payload.
///
/// The receiver will decode this with [`decode_correlation_frame`] and
/// deliver the payload to the waiter registered under `correlation_id`.
pub fn encode_correlation_response(correlation_id: u64, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(CORRELATION_HEADER_LEN + payload.len());
    frame.extend_from_slice(&correlation_id.to_le_bytes());
    frame.push(0); // response: is_request bit clear, reserved bits zero
    frame.extend_from_slice(payload);
    frame
}

/// Result of decoding a correlation frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CorrelationFrameKind {
    /// The frame carries a request (correlation ID + flags with is_request set).
    Request { correlation_id: u64 },
    /// The frame carries a response (correlation ID + payload).
    Response {
        correlation_id: u64,
        payload: Vec<u8>,
    },
}

/// Decode a correlation frame from a received payload.
///
/// Returns [`CorrelationFrameError::TooShort`] if the payload is shorter
/// than [`CORRELATION_HEADER_LEN`], or [`CorrelationFrameError::ReservedBitsSet`]
/// if any reserved flag bits (1-7) are non-zero.
pub fn decode_correlation_frame(
    data: &[u8],
) -> Result<CorrelationFrameKind, CorrelationFrameError> {
    if data.len() < CORRELATION_HEADER_LEN {
        return Err(CorrelationFrameError::TooShort(data.len()));
    }
    let correlation_id = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let flags = data[8];
    if flags & !FLAG_IS_REQUEST != 0 {
        return Err(CorrelationFrameError::ReservedBitsSet(flags));
    }
    let payload = data[CORRELATION_HEADER_LEN..].to_vec();
    if flags & FLAG_IS_REQUEST != 0 {
        Ok(CorrelationFrameKind::Request { correlation_id })
    } else {
        Ok(CorrelationFrameKind::Response {
            correlation_id,
            payload,
        })
    }
}

/// Check whether a received payload starts with a correlation header.
///
/// Returns `true` if the payload is at least [`CORRELATION_HEADER_LEN`] bytes
/// and the reserved flag bits are all zero. This is a fast pre-check before
/// calling [`decode_correlation_frame`].
pub fn has_correlation_header(data: &[u8]) -> bool {
    if data.len() < CORRELATION_HEADER_LEN {
        return false;
    }
    // Reserved bits (1-7) must be zero for a valid correlation frame.
    data[8] & !FLAG_IS_REQUEST == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_request_roundtrip() {
        let payload = b"hello-request".to_vec();
        let frame = encode_correlation_request(42, &payload);
        assert!(frame.len() >= CORRELATION_HEADER_LEN + payload.len());

        let decoded = decode_correlation_frame(&frame).unwrap();
        assert_eq!(
            decoded,
            CorrelationFrameKind::Request { correlation_id: 42 }
        );
    }

    #[test]
    fn encode_response_roundtrip() {
        let payload = b"hello-response".to_vec();
        let frame = encode_correlation_response(7, &payload);
        assert!(frame.len() >= CORRELATION_HEADER_LEN + payload.len());

        let decoded = decode_correlation_frame(&frame).unwrap();
        assert_eq!(
            decoded,
            CorrelationFrameKind::Response {
                correlation_id: 7,
                payload: payload.clone(),
            }
        );
    }

    #[test]
    fn decode_too_short() {
        let err = decode_correlation_frame(&[0u8; 3]).unwrap_err();
        assert!(matches!(err, CorrelationFrameError::TooShort(3)));
    }

    #[test]
    fn decode_rejects_reserved_bits() {
        let mut frame = encode_correlation_request(1, b"x");
        frame[8] = 0xFF; // set reserved bits
        let err = decode_correlation_frame(&frame).unwrap_err();
        assert!(matches!(err, CorrelationFrameError::ReservedBitsSet(0xFF)));
    }

    #[test]
    fn has_correlation_header_detects() {
        let req = encode_correlation_request(1, b"x");
        assert!(has_correlation_header(&req));

        let resp = encode_correlation_response(1, b"y");
        assert!(has_correlation_header(&resp));

        // Too short
        assert!(!has_correlation_header(&[0u8; 3]));

        // Reserved bits set
        let mut bad = encode_correlation_request(1, b"x");
        bad[8] = 0x02;
        assert!(!has_correlation_header(&bad));
    }

    #[test]
    fn correlation_id_le_endian() {
        let frame = encode_correlation_request(0x0102030405060708, b"data");
        assert_eq!(frame[0], 0x08);
        assert_eq!(frame[7], 0x01);
        let decoded = decode_correlation_frame(&frame).unwrap();
        assert_eq!(
            decoded,
            CorrelationFrameKind::Request {
                correlation_id: 0x0102030405060708
            }
        );
    }
}
