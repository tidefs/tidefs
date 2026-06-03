//! Transport message fragmentation and reassembly for payloads exceeding
//! the connection MTU.
//!
//! Large transport messages are split into ordered fragments at the sender
//! and reassembled before dispatch at the receiver. Each fragment carries
//! a [`FragmentHeader`] that identifies the parent message, the fragment
//! position within it, the total fragment count, and the message type tag.
//!
//! ## Wire format
//!
//! ```text
//! [0..4)    magic        b"VFRG"
//! [4..]     header       bincode(FragmentHeader)
//! [...]     payload      fragment payload bytes
//! ```
//!
//! ## Reassembly
//!
//! [`FragmentReassembler`] buffers incoming fragments per message_id,
//! tracks coverage via a bitmap, and emits the reassembled payload when
//! all fragments have arrived. A configurable timeout evicts incomplete
//! messages.

use bincode;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Wire constants
// ---------------------------------------------------------------------------

/// Magic bytes prefixing every fragment frame: "VFRG" = TideFS Fragment.
pub const FRAGMENT_MAGIC: [u8; 4] = *b"VFRG";

/// Minimum fragment header size on the wire (for bounds checks).
pub const FRAGMENT_HEADER_MIN_SIZE: usize = 4; // magic only; bincode header follows

/// Default MTU when none is negotiated.
pub const DEFAULT_MTU: usize = 65536;

/// Maximum number of fragments per message (limits bitmap and buffer size).
pub const MAX_FRAGMENTS_PER_MESSAGE: u32 = 1024;

/// Default reassembly timeout before an incomplete message is evicted.
pub const DEFAULT_REASSEMBLY_TIMEOUT_MS: u64 = 30_000;

// ---------------------------------------------------------------------------
// FragmentHeader
// ---------------------------------------------------------------------------

/// Header prepended to every fragment carrying reassembly metadata.
///
/// Encoded with bincode immediately after the FRAGMENT_MAGIC bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FragmentHeader {
    /// Unique identifier for the original (pre-fragmentation) message.
    /// All fragments of the same message share this id.
    pub message_id: u64,
    /// Zero-based index of this fragment within the message.
    pub fragment_index: u32,
    /// Total number of fragments the message was split into.
    pub total_fragments: u32,
    /// Upper-layer message type tag (preserved through reassembly).
    pub type_tag: u8,
}

impl FragmentHeader {
    /// Create a new fragment header.
    #[must_use]
    pub fn new(message_id: u64, fragment_index: u32, total_fragments: u32, type_tag: u8) -> Self {
        Self {
            message_id,
            fragment_index,
            total_fragments,
            type_tag,
        }
    }

    /// Encode this header to wire bytes (bincode, without magic).
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Decode a FragmentHeader from bytes (bincode, magic already consumed).
    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// Whether this is the last fragment (fragment_index == total_fragments - 1).
    #[must_use]
    pub fn is_last(&self) -> bool {
        self.fragment_index == self.total_fragments.saturating_sub(1)
    }

    /// Whether this is the first fragment (fragment_index == 0).
    #[must_use]
    pub fn is_first(&self) -> bool {
        self.fragment_index == 0
    }
}

// ---------------------------------------------------------------------------
// Fragment wire encoding / decoding
// ---------------------------------------------------------------------------

/// Encode a single fragment to wire format: `VFRG || bincode(header) || payload`.
#[must_use]
pub fn encode_fragment(header: &FragmentHeader, payload: &[u8]) -> Vec<u8> {
    let header_bytes = header
        .encode()
        .expect("FragmentHeader bincode encode is infallible for valid fields");
    let mut wire = Vec::with_capacity(4 + header_bytes.len() + payload.len());
    wire.extend_from_slice(&FRAGMENT_MAGIC);
    wire.extend_from_slice(&header_bytes);
    wire.extend_from_slice(payload);
    wire
}

/// Try to decode a fragment from wire bytes.
///
/// Returns `Ok((header, payload))` on success, or `FragmentError` if the
/// magic is missing or the header cannot be decoded.
pub fn decode_fragment(wire: &[u8]) -> Result<(FragmentHeader, Vec<u8>), FragmentError> {
    if wire.len() < 4 {
        return Err(FragmentError::TooShort {
            got: wire.len(),
            min: 4,
        });
    }
    if wire[0..4] != FRAGMENT_MAGIC {
        let mut got = [0u8; 4];
        got.copy_from_slice(&wire[0..4]);
        return Err(FragmentError::BadMagic { got });
    }
    let header: FragmentHeader =
        bincode::deserialize(&wire[4..]).map_err(|e| FragmentError::Decode(e.to_string()))?;
    let header_len = bincode::serialized_size(&header)
        .map_err(|e| FragmentError::Decode(e.to_string()))? as usize;
    let payload_start = 4 + header_len;
    let payload = if wire.len() > payload_start {
        wire[payload_start..].to_vec()
    } else {
        Vec::new()
    };
    Ok((header, payload))
}

/// Check whether a wire buffer starts with the fragment magic.
#[must_use]
pub fn is_fragment(wire: &[u8]) -> bool {
    wire.len() >= 4 && wire[0..4] == FRAGMENT_MAGIC
}

// ---------------------------------------------------------------------------
// fragment_message: split a payload into MTU-sized fragments
// ---------------------------------------------------------------------------

/// Compute the overhead per fragment in bytes.
///
/// This is: magic (4) + bincode header size for a FragmentHeader.
/// Measured from a sample encoding for accuracy.
#[must_use]
pub fn fragment_overhead() -> usize {
    let sample = FragmentHeader::new(0, 0, 1, 0);
    let encoded = sample.encode().expect("encode");
    4 + encoded.len()
}

/// Split a message payload into fragments respecting the given MTU.
///
/// Each fragment's wire size (including magic + header + payload) will
/// not exceed `mtu`. Returns one wire-format buffer per fragment.
///
/// # Panics
///
/// Panics if `mtu` is too small to hold even the fragment overhead with
/// zero payload.
#[must_use]
pub fn fragment_message(message_id: u64, payload: &[u8], mtu: usize, type_tag: u8) -> Vec<Vec<u8>> {
    let overhead = fragment_overhead();
    assert!(
        mtu > overhead,
        "MTU {mtu} too small for fragment overhead {overhead}"
    );
    let max_fragment_payload = mtu - overhead;
    let total_fragments = if payload.is_empty() {
        1u32
    } else {
        payload.len().div_ceil(max_fragment_payload) as u32
    };

    assert!(
        total_fragments <= MAX_FRAGMENTS_PER_MESSAGE,
        "message too large: would require {total_fragments} fragments, max {MAX_FRAGMENTS_PER_MESSAGE}"
    );

    let mut fragments = Vec::with_capacity(total_fragments as usize);
    for i in 0..total_fragments {
        let start = i as usize * max_fragment_payload;
        let end = ((i as usize + 1) * max_fragment_payload).min(payload.len());
        let chunk = &payload[start..end];

        let header = FragmentHeader::new(message_id, i, total_fragments, type_tag);
        fragments.push(encode_fragment(&header, chunk));
    }
    fragments
}

// ---------------------------------------------------------------------------
// FragmentReassembler
// ---------------------------------------------------------------------------

/// State for an in-progress reassembly.
#[derive(Clone, Debug)]
struct PendingReassembly {
    /// Total number of fragments expected.
    total_fragments: u32,
    /// Per-fragment data: None for fragments not yet received.
    fragments: Vec<Option<Vec<u8>>>,
    /// Count of fragments received so far.
    received_count: u32,
    /// Total payload size (sum of all received fragment payload lengths).
    total_payload_size: usize,
    /// Type tag from the first fragment (preserved for caller inspection).
    #[allow(dead_code)]
    type_tag: u8,
    /// When the first fragment was received (for timeout).
    started_at: Instant,
}

impl PendingReassembly {
    fn new(total_fragments: u32, type_tag: u8) -> Self {
        Self {
            total_fragments,
            fragments: vec![None; total_fragments as usize],
            received_count: 0,
            total_payload_size: 0,
            type_tag,
            started_at: Instant::now(),
        }
    }

    /// Insert a fragment. Returns true if this completes the reassembly.
    fn insert(
        &mut self,
        index: u32,
        data: Vec<u8>,
        message_id: u64,
    ) -> Result<bool, FragmentError> {
        if index >= self.total_fragments {
            return Err(FragmentError::FragmentIndexOutOfRange {
                index,
                total_fragments: self.total_fragments,
            });
        }
        let idx = index as usize;
        if self.fragments[idx].is_some() {
            return Err(FragmentError::DuplicateFragment {
                message_id,
                fragment_index: index,
            });
        }
        self.total_payload_size += data.len();
        self.fragments[idx] = Some(data);
        self.received_count += 1;
        Ok(self.received_count == self.total_fragments)
    }

    /// Reassemble all fragments into the final payload in order.
    fn reassemble(self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(self.total_payload_size);
        for data in self.fragments.into_iter().flatten() {
            payload.extend_from_slice(&data);
        }
        payload
    }
}

/// Reassembles fragmented messages from incoming fragment data.
///
/// Thread-safe: all methods take `&mut self`. The caller must wrap in
/// `Arc<Mutex<>>` if shared across threads.
#[derive(Clone, Debug)]
pub struct FragmentReassembler {
    /// Pending reassemblies keyed by message_id.
    pending: BTreeMap<u64, PendingReassembly>,
    /// Timeout for incomplete reassemblies.
    timeout: Duration,
    /// Next message_id counter for outbound fragmentation.
    next_message_id: u64,
}

impl FragmentReassembler {
    /// Create a new FragmentReassembler with the given timeout.
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        Self {
            pending: BTreeMap::new(),
            timeout,
            next_message_id: 0,
        }
    }

    /// Allocate and return the next message_id for outbound messages.
    pub fn next_message_id(&mut self) -> u64 {
        let id = self.next_message_id;
        self.next_message_id = self.next_message_id.wrapping_add(1);
        id
    }

    /// Feed a received fragment into the reassembler.
    ///
    /// Returns `Ok(Some(payload))` when reassembly is complete and the
    /// full message payload is ready for dispatch. Returns `Ok(None)` when
    /// the fragment was accepted but more are needed.
    ///
    /// # Errors
    ///
    /// Returns `FragmentError` for out-of-range, duplicate, or malformed fragments.
    pub fn feed(
        &mut self,
        header: &FragmentHeader,
        payload: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, FragmentError> {
        let entry = self
            .pending
            .entry(header.message_id)
            .or_insert_with(|| PendingReassembly::new(header.total_fragments, header.type_tag));

        // Sanity: total_fragments must be consistent
        if entry.total_fragments != header.total_fragments {
            return Err(FragmentError::InconsistentTotalFragments {
                message_id: header.message_id,
                expected: entry.total_fragments,
                got: header.total_fragments,
            });
        }

        let complete = entry.insert(header.fragment_index, payload, header.message_id)?;
        if complete {
            let pending = self
                .pending
                .remove(&header.message_id)
                .expect("just inserted");
            Ok(Some(pending.reassemble()))
        } else {
            Ok(None)
        }
    }

    /// Evict expired incomplete reassemblies. Returns the number evicted.
    pub fn evict_expired(&mut self) -> usize {
        let now = Instant::now();
        let expired: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, p)| now.duration_since(p.started_at) > self.timeout)
            .map(|(id, _)| *id)
            .collect();
        let count = expired.len();
        for id in &expired {
            self.pending.remove(id);
        }
        count
    }

    /// Number of in-progress reassemblies.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Whether a reassembly is in progress for the given message_id.
    #[must_use]
    pub fn has_pending(&self, message_id: u64) -> bool {
        self.pending.contains_key(&message_id)
    }

    /// Cancel and remove a pending reassembly, returning the fragments
    /// received so far (or None if not found).
    pub fn cancel(&mut self, message_id: u64) -> Option<Vec<Vec<u8>>> {
        self.pending
            .remove(&message_id)
            .map(|p| p.fragments.into_iter().flatten().collect())
    }
}

impl Default for FragmentReassembler {
    fn default() -> Self {
        Self::new(Duration::from_millis(DEFAULT_REASSEMBLY_TIMEOUT_MS))
    }
}

// ---------------------------------------------------------------------------
// FragmentError
// ---------------------------------------------------------------------------

/// Errors from fragment decode and reassembly.
#[derive(Debug, Clone, thiserror::Error)]
pub enum FragmentError {
    #[error("fragment too short: got {got}, min {min}")]
    TooShort { got: usize, min: usize },

    #[error("bad fragment magic: got {got:02x?}")]
    BadMagic { got: [u8; 4] },

    #[error("fragment decode error: {0}")]
    Decode(String),

    #[error("fragment index {index} out of range (0..{total_fragments})")]
    FragmentIndexOutOfRange { index: u32, total_fragments: u32 },

    #[error(
        "inconsistent total_fragments for message {message_id}: expected {expected}, got {got}"
    )]
    InconsistentTotalFragments {
        message_id: u64,
        expected: u32,
        got: u32,
    },

    #[error("duplicate fragment {fragment_index} for message {message_id}")]
    DuplicateFragment {
        message_id: u64,
        fragment_index: u32,
    },

    #[error("fragment reassembly timeout for message {message_id}")]
    Timeout { message_id: u64 },

    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── FragmentHeader round-trip ──────────────────────────────────────

    #[test]
    fn fragment_header_roundtrip_bincode() {
        let h = FragmentHeader::new(42, 3, 10, 7);
        let encoded = h.encode().expect("encode");
        let decoded = FragmentHeader::decode(&encoded).expect("decode");
        assert_eq!(decoded, h);
    }

    #[test]
    fn fragment_header_first_last() {
        let h = FragmentHeader::new(0, 0, 5, 0);
        assert!(h.is_first());
        assert!(!h.is_last());

        let h = FragmentHeader::new(0, 4, 5, 0);
        assert!(!h.is_first());
        assert!(h.is_last());

        let h = FragmentHeader::new(0, 0, 1, 0);
        assert!(h.is_first());
        assert!(h.is_last());
    }

    #[test]
    fn fragment_header_max_values() {
        let h = FragmentHeader::new(u64::MAX, u32::MAX, u32::MAX, u8::MAX);
        let encoded = h.encode().expect("encode");
        let decoded = FragmentHeader::decode(&encoded).expect("decode");
        assert_eq!(decoded, h);
    }

    // ── encode_fragment / decode_fragment round-trip ───────────────────

    #[test]
    fn encode_decode_fragment_roundtrip() {
        let header = FragmentHeader::new(1, 0, 1, 0);
        let payload = b"hello fragment";
        let wire = encode_fragment(&header, payload);
        assert!(is_fragment(&wire));

        let (decoded_header, decoded_payload) = decode_fragment(&wire).expect("decode");
        assert_eq!(decoded_header, header);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn encode_decode_fragment_empty_payload() {
        let header = FragmentHeader::new(99, 2, 3, 1);
        let wire = encode_fragment(&header, &[]);
        let (decoded_header, decoded_payload) = decode_fragment(&wire).expect("decode");
        assert_eq!(decoded_header, header);
        assert!(decoded_payload.is_empty());
    }

    #[test]
    fn is_fragment_detects_magic() {
        let header = FragmentHeader::new(0, 0, 1, 0);
        let wire = encode_fragment(&header, b"x");
        assert!(is_fragment(&wire));

        let not_fragment = b"just a regular message";
        assert!(!is_fragment(not_fragment));
    }

    #[test]
    fn is_fragment_short_buffer() {
        assert!(!is_fragment(b"VF"));
        assert!(!is_fragment(&[]));
    }

    #[test]
    fn decode_fragment_bad_magic() {
        let result = decode_fragment(b"BOGUS_DATA_HERE");
        assert!(matches!(result, Err(FragmentError::BadMagic { .. })));
    }

    #[test]
    fn decode_fragment_too_short() {
        let result = decode_fragment(b"VFR");
        assert!(matches!(result, Err(FragmentError::TooShort { .. })));
    }

    // ── fragment_message ───────────────────────────────────────────────

    #[test]
    fn fragment_message_single_fragment_below_mtu() {
        let payload = b"small payload";
        let mtu = 1024;
        let fragments = fragment_message(0, payload, mtu, 0);
        assert_eq!(fragments.len(), 1);

        let (header, frag_payload) = decode_fragment(&fragments[0]).expect("decode");
        assert_eq!(header.message_id, 0);
        assert_eq!(header.fragment_index, 0);
        assert_eq!(header.total_fragments, 1);
        assert_eq!(header.type_tag, 0);
        assert_eq!(frag_payload, payload);
    }

    #[test]
    fn fragment_message_empty_payload() {
        let fragments = fragment_message(0, &[], 1024, 0);
        assert_eq!(fragments.len(), 1);

        let (header, frag_payload) = decode_fragment(&fragments[0]).expect("decode");
        assert_eq!(header.total_fragments, 1);
        assert!(frag_payload.is_empty());
    }

    #[test]
    fn fragment_message_multi_fragment() {
        let payload = vec![0xABu8; 3000];
        let mtu = 1024;
        let fragments = fragment_message(42, &payload, mtu, 5);

        assert!(fragments.len() > 1);
        assert!(fragments.len() <= 5, "should fit in a few 1K fragments");

        let total_fragments = fragments.len() as u32;

        let mut reassembled = Vec::new();
        for (i, wire) in fragments.iter().enumerate() {
            assert!(is_fragment(wire));
            let (header, frag_payload) = decode_fragment(wire).expect("decode");
            assert_eq!(header.message_id, 42);
            assert_eq!(header.fragment_index, i as u32);
            assert_eq!(header.total_fragments, total_fragments);
            assert_eq!(header.type_tag, 5);
            assert!(
                wire.len() <= mtu,
                "fragment wire size {} exceeds MTU {mtu}",
                wire.len()
            );
            reassembled.extend_from_slice(&frag_payload);
        }

        assert_eq!(reassembled, payload);
    }

    #[test]
    fn fragment_message_exact_mtu_boundary() {
        let overhead = fragment_overhead();
        let mtu = 512;
        let max_payload = mtu - overhead;
        // Exactly one fragment's worth
        let payload = vec![0xCDu8; max_payload];
        let fragments = fragment_message(0, &payload, mtu, 0);
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].len(), mtu);
    }

    #[test]
    fn fragment_message_one_byte_over_mtu() {
        let overhead = fragment_overhead();
        let mtu = 512;
        let max_payload = mtu - overhead;
        // One byte more than one fragment can hold
        let payload = vec![0xEFu8; max_payload + 1];
        let fragments = fragment_message(0, &payload, mtu, 0);
        assert_eq!(fragments.len(), 2);
        assert!(fragments[0].len() <= mtu);
        assert!(fragments[1].len() <= mtu);
    }

    #[test]
    #[should_panic(expected = "MTU")]
    fn fragment_message_mtu_too_small() {
        let overhead = fragment_overhead();
        let _ = fragment_message(0, b"data", overhead, 0); // should panic
    }

    // ── FragmentReassembler: in-order ──────────────────────────────────

    #[test]
    fn reassembler_in_order() {
        let mut reassembler = FragmentReassembler::default();
        let payload = b"multi fragment test payload that is long enough to split";
        let mtu = 64;
        let fragments = fragment_message(0, payload, mtu, 1);

        let mut result = None;
        for wire in &fragments {
            let (header, frag_payload) = decode_fragment(wire).expect("decode");
            let maybe = reassembler.feed(&header, frag_payload).expect("feed");
            if maybe.is_some() {
                result = maybe;
            }
        }

        let reassembled = result.expect("should have completed");
        assert_eq!(reassembled, payload);
        assert_eq!(reassembler.pending_count(), 0);
    }

    // ── FragmentReassembler: out-of-order ──────────────────────────────

    #[test]
    fn reassembler_out_of_order() {
        let mut reassembler = FragmentReassembler::default();
        let payload = b"0123456789ABCDEF0123456789ABCDEF";
        let mtu = 48;
        let fragments = fragment_message(0, payload, mtu, 2);

        assert!(fragments.len() >= 2, "need at least 2 fragments");

        // Feed in reverse order
        let mut result = None;
        for wire in fragments.iter().rev() {
            let (header, frag_payload) = decode_fragment(wire).expect("decode");
            let maybe = reassembler.feed(&header, frag_payload).expect("feed");
            if maybe.is_some() {
                result = maybe;
            }
        }

        let reassembled = result.expect("should have completed");
        assert_eq!(reassembled, payload);
    }

    // ── FragmentReassembler: duplicate rejection ───────────────────────

    #[test]
    fn reassembler_rejects_duplicate() {
        let mut reassembler = FragmentReassembler::default();
        let payload = b"test duplicate fragment handling with a longer payload that requires at least two fragments to be split across the MTU boundary";
        let mtu = 64;
        let fragments = fragment_message(0, payload, mtu, 0);

        // Feed first fragment twice
        let (header, frag_payload) = decode_fragment(&fragments[0]).expect("decode");
        reassembler
            .feed(&header, frag_payload.clone())
            .expect("first feed");

        let result = reassembler.feed(&header, frag_payload);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FragmentError::DuplicateFragment { .. }
        ));
    }

    // ── FragmentReassembler: wrong index rejection ─────────────────────

    #[test]
    fn reassembler_rejects_out_of_range_index() {
        let mut reassembler = FragmentReassembler::default();
        let header = FragmentHeader::new(0, 999, 5, 0);
        let result = reassembler.feed(&header, b"bad".to_vec());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FragmentError::FragmentIndexOutOfRange { .. }
        ));
    }

    // ── FragmentReassembler: inconsistent total_fragments ──────────────

    #[test]
    fn reassembler_rejects_inconsistent_total() {
        let mut reassembler = FragmentReassembler::default();

        let h1 = FragmentHeader::new(0, 0, 5, 0);
        reassembler.feed(&h1, b"first".to_vec()).expect("first");

        let h2 = FragmentHeader::new(0, 1, 3, 0); // inconsistent total
        let result = reassembler.feed(&h2, b"second".to_vec());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FragmentError::InconsistentTotalFragments { .. }
        ));
    }

    // ── FragmentReassembler: timeout eviction ──────────────────────────

    #[test]
    fn reassembler_evicts_expired() {
        let mut reassembler = FragmentReassembler::new(Duration::from_millis(1));
        let header = FragmentHeader::new(0, 0, 3, 0);
        reassembler
            .feed(&header, b"partial".to_vec())
            .expect("feed");
        assert_eq!(reassembler.pending_count(), 1);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(10));

        let evicted = reassembler.evict_expired();
        assert_eq!(evicted, 1);
        assert_eq!(reassembler.pending_count(), 0);
    }

    // ── FragmentReassembler: cancel ────────────────────────────────────

    #[test]
    fn reassembler_cancel() {
        let mut reassembler = FragmentReassembler::default();
        let header = FragmentHeader::new(42, 0, 2, 0);
        reassembler.feed(&header, b"part 1".to_vec()).expect("feed");
        assert!(reassembler.has_pending(42));

        let cancelled = reassembler.cancel(42);
        assert!(cancelled.is_some());
        assert_eq!(cancelled.unwrap().len(), 1);
        assert!(!reassembler.has_pending(42));
        assert_eq!(reassembler.pending_count(), 0);
    }

    // ── FragmentReassembler: next_message_id ───────────────────────────

    #[test]
    fn reassembler_message_id_counter() {
        let mut reassembler = FragmentReassembler::default();
        assert_eq!(reassembler.next_message_id(), 0);
        assert_eq!(reassembler.next_message_id(), 1);
        assert_eq!(reassembler.next_message_id(), 2);
    }

    // ── fragment_overhead consistency ──────────────────────────────────

    #[test]
    fn fragment_overhead_matches_actual() {
        let overhead = fragment_overhead();
        let header = FragmentHeader::new(0, 0, 1, 0);
        let wire = encode_fragment(&header, &[]);
        assert_eq!(wire.len(), overhead);
    }

    // ── Large payload round-trip ───────────────────────────────────────

    #[test]
    fn large_payload_roundtrip() {
        let mut reassembler = FragmentReassembler::default();
        let payload = vec![0x55u8; 65536]; // 64 KiB
        let mtu = 1024; // 1 KiB MTU
        let msg_id = 7;
        let fragments = fragment_message(msg_id, &payload, mtu, 3);

        assert!(fragments.len() > 1, "should produce multiple fragments");

        let mut result = None;
        for wire in &fragments {
            assert!(wire.len() <= mtu, "wire length exceeds MTU");
            let (header, frag_payload) = decode_fragment(wire).expect("decode");
            assert_eq!(header.message_id, msg_id);
            assert_eq!(header.type_tag, 3);
            let complete = reassembler.feed(&header, frag_payload).expect("feed");
            if complete.is_some() {
                result = complete;
            }
        }

        let reassembled = result.expect("reassembly should complete");
        assert_eq!(reassembled.len(), payload.len());
        assert_eq!(reassembled, payload);
    }

    // ── Multiple concurrent reassemblies ───────────────────────────────

    #[test]
    fn multiple_concurrent_reassemblies() {
        let mut reassembler = FragmentReassembler::default();
        let mtu = 64;

        let payload_a = vec![0xAAu8; 200];
        let payload_b = vec![0xBBu8; 300];

        let frags_a = fragment_message(1, &payload_a, mtu, 0);
        let frags_b = fragment_message(2, &payload_b, mtu, 1);

        // Interleave fragments from both messages
        let mut results: BTreeMap<u64, Vec<u8>> = BTreeMap::new();

        let max = frags_a.len().max(frags_b.len());
        for i in 0..max {
            if i < frags_a.len() {
                let (h, p) = decode_fragment(&frags_a[i]).expect("decode");
                if let Some(payload) = reassembler.feed(&h, p).expect("feed") {
                    results.insert(h.message_id, payload);
                }
            }
            if i < frags_b.len() {
                let (h, p) = decode_fragment(&frags_b[i]).expect("decode");
                if let Some(payload) = reassembler.feed(&h, p).expect("feed") {
                    results.insert(h.message_id, payload);
                }
            }
        }

        assert_eq!(results.get(&1).unwrap(), &payload_a);
        assert_eq!(results.get(&2).unwrap(), &payload_b);
        assert_eq!(reassembler.pending_count(), 0);
    }
}
