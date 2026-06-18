// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Object-level chunk framer that reads objects from
//! [`tidefs_local_object_store::ObjectStore`], splits them into fixed-size
//! chunks with monotonic sequence numbers, computes BLAKE3-256 per-chunk
//! hashes, and yields framed [`ChunkPacket`] structs for transport.
//!
//! # Example
//!
//! ```ignore
//! use tidefs_send_stream::object_chunk_framer::{ObjectChunkFramer, ChunkPacket};
//! use tidefs_local_object_store::ObjectStore;
//!
//! let framer = ObjectChunkFramer::new(65536);
//! let packets = framer.frame_object(&store, object_key)?;
//! for pkt in &packets {
//!     assert_eq!(pkt.blake3_hash, blake3::hash(&pkt.payload).into());
//! }
//! ```

use std::fmt;

use tidefs_local_object_store::{ObjectKey, ObjectStore};

/// A single framed chunk packet ready for transport dispatch.
///
/// Each packet carries the object identity, byte range, sequence number,
/// payload, and a BLAKE3-256 hash for end-to-end integrity verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkPacket {
    /// Stable 256-bit object identifier.
    pub object_id: [u8; 32],
    /// Zero-based chunk sequence number within the object.
    pub chunk_seq: u32,
    /// Total number of chunks the object will be split into.
    pub total_chunks: u32,
    /// Byte offset of this chunk within the object.
    pub offset: u64,
    /// Raw payload bytes for this chunk.
    pub payload: Vec<u8>,
    /// BLAKE3-256 hash of the payload for integrity verification.
    pub blake3_hash: [u8; 32],
    /// True when this is the final chunk of the object.
    pub is_last: bool,
}

impl ChunkPacket {
    /// Verify that the stored BLAKE3 hash matches the current payload.
    #[must_use]
    pub fn verify(&self) -> bool {
        let computed: [u8; 32] = blake3::hash(&self.payload).into();
        computed == self.blake3_hash
    }

    /// Compute a new BLAKE3-256 hash for the stored payload.
    fn compute_hash(payload: &[u8]) -> [u8; 32] {
        blake3::hash(payload).into()
    }
}

/// Error returned by [`ObjectChunkFramer::frame_object`].
#[derive(Clone, Debug, PartialEq)]
pub enum FrameError {
    /// The requested object was not found in the store.
    NotFound([u8; 32]),
    /// A store-level error occurred during read.
    StoreError(String),
    /// Chunk size is zero (must be at least 1).
    ZeroChunkSize,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(id) => write!(f, "object {} not found in store", hex32(id)),
            Self::StoreError(msg) => write!(f, "store error: {msg}"),
            Self::ZeroChunkSize => write!(f, "chunk size must be at least 1"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Splits objects read from an [`ObjectStore`] into fixed-size chunks
/// with BLAKE3-256 per-chunk hashes and monotonic sequence numbers.
///
/// Created with [`ObjectChunkFramer::new`]. Call
/// [`frame_object`](Self::frame_object) for each object to produce
/// a `Vec` of [`ChunkPacket`]s.
///
/// # Chunk size
///
/// The chunk size is clamped to a minimum of 1 byte. The default is
/// 65536 bytes (64 KiB). An empty object produces a single packet
/// with an empty payload so the receiver sees the object boundary.
#[derive(Clone, Debug)]
pub struct ObjectChunkFramer {
    chunk_size: usize,
}

impl ObjectChunkFramer {
    /// Create a new framer with the given maximum chunk size in bytes.
    ///
    /// The chunk size is clamped to a minimum of 1.
    pub fn new(chunk_size: usize) -> Self {
        Self {
            chunk_size: chunk_size.max(1),
        }
    }

    /// Returns the configured chunk size.
    #[must_use]
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Read an object from `store` by key, split it into chunks, and
    /// return framed [`ChunkPacket`]s with BLAKE3-256 per-chunk hashes.
    ///
    /// An empty object produces one packet with an empty payload.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::NotFound`] when the key is not live, or
    /// [`FrameError::StoreError`] on underlying store failures.
    pub fn frame_object<S: ObjectStore>(
        &self,
        store: &S,
        key: ObjectKey,
    ) -> Result<Vec<ChunkPacket>, FrameError> {
        let data = store
            .get(key)
            .map_err(|e| FrameError::StoreError(format!("{e:?}")))?
            .ok_or(FrameError::NotFound(*key.as_bytes()))?;

        Ok(self.frame_data(*key.as_bytes(), &data))
    }

    /// Split raw object data into chunk packets without a store lookup.
    ///
    /// Useful when the caller already has the data in memory, or for
    /// testing without a real store.
    pub fn frame_data(&self, object_id: [u8; 32], data: &[u8]) -> Vec<ChunkPacket> {
        let chunk_size = self.chunk_size;
        if data.is_empty() {
            let blake3_hash = ChunkPacket::compute_hash(&[]);
            return vec![ChunkPacket {
                object_id,
                chunk_seq: 0,
                total_chunks: 1,
                offset: 0,
                payload: Vec::new(),
                blake3_hash,
                is_last: true,
            }];
        }

        let total_chunks = data.len().div_ceil(chunk_size) as u32;
        let mut packets = Vec::with_capacity(total_chunks as usize);

        for (i, chunk_bytes) in data.chunks(chunk_size).enumerate() {
            let is_last = i + 1 == total_chunks as usize;
            let blake3_hash = ChunkPacket::compute_hash(chunk_bytes);
            packets.push(ChunkPacket {
                object_id,
                chunk_seq: i as u32,
                total_chunks,
                offset: (i * chunk_size) as u64,
                payload: chunk_bytes.to_vec(),
                blake3_hash,
                is_last,
            });
        }

        packets
    }

    /// Compute the number of chunks an object of `data_len` bytes will
    /// produce without actually framing.
    pub fn chunk_count(&self, data_len: usize) -> usize {
        if data_len == 0 {
            1
        } else {
            data_len.div_ceil(self.chunk_size)
        }
    }
}

impl Default for ObjectChunkFramer {
    fn default() -> Self {
        Self::new(65536)
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn obj_id(b: u8) -> [u8; 32] {
        [b; 32]
    }

    // -- ChunkPacket --

    #[test]
    fn chunk_packet_verify_passes() {
        let payload = b"verify me".to_vec();
        let hash = ChunkPacket::compute_hash(&payload);
        let pkt = ChunkPacket {
            object_id: obj_id(1),
            chunk_seq: 0,
            total_chunks: 1,
            offset: 0,
            payload,
            blake3_hash: hash,
            is_last: true,
        };
        assert!(pkt.verify());
    }

    #[test]
    fn chunk_packet_verify_fails_on_corruption() {
        let payload = b"original".to_vec();
        let hash = ChunkPacket::compute_hash(&payload);
        let mut pkt = ChunkPacket {
            object_id: obj_id(1),
            chunk_seq: 0,
            total_chunks: 1,
            offset: 0,
            payload,
            blake3_hash: hash,
            is_last: true,
        };
        pkt.payload[0] ^= 0xFF;
        assert!(!pkt.verify());
    }

    #[test]
    fn chunk_packet_blake3_is_deterministic() {
        let data = b"deterministic data";
        let h1 = ChunkPacket::compute_hash(data);
        let h2 = ChunkPacket::compute_hash(data);
        assert_eq!(h1, h2);
    }

    // -- ObjectChunkFramer::frame_data --

    #[test]
    fn frame_data_single_chunk_smaller_than_chunk_size() {
        let framer = ObjectChunkFramer::new(1024);
        let data = b"hello";
        let packets = framer.frame_data(obj_id(1), data);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].chunk_seq, 0);
        assert_eq!(packets[0].total_chunks, 1);
        assert_eq!(packets[0].offset, 0);
        assert_eq!(packets[0].payload, data);
        assert!(packets[0].is_last);
        assert!(packets[0].verify());
    }

    #[test]
    fn frame_data_multi_chunk_splitting() {
        let framer = ObjectChunkFramer::new(4);
        let data = b"0123456789"; // 10 bytes -> 3 chunks (4+4+2)
        let packets = framer.frame_data(obj_id(2), data);
        assert_eq!(packets.len(), 3);

        assert_eq!(packets[0].chunk_seq, 0);
        assert_eq!(packets[0].offset, 0);
        assert_eq!(packets[0].payload, b"0123");
        assert!(!packets[0].is_last);

        assert_eq!(packets[1].chunk_seq, 1);
        assert_eq!(packets[1].offset, 4);
        assert_eq!(packets[1].payload, b"4567");
        assert!(!packets[1].is_last);

        assert_eq!(packets[2].chunk_seq, 2);
        assert_eq!(packets[2].offset, 8);
        assert_eq!(packets[2].payload, b"89");
        assert!(packets[2].is_last);

        for pkt in &packets {
            assert!(pkt.verify());
            assert_eq!(pkt.object_id, obj_id(2));
            assert_eq!(pkt.total_chunks, 3);
        }

        // Reassembly
        let mut reassembled = Vec::new();
        for pkt in &packets {
            reassembled.extend_from_slice(&pkt.payload);
        }
        assert_eq!(reassembled, data);
    }

    #[test]
    fn frame_data_exact_chunk_size_boundary() {
        let framer = ObjectChunkFramer::new(4);
        let data = b"ABCD";
        let packets = framer.frame_data(obj_id(3), data);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].payload, data);
        assert!(packets[0].is_last);
    }

    #[test]
    fn frame_data_empty_object() {
        let framer = ObjectChunkFramer::new(256);
        let packets = framer.frame_data(obj_id(4), &[]);
        assert_eq!(packets.len(), 1, "empty object produces one empty packet");
        assert_eq!(packets[0].payload.len(), 0);
        assert!(packets[0].is_last);
        assert!(packets[0].verify());
    }

    #[test]
    fn frame_data_sequence_numbers_monotonic() {
        let framer = ObjectChunkFramer::new(1);
        let data = vec![0xAAu8; 5];
        let packets = framer.frame_data(obj_id(5), &data);
        assert_eq!(packets.len(), 5);
        for (i, pkt) in packets.iter().enumerate() {
            assert_eq!(pkt.chunk_seq, i as u32);
            assert_eq!(pkt.offset, i as u64);
            assert_eq!(pkt.payload.len(), 1);
            assert_eq!(pkt.total_chunks, 5);
        }
        assert!(packets.last().unwrap().is_last);
    }

    #[test]
    fn frame_data_large_object_many_chunks() {
        let framer = ObjectChunkFramer::new(512);
        let data = vec![0x42u8; 10000];
        let packets = framer.frame_data(obj_id(6), &data);
        let expected = 10000usize.div_ceil(512);
        assert_eq!(packets.len(), expected);
        for pkt in &packets {
            assert!(pkt.verify());
            assert_eq!(pkt.object_id, obj_id(6));
        }
        assert!(packets.last().unwrap().is_last);
        assert_eq!(packets.first().unwrap().chunk_seq, 0);
        assert_eq!(packets.last().unwrap().chunk_seq as usize, expected - 1);
    }

    #[test]
    fn frame_data_different_objects_same_payload_same_hash() {
        let framer = ObjectChunkFramer::new(256);
        let data = b"same data";
        let p1 = &framer.frame_data(obj_id(0x10), data)[0];
        let p2 = &framer.frame_data(obj_id(0x20), data)[0];
        assert_eq!(p1.blake3_hash, p2.blake3_hash, "same payload -> same hash");
        assert_ne!(p1.object_id, p2.object_id, "different objects");
    }

    // -- ObjectChunkFramer::chunk_count --

    #[test]
    fn chunk_count() {
        let framer = ObjectChunkFramer::new(100);
        assert_eq!(framer.chunk_count(0), 1);
        assert_eq!(framer.chunk_count(1), 1);
        assert_eq!(framer.chunk_count(100), 1);
        assert_eq!(framer.chunk_count(101), 2);
        assert_eq!(framer.chunk_count(250), 3);
    }

    // -- ObjectChunkFramer defaults --

    #[test]
    fn default_framer_uses_64kib() {
        let framer = ObjectChunkFramer::default();
        assert_eq!(framer.chunk_size(), 65536);
    }

    // -- FrameError --

    #[test]
    fn frame_error_display() {
        let e = FrameError::NotFound([0xAB; 32]);
        let s = format!("{e}");
        assert!(s.contains("not found"));

        let e = FrameError::StoreError("disk full".into());
        let s = format!("{e}");
        assert!(s.contains("disk full"));

        let e = FrameError::ZeroChunkSize;
        let s = format!("{e}");
        assert!(s.contains("chunk size"));
    }
}
