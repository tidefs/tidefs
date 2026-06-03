use tidefs_frame::CompressionAlgorithm;

/// Outcome of a threshold-aware compression attempt.
///
/// When `compress_with_threshold` determines that compression doesn't
/// save enough space (relative to the configured threshold), it returns
/// `Unchanged` so the caller can store the original payload without
/// the framing overhead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompressionDecision {
    /// Compression succeeded and met the size threshold.
    /// The framed bytes include the 5-byte header.
    Compressed {
        algorithm: CompressionAlgorithm,
        framed: Vec<u8>,
    },
    /// Compression did not meet the threshold; the caller
    /// should store `original` as-is (uncompressed).
    Unchanged { original: Vec<u8> },
}

impl CompressionDecision {
    /// True when the decision is `Compressed`.
    pub fn is_compressed(&self) -> bool {
        matches!(self, Self::Compressed { .. })
    }

    /// The byte length of the stored payload.
    pub fn stored_len(&self) -> usize {
        match self {
            Self::Compressed { framed, .. } => framed.len(),
            Self::Unchanged { original } => original.len(),
        }
    }

    /// The algorithm byte that should appear in the frame header.
    pub fn algorithm_byte(&self) -> u8 {
        match self {
            Self::Compressed { algorithm, .. } => *algorithm as u8,
            Self::Unchanged { .. } => CompressionAlgorithm::Uncompressed as u8,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressed_decision_is_compressed() {
        let d = CompressionDecision::Compressed {
            algorithm: CompressionAlgorithm::Lz4,
            framed: vec![0x02, 0x05, 0x00, 0x00, 0x00, b'h', b'e', b'l', b'l', b'o'],
        };
        assert!(d.is_compressed());
        assert_eq!(d.stored_len(), 10);
        assert_eq!(d.algorithm_byte(), 0x02);
    }

    #[test]
    fn unchanged_decision_not_compressed() {
        let d = CompressionDecision::Unchanged {
            original: b"hello".to_vec(),
        };
        assert!(!d.is_compressed());
        assert_eq!(d.stored_len(), 5);
        assert_eq!(d.algorithm_byte(), 0x00);
    }

    #[test]
    fn stored_len_reflects_framing_overhead() {
        let _payload = [0x41u8; 100];
        let compressed = vec![0x42u8; 20];
        let mut framed = Vec::with_capacity(5 + 20);
        framed.push(0x01); // zstd
        framed.extend_from_slice(&100u32.to_le_bytes());
        framed.extend_from_slice(&compressed);

        let d = CompressionDecision::Compressed {
            algorithm: CompressionAlgorithm::Zstd,
            framed: framed.clone(),
        };
        assert_eq!(d.stored_len(), framed.len());
        assert_eq!(d.stored_len(), 5 + 20);
    }
}
