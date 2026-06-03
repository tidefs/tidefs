// Deterministic codec for WitnessSet and WitnessEntry using
// tidefs-binary_schema-core LE wrappers for wire-format identity
// compatible with the quorum-write commit path and replication dispatch.

use crate::types::WitnessEntry;
use crate::witness_set::{QuorumThreshold, WitnessSet};
use tidefs_binary_schema_core::{U32Le, U64Le};

/// Codec error variants.
#[derive(Debug, PartialEq, Eq)]
pub enum CodecError {
    /// Buffer too short for the expected payload.
    BufferUnderrun,
    /// Invalid discriminant for an enum variant.
    InvalidVariant(u8),
}

// ---------------------------------------------------------------------------
// WitnessSetCodec
// ---------------------------------------------------------------------------

/// Deterministic little-endian codec for [`WitnessSet`].
///
/// ```text
/// [threshold_disc: u8] [threshold_param: u8] [epoch: U64Le]
/// [witness_count: U32Le] [witness_ids...: U64Le × count]
/// [op_count: U32Le]
///   [op_id: U64Le] [ack_count: U32Le] [acker_ids: U64Le × count]...
/// ```
pub struct WitnessSetCodec;

impl WitnessSetCodec {
    /// Encode a [`WitnessSet`] into a deterministic LE byte buffer.
    pub fn encode(ws: &WitnessSet, buf: &mut Vec<u8>) {
        // Threshold discriminant + parameter
        match ws.threshold() {
            QuorumThreshold::StrictMajority => {
                buf.push(0);
                buf.push(0);
            }
            QuorumThreshold::SuperMajority => {
                buf.push(1);
                buf.push(0);
            }
            QuorumThreshold::Exact(n) => {
                buf.push(2);
                buf.push(n as u8);
            }
        }

        // Epoch
        buf.extend_from_slice(&U64Le::from(ws.epoch()).encode());

        // Witness membership
        let witnesses: Vec<u64> = ws.iter().collect();
        buf.extend_from_slice(&U32Le::from(witnesses.len() as u32).encode());
        for &id in &witnesses {
            buf.extend_from_slice(&U64Le::from(id).encode());
        }

        // Operations and their ack sets
        let ops: Vec<u64> = ws.operations().collect();
        buf.extend_from_slice(&U32Le::from(ops.len() as u32).encode());
        for op_id in ops {
            buf.extend_from_slice(&U64Le::from(op_id).encode());
            if let Some(ack_set) = ws.ack_set(op_id) {
                buf.extend_from_slice(&U32Le::from(ack_set.len() as u32).encode());
                for &node_id in ack_set {
                    buf.extend_from_slice(&U64Le::from(node_id).encode());
                }
            } else {
                buf.extend_from_slice(&U32Le::from(0u32).encode());
            }
        }
    }

    /// Decode a [`WitnessSet`] from a deterministic LE byte buffer.
    pub fn decode(buf: &[u8]) -> Result<WitnessSet, CodecError> {
        let mut pos: usize = 0;

        if pos + 2 > buf.len() {
            return Err(CodecError::BufferUnderrun);
        }
        let disc = buf[pos];
        let param = buf[pos + 1];
        pos += 2;

        let threshold = match disc {
            0 => QuorumThreshold::StrictMajority,
            1 => QuorumThreshold::SuperMajority,
            2 => QuorumThreshold::Exact(param as usize),
            _ => return Err(CodecError::InvalidVariant(disc)),
        };

        if pos + 8 > buf.len() {
            return Err(CodecError::BufferUnderrun);
        }
        let epoch = u64::from(U64Le::from_le_bytes(buf[pos..pos + 8].try_into().unwrap()));
        pos += 8;

        let mut ws = WitnessSet::with_epoch(threshold, epoch);

        if pos + 4 > buf.len() {
            return Err(CodecError::BufferUnderrun);
        }
        let wc = u32::from(U32Le::from_le_bytes(buf[pos..pos + 4].try_into().unwrap())) as usize;
        pos += 4;
        for _ in 0..wc {
            if pos + 8 > buf.len() {
                return Err(CodecError::BufferUnderrun);
            }
            let id = u64::from(U64Le::from_le_bytes(buf[pos..pos + 8].try_into().unwrap()));
            ws.add_witness(id);
            pos += 8;
        }

        if pos + 4 > buf.len() {
            return Err(CodecError::BufferUnderrun);
        }
        let op_count =
            u32::from(U32Le::from_le_bytes(buf[pos..pos + 4].try_into().unwrap())) as usize;
        pos += 4;
        for _ in 0..op_count {
            if pos + 12 > buf.len() {
                return Err(CodecError::BufferUnderrun);
            }
            let op_id = u64::from(U64Le::from_le_bytes(buf[pos..pos + 8].try_into().unwrap()));
            pos += 8;
            let ack_count =
                u32::from(U32Le::from_le_bytes(buf[pos..pos + 4].try_into().unwrap())) as usize;
            pos += 4;
            for _ in 0..ack_count {
                if pos + 8 > buf.len() {
                    return Err(CodecError::BufferUnderrun);
                }
                let node_id =
                    u64::from(U64Le::from_le_bytes(buf[pos..pos + 8].try_into().unwrap()));
                ws.ack(node_id, op_id);
                pos += 8;
            }
        }

        Ok(ws)
    }

    /// Convenience: encode to a fresh Vec<u8>.
    pub fn encode_to_vec(ws: &WitnessSet) -> Vec<u8> {
        let mut buf = Vec::new();
        Self::encode(ws, &mut buf);
        buf
    }
}

// ---------------------------------------------------------------------------
// WitnessEntryCodec
// ---------------------------------------------------------------------------

/// Deterministic LE codec for [`WitnessEntry`].
///
/// Fixed size: node_id(U64Le) + object_id(U64Le) + txg_id(U64Le) +
/// ack_kind(u8) + timestamp_ns(U64Le) = 33 bytes.
pub struct WitnessEntryCodec;

impl WitnessEntryCodec {
    pub const ENCODED_SIZE: usize = 33;

    pub fn encode(entry: &WitnessEntry, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&U64Le::from(entry.node_id.0).encode());
        buf.extend_from_slice(&U64Le::from(entry.object_id.0).encode());
        buf.extend_from_slice(&U64Le::from(entry.txg_id.0).encode());
        buf.push(match entry.ack_kind {
            crate::types::AckKind::WriteComplete => 0u8,
            crate::types::AckKind::IntentLogged => 1u8,
            crate::types::AckKind::Received => 2u8,
            crate::types::AckKind::Refuted => 3u8,
        });
        buf.extend_from_slice(&U64Le::from(entry.timestamp_ns).encode());
    }

    pub fn decode(buf: &[u8], pos: &mut usize) -> Result<WitnessEntry, CodecError> {
        if *pos + Self::ENCODED_SIZE > buf.len() {
            return Err(CodecError::BufferUnderrun);
        }

        let node_id = crate::types::NodeId(u64::from(U64Le::from_le_bytes(
            buf[*pos..*pos + 8].try_into().unwrap(),
        )));
        *pos += 8;

        let object_id = crate::types::ObjectId(u64::from(U64Le::from_le_bytes(
            buf[*pos..*pos + 8].try_into().unwrap(),
        )));
        *pos += 8;

        let txg_id = crate::types::TxgId(u64::from(U64Le::from_le_bytes(
            buf[*pos..*pos + 8].try_into().unwrap(),
        )));
        *pos += 8;

        let ack_kind = match buf[*pos] {
            0 => crate::types::AckKind::WriteComplete,
            1 => crate::types::AckKind::IntentLogged,
            2 => crate::types::AckKind::Received,
            3 => crate::types::AckKind::Refuted,
            other => return Err(CodecError::InvalidVariant(other)),
        };
        *pos += 1;

        let timestamp_ns = u64::from(U64Le::from_le_bytes(
            buf[*pos..*pos + 8].try_into().unwrap(),
        ));
        *pos += 8;

        Ok(WitnessEntry {
            node_id,
            object_id,
            txg_id,
            ack_kind,
            timestamp_ns,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AckKind, NodeId, ObjectId, TxgId};

    // -- WitnessSet codec ------------------------------------------------

    #[test]
    fn test_witness_set_codec_empty_roundtrip() {
        let ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        let enc = WitnessSetCodec::encode_to_vec(&ws);
        let dec = WitnessSetCodec::decode(&enc).unwrap();
        assert!(dec.is_empty());
        assert_eq!(dec.epoch(), 0);
        assert_eq!(dec.threshold(), QuorumThreshold::StrictMajority);
    }

    #[test]
    fn test_witness_set_codec_with_witnesses() {
        let mut ws = WitnessSet::new(QuorumThreshold::SuperMajority);
        ws.add_witness(10);
        ws.add_witness(20);
        ws.add_witness(30);
        let enc = WitnessSetCodec::encode_to_vec(&ws);
        let dec = WitnessSetCodec::decode(&enc).unwrap();
        assert_eq!(dec.len(), 3);
        assert!(dec.contains(10) && dec.contains(20) && dec.contains(30));
        assert_eq!(dec.threshold(), QuorumThreshold::SuperMajority);
    }

    #[test]
    fn test_witness_set_codec_with_epoch() {
        let ws = WitnessSet::with_epoch(QuorumThreshold::Exact(2), 42);
        let enc = WitnessSetCodec::encode_to_vec(&ws);
        let dec = WitnessSetCodec::decode(&enc).unwrap();
        assert_eq!(dec.epoch(), 42);
        assert_eq!(dec.threshold(), QuorumThreshold::Exact(2));
    }

    #[test]
    fn test_witness_set_codec_all_thresholds() {
        for t in [
            QuorumThreshold::StrictMajority,
            QuorumThreshold::SuperMajority,
            QuorumThreshold::Exact(5),
        ] {
            let ws = WitnessSet::new(t);
            let enc = WitnessSetCodec::encode_to_vec(&ws);
            let dec = WitnessSetCodec::decode(&enc).unwrap();
            assert_eq!(dec.threshold(), t);
        }
    }

    #[test]
    fn test_witness_set_codec_buffer_underrun() {
        assert_eq!(
            WitnessSetCodec::decode(&[0u8; 1]),
            Err(CodecError::BufferUnderrun)
        );
    }

    #[test]
    fn test_witness_set_codec_invalid_variant() {
        let mut buf = vec![99u8, 0u8];
        buf.extend_from_slice(&U64Le::from(0u64).encode());
        buf.extend_from_slice(&U32Le::from(0u32).encode());
        buf.extend_from_slice(&U32Le::from(0u32).encode());
        assert_eq!(
            WitnessSetCodec::decode(&buf),
            Err(CodecError::InvalidVariant(99))
        );
    }

    #[test]
    fn test_witness_set_codec_roundtrip_with_acks() {
        let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        for id in 1..=5u64 {
            ws.add_witness(id);
        }
        ws.ack(1, 100);
        ws.ack(2, 100);
        ws.ack(3, 100);
        ws.ack(4, 200);
        ws.ack(5, 200);

        let enc = WitnessSetCodec::encode_to_vec(&ws);
        let dec = WitnessSetCodec::decode(&enc).unwrap();

        assert_eq!(dec.len(), 5);
        assert_eq!(dec.threshold(), QuorumThreshold::StrictMajority);
        assert_eq!(dec.ack_count(100), 3);
        assert_eq!(dec.ack_count(200), 2);
        assert!(dec.has_quorum(100));
        assert!(!dec.has_quorum(200));
    }

    #[test]
    fn test_witness_set_codec_roundtrip_epoch_and_exact_threshold() {
        let mut ws = WitnessSet::with_epoch(QuorumThreshold::Exact(2), 42);
        ws.add_witness(10);
        ws.add_witness(20);
        ws.add_witness(30);
        ws.ack(10, 1);
        ws.ack(20, 1);

        let enc = WitnessSetCodec::encode_to_vec(&ws);
        let dec = WitnessSetCodec::decode(&enc).unwrap();

        assert_eq!(dec.epoch(), 42);
        assert_eq!(dec.threshold(), QuorumThreshold::Exact(2));
        assert!(dec.has_quorum(1));
    }

    #[test]
    fn test_witness_set_codec_roundtrip_empty_operations() {
        let mut ws = WitnessSet::new(QuorumThreshold::SuperMajority);
        ws.add_witness(5);
        ws.add_witness(6);
        assert_eq!(ws.operation_count(), 0);

        let enc = WitnessSetCodec::encode_to_vec(&ws);
        let dec = WitnessSetCodec::decode(&enc).unwrap();

        assert_eq!(dec.len(), 2);
        assert_eq!(dec.operation_count(), 0);
    }

    #[test]
    fn test_witness_set_codec_roundtrip_operations_preserved() {
        let mut ws = WitnessSet::new(QuorumThreshold::StrictMajority);
        for id in 1..=7u64 {
            ws.add_witness(id);
        }
        ws.ack(1, 10);
        ws.ack(2, 10);
        ws.ack(3, 10);
        ws.ack(4, 10);
        ws.ack(5, 20);
        ws.ack(6, 20);
        ws.ack(7, 30);

        let enc = WitnessSetCodec::encode_to_vec(&ws);
        let dec = WitnessSetCodec::decode(&enc).unwrap();

        assert_eq!(dec.len(), 7);
        assert_eq!(dec.operation_count(), 3);
        assert!(dec.has_quorum(10));
        assert!(!dec.has_quorum(20));
        assert!(!dec.has_quorum(30));
    }

    // -- WitnessEntry codec -----------------------------------------------

    #[test]
    fn test_entry_codec_roundtrip() {
        let e = WitnessEntry {
            node_id: NodeId(1),
            object_id: ObjectId(100),
            txg_id: TxgId(5),
            ack_kind: AckKind::WriteComplete,
            timestamp_ns: 123456789,
        };
        let mut buf = Vec::new();
        WitnessEntryCodec::encode(&e, &mut buf);
        assert_eq!(buf.len(), WitnessEntryCodec::ENCODED_SIZE);

        let mut pos = 0;
        let dec = WitnessEntryCodec::decode(&buf, &mut pos).unwrap();
        assert_eq!(dec, e);
        assert_eq!(pos, WitnessEntryCodec::ENCODED_SIZE);
    }

    #[test]
    fn test_entry_codec_all_ack_kinds() {
        for kind in [
            AckKind::WriteComplete,
            AckKind::IntentLogged,
            AckKind::Received,
            AckKind::Refuted,
        ] {
            let e = WitnessEntry {
                node_id: NodeId(7),
                object_id: ObjectId(77),
                txg_id: TxgId(777),
                ack_kind: kind,
                timestamp_ns: 0,
            };
            let mut buf = Vec::new();
            WitnessEntryCodec::encode(&e, &mut buf);
            let mut pos = 0;
            let dec = WitnessEntryCodec::decode(&buf, &mut pos).unwrap();
            assert_eq!(dec.ack_kind, kind);
        }
    }

    #[test]
    fn test_entry_codec_underrun() {
        assert_eq!(
            WitnessEntryCodec::decode(&[0u8; 10], &mut 0),
            Err(CodecError::BufferUnderrun)
        );
    }

    #[test]
    fn test_entry_codec_invalid_variant() {
        let mut buf = vec![0u8; WitnessEntryCodec::ENCODED_SIZE];
        buf[24] = 99;
        assert_eq!(
            WitnessEntryCodec::decode(&buf, &mut 0),
            Err(CodecError::InvalidVariant(99))
        );
    }

    #[test]
    fn test_entry_codec_multiple_entries() {
        let entries = vec![
            WitnessEntry {
                node_id: NodeId(1),
                object_id: ObjectId(10),
                txg_id: TxgId(100),
                ack_kind: AckKind::WriteComplete,
                timestamp_ns: 1000,
            },
            WitnessEntry {
                node_id: NodeId(2),
                object_id: ObjectId(20),
                txg_id: TxgId(200),
                ack_kind: AckKind::IntentLogged,
                timestamp_ns: 2000,
            },
        ];
        let mut buf = Vec::new();
        for e in &entries {
            WitnessEntryCodec::encode(e, &mut buf);
        }
        let mut pos = 0;
        let mut decs = Vec::new();
        while pos < buf.len() {
            decs.push(WitnessEntryCodec::decode(&buf, &mut pos).unwrap());
        }
        assert_eq!(decs, entries);
    }
}
