// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_main]

use libfuzzer_sys::fuzz_target;
use tidefs_send_stream::encoder::{ChunkDecoder, ChunkEncoder, ChunkEncoderConfig, ChunkFrame};
use tidefs_send_stream::{
    decode_stream, DeltaObject, ObjectKind, SendBuilder, SendStreamHeader, SnapshotDelta,
};

const MAX_PAYLOAD: usize = 4096;
const MAX_NOISE: usize = 64;
const MAX_STREAM_PAYLOAD: usize = 512;

fn bytes32(data: &[u8], fill: u8) -> [u8; 32] {
    let mut out = [fill; 32];
    let n = data.len().min(out.len());
    out[..n].copy_from_slice(&data[..n]);
    out
}

fn id128(data: &[u8], fill: u8) -> [u8; 16] {
    let mut out = [fill; 16];
    let n = data.len().min(out.len());
    out[..n].copy_from_slice(&data[..n]);
    out
}

fuzz_target!(|data: &[u8]| {
    let _ = ChunkFrame::decode(data);
    let (decoded_frames, consumed) = ChunkDecoder::decode_all(data);
    assert!(consumed <= data.len());
    for frame in decoded_frames {
        assert!(frame.verify());
        let encoded = frame.encode();
        assert!(ChunkFrame::decode(&encoded).is_some());
    }

    let payload_offset = data.len().min(32);
    let payload = &data[payload_offset..data.len().min(payload_offset + MAX_PAYLOAD)];
    let chunk_size = data
        .first()
        .map(|byte| usize::from(*byte % 63) + 1)
        .unwrap_or(1);
    let object_id = bytes32(data, 0x5a);
    let frame = ChunkFrame::new(
        object_id,
        data.get(1).copied().unwrap_or(0) as u32,
        0,
        payload.to_vec(),
    );
    let encoded = frame.encode();
    let decoded = ChunkFrame::decode(&encoded).expect("locally encoded chunk frame decodes");
    assert_eq!(decoded.payload, payload);
    assert!(decoded.verify());

    let encoder = ChunkEncoder::new(ChunkEncoderConfig {
        chunk_size: chunk_size as u32,
    });
    let mut framed_stream = data[..data.len().min(MAX_NOISE)].to_vec();
    for frame in encoder.encode_object(object_id, payload) {
        framed_stream.extend_from_slice(&frame.encode());
    }
    let (decoded_stream_frames, stream_consumed) = ChunkDecoder::decode_all(&framed_stream);
    assert!(stream_consumed <= framed_stream.len());
    for frame in decoded_stream_frames {
        assert!(frame.verify());
    }

    let _ = SendStreamHeader::decode(data);
    let _ = decode_stream(data);

    let mut header = SendStreamHeader::new(
        id128(data, 0x11),
        id128(data.get(16..).unwrap_or(&[]), 0x22),
        id128(data.get(32..).unwrap_or(&[]), 0x33),
    );
    let stream_record_payload =
        u32::from(data.get(3).copied().unwrap_or(0) % 128).saturating_add(32);
    let stream_payload = &payload[..payload.len().min(MAX_STREAM_PAYLOAD)];
    header.max_record_payload = stream_record_payload;
    header.checkpoint_interval_records = u32::from(data.get(2).copied().unwrap_or(0) % 8) + 1;

    let mut snapshot = SnapshotDelta::new(id128(data.get(48..).unwrap_or(&[]), 0x44), b"fuzz", 1);
    snapshot.objects.push(DeltaObject::new(
        object_id,
        ObjectKind::Extent,
        stream_payload.to_vec(),
    ));
    if let Ok(builder) = SendBuilder::full(header, vec![snapshot]) {
        let stream = builder.encode().expect("locally built send stream encodes");
        let (_decoded_header, records) =
            decode_stream(&stream).expect("locally built send stream decodes");
        assert!(!records.is_empty());
    }
});
