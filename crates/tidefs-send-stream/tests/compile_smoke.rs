//! Compilation smoke test: ensures the crate remains buildable and that
//! key public types and functions are reachable from integration tests.

use tidefs_send_stream::{
    decode_stream, DeltaObject, ObjectKind, SendBuilder, SendStreamHeader, STREAM_MAGIC,
};

#[test]
fn smoke_crate_builds_and_public_api_accessible() {
    let header = SendStreamHeader::new([1u8; 16], [2u8; 16], [3u8; 16]);
    assert_eq!(header.to_snapshot_id, [3u8; 16]);

    let inc = header.incremental_from([9u8; 16]);
    assert!(inc
        .flags
        .contains(tidefs_send_stream::StreamFlags::INCREMENTAL));

    let obj = DeltaObject::new([10u8; 32], ObjectKind::Extent, b"smoke".to_vec());
    let mut snapshot = tidefs_send_stream::SnapshotDelta::new([11u8; 16], "test", 1);
    snapshot.objects.push(obj);
    let builder = SendBuilder::full(
        SendStreamHeader::new([1u8; 16], [2u8; 16], [3u8; 16]),
        vec![snapshot],
    )
    .unwrap();

    let encoded = builder.encode().unwrap();
    let (decoded_header, records) = decode_stream(&encoded).unwrap();
    assert_eq!(decoded_header.to_snapshot_id, [3u8; 16]);
    assert!(!records.is_empty());
}

#[test]
fn smoke_stream_magic_constant() {
    assert_eq!(&STREAM_MAGIC, b"VFSSEND2");
}
