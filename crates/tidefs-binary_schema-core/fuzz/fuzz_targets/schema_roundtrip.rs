#![no_main]

use libfuzzer_sys::fuzz_target;
use tidefs_binary_schema_core::*;

fuzz_target!(|data: &[u8]| {
    // Feed arbitrary bytes to every decode path; every path must either
    // succeed with valid output or return an error — never panic.

    // --- U16Le ---
    if data.len() >= 2 {
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(&data[..2]);
        let _ = U16Le::from_le_bytes(bytes);
    }

    // --- U32Le ---
    if data.len() >= 4 {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&data[..4]);
        let _ = U32Le::from_le_bytes(bytes);
    }

    // --- U64Le ---
    if data.len() >= 8 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&data[..8]);
        let _ = U64Le::from_le_bytes(bytes);
    }

    // --- I32Le ---
    if data.len() >= 4 {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&data[..4]);
        let _ = I32Le::from_le_bytes(bytes);
    }

    // --- I64Le ---
    if data.len() >= 8 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&data[..8]);
        let _ = I64Le::from_le_bytes(bytes);
    }

    // --- SchemaVersion ---
    if data.len() >= 4 {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&data[..4]);
        let _ = SchemaVersion::decode(bytes);
    }

    // --- SchemaFingerprint ---
    if data.len() >= 32 {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&data[..32]);
        let _ = SchemaFingerprint::decode(bytes);
    }

    // --- canonical_bool ---
    if !data.is_empty() {
        let _ = decode_canonical_bool(data[0]);
    }

    // --- ChecksumProfile ---
    if !data.is_empty() {
        let _ = ChecksumProfile::from_discriminant(data[0]);
    }

    // --- PayloadClass ---
    if data.len() >= 2 {
        let d = u16::from_le_bytes([data[0], data[1]]);
        let _ = PayloadClass::from_discriminant(d);
    }

    // --- ChunkFrameSizeClass ---
    if data.len() >= 2 {
        let d = u16::from_le_bytes([data[0], data[1]]);
        let _ = ChunkFrameSizeClass::from_discriminant(d);
    }

    // --- FeatureBits encode ---
    if data.len() >= 8 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&data[..8]);
        let fb = FeatureBits(u64::from_le_bytes(bytes));
        let _ = fb.encode();
        let _ = fb.has(0);
        let _ = fb.has(63);
        let _ = fb.with(0);
        let _ = fb.is_subset_of(FeatureBits::NONE);
    }

    // --- Compatibility check ---
    if data.len() >= 8 {
        let reader = SchemaVersion::new(
            u16::from_le_bytes([data[0], data[1]]),
            u16::from_le_bytes([data[2], data[3]]),
        );
        let writer = SchemaVersion::new(
            u16::from_le_bytes([data[4], data[5]]),
            u16::from_le_bytes([data[6], data[7]]),
        );
        let _ = reader.can_read(&writer);
        let _ = reader.can_be_read_by(&writer);
    }

    // --- compatibility_matrix ---
    let _ = compatibility_matrix();
});
