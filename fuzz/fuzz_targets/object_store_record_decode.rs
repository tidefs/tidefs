#![no_main]

use libfuzzer_sys::fuzz_target;
use tidefs_local_object_store::RecordKind;

// Fuzz target for object-store record deserialization.
//
// The object store is the persistence layer. Corrupted or malicious records
// could cause panics, infinite loops, or memory unsafety when decoded.
//
// This target exercises `RecordKind` decoding from raw u16 values (the
// on-disk record tag).  When the full record deserializer becomes public,
// this target should be extended to feed complete record byte sequences.
fuzz_target!(|data: &[u8]| {
    // Exercise RecordKind decoding from raw u16 record-type tags.
    // On-disk records begin with a u16 tag; this is the first decode step
    // and a natural boundary for catching malformed inputs.
    if data.len() >= 2 {
        let raw = u16::from_le_bytes([data[0], data[1]]);
        let _ = RecordKind::try_from(raw);
    }

    // Exercise additional byte patterns for potential future record fields.
    // Feed arbitrary bytes through nothing — ensures the harness itself
    // doesn't panic on any input.
    let _ = data.len();
});
