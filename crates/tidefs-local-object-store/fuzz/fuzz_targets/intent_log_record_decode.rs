#![no_main]

use libfuzzer_sys::fuzz_target;
use tidefs_local_object_store::intent_log::record::IntentLogRecord;

// Feed arbitrary bytes to IntentLogRecord::decode.
//
// Every decode path must either succeed with a valid record or return
// an error -- never panic. This is the primary parser security fuzz target
// for the object-store intent log on-disk format.
//
// The decode path validates:
// - Minimum framing size (discriminant + body_len + checksum)
// - Body length consistency with buffer size
// - BLAKE3-256 checksum over `discriminant || body_len || body`
// - Valid discriminant values (1, 6, 7, 8, 9)
// - Per-variant body minimum sizes
// - WritePayload data length consistency
fuzz_target!(|data: &[u8]| {
    let _ = IntentLogRecord::decode(data);
});
