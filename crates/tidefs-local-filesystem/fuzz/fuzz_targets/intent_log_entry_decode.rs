#![no_main]

use libfuzzer_sys::fuzz_target;
use tidefs_local_filesystem::fuzz_decode_intent_log_entry;

// Feed arbitrary bytes to the filesystem-level intent-log entry decoder.
//
// Every decode path must either succeed or return an error -- never panic.
// The decoder validates:
// - Magic bytes (VFSILOG1)
// - Format version (2)
// - Reserved field (must be 0)
// - Entry kind discriminant (1-7 valid, other rejected)
// - Per-kind body field sizes
// - Decoder state consistency (finish check)
fuzz_target!(|data: &[u8]| {
    fuzz_decode_intent_log_entry(data);
});
