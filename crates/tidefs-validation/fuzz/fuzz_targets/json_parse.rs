#![no_main]

use libfuzzer_sys::fuzz_target;

// Feed arbitrary bytes as UTF-8 to serde_json::from_slice for Value parsing.
//
// Every parse must either succeed or return an error -- never panic.
// This covers the general CLI/JSON parsing surface used throughout
// tidefs-validation for validation reports, scoreboards, and trace data.
fuzz_target!(|data: &[u8]| {
    // Attempt to parse as serde_json::Value (the most general target).
    // Invalid UTF-8 is rejected by serde_json, so we convert lossily.
    let s = String::from_utf8_lossy(data);
    let _ = serde_json::from_str::<serde_json::Value>(&s);
});
