#![no_main]

use libfuzzer_sys::fuzz_target;
use tidefs_local_filesystem::fuzz_decode_receive_checkpoint;

// Feed arbitrary bytes to the receive-checkpoint decoder.
//
// Every decode path must either succeed or return an error -- never panic.
// The decoder validates:
// - Minimum buffer size (30 bytes: magic + version + export_id + total + key_count)
// - Magic bytes (VFSRCPT1)
// - Format version (1)
// - Key count consistency with buffer size
// - Overflow prevention on key count arithmetic
fuzz_target!(|data: &[u8]| {
    fuzz_decode_receive_checkpoint(data);
});
