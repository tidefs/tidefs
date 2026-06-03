#![no_main]

use libfuzzer_sys::fuzz_target;
use tidefs_local_object_store::pool_label::decode_label;

// Feed arbitrary bytes to pool label decode_label.
//
// Every decode path must either succeed with a valid PoolLabelV1 or
// return a LabelError -- never panic. Pool labels are the first bytes
// read from any device and are an untrusted input surface.
//
// The decode path validates:
// - Minimum buffer size (POOL_LABEL_V1_WIRE_SIZE for basic, EXT for extended)
// - Magic bytes ("VBFS")
// - Supported format version (1)
// - Valid PoolState discriminant (0-2)
// - Valid DeviceClass discriminant (0-6)
// - Pool name length within bounds
// - BLAKE3-256 checksum over all preceding fields
fuzz_target!(|data: &[u8]| {
    let _ = decode_label(data);
});
