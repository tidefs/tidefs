#![no_main]

use libfuzzer_sys::fuzz_target;
use tidefs_ublk_abi::UblkDeviceState;

// Fuzz target for ublk ABI data parsing.
//
// ublk control and I/O data is received from the kernel via io_uring CQEs.
// This fuzzer exercises parsing of raw numeric values that could appear
// in struct fields read from the kernel or from shared memory.
fuzz_target!(|data: &[u8]| {
    if data.len() >= 2 {
        let raw = u16::from_le_bytes([data[0], data[1]]);
        // Exercise device state parsing from raw kernel value
        let _state = UblkDeviceState::from_raw(raw);

        // Exercise bit-level user_data encoding (see lib.rs fetch_req_user_data)
        let tag = u16::from(data[0]);
        let cmd_bits = if data.len() > 2 { u16::from_le_bytes([data[1], data[2]]) } else { 0 };
        let q_id_bits = if data.len() > 4 { u16::from_le_bytes([data[3], data[4]]) } else { 0 };
        let _encoded = (tag as u64) | ((cmd_bits as u64) << 16) | ((q_id_bits as u64) << 32);
    }
});
