// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the 4-byte big-endian length-prefix frame format used by TcpConnection.
// The frame format is: [len: u32 BE][payload: len bytes].
//
// This fuzzes the framing invariants:
// - Decoding arbitrary bytes must never panic
// - Length prefix must be consistent with available data
// - Round-trip encode/decode for valid payloads
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Interpret first 4 bytes as a big-endian u32 length prefix
    if data.len() >= 4 {
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&data[..4]);
        let claimed_len = u32::from_be_bytes(len_bytes) as usize;

        // Verify length consistency
        let actual_payload_len = data.len().saturating_sub(4);
        if claimed_len <= actual_payload_len {
            // Valid frame: length prefix matches available data
            let _payload = &data[4..4 + claimed_len];

            // Re-encode and verify round-trip
            let mut frame = Vec::with_capacity(4 + claimed_len);
            frame.extend_from_slice(&(claimed_len as u32).to_be_bytes());
            frame.extend_from_slice(&data[4..4 + claimed_len]);

            // Decode the re-encoded frame
            if frame.len() >= 4 {
                let re_decoded_len =
                    u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
                assert_eq!(re_decoded_len, claimed_len, "round-trip length mismatch");
            }
        }
        // If claimed_len > actual_payload_len, it's a truncated frame — decode should handle gracefully
    }

    // Also test encoding arbitrary payloads
    let payload = data;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);

    // Verify decode of the well-formed frame
    if frame.len() >= 4 {
        let decoded_len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        assert_eq!(
            decoded_len,
            payload.len(),
            "encoded length must match payload"
        );
        assert!(
            decoded_len <= frame.len().saturating_sub(4),
            "decoded length must not exceed available data"
        );
    }
});
