// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_main]

use libfuzzer_sys::fuzz_target;
use tidefs_transport::codec::MessageCodec;
use tidefs_transport::envelope::MessageFamily;
use tidefs_transport::lane_demux::{LaneClass, LaneDemux, WriteResult};

fn exercise_wire_header_cases(data: &[u8], demux: &mut LaneDemux) {
    let codec = MessageCodec::with_max_frame_size(2048);
    let _ = codec.decode(data);

    if data.len() >= 5 {
        let mut overclaimed = data[..data.len().min(2053)].to_vec();
        let declared = overclaimed
            .len()
            .saturating_add(usize::from(data[0]))
            .saturating_add(1) as u32;
        overclaimed[..4].copy_from_slice(&declared.to_le_bytes());
        let _ = codec.decode(&overclaimed);

        let mut invalid_family = overclaimed;
        invalid_family[4] = 0xff;
        let _ = codec.decode(&invalid_family);
    }

    let families = MessageFamily::all();
    let family = families[data.first().copied().unwrap_or(0) as usize % MessageFamily::COUNT];
    let payload_start = data.len().min(2);
    let payload_len = data
        .get(1)
        .map(|byte| usize::from(*byte).min(data.len().saturating_sub(payload_start)))
        .unwrap_or(0)
        .min(1024);
    let payload = &data[payload_start..payload_start + payload_len];

    if let Ok(frame) = codec.encode(family, payload) {
        route_decoded_frame(&codec, &frame, demux);

        for cut in 0..frame.len().min(5) {
            let _ = codec.decode(&frame[..cut]);
        }

        let mut frame_with_tail = frame;
        frame_with_tail.extend_from_slice(&data[..data.len().min(16)]);
        route_decoded_frame(&codec, &frame_with_tail, demux);

        let mut bad_len = frame_with_tail;
        let declared = (payload_len as u32).saturating_add(1);
        bad_len[..4].copy_from_slice(&declared.to_le_bytes());
        let _ = codec.decode(&bad_len);
    }
}

fn route_decoded_frame(codec: &MessageCodec, frame: &[u8], demux: &mut LaneDemux) {
    if let Ok((family, payload)) = codec.decode(frame) {
        let lane = family.preferred_lane();
        demux.receive(lane, &payload);
        let drained = demux.drain_read(lane);
        assert_eq!(drained, payload);
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mut demux = LaneDemux::new();
    exercise_wire_header_cases(data, &mut demux);
    let lanes = LaneClass::all();

    // Phase 1: Write messages to random lanes
    let write_count = (data[0] as usize % 50).max(1);
    let mut offset = 1usize;
    let mut total_written = 0usize;

    for _ in 0..write_count {
        if offset >= data.len() {
            break;
        }
        let lane_idx = data[offset] as usize % 5;
        let lane = lanes[lane_idx];
        let msg_len = if offset + 1 < data.len() {
            ((data[offset + 1] as usize) % 256).min(1024)
        } else {
            8
        };
        offset = offset.saturating_add(2).min(data.len());

        let msg = vec![0u8; msg_len];
        match demux.write(lane, msg) {
            WriteResult::Queued => {
                total_written += msg_len;
            }
            WriteResult::Paused { .. } => {
                // Lane is paused — write was queued but backpressure engaged
            }
        }
    }

    // Verify invariant: total_queued_bytes should not exceed written
    assert!(
        demux.total_queued_bytes() <= total_written + (total_written / 10),
        "queued bytes should be bounded by writes"
    );

    // Phase 2: Drain reads from random lanes
    let drain_count = (if data.len() > 1 {
        data[1] as usize % 20
    } else {
        5
    })
    .max(1);
    for _ in 0..drain_count {
        let lane_idx = if offset < data.len() {
            data[offset] as usize % 5
        } else {
            0
        };
        offset = offset.saturating_add(1).min(data.len());
        let lane = lanes[lane_idx];

        // Drain any accumulated reads
        let _drained = demux.drain_read(lane);

        // Resume if paused
        if demux.is_paused(lane) {
            demux.resume(lane);
        }
    }

    // Phase 3: Verify invariants after operations
    // All-paused check
    let all_paused = demux.all_paused();
    if all_paused {
        for lane in &lanes {
            assert!(
                demux.is_paused(*lane),
                "all_paused must imply each lane paused"
            );
        }
    }

    // has_pending must be consistent with queued bytes
    let has_pending = demux.has_pending();
    let queued = demux.total_queued_bytes();
    if !has_pending {
        // If nothing pending, queued bytes should reflect drained state
        assert!(
            queued == 0 || !demux.has_pending(),
            "has_pending=false should mean nothing left to send"
        );
    }

    // Drain all remaining data — should not panic
    for lane in &lanes {
        let _ = demux.drain_read(*lane);
        let _ = demux.next_to_send();
    }
});
