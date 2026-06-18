// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_main]

use libfuzzer_sys::fuzz_target;
use tidefs_transport::chunk_shipper::{ChunkShipper, ChunkTransferHeader, ChunkTransferState};
use tidefs_transport::error::ChunkTransferError;
use tidefs_transport::types::{ChunkId, ChunkTransferId, FenceVersion, Hash, SessionId};

fn make_digest(seed: u8) -> Hash {
    let mut d = [0u8; 32];
    for (i, byte) in d.iter_mut().enumerate() {
        *byte = seed.wrapping_add(i as u8);
    }
    Hash(d)
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    let session_id = SessionId(data[0] as u64);
    let mut shipper = ChunkShipper::new(session_id, tidefs_transport::backend::TransportBackendKind::Tcp);
    let max_chunks = (data[1] as usize % 12).max(1);

    // Send chunks
    let mut sent_ids = Vec::new();
    for i in 0..max_chunks {
        let cid = ChunkId(i as u64);
        let payload_len = 64u64 + ((i as u64) * 16);

        match shipper.send_chunk(cid, payload_len) {
            Ok(tid) => sent_ids.push(tid),
            Err(_) => {}
        }
    }

    // Accept and complete chunks
    for i in 0..(max_chunks / 2).max(1) {
        let tid = ChunkTransferId(i as u64 + 1000);
        let header = ChunkTransferHeader::new(
            ChunkId(i as u64),
            64,
            make_digest(0xAA),
            tid,
            FenceVersion(0),
        );

        match shipper.accept_chunk(&header) {
            Ok(transfer_id) => {
                if data[i % data.len()] % 2 == 0 {
                    let _ = shipper.complete(transfer_id, make_digest(0xBB));
                } else {
                    let _ = shipper.fail(transfer_id, ChunkTransferError::Timeout { at_offset: 0 });
                }
            }
            Err(_) => {}
        }
    }

    // Remove some transfers
    for tid in &sent_ids[..sent_ids.len().min(4)] {
        let _ = shipper.remove(*tid);
    }

    // Verify invariants
    for tid in &sent_ids {
        if let Some(t) = shipper.get(*tid) {
            match &t.state {
                ChunkTransferState::Complete { checksum: _ } => {}
                ChunkTransferState::Failed {
                    error: _,
                    at_offset: _,
                } => {}
                _ => {}
            }
        }
    }
});
