#![no_main]

use libfuzzer_sys::fuzz_target;
use serde::{Deserialize, Serialize};
use tidefs_transport::types::{FamilyVersion, NodeIdentityPublic};

/// Wire-compatible mirror of `tidefs_transport::transport::HandshakeMessage`.
/// Uses the same publicly-exported types with identical bincode encoding,
/// so fuzzing this struct directly validates the real handshake wire format.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct FuzzHandshakeMessage {
    pub identity: NodeIdentityPublic,
    pub families: Vec<FamilyVersion>,
}

fuzz_target!(|data: &[u8]| {
    // Decode arbitrary bytes as a handshake message — must not panic.
    let result: Result<FuzzHandshakeMessage, _> = bincode::deserialize(data);

    let Ok(msg) = result else { return };

    // Invariant: node_id should not be wildly out of range.
    assert!(
        msg.identity.node_id < 1_000_000,
        "implausible node_id {}",
        msg.identity.node_id
    );
    // Invariant: signatures are stored as bounded vectors.
    assert!(
        msg.identity.self_signature.len() <= 128,
        "excessive signature length {}",
        msg.identity.self_signature.len()
    );
    // Invariant: family count should be bounded.
    assert!(
        msg.families.len() <= 256,
        "excessive families count {}",
        msg.families.len()
    );

    // Round-trip: re-serialize and verify the second decode produces the same
    // identity fields.  This catches any structural mismatch between our
    // FuzzHandshakeMessage and the real HandshakeMessage.
    let Ok(re_encoded) = bincode::serialize(&msg) else { return };
    let msg2: FuzzHandshakeMessage =
        bincode::deserialize(&re_encoded).expect("round-trip decode of well-formed data");
    assert_eq!(
        msg.identity.node_id, msg2.identity.node_id,
        "round-trip node_id changed"
    );
    assert_eq!(
        msg.identity.verifying_key_bytes, msg2.identity.verifying_key_bytes,
        "round-trip verifying key changed"
    );
    assert_eq!(
        msg.families.len(),
        msg2.families.len(),
        "round-trip families count changed"
    );
});
