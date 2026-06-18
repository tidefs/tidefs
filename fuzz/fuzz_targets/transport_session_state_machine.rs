// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tidefs_transport::TransportAddr;
use tidefs_transport::session::{Session, SessionCloseReason, SessionState};
use tidefs_transport::types::{HlcTimestamp, SessionId};
use tidefs_types_transport_session::EndpointFamily;

fn ts() -> HlcTimestamp {
    HlcTimestamp::new(0, 0)
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9000);

    // Session::new(session_id, local_node, peer_node, peer_addr)
    let mut session = Session::new(
        SessionId(1),
        0, // local_node
        1, // peer_node
        TransportAddr::Tcp(addr),
        EndpointFamily::LocalEmbed,
        tidefs_transport::backend::TransportBackendKind::Tcp,
    );

    let op_count = (data[0] as usize % 25).max(1);
    let mut offset = 1;

    for _ in 0..op_count {
        if offset + 2 > data.len() {
            break;
        }
        let op = data[offset] % 6;
        let reason_code = data[offset + 1] % 5;
        offset = offset.saturating_add(2).min(data.len());

        let reason = match reason_code {
            0 => SessionCloseReason::PeerRemoved,
            1 => SessionCloseReason::AuthFailed,
            2 => SessionCloseReason::ProtocolVersionMismatch,
            3 => SessionCloseReason::LocalShutdown,
            _ => SessionCloseReason::TransportError,
        };

        let current = &session.state;
        let target = match (op, current) {
            (0, SessionState::Unconnected) => SessionState::Connecting { started_at: ts() },
            (1, _) => SessionState::Handshaking { started_at: ts() },
            (2, SessionState::Handshaking { .. }) => SessionState::Established { since: ts() },
            (3, SessionState::Connecting { .. }) => SessionState::Handshaking { started_at: ts() },
            (4, _) => SessionState::Reconnecting {
                attempt: 1,
                since: ts(),
                backoff: Duration::from_millis(100),
            },
            (5, _) => SessionState::Closed { reason },
            _ => continue,
        };

        let result = session.transition(target);
        if result.is_ok() {
            if let SessionState::Closed { .. } = session.state {
                assert!(session.is_closed(), "Closed state must report is_closed");
            }
            if let SessionState::Established { .. } = session.state {
                assert!(
                    session.is_established(),
                    "Established must report is_established"
                );
            }
        }
    }
});
