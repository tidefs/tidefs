//! Integration tests for the BLAKE3-verified reconnect protocol.
//!
//! These tests exercise the full reconnect lifecycle across the boundary
//! between [`ReconnectDriver`], [`Session`], and the wire types
//! [`SessionResumeRequest`]/[`SessionResumeResponse`]. They verify:
//! - Session state transitions during reconnect (Enter → Reconnecting → Established)
//! - Reconnect abandon path (Reconnecting → Closed)
//! - Full driver lifecycle with resume token verification
//! - Message continuity with paired send/receive streams across reconnect
//! - Double-reconnect idempotency (reset after success)
//! - Session key binding and driver creation from session state

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::time::Duration;
use tidefs_transport::{
    self,
    backend::TransportBackendKind,
    message_priority::MessagePriority,
    reconnect::{apply_jitter, ReconnectConfig, ReconnectPhase, SessionResumeResponse},
    Session, SessionCloseReason, SessionId, SessionState,
};
use tidefs_types_transport_session::EndpointFamily;
pub use tidefs_types_transport_session::MessageSequenceNumber;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a Session in Established state for use in reconnect tests.
fn make_established_session() -> Session {
    let peer_addr = tidefs_transport::TransportAddr::Tcp(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        9999,
    ));
    let mut session = Session::new(
        SessionId::new(42),
        1, // local_node
        2, // peer_node
        peer_addr,
        EndpointFamily::Data,
        TransportBackendKind::Tcp,
    );

    // Transition through the state machine to Established
    let ts = tidefs_transport::HlcTimestamp::default();
    session
        .transition(SessionState::Connecting { started_at: ts })
        .unwrap();
    session
        .transition(SessionState::Handshaking { started_at: ts })
        .unwrap();
    session
        .transition(SessionState::Bound { since: ts })
        .unwrap();
    session
        .transition(SessionState::CohortAttached { since: ts })
        .unwrap();
    session
        .transition(SessionState::Established { since: ts })
        .unwrap();

    // Establish a session key (simulating post-handshake state)
    session.init_reconnect_session_key([0x42u8; 32]);

    session
}

// ---------------------------------------------------------------------------
// Session state transition tests
// ---------------------------------------------------------------------------

#[test]
fn enter_reconnecting_from_established() {
    let mut session = make_established_session();
    let result = session.enter_reconnecting(1, Duration::from_millis(100));
    assert!(result.is_ok());
    assert!(matches!(
        session.state,
        SessionState::Reconnecting { attempt: 1, .. }
    ));
    assert_eq!(session.stats.reconnections.load(Ordering::Relaxed), 1);
}

#[test]
fn enter_reconnecting_rejects_unestablished_session() {
    let peer_addr = tidefs_transport::TransportAddr::Tcp(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        9999,
    ));
    let mut session = Session::new(
        SessionId::new(1),
        1,
        2,
        peer_addr,
        EndpointFamily::Data,
        TransportBackendKind::Tcp,
    );
    // Session is in Unconnected state — cannot resume
    let result = session.enter_reconnecting(1, Duration::from_millis(100));
    assert!(result.is_err());
}

#[test]
fn complete_reconnect_transitions_to_established() {
    let mut session = make_established_session();
    session
        .enter_reconnecting(1, Duration::from_millis(100))
        .unwrap();

    let result = session.complete_reconnect();
    assert!(result.is_ok());
    assert!(matches!(session.state, SessionState::Established { .. }));
}

#[test]
fn complete_reconnect_rejects_wrong_state() {
    let mut session = make_established_session();
    // Session is still Established, not Reconnecting
    let result = session.complete_reconnect();
    assert!(result.is_err());
}

#[test]
fn abandon_reconnect_closes_session() {
    let mut session = make_established_session();
    session
        .enter_reconnecting(1, Duration::from_millis(100))
        .unwrap();

    let result = session.abandon_reconnect(SessionCloseReason::TransportError);
    assert!(result.is_ok());
    assert!(matches!(
        session.state,
        SessionState::Closed {
            reason: SessionCloseReason::TransportError
        }
    ));
    assert!(session.is_closed());
}

#[test]
fn abandon_reconnect_rejects_wrong_state() {
    let mut session = make_established_session();
    let result = session.abandon_reconnect(SessionCloseReason::LocalShutdown);
    assert!(result.is_err());
}

#[test]
fn reconnect_attempt_counter_increments() {
    let mut session = make_established_session();

    session
        .enter_reconnecting(1, Duration::from_millis(100))
        .unwrap();
    assert_eq!(session.stats.reconnections.load(Ordering::Relaxed), 1);

    // Complete reconnect, then reconnect again
    session.complete_reconnect().unwrap();
    session
        .enter_reconnecting(2, Duration::from_millis(200))
        .unwrap();
    assert_eq!(session.stats.reconnections.load(Ordering::Relaxed), 2);
}

#[test]
fn double_reconnect_idempotency() {
    let mut session = make_established_session();

    // First reconnect cycle
    session
        .enter_reconnecting(1, Duration::from_millis(100))
        .unwrap();
    session.complete_reconnect().unwrap();
    assert!(matches!(session.state, SessionState::Established { .. }));

    // Second reconnect cycle — should work again
    session
        .enter_reconnecting(1, Duration::from_millis(200))
        .unwrap();
    session.complete_reconnect().unwrap();
    assert!(matches!(session.state, SessionState::Established { .. }));
}

// ---------------------------------------------------------------------------
// ReconnectDriver integration tests
// ---------------------------------------------------------------------------

#[test]
fn driver_from_session_produces_valid_resume_request() {
    let session = make_established_session();
    let driver = session
        .create_reconnect_driver()
        .expect("driver should exist");

    let req = driver.build_resume_request(MessageSequenceNumber(7));
    assert_eq!(req.session_id, 42);
    assert_eq!(req.last_acknowledged_seq, MessageSequenceNumber(7));
    // Token must verify against the session key
    assert!(req.verify_token(&[0x42u8; 32]));
}

#[test]
fn driver_from_session_rejects_wrong_key() {
    let session = make_established_session();
    let driver = session
        .create_reconnect_driver()
        .expect("driver should exist");

    let req = driver.build_resume_request(MessageSequenceNumber(1));
    // Token should NOT verify with a different key
    assert!(!req.verify_token(&[0xFFu8; 32]));
}

#[test]
fn driver_full_lifecycle_accept_path() {
    let session = make_established_session();
    let mut driver = session.create_reconnect_driver().unwrap();

    // Start reconnect
    let backoff = driver.start_reconnect();
    assert!(backoff > Duration::ZERO);
    assert!(matches!(driver.phase, ReconnectPhase::BackingOff { .. }));

    // Enter resuming
    driver.enter_resuming();

    // Build a request
    let _req = driver.build_resume_request(MessageSequenceNumber(42));

    // Simulate peer accepting
    let response =
        SessionResumeResponse::accepted(MessageSequenceNumber(43), 64, &driver.session_key);
    assert!(driver.verify_response(&response));

    let result = driver.handle_resume_response(&response);
    assert!(result.is_ok());
    assert!(matches!(driver.phase, ReconnectPhase::Resumed));
    assert_eq!(driver.attempt(), 0); // counter reset on success
}

#[test]
fn driver_full_lifecycle_reject_then_accept() {
    let session = make_established_session();
    let mut driver = session.create_reconnect_driver().unwrap();

    // First attempt: rejected
    let _ = driver.start_reconnect();
    driver.enter_resuming();
    let rejected_resp = SessionResumeResponse::rejected(&driver.session_key);
    let result = driver.handle_resume_response(&rejected_resp);
    assert!(result.is_err());
    assert!(matches!(driver.phase, ReconnectPhase::BackingOff { .. }));

    // Second attempt: accepted
    driver.enter_resuming();
    let accepted_resp =
        SessionResumeResponse::accepted(MessageSequenceNumber(100), 64, &driver.session_key);
    let result = driver.handle_resume_response(&accepted_resp);
    assert!(result.is_ok());
    assert!(matches!(driver.phase, ReconnectPhase::Resumed));
}

#[test]
fn driver_exhaustion_path() {
    let mut session = make_established_session();
    let config = ReconnectConfig {
        max_retries: 2,
        ..ReconnectConfig::default()
    };
    session.set_reconnect_config(config);
    let mut driver = session.create_reconnect_driver().unwrap();

    // Attempt 1: reject
    let _ = driver.start_reconnect();
    driver.enter_resuming();
    let resp = SessionResumeResponse::rejected(&driver.session_key);
    let _ = driver.handle_resume_response(&resp);

    // Attempt 2: reject
    if !driver.is_exhausted() {
        driver.enter_resuming();
        let _ = driver.handle_resume_response(&resp);
    }

    assert!(driver.is_exhausted());
}

#[test]
fn session_enter_reconnecting_then_complete_driver_integration() {
    let mut session = make_established_session();

    // Enter reconnecting via session method
    session
        .enter_reconnecting(1, Duration::from_millis(100))
        .unwrap();
    assert!(matches!(
        session.state,
        SessionState::Reconnecting { attempt: 1, .. }
    ));

    // Simulate successful resume
    let driver = session.create_reconnect_driver().unwrap();
    let req = driver.build_resume_request(MessageSequenceNumber(10));
    assert!(req.verify_token(&[0x42u8; 32]));

    // Complete reconnect back to Established
    session.complete_reconnect().unwrap();
    assert!(matches!(session.state, SessionState::Established { .. }));
}

// ---------------------------------------------------------------------------
// Session resume request/response wire type integration
// ---------------------------------------------------------------------------

#[test]
fn resume_request_from_driver_matches_session_key() {
    let session = make_established_session();
    let driver = session.create_reconnect_driver().unwrap();
    let req = driver.build_resume_request(MessageSequenceNumber(55));

    // The request token should verify with the session's key
    assert!(req.verify_token(&[0x42u8; 32]));

    // And the session should be able to verify its own request
    let response = SessionResumeResponse::accepted(req.last_acknowledged_seq, 32, &[0x42u8; 32]);
    assert!(response.verify(&[0x42u8; 32]));
    assert!(driver.verify_response(&response));
}

#[test]
fn resume_token_rejects_tampered_session_id() {
    let session = make_established_session();
    let driver = session.create_reconnect_driver().unwrap();
    let mut req = driver.build_resume_request(MessageSequenceNumber(1));

    // Tamper with session_id
    req.session_id = 999;
    assert!(!req.verify_token(&[0x42u8; 32]));
}

#[test]
fn resume_response_tamper_new_seq_base() {
    let mut response =
        SessionResumeResponse::accepted(MessageSequenceNumber(100), 64, &[0x42u8; 32]);
    response.new_seq_base = MessageSequenceNumber(999);
    assert!(!response.verify(&[0x42u8; 32]));
}

// ---------------------------------------------------------------------------
// Jitter and backoff integration tests
// ---------------------------------------------------------------------------

#[test]
fn jitter_within_expected_range() {
    let base = Duration::from_millis(100);
    for _ in 0..100 {
        let result = apply_jitter(base, 0.2);
        let min = Duration::from_millis(80);
        let max = Duration::from_millis(120);
        assert!(result >= min, "jitter {result:?} below min {min:?}");
        assert!(result <= max, "jitter {result:?} above max {max:?}");
    }
}

#[test]
fn jitter_zero_fraction_is_identity() {
    assert_eq!(
        apply_jitter(Duration::from_millis(500), 0.0),
        Duration::from_millis(500)
    );
}

#[test]
fn config_default_values_are_reasonable() {
    let cfg = ReconnectConfig::default();
    assert_eq!(cfg.max_retries, 10);
    assert!(cfg.base_backoff_ms >= 10);
    assert!(cfg.max_backoff_ms >= cfg.base_backoff_ms);
    assert!(cfg.session_resumption_timeout_ms >= 100);
    assert!(cfg.jitter_factor >= 0.0 && cfg.jitter_factor <= 0.5);
}

// ---------------------------------------------------------------------------
// Message continuity across reconnect boundary
// ---------------------------------------------------------------------------

/// Simulate a paired send/receive stream across the reconnect boundary.
///
/// This test exercises the full message-continuity lifecycle:
/// establish → send messages → receive messages → simulate disconnect →
/// enter reconnecting → build resume request with last_acknowledged_seq →
/// simulate peer accepting with new_seq_base → complete reconnect →
/// continue sending messages.
#[test]
fn message_continuity_send_recv_across_reconnect() {
    let mut session = make_established_session();

    // --- Phase 1: pre-disconnect message exchange ---
    // Send 5 messages
    for _ in 0..5 {
        let _ = session.next_send_seq();
        session.on_send(0, MessagePriority::Data);
    }
    assert_eq!(session.last_sent_seq(), MessageSequenceNumber(5));
    assert_eq!(session.send_seq, MessageSequenceNumber(5));

    // Receive 3 messages (simulating peer sending to us)
    for seq_num in 1..=3 {
        let outcome = session.accept_recv_seq(MessageSequenceNumber(seq_num));
        assert!(matches!(
            outcome,
            tidefs_transport::session::SeqReceiveOutcome::Accepted
        ));
    }
    assert_eq!(session.last_recv_seq(), MessageSequenceNumber(3));

    // --- Phase 2: disconnect and reconnect ---
    // Record last acknowledged sequence before disconnect
    let last_ack = session.last_recv_seq();
    assert_eq!(last_ack, MessageSequenceNumber(3));

    // Enter reconnecting state
    session
        .enter_reconnecting(1, Duration::from_millis(100))
        .unwrap();
    assert!(matches!(
        session.state,
        SessionState::Reconnecting { attempt: 1, .. }
    ));

    // Build resume request with last_acknowledged_seq
    let driver = session.create_reconnect_driver().unwrap();
    let resume_req = driver.build_resume_request(last_ack);
    assert_eq!(resume_req.session_id, 42);
    assert_eq!(resume_req.last_acknowledged_seq, MessageSequenceNumber(3));
    assert!(resume_req.verify_token(&[0x42u8; 32]));

    // Simulate peer accepting with new_seq_base = 4 (next expected)
    let resume_resp = SessionResumeResponse::accepted(
        MessageSequenceNumber(4), // new_seq_base: next message from peer
        64,                       // flow_credit_window
        &[0x42u8; 32],
    );
    assert!(resume_resp.verify(&[0x42u8; 32]));

    // Complete reconnect
    session.complete_reconnect().unwrap();
    assert!(matches!(session.state, SessionState::Established { .. }));

    // --- Phase 3: post-reconnect message exchange ---
    // Send continues from where we left off (send_seq was 5, still 5)
    assert_eq!(session.last_sent_seq(), MessageSequenceNumber(5));

    // Send 3 more messages
    for _ in 0..3 {
        let _ = session.next_send_seq();
        session.on_send(0, MessagePriority::Data);
    }
    assert_eq!(session.last_sent_seq(), MessageSequenceNumber(8));

    // Receive messages continuing from new_seq_base (4)
    for seq_num in 4..=7 {
        let outcome = session.accept_recv_seq(MessageSequenceNumber(seq_num));
        assert!(matches!(
            outcome,
            tidefs_transport::session::SeqReceiveOutcome::Accepted
        ));
    }
    assert_eq!(session.last_recv_seq(), MessageSequenceNumber(7));

    // Verify total messages exchanged: 8 sent, 7 received
    assert_eq!(session.send_seq, MessageSequenceNumber(8));
    assert_eq!(session.recv_seq, MessageSequenceNumber(7));
}

#[test]
fn resume_request_carries_correct_last_acknowledged_seq() {
    let mut session = make_established_session();

    // Receive 5 messages from peer
    for seq_num in 1..=5 {
        let _ = session.accept_recv_seq(MessageSequenceNumber(seq_num));
    }
    assert_eq!(session.last_recv_seq(), MessageSequenceNumber(5));

    // Enter reconnecting
    session
        .enter_reconnecting(1, Duration::from_millis(100))
        .unwrap();

    // The resume request should carry the correct last_acknowledged_seq
    let driver = session.create_reconnect_driver().unwrap();
    let req = driver.build_resume_request(session.last_recv_seq());
    assert_eq!(req.last_acknowledged_seq, MessageSequenceNumber(5));
    assert!(req.verify_token(&[0x42u8; 32]));
}

#[test]
fn send_seq_continues_across_multiple_reconnect_cycles() {
    let mut session = make_established_session();

    // Send 2 messages
    let _ = session.next_send_seq();
    session.on_send(0, MessagePriority::Data);
    let _ = session.next_send_seq();
    session.on_send(0, MessagePriority::Data);
    assert_eq!(session.last_sent_seq(), MessageSequenceNumber(2));

    // Reconnect cycle 1
    session
        .enter_reconnecting(1, Duration::from_millis(100))
        .unwrap();
    session.complete_reconnect().unwrap();
    assert_eq!(session.last_sent_seq(), MessageSequenceNumber(2));

    // Send 3 more messages after first reconnect
    for _ in 0..3 {
        let _ = session.next_send_seq();
        session.on_send(0, MessagePriority::Data);
    }
    assert_eq!(session.last_sent_seq(), MessageSequenceNumber(5));

    // Reconnect cycle 2
    session
        .enter_reconnecting(2, Duration::from_millis(200))
        .unwrap();
    session.complete_reconnect().unwrap();
    assert_eq!(session.last_sent_seq(), MessageSequenceNumber(5));

    // Send 2 more messages after second reconnect
    let _ = session.next_send_seq();
    session.on_send(0, MessagePriority::Data);
    let _ = session.next_send_seq();
    session.on_send(0, MessagePriority::Data);
    assert_eq!(session.last_sent_seq(), MessageSequenceNumber(7));
}
