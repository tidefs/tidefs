// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration tests for per-session response tracking with timeout expiry.
//!
//! Tests cover:
//! - Session set_response_tracker creates table and spawns timeout task
//! - register_response_waiter + deliver_response round-trip through session
//! - fail_all_pending_responses drains all entries and unblocks waiters
//! - abort_response_timeout_task stops the background reaper
//! - Duplicate response delivery after original timed out is handled correctly
//! - Background timeout reaping fires and unblocks expired waiters

use std::time::Duration;

use tidefs_transport::backend::TransportBackendKind;
use tidefs_transport::request_response::CorrelationError;
use tidefs_transport::session::Session;
use tidefs_transport::{SessionId, TransportAddr};
use tidefs_types_transport_session::EndpointFamily;

fn new_test_session() -> Session {
    Session::new(
        SessionId::new(1),
        100,
        200,
        TransportAddr::Tcp(std::net::SocketAddr::from(([127, 0, 0, 1], 9000))),
        EndpointFamily::Data,
        TransportBackendKind::Tcp,
    )
}

// ── Session tracker creation ────────────────────────────────────────

#[tokio::test]
async fn set_response_tracker_creates_table_and_spawns_task() {
    let mut session = new_test_session();

    session.set_response_tracker(Some(64), Duration::from_secs(30), Duration::from_secs(1));

    assert!(session.response_tracker.is_some());
    assert!(session.response_timeout_task.is_some());

    // Verify the tracker works: register a request.
    let result = session.register_response_waiter().await;
    assert!(result.is_some());
    let (id, _rx) = result.unwrap().unwrap();

    // Deliver a response and verify it arrives.
    let payload = b"response-data".to_vec();
    let delivered = session.deliver_response(id, payload.clone()).await;
    assert!(delivered.is_some());
    assert!(delivered.unwrap().is_ok());
}

// ── Session-level register and deliver round-trip ───────────────────

#[tokio::test]
async fn register_and_deliver_through_session_roundtrip() {
    let mut session = new_test_session();
    session.set_response_tracker(Some(128), Duration::from_secs(60), Duration::from_secs(2));

    // Register a request through the session convenience method.
    let (correlation_id, rx) = session.register_response_waiter().await.unwrap().unwrap();

    assert_eq!(
        session.pending_response_count().await,
        Some(1),
        "one entry should be pending"
    );

    // Deliver the response payload.
    let payload = b"hello from peer".to_vec();
    let result = session
        .deliver_response(correlation_id, payload.clone())
        .await;
    assert!(result.unwrap().is_ok());

    // The waiter receives the payload.
    let received = rx.await.unwrap().unwrap();
    assert_eq!(received, payload);

    // Entry is cleared after delivery.
    assert_eq!(session.pending_response_count().await, Some(0));
}

// ── Session-level fail_all_pending ──────────────────────────────────

#[tokio::test]
async fn fail_all_pending_through_session_unblocks_all_waiters() {
    let mut session = new_test_session();
    session.set_response_tracker(Some(32), Duration::from_secs(60), Duration::from_secs(2));

    // Register several requests.
    let mut receivers = Vec::new();
    for _ in 0..5 {
        let (_id, rx) = session.register_response_waiter().await.unwrap().unwrap();
        receivers.push(rx);
    }
    assert_eq!(session.pending_response_count().await, Some(5));

    // Fail all pending through the session method.
    let cancelled = session.fail_all_pending_responses().await;
    assert_eq!(cancelled, Some(5));
    assert_eq!(session.pending_response_count().await, Some(0));

    // Every receiver gets a timeout error.
    for rx in receivers {
        let result = rx.await.unwrap();
        assert!(
            matches!(result, Err(CorrelationError::Timeout(_))),
            "expected Timeout, got {result:?}"
        );
    }
}

// ── abort_response_timeout_task ─────────────────────────────────────

#[tokio::test]
async fn abort_response_timeout_task_stops_background_reaper() {
    let mut session = new_test_session();
    session.set_response_tracker(Some(16), Duration::from_secs(30), Duration::from_secs(1));

    assert!(session.response_timeout_task.is_some());

    // Register a request so the table is non-empty.
    let (_id, _rx) = session.register_response_waiter().await.unwrap().unwrap();

    // Abort the timeout task.
    session.abort_response_timeout_task();
    assert!(session.response_timeout_task.is_none());

    // The tracker handle is still usable: we can still deliver.
    // (The background reaper is gone, but manual delivery still works.)
    let (id2, rx2) = session.register_response_waiter().await.unwrap().unwrap();
    let payload = b"after-abort".to_vec();
    session.deliver_response(id2, payload.clone()).await;
    let received = rx2.await.unwrap().unwrap();
    assert_eq!(received, payload);
}

// ── Duplicate response after timeout ────────────────────────────────

#[tokio::test]
async fn duplicate_response_after_timeout_returns_unknown_correlation_id() {
    let mut session = new_test_session();
    // Short timeout so we can trigger expiry quickly.
    session.set_response_tracker(
        Some(16),
        Duration::from_millis(10),
        Duration::from_millis(5),
    );

    let (id, rx) = session.register_response_waiter().await.unwrap().unwrap();

    // Wait for the background reaper to expire the entry.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // The waiter should get a timeout error.
    let result = rx.await.unwrap();
    assert!(
        matches!(result, Err(CorrelationError::Timeout(_))),
        "expected Timeout after sleep, got {result:?}"
    );

    // Trying to deliver to the same (now-expired) correlation ID returns
    // UnknownCorrelationId.
    let delivery = session
        .deliver_response(id, b"late-response".to_vec())
        .await;
    assert!(delivery.is_some());
    let err = delivery.unwrap().unwrap_err();
    assert!(
        matches!(err, CorrelationError::UnknownCorrelationId(_)),
        "expected UnknownCorrelationId for late delivery, got {err:?}"
    );
}

// ── No tracker attached returns None ────────────────────────────────

#[tokio::test]
async fn methods_return_none_when_no_tracker_attached() {
    let session = new_test_session();

    assert!(session.register_response_waiter().await.is_none());
    assert!(session
        .deliver_response(1, b"data".to_vec())
        .await
        .is_none());
    assert!(session.fail_all_pending_responses().await.is_none());
    assert!(session.pending_response_count().await.is_none());
}

// ── Request limit backpressure through session ──────────────────────

#[tokio::test]
async fn register_response_waiter_returns_request_limit_at_capacity() {
    let mut session = new_test_session();
    const CAP: usize = 4;
    session.set_response_tracker(Some(CAP), Duration::from_secs(60), Duration::from_secs(2));

    // Fill the table.
    for _ in 0..CAP {
        session.register_response_waiter().await.unwrap().unwrap();
    }
    assert_eq!(session.pending_response_count().await, Some(CAP));

    // Next registration fails at the configured request limit.
    let result = session.register_response_waiter().await;
    assert!(result.is_some());
    let err = result.unwrap().unwrap_err();
    assert!(matches!(
        err,
        CorrelationError::RequestLimitExceeded(CAP, CAP)
    ));
}

// ── Correlation framing round-trip through session ─────────────────

#[tokio::test]
async fn correlation_frame_request_encode_and_decode() {
    use tidefs_transport::correlation_frame::{
        decode_correlation_frame, encode_correlation_request, has_correlation_header,
        CorrelationFrameKind, CORRELATION_HEADER_LEN,
    };

    let payload = b"lease-renew-request".to_vec();
    let frame = encode_correlation_request(42, &payload);
    assert!(frame.len() >= CORRELATION_HEADER_LEN + payload.len());
    assert!(has_correlation_header(&frame));

    let decoded = decode_correlation_frame(&frame).unwrap();
    assert_eq!(
        decoded,
        CorrelationFrameKind::Request { correlation_id: 42 }
    );
}

#[tokio::test]
async fn correlation_frame_response_encode_and_decode() {
    use tidefs_transport::correlation_frame::{
        decode_correlation_frame, encode_correlation_response, has_correlation_header,
        CorrelationFrameKind, CORRELATION_HEADER_LEN,
    };

    let payload = b"grant-lease".to_vec();
    let frame = encode_correlation_response(7, &payload);
    assert!(frame.len() >= CORRELATION_HEADER_LEN + payload.len());
    assert!(has_correlation_header(&frame));

    let decoded = decode_correlation_frame(&frame).unwrap();
    assert_eq!(
        decoded,
        CorrelationFrameKind::Response {
            correlation_id: 7,
            payload: payload.clone(),
        }
    );
}

#[tokio::test]
async fn correlation_frame_session_roundtrip() {
    use tidefs_transport::correlation_frame::{
        decode_correlation_frame, encode_correlation_request, encode_correlation_response,
        CorrelationFrameKind,
    };

    let mut session = new_test_session();
    session.set_response_tracker(Some(16), Duration::from_secs(30), Duration::from_secs(1));

    // Sender side: register request, encode frame
    let (correlation_id, rx) = session.register_response_waiter().await.unwrap().unwrap();
    let framed_request = encode_correlation_request(correlation_id, b"lease-request-payload");

    // Receiver side: decode frame (request), then build response
    let decoded = decode_correlation_frame(&framed_request).unwrap();
    let req_id = match decoded {
        CorrelationFrameKind::Request { correlation_id } => correlation_id,
        _ => panic!("expected Request"),
    };

    // Receiver builds a response frame
    let response_payload = b"lease-granted".to_vec();
    let framed_response = encode_correlation_response(req_id, &response_payload);

    // Deliver the response through the session
    let decoded_resp = decode_correlation_frame(&framed_response).unwrap();
    match decoded_resp {
        CorrelationFrameKind::Response {
            correlation_id: resp_id,
            payload,
        } => {
            session.deliver_response(resp_id, payload).await;
        }
        _ => panic!("expected Response"),
    }

    // Original sender receives the response
    let result = rx.await.unwrap().unwrap();
    assert_eq!(result, response_payload);
}
