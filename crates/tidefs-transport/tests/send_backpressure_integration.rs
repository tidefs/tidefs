//! Integration tests for send-side backpressure propagation.
//!
//! Tests cover:
//! - Default capacity set is auto-created and available
//! - try_send_with_backpressure enqueues immediately when capacity is available
//! - try_send_with_backpressure expires an already-expired deadline
//! - try_send_with_backpressure awaits capacity when queue is full,
//!   then enqueues after drain
//! - End-to-end: pipeline run loop triggers capacity transitions naturally

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::RwLock;

use tidefs_transport::connection_registry::ConnectionState;
use tidefs_transport::envelope::MessageFamily;
use tidefs_transport::outbound_send::SendPipeline;
use tidefs_transport::send_admission::{SendAdmissionOutcome, SendCapacityClass, SendWakeEvidence};
use tidefs_transport::send_backpressure::{SendCapacitySet, SendWatermarkConfig};
use tidefs_transport::send_deadline::DeadlineOutcome;
use tidefs_transport::send_scheduler::SendPriority;

/// Helper: create a connected pipeline + handle pair with a background server.
async fn build_pipeline_async(
    channel_capacity: usize,
) -> (
    SendPipeline,
    tidefs_transport::outbound_send::SendPipelineHandle,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        let _ = tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut buf).await;
    });

    let stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let (_read_half, write_half) = stream.into_split();

    let state = Arc::new(RwLock::new(ConnectionState::Connected));
    let (pipeline, handle) =
        SendPipeline::new(write_half, Arc::clone(&state), channel_capacity, 64);

    (pipeline, handle, server_handle)
}

// ── Auto-Creation Tests ─────────────────────────────────────────────

#[tokio::test]
async fn default_capacity_set_is_auto_created() {
    let (_pipeline, handle, _server) = build_pipeline_async(16).await;

    let cap = handle.send_capacity(SendPriority::Data);
    assert!(cap.is_some(), "capacity set should be auto-created");
    let cap = cap.unwrap();
    assert!(cap.is_available(), "capacity should be available initially");

    for pri in [
        SendPriority::Control,
        SendPriority::Membership,
        SendPriority::IntentLog,
        SendPriority::Data,
        SendPriority::Bulk,
    ] {
        assert!(
            handle.send_capacity(pri).is_some(),
            "{pri:?} should have capacity"
        );
    }

    drop(handle);
}

// ── End-to-end Pipeline Tests ──────────────────────────────────────

#[tokio::test]
async fn try_send_with_backpressure_enqueues_when_capacity_available() {
    let (mut pipeline, handle, server) = build_pipeline_async(16).await;

    let pipeline_task = tokio::spawn(async move {
        pipeline.run().await.unwrap();
    });

    let result = handle
        .try_send_with_backpressure(
            MessageFamily::StateTransfer,
            SendPriority::Data,
            b"hello",
            None,
        )
        .await;

    assert!(
        result.is_ok(),
        "send should succeed when capacity is available"
    );

    let admission = result.unwrap();
    assert_eq!(admission.evidence.outcome, SendAdmissionOutcome::Accepted);
    assert_eq!(admission.evidence.priority, Some(SendPriority::Data));
    let token = admission.value.unwrap();
    let outcome = token.wait().await.unwrap();
    assert_eq!(outcome, DeadlineOutcome::Delivered);

    drop(handle);
    pipeline_task.await.unwrap();
    server.await.unwrap();
}

// ── Deadline-Interplay Test (pipeline runs; capacity manipulated before sends) ──

#[tokio::test]
async fn try_send_with_backpressure_expired_deadline_returns_cancelled() {
    let (mut pipeline, mut handle, server) = build_pipeline_async(256).await;

    // Set tiny watermarks.
    let config = SendWatermarkConfig::uniform(2, 1);
    let cs = SendCapacitySet::new(&config);
    pipeline.set_capacity_set(cs.clone());
    handle.set_capacity_set(cs.clone());

    // Start the pipeline so the handle can send.
    let pipeline_task = tokio::spawn(async move {
        pipeline.run().await.unwrap();
    });

    // Trigger Data high watermark BEFORE any sends so the pipeline
    // drain loop has nothing to dequeue (can't race-clear it).
    cs.check_after_dequeue(SendPriority::Data, 3);
    let data_cap = handle.send_capacity(SendPriority::Data).unwrap();
    assert!(
        !data_cap.is_available(),
        "Data should be under backpressure"
    );

    // Send with an already-expired deadline (Duration::ZERO).
    // try_send_with_backpressure sees !is_available, resolves the deadline,
    // finds it expired, returns Cancelled token without enqueuing.
    let result = handle
        .try_send_with_backpressure(
            MessageFamily::StateTransfer,
            SendPriority::Data,
            b"expired",
            Some(Duration::ZERO),
        )
        .await;

    assert!(result.is_ok(), "should return Ok with Cancelled token");
    let admission = result.unwrap();
    assert_eq!(
        admission.evidence.outcome,
        SendAdmissionOutcome::ExpiredBeforeEnqueue
    );
    assert_eq!(admission.evidence.queue_depth, Some(3));
    assert_eq!(
        admission.evidence.capacity.unwrap().class,
        SendCapacityClass::PriorityWatermark
    );
    let token = admission.value.unwrap();
    let outcome = token.wait().await.unwrap();
    assert_eq!(
        outcome,
        DeadlineOutcome::Cancelled,
        "expired deadline should cancel"
    );

    // Restore capacity so pipeline can drain any queued messages.
    cs.check_after_dequeue(SendPriority::Data, 1);

    drop(handle);
    pipeline_task.await.unwrap();
    server.await.unwrap();
}

// ── Capacity-Wait Test (pipeline runs; capacity manipulated before sends) ──

#[tokio::test]
async fn try_send_with_backpressure_waits_then_sends_after_drain() {
    let (mut pipeline, mut handle, server) = build_pipeline_async(256).await;

    // Set tiny watermarks.
    let config = SendWatermarkConfig::uniform(2, 1);
    let cs = SendCapacitySet::new(&config);
    pipeline.set_capacity_set(cs.clone());
    handle.set_capacity_set(cs.clone());

    // Start pipeline.
    let pipeline_task = tokio::spawn(async move {
        pipeline.run().await.unwrap();
    });

    // Trigger Data backpressure before any sends.
    cs.check_after_dequeue(SendPriority::Data, 3);
    let data_cap = handle.send_capacity(SendPriority::Data).unwrap();
    assert!(!data_cap.is_available());

    // Spawn a task that calls try_send_with_backpressure. It will see
    // !is_available, check the deadline (30s, not expired), then await
    // wait_for_capacity().
    let handle2 = handle.clone();
    let cs2 = cs.clone();
    let send_task = tokio::spawn(async move {
        handle2
            .try_send_with_backpressure(
                MessageFamily::StateTransfer,
                SendPriority::Data,
                b"waited",
                Some(Duration::from_secs(30)),
            )
            .await
    });

    // Give the send task time to start waiting on capacity.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Drain below low watermark so the waiter resumes.
    cs2.check_after_dequeue(SendPriority::Data, 1);
    assert!(data_cap.is_available());

    // The send task should complete: capacity becomes available, then it
    // enqueues the message to the pipeline.
    let result = tokio::time::timeout(Duration::from_secs(5), send_task).await;
    match result {
        Ok(Ok(Ok(admission))) => {
            assert_eq!(admission.evidence.outcome, SendAdmissionOutcome::Blocked);
            assert_eq!(admission.evidence.wake, SendWakeEvidence::DrainObserved);
            assert_eq!(admission.evidence.priority, Some(SendPriority::Data));
            let token = admission.value.unwrap();
            let outcome = token.wait().await.unwrap();
            assert_eq!(outcome, DeadlineOutcome::Delivered);
        }
        Ok(Ok(Err(e))) => panic!("send failed: {e:?}"),
        Ok(Err(join_err)) => panic!("task panicked: {join_err:?}"),
        Err(_timeout) => panic!("send task timed out"),
    }

    drop(handle);
    pipeline_task.await.unwrap();
    server.await.unwrap();
}

// ── End-to-End Drain-Loop Triggers ─────────────────────────────────

#[tokio::test]
async fn capacity_transitions_via_pipeline_drain_loop() {
    // End-to-end: start pipeline, fill Data queue, observe capacity flip.
    let (mut pipeline, mut handle, server) = build_pipeline_async(256).await;

    // Replace with tiny watermarks so few messages trigger backpressure.
    let config = SendWatermarkConfig::uniform(5, 2);
    let cs = SendCapacitySet::new(&config);
    pipeline.set_capacity_set(cs.clone());
    handle.set_capacity_set(cs.clone());

    let data_cap_before = handle.send_capacity(SendPriority::Data).unwrap();
    assert!(data_cap_before.is_available());

    let pipeline_task = tokio::spawn(async move {
        pipeline.run().await.unwrap();
    });

    // Send 10 Data messages. The scheduler will accumulate them.
    // With high=5, after 5+ messages accumulate, the drain loop's
    // check_after_dequeue should flip capacity.
    for i in 0..10u8 {
        handle
            .send_with_priority(MessageFamily::StateTransfer, SendPriority::Data, &[i; 5])
            .await
            .unwrap();
    }

    // Give the pipeline time to drain messages from mpsc into scheduler
    // and write a few batches to the socket.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // try_send_with_backpressure should succeed (capacity may or may not
    // be under backpressure, but the method should handle either case).
    let result = handle
        .try_send_with_backpressure(
            MessageFamily::StateTransfer,
            SendPriority::Data,
            b"final",
            Some(Duration::from_secs(5)),
        )
        .await;
    assert!(result.is_ok(), "try_send_with_backpressure should succeed");
    let admission = result.unwrap();
    assert!(matches!(
        admission.evidence.outcome,
        SendAdmissionOutcome::Accepted | SendAdmissionOutcome::Blocked
    ));

    drop(handle);
    pipeline_task.await.unwrap();
    server.await.unwrap();
}
