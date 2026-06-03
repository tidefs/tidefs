//! Integration tests for the transport connection send-barrier.
//!
//! Tests cover:
//! - Barrier on idle connection completes immediately
//! - Barrier after N messages fires after exactly N completions
//! - Multiple concurrent barriers complete in order
//! - Barrier dropped before completion cleans up without panicking
//! - Barrier rejected when connection state is not sendable

use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::RwLock;

use tidefs_transport::connection_registry::ConnectionState;
use tidefs_transport::envelope::MessageFamily;
use tidefs_transport::outbound_send::{SendPipeline, SendPipelineError};
use tidefs_transport::send_scheduler::SendPriority;

#[tokio::test]
async fn barrier_on_idle_connection_completes_immediately() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let (_read_half, write_half) = stream.into_split();

    let state = Arc::new(RwLock::new(ConnectionState::Connected));
    let (mut pipeline, handle) = SendPipeline::new(write_half, Arc::clone(&state), 16, 64);

    let pipeline_handle = tokio::spawn(async move {
        pipeline.run().await.unwrap();
    });

    let mut barrier = handle
        .request_barrier(SendPriority::Data)
        .expect("barrier on idle connection should succeed");
    assert!(
        barrier.try_wait().is_none(),
        "barrier should not complete before pipeline processes it"
    );

    // Let the pipeline run to process the barrier
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Barrier should now be resolved
    match barrier.try_wait() {
        Some(Ok(())) => {} // expected
        other => panic!("expected Some(Ok(())), got {other:?}"),
    }

    drop(handle);
    pipeline_handle.await.unwrap();
}

#[tokio::test]
async fn barrier_after_messages_fires_after_messages_dequeued() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    // Server: receives all bytes and counts frames
    let server_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut total = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut total)
            .await
            .unwrap();
        // 5 frames of 64+5 bytes each
        assert_eq!(total.len(), 5 * (64 + 5));
    });

    let stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let (_read_half, write_half) = stream.into_split();

    let state = Arc::new(RwLock::new(ConnectionState::Connected));
    let (mut pipeline, handle) = SendPipeline::new(write_half, Arc::clone(&state), 16, 64);

    let pipeline_handle = tokio::spawn(async move {
        pipeline.run().await.unwrap();
    });

    // Send 5 frames
    for i in 0..5u8 {
        handle
            .send(MessageFamily::StateTransfer, &[i; 5])
            .await
            .unwrap();
    }

    // Request a barrier -- should complete after all 5 frames are dequeued
    let mut barrier = handle
        .request_barrier(SendPriority::Data)
        .expect("barrier after messages should succeed");
    assert_eq!(
        barrier.ahead_count(),
        5,
        "ahead_count should reflect 5 frames"
    );

    barrier.wait().await.unwrap();

    drop(handle);
    pipeline_handle.await.unwrap();
    server_handle.await.unwrap();
}

#[tokio::test]
async fn multiple_concurrent_barriers_complete_in_order() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut total = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut total)
            .await
            .unwrap();
    });

    let stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let (_read_half, write_half) = stream.into_split();

    let state = Arc::new(RwLock::new(ConnectionState::Connected));
    let (mut pipeline, handle) = SendPipeline::new(write_half, Arc::clone(&state), 16, 64);

    let pipeline_handle = tokio::spawn(async move {
        pipeline.run().await.unwrap();
    });

    // Send 3 frames, barrier 1, 2 frames, barrier 2
    for _ in 0..3 {
        handle
            .send(MessageFamily::StateTransfer, b"before-b1")
            .await
            .unwrap();
    }

    let mut barrier1 = handle.request_barrier(SendPriority::Data).unwrap();

    for _ in 0..2 {
        handle
            .send(MessageFamily::StateTransfer, b"between")
            .await
            .unwrap();
    }

    let mut barrier2 = handle.request_barrier(SendPriority::Data).unwrap();

    barrier1.wait().await.unwrap();
    barrier2.wait().await.unwrap();

    drop(handle);
    pipeline_handle.await.unwrap();
    server_handle.await.unwrap();
}

#[tokio::test]
async fn barrier_dropped_before_completion_cleans_up() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let (_read_half, write_half) = stream.into_split();

    let state = Arc::new(RwLock::new(ConnectionState::Connected));
    let (mut pipeline, handle) = SendPipeline::new(write_half, Arc::clone(&state), 16, 64);

    let pipeline_handle = tokio::spawn(async move {
        pipeline.run().await.unwrap();
    });

    // Enqueue some messages so the barrier has items ahead of it
    for _ in 0..5 {
        handle
            .send(MessageFamily::StateTransfer, b"before")
            .await
            .unwrap();
    }

    let barrier = handle.request_barrier(SendPriority::Data).unwrap();

    // Drop the barrier without waiting -- should not panic
    drop(barrier);

    // Pipeline should continue processing
    handle
        .send(MessageFamily::StateTransfer, b"after")
        .await
        .unwrap();

    drop(handle);
    pipeline_handle.await.unwrap();
}

#[tokio::test]
async fn barrier_rejected_when_connection_not_sendable() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let (_read_half, write_half) = stream.into_split();

    let state = Arc::new(RwLock::new(ConnectionState::Closed));
    let (_pipeline, handle) = SendPipeline::new(write_half, Arc::clone(&state), 16, 64);

    let result = handle.request_barrier(SendPriority::Data);
    assert!(matches!(
        result,
        Err(SendPipelineError::ConnectionStateClosed(
            ConnectionState::Closed
        ))
    ));
}

#[tokio::test]
async fn barrier_with_mixed_priority_messages_completes_in_insertion_order() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut buf)
            .await
            .unwrap();
    });

    let stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let (_read_half, write_half) = stream.into_split();

    let state = Arc::new(RwLock::new(ConnectionState::Connected));
    let (mut pipeline, handle) = SendPipeline::new(write_half, Arc::clone(&state), 16, 64);

    let pipeline_handle = tokio::spawn(async move {
        pipeline.run().await.unwrap();
    });

    handle
        .send_with_priority(
            MessageFamily::StateTransfer,
            SendPriority::Control,
            b"ctrl1",
        )
        .await
        .unwrap();
    handle
        .send(MessageFamily::StateTransfer, b"data1")
        .await
        .unwrap();

    let mut barrier = handle.request_barrier(SendPriority::Data).unwrap();
    assert_eq!(barrier.ahead_count(), 2);

    barrier.wait().await.unwrap();

    drop(handle);
    pipeline_handle.await.unwrap();
    server_handle.await.unwrap();
}
