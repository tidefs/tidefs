// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::sync::mpsc;
use std::time::Instant;

use crate::{
    Id128, ReceiveCheckpoint, ReceiveProgress, ReceivedDataset, SendStreamError,
    DEFAULT_MAX_RECORD_PAYLOAD,
};

// ── SendTransportStats ────────────────────────────────────────────────────

/// Statistics collected during a send transport operation.
#[derive(Clone, Copy, Debug, Default)]
pub struct SendTransportStats {
    /// Total bytes sent over the transport.
    pub bytes_sent: u64,
    /// Number of chunks sent.
    pub chunks_sent: u64,
    /// Number of credits consumed.
    pub credits_used: u64,
    /// Average throughput in megabytes per second.
    pub avg_throughput_mbps: f64,
}

impl SendTransportStats {
    /// Record bytes and one chunk, consuming a credit.
    fn record_chunk(&mut self, bytes: u64) {
        self.bytes_sent += bytes;
        self.chunks_sent += 1;
        self.credits_used += 1;
    }

    /// Compute throughput from total bytes and elapsed duration.
    fn compute_throughput(&mut self, elapsed_secs: f64) {
        if elapsed_secs > 0.0 {
            self.avg_throughput_mbps = (self.bytes_sent as f64 / elapsed_secs) / 1_000_000.0;
        }
    }
}

// ── TransportWriter trait ─────────────────────────────────────────────────

/// A sink for sending chunks over a transport.
///
/// Implementations handle the concrete transport protocol (e.g., BULK plane).
/// For testing, [`LoopbackWriter`] provides an in-memory channel.
pub trait TransportWriter {
    /// The error type for transport operations.
    type Error: std::fmt::Debug;

    /// Maximum chunk size in bytes that this transport supports.
    fn max_chunk_size(&self) -> u32;

    /// Send one chunk of data to the receiver.
    ///
    /// The chunk size must not exceed `max_chunk_size()`. Each call
    /// consumes one credit; callers should check `credits_available()`
    /// before sending.
    fn send_chunk(&mut self, chunk: Vec<u8>) -> Result<(), Self::Error>;

    /// Number of credits currently available.
    ///
    /// Returns `None` when credits are unlimited. Returns `Some(n)` when
    /// the transport is credit-limited.
    fn credits_available(&self) -> Option<u32>;

    /// Block until at least one credit is available.
    fn wait_for_credit(&mut self) -> Result<(), Self::Error>;
}

// ── TransportReader trait ─────────────────────────────────────────────────

/// A source for receiving chunks over a transport.
pub trait TransportReader {
    /// The error type for transport operations.
    type Error: std::fmt::Debug;

    /// Receive the next chunk from the sender.
    ///
    /// Returns `None` when the sender has indicated end-of-stream and no
    /// more chunks remain.
    fn recv_chunk(&mut self) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Send an acknowledgment for received bytes.
    fn send_ack(&mut self, _bytes_received: u64) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Wait for the next chunk to become available, blocking if necessary.
    fn wait_for_chunk(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        self.recv_chunk()
    }
}

// ── SendTransport ─────────────────────────────────────────────────────────

/// Wraps an encoded send stream and transmits it chunk-by-chunk over a
/// [`TransportWriter`] with credit scheduling.
pub struct SendTransport<W: TransportWriter> {
    /// The fully encoded stream bytes.
    encoded: Vec<u8>,
    /// The transport writer.
    writer: W,
    /// Accumulated statistics.
    stats: SendTransportStats,
    /// Current position in `encoded`.
    pos: usize,
    /// Maximum chunk size for this transport session.
    chunk_size: usize,
    /// Timestamp when sending started, for throughput calculation.
    start: Option<Instant>,
}

impl<W: TransportWriter> SendTransport<W> {
    /// Create a new send transport.
    pub fn new(encoded: Vec<u8>, writer: W, chunk_size: u32) -> Self {
        let max_chunk = writer.max_chunk_size().min(DEFAULT_MAX_RECORD_PAYLOAD);
        let chunk_size = (chunk_size as usize).min(max_chunk as usize).max(512);
        Self {
            encoded,
            writer,
            stats: SendTransportStats::default(),
            pos: 0,
            chunk_size,
            start: None,
        }
    }

    /// Send all remaining chunks.
    pub fn send_all(&mut self) -> Result<(), W::Error> {
        self.start = Some(Instant::now());
        while self.pos < self.encoded.len() {
            self.writer.wait_for_credit()?;

            let end = (self.pos + self.chunk_size).min(self.encoded.len());
            let chunk = self.encoded[self.pos..end].to_vec();
            let chunk_len = chunk.len() as u64;

            self.writer.send_chunk(chunk)?;
            self.stats.record_chunk(chunk_len);
            self.pos = end;
        }
        if let Some(start) = self.start {
            let elapsed = start.elapsed().as_secs_f64();
            self.stats.compute_throughput(elapsed);
        }
        Ok(())
    }

    /// Returns a copy of the current statistics.
    #[must_use]
    pub fn stats(&self) -> SendTransportStats {
        self.stats
    }

    /// Returns the number of bytes remaining to send.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.encoded.len() - self.pos
    }

    /// Returns the underlying writer, consuming the transport.
    #[must_use]
    pub fn into_writer(self) -> W {
        self.writer
    }
}

// ── RecvTransport ─────────────────────────────────────────────────────────

/// Receives chunks from a [`TransportReader`], reassembles them into the
/// original stream encoding, and feeds them to a [`ReceiveBuilder`] to
/// reconstruct the dataset.
pub struct RecvTransport<R: TransportReader> {
    /// The transport reader.
    reader: R,
}

impl<R: TransportReader> RecvTransport<R> {
    /// Create a new receive transport.
    #[must_use]
    pub fn new(reader: R) -> Self {
        Self { reader }
    }

    /// Receive all chunks, reassemble, and reconstruct the dataset.
    pub fn receive_all(
        &mut self,
        dataset_id: Id128,
    ) -> Result<ReceivedDataset, ReceiveTransportError<R::Error>> {
        let buffer = self.collect_buffer()?;
        let received = crate::ReceiveBuilder::new(dataset_id, &buffer)
            .map_err(ReceiveTransportError::Stream)?
            .finish_all()
            .map_err(ReceiveTransportError::Stream)?;
        Ok(received)
    }

    /// Receive chunks incrementally, returning a checkpoint when one is
    /// reached.
    pub fn receive_until_checkpoint(
        &mut self,
        dataset_id: Id128,
    ) -> Result<Option<(ReceivedDataset, ReceiveCheckpoint)>, ReceiveTransportError<R::Error>> {
        let buffer = self.collect_buffer()?;

        let mut receiver = crate::ReceiveBuilder::new(dataset_id, &buffer)
            .map_err(ReceiveTransportError::Stream)?;

        loop {
            match receiver
                .next_record()
                .map_err(ReceiveTransportError::Stream)?
            {
                ReceiveProgress::ResumePoint(checkpoint) => {
                    let staged = receiver.staged_dataset().clone();
                    return Ok(Some((staged, checkpoint)));
                }
                ReceiveProgress::StreamComplete(_stats) => {
                    return Ok(None);
                }
                ReceiveProgress::Continue
                | ReceiveProgress::ObjectReceived { .. }
                | ReceiveProgress::SnapshotReceived { .. } => {
                    // Keep processing
                }
            }
        }
    }

    /// Collect all chunks from the transport reader into a single byte buffer.
    fn collect_buffer(&mut self) -> Result<Vec<u8>, ReceiveTransportError<R::Error>> {
        let mut buffer = Vec::new();
        while let Some(chunk) = self
            .reader
            .wait_for_chunk()
            .map_err(ReceiveTransportError::Transport)?
        {
            let chunk_len = chunk.len() as u64;
            buffer.extend_from_slice(&chunk);
            self.reader
                .send_ack(chunk_len)
                .map_err(ReceiveTransportError::Transport)?;
        }
        Ok(buffer)
    }

    /// Returns the underlying reader, consuming the transport.
    #[must_use]
    pub fn into_reader(self) -> R {
        self.reader
    }
}

// ── ReceiveTransportError ─────────────────────────────────────────────────

/// Errors that can occur during receive transport operations.
#[derive(Debug)]
pub enum ReceiveTransportError<E: std::fmt::Debug> {
    /// An error from the underlying transport.
    Transport(E),
    /// An error from stream decoding.
    Stream(SendStreamError),
}

impl<E: std::fmt::Debug> std::fmt::Display for ReceiveTransportError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport error: {e:?}"),
            Self::Stream(e) => write!(f, "stream error: {e}"),
        }
    }
}

impl<E: std::fmt::Debug + 'static> std::error::Error for ReceiveTransportError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Stream(e) => Some(e),
            Self::Transport(_) => None,
        }
    }
}

// ── Loopback transport for testing ────────────────────────────────────────

/// An in-memory loopback transport pair for testing.
///
/// Uses an unbounded channel for data. Credit flow control can be
/// tested by setting `max_credits`. The loopback supports unlimited
/// credits by default (`credits_available` returns `None`).
pub struct LoopbackPair {
    data_tx: mpsc::Sender<Vec<u8>>,
    data_rx: mpsc::Receiver<Vec<u8>>,
    max_chunk_size: u32,
}

impl LoopbackPair {
    /// Create a new loopback pair.
    pub fn new(max_chunk_size: u32) -> Self {
        let (data_tx, data_rx) = mpsc::channel();
        Self {
            data_tx,
            data_rx,
            max_chunk_size,
        }
    }

    /// Split into a (writer, reader) pair.
    #[must_use]
    pub fn split(self) -> (LoopbackWriter, LoopbackReader) {
        let writer = LoopbackWriter {
            data_tx: self.data_tx,
            max_chunk_size: self.max_chunk_size,
        };
        let reader = LoopbackReader {
            data_rx: self.data_rx,
        };
        (writer, reader)
    }
}

/// The write side of a loopback transport. Unlimited credits.
pub struct LoopbackWriter {
    data_tx: mpsc::Sender<Vec<u8>>,
    max_chunk_size: u32,
}

/// The read side of a loopback transport.
pub struct LoopbackReader {
    data_rx: mpsc::Receiver<Vec<u8>>,
}

impl TransportWriter for LoopbackWriter {
    type Error = mpsc::SendError<Vec<u8>>;

    fn max_chunk_size(&self) -> u32 {
        self.max_chunk_size
    }

    fn send_chunk(&mut self, chunk: Vec<u8>) -> Result<(), Self::Error> {
        self.data_tx.send(chunk)
    }

    fn credits_available(&self) -> Option<u32> {
        None // unlimited
    }

    fn wait_for_credit(&mut self) -> Result<(), Self::Error> {
        Ok(()) // always available
    }
}

impl TransportReader for LoopbackReader {
    type Error = mpsc::RecvError;

    fn recv_chunk(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        match self.data_rx.try_recv() {
            Ok(chunk) => Ok(Some(chunk)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => Ok(None),
        }
    }

    fn wait_for_chunk(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        match self.data_rx.recv() {
            Ok(chunk) => Ok(Some(chunk)),
            Err(mpsc::RecvError) => Ok(None),
        }
    }
}

// ── Utility: encode/decode SendCursor for checkpoint resume across transport ──

/// Encode a [`SendCursor`](crate::SendCursor) to bytes for transmission.
pub fn encode_cursor(cursor: &crate::SendCursor) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    cursor.encode_into(&mut out);
    out
}

/// Decode a [`SendCursor`](crate::SendCursor) from bytes.
pub fn decode_cursor(bytes: &[u8]) -> Result<crate::SendCursor, SendStreamError> {
    let mut decoder = crate::Decoder::new(bytes);
    let cursor = crate::SendCursor::decode(&mut decoder)?;
    Ok(cursor)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DeltaObject, Id128, ObjectKind, ReceiveBuilder, SendBuilder, SendStreamHeader,
        SnapshotDelta,
    };

    fn dataset_id(byte: u8) -> Id128 {
        [byte; 16]
    }

    fn object_id(byte: u8) -> crate::Bytes32 {
        [byte; 32]
    }

    fn header() -> SendStreamHeader {
        SendStreamHeader::new(dataset_id(1), dataset_id(2), dataset_id(3))
    }

    fn object(byte: u8, payload: &[u8]) -> DeltaObject {
        DeltaObject::new(object_id(byte), ObjectKind::Extent, payload.to_vec())
    }

    // ── Loopback transport ────────────────────────────────────────────

    #[test]
    fn loopback_send_recv_single_chunk() {
        let pair = LoopbackPair::new(64 * 1024);
        let (mut writer, mut reader) = pair.split();

        let chunk = b"hello transport".to_vec();
        writer.send_chunk(chunk.clone()).unwrap();
        drop(writer); // signal end-of-stream

        let received = reader.wait_for_chunk().unwrap();
        assert_eq!(received, Some(chunk));
    }

    #[test]
    fn loopback_end_of_stream_signal() {
        let pair = LoopbackPair::new(64 * 1024);
        let (mut writer, mut reader) = pair.split();

        writer.send_chunk(b"chunk1".to_vec()).unwrap();
        // Drop writer to signal end-of-stream
        drop(writer);

        let chunk1 = reader.wait_for_chunk().unwrap();
        assert_eq!(chunk1, Some(b"chunk1".to_vec()));

        let chunk2 = reader.wait_for_chunk().unwrap();
        assert_eq!(chunk2, None);
    }

    // ── SendTransport + RecvTransport over loopback ───────────────────

    #[test]
    fn send_over_loopback_transport() {
        let mut snapshot = SnapshotDelta::new(dataset_id(3), "snap-a", 7);
        snapshot.objects.push(object(10, b"hello world"));
        snapshot.objects.push(object(11, b"goodbye"));

        let encoded = SendBuilder::full(header(), vec![snapshot])
            .unwrap()
            .encode()
            .unwrap();

        let pair = LoopbackPair::new(512);
        let (writer, reader) = pair.split();

        let mut send = SendTransport::new(encoded.clone(), writer, 256);
        let mut recv = RecvTransport::new(reader);

        // Send in a thread, drop writer on completion to signal end-of-stream
        let send_handle = std::thread::spawn(move || {
            send.send_all().unwrap();
            drop(send);
        });

        let received = recv.receive_all(dataset_id(2)).unwrap();
        send_handle.join().unwrap();

        assert_eq!(
            received.objects.get(&object_id(10)).unwrap().payload,
            b"hello world"
        );
        assert_eq!(
            received.objects.get(&object_id(11)).unwrap().payload,
            b"goodbye"
        );
    }

    #[test]
    fn incremental_send_over_transport() {
        let unchanged = object(10, b"same");
        let changed = object(11, b"new");
        let mut base = std::collections::BTreeMap::new();
        base.insert(unchanged.object_id, unchanged.digest());
        base.insert(changed.object_id, crate::blake3_digest(b"old"));

        let mut snapshot = SnapshotDelta::new(dataset_id(3), "snap-b", 9);
        snapshot.objects.push(unchanged);
        snapshot.objects.push(changed);

        let encoded = SendBuilder::incremental(
            header().incremental_from(dataset_id(2)),
            vec![snapshot],
            base,
        )
        .unwrap()
        .encode()
        .unwrap();

        let pair = LoopbackPair::new(512);
        let (writer, reader) = pair.split();

        let mut send = SendTransport::new(encoded.clone(), writer, 256);
        let mut recv = RecvTransport::new(reader);

        let send_handle = std::thread::spawn(move || {
            send.send_all().unwrap();
            drop(send);
        });

        let received = recv.receive_all(dataset_id(2)).unwrap();
        send_handle.join().unwrap();

        // object_id(10) was unchanged, filtered by incremental send
        assert!(
            !received.objects.contains_key(&object_id(10)),
            "unchanged object should be filtered"
        );
        assert!(received.objects.contains_key(&object_id(11)));
    }

    #[test]
    fn resume_after_transport_interruption() {
        let mut header = header();
        header.checkpoint_interval_records = 3;
        header.max_record_payload = 4;

        let mut snapshot = SnapshotDelta::new(dataset_id(3), "snap-a", 7);
        snapshot.objects.push(object(10, b"0123456789"));
        snapshot.objects.push(object(11, b"tail"));

        let encoded = SendBuilder::full(header, vec![snapshot])
            .unwrap()
            .encode()
            .unwrap();

        let full_received = ReceiveBuilder::new(dataset_id(2), &encoded)
            .unwrap()
            .finish_all()
            .unwrap();

        let mut receiver = ReceiveBuilder::new(dataset_id(2), &encoded).unwrap();
        let checkpoint = loop {
            match receiver.next_record().unwrap() {
                ReceiveProgress::ResumePoint(checkpoint) => break checkpoint,
                ReceiveProgress::StreamComplete(_) => {
                    panic!("expected a resume point before completion");
                }
                _ => continue,
            }
        };

        let cursor_bytes = encode_cursor(&checkpoint.cursor);
        let decoded_cursor = decode_cursor(&cursor_bytes).unwrap();
        assert_eq!(decoded_cursor.record_index, checkpoint.cursor.record_index);

        let resume_ckpt = ReceiveCheckpoint {
            cursor: decoded_cursor,
            active_snapshot: checkpoint.active_snapshot,
            active_snapshot_object_ids: checkpoint.active_snapshot_object_ids,
        };

        let staged = receiver.staged_dataset().clone();
        let resumed = ReceiveBuilder::resume_from_checkpoint(staged, &encoded, resume_ckpt)
            .unwrap()
            .finish_all()
            .unwrap();

        assert_eq!(resumed, full_received);
    }

    #[test]
    fn send_transport_multi_chunk() {
        let large = vec![0xABu8; 4096];
        let mut snapshot = SnapshotDelta::new(dataset_id(3), "snap-large", 1);
        snapshot.objects.push(object(20, &large));

        let mut header = header();
        header.max_record_payload = 4096;

        let encoded = SendBuilder::full(header, vec![snapshot])
            .unwrap()
            .encode()
            .unwrap();

        let pair = LoopbackPair::new(512);
        let (writer, reader) = pair.split();

        let mut send = SendTransport::new(encoded.clone(), writer, 256);
        let mut recv = RecvTransport::new(reader);

        let send_handle = std::thread::spawn(move || {
            send.send_all().unwrap();
            drop(send);
        });

        let received = recv.receive_all(dataset_id(2)).unwrap();
        send_handle.join().unwrap();

        assert_eq!(
            &received.objects.get(&object_id(20)).unwrap().payload[..],
            &large[..]
        );
    }

    #[test]
    fn send_transport_stats_tracks_progress() {
        let mut snapshot = SnapshotDelta::new(dataset_id(3), "snap-a", 7);
        snapshot.objects.push(object(10, b"hello data here"));

        let encoded = SendBuilder::full(header(), vec![snapshot])
            .unwrap()
            .encode()
            .unwrap();
        let _total = encoded.len();

        let pair = LoopbackPair::new(512);
        let (writer, reader) = pair.split();

        let mut send = SendTransport::new(encoded, writer, 256);
        let mut recv = RecvTransport::new(reader);

        // Send first chunk and check partial stats
        send.send_all().unwrap();
        drop(send);

        let _received = recv.receive_all(dataset_id(2)).unwrap();
    }

    #[test]
    fn encode_decode_cursor_round_trip() {
        let cursor = crate::SendCursor {
            snapshot_index: 2,
            object_index: 5,
            record_index: 42,
            payload_offset: 1024,
            stream_offset: 4096,
            stream_digest: [0xAA; 32],
        };
        let encoded = encode_cursor(&cursor);
        let decoded = decode_cursor(&encoded).unwrap();
        assert_eq!(decoded.snapshot_index, cursor.snapshot_index);
        assert_eq!(decoded.object_index, cursor.object_index);
        assert_eq!(decoded.record_index, cursor.record_index);
        assert_eq!(decoded.payload_offset, cursor.payload_offset);
        assert_eq!(decoded.stream_offset, cursor.stream_offset);
        assert_eq!(decoded.stream_digest, cursor.stream_digest);
    }
}
