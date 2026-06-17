//! Send dispatch trait for pushing framed chunks through a transport layer.
//!
//! Provides a trait-based abstraction so the send-stream crate can push
//! [`FramedChunk`]s to different transport backends (loopback for testing,
//! TCP/simnet, or ublk block-device transport) without coupling to a
//! concrete protocol.

use crate::framer::{FramedChunk, FramedManifest};
use crate::LineageManifest;

/// Trait for dispatching framed chunks to a transport backend.
///
/// Implementations handle the concrete transport protocol. A no-op
/// implementation ([`NoOpDispatch`]) is provided for testing.
pub trait SendDispatch {
    /// The error type for dispatch operations.
    type Error: std::fmt::Debug;

    /// Push the send-lineage manifest before any object chunks.
    fn send_manifest(&mut self, _manifest: FramedManifest) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Push one framed chunk to the transport.
    ///
    /// The implementation is responsible for any framing, credit
    /// management, or flow control needed by the transport protocol.
    fn send_chunk(&mut self, chunk: FramedChunk) -> Result<(), Self::Error>;

    /// Flush any buffered chunks through the transport.
    ///
    /// Default implementation is a no-op.
    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// A no-op dispatch for testing the framing pipeline without a real transport.
///
/// Stores all dispatched chunks in a `Vec` for later inspection.
#[derive(Debug, Default)]
pub struct NoOpDispatch {
    /// Lineage manifests dispatched so far.
    pub manifests_sent: Vec<FramedManifest>,
    /// Chunks dispatched so far.
    pub chunks_sent: Vec<FramedChunk>,
    /// Total bytes dispatched.
    pub total_bytes_sent: u64,
}

impl NoOpDispatch {
    /// Create a new no-op dispatch buffer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            manifests_sent: Vec::new(),
            chunks_sent: Vec::new(),
            total_bytes_sent: 0,
        }
    }
}

impl SendDispatch for NoOpDispatch {
    type Error = std::convert::Infallible;

    fn send_manifest(&mut self, manifest: FramedManifest) -> Result<(), Self::Error> {
        self.manifests_sent.push(manifest);
        Ok(())
    }

    fn send_chunk(&mut self, chunk: FramedChunk) -> Result<(), Self::Error> {
        self.total_bytes_sent += chunk.payload.len() as u64;
        self.chunks_sent.push(chunk);
        Ok(())
    }
}

/// Send the lineage manifest first, then all chunks for one object.
///
/// # Errors
///
/// Returns the first dispatch error encountered.
pub fn send_manifest_then_object<D: SendDispatch>(
    manifest: LineageManifest,
    object_id: [u8; 32],
    data: &[u8],
    chunk_size: usize,
    dispatch: &mut D,
) -> Result<crate::framer::ChunkFramer, D::Error> {
    dispatch.send_manifest(FramedManifest::new(manifest))?;
    send_object(object_id, data, chunk_size, dispatch)
}

/// Send all chunks from a [`ChunkFramer`](crate::framer::ChunkFramer)
/// through a dispatch.
///
/// # Errors
///
/// Returns the first dispatch error encountered.
pub fn send_object<D: SendDispatch>(
    object_id: [u8; 32],
    data: &[u8],
    chunk_size: usize,
    dispatch: &mut D,
) -> Result<crate::framer::ChunkFramer, D::Error> {
    let mut framer = crate::framer::ChunkFramer::new(object_id, data.to_vec(), chunk_size);
    while let Some(chunk) = framer.next_chunk() {
        dispatch.send_chunk(chunk)?;
    }
    dispatch.flush()?;
    Ok(framer)
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LineageManifest, SendStreamHeader};

    fn obj_id() -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = 0x42;
        id
    }

    fn manifest() -> LineageManifest {
        let header = SendStreamHeader::new([1; 16], [2; 16], [3; 16]);
        LineageManifest::full(&header, [4; 32])
    }

    #[test]
    fn noop_dispatch_collects_all_chunks() {
        let data = b"hello transport";
        let mut dispatch = NoOpDispatch::new();
        let framer = send_object(obj_id(), data, 4, &mut dispatch).unwrap();
        assert!(framer.is_exhausted());
        assert_eq!(dispatch.chunks_sent.len(), 4); // ceil(15/4) = 4
        assert_eq!(dispatch.total_bytes_sent, 15);
        for chunk in &dispatch.chunks_sent {
            assert!(chunk.verify_auth_tag());
        }
    }

    #[test]
    fn send_object_single_chunk() {
        let data = b"tiny";
        let mut dispatch = NoOpDispatch::new();
        let framer = send_object(obj_id(), data, 1024, &mut dispatch).unwrap();
        assert_eq!(framer.total_chunks(), 1);
        assert_eq!(dispatch.chunks_sent.len(), 1);
        assert_eq!(dispatch.total_bytes_sent, 4);
        assert_eq!(dispatch.chunks_sent[0].payload, data);
    }

    #[test]
    fn send_object_empty_data() {
        let data = b"";
        let mut dispatch = NoOpDispatch::new();
        let framer = send_object(obj_id(), data, 256, &mut dispatch).unwrap();
        assert_eq!(framer.total_chunks(), 0);
        assert_eq!(dispatch.chunks_sent.len(), 0);
        assert_eq!(dispatch.total_bytes_sent, 0);
    }

    #[test]
    fn send_manifest_then_object_dispatches_manifest_first() {
        let data = b"with lineage";
        let mut dispatch = NoOpDispatch::new();
        let framer =
            send_manifest_then_object(manifest(), obj_id(), data, 4, &mut dispatch).unwrap();
        assert!(framer.is_exhausted());
        assert_eq!(dispatch.manifests_sent.len(), 1);
        assert!(dispatch.manifests_sent[0].verify_auth_tag());
        assert_eq!(dispatch.chunks_sent.len(), data.len().div_ceil(4));
    }

    #[test]
    fn send_object_large_data_many_chunks() {
        let data = vec![0xAAu8; 5000];
        let mut dispatch = NoOpDispatch::new();
        let framer = send_object(obj_id(), &data, 512, &mut dispatch).unwrap();
        let expected = 5000usize.div_ceil(512);
        assert_eq!(framer.chunks_emitted() as usize, expected);
        assert_eq!(dispatch.chunks_sent.len(), expected);
        assert_eq!(dispatch.total_bytes_sent, 5000);
        assert!(dispatch.chunks_sent.last().unwrap().is_last);
    }
}
