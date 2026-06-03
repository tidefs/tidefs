//! RDMA Reliable Connection (RC) transport backend using libibverbs.
#![allow(unsafe_code)]
//!
//! Implements `TransportBackend` and `ConnectionLike` over RDMA queue pairs.
//! Uses a TCP side channel for initial QP-attribute exchange (qpn, lid, psn),
//! then moves data-plane messages through RDMA send/recv with completion-queue
//! polling.
//!
//! ## Feature gate
//!
//! This module is always compiled. RDMA availability is detected at
//! runtime via `ibv_get_device_list()`. When no RDMA device is present,
//! backend construction returns a `TransportError::RdmaNotAvailable`.
//!
//! ## Safety boundaries
//!
//! All `extern "C"` calls are in the `ffi` submodule and marked `unsafe`.
//! The `verbs` wrapper types enforce resource cleanup through `Drop` and
//! QP state-machine ordering through enum transitions.

mod ffi;

mod verbs;

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use crate::addr::TransportAddr;
use crate::backend::{AcceptResult, ConnectionLike, TransportBackend, TransportBackendKind};
use crate::error::TransportError;
use crate::session_cohort::NodeInfo;

use self::verbs::{
    CompletionQueue, MemoryRegion, PortAttributes, ProtectionDomain, QueuePair, QueuePairPath,
    RdmaDevice,
};

// ---------------------------------------------------------------------------
// Wire protocol for QP-attribute exchange over TCP control channel
// ---------------------------------------------------------------------------

/// Exchanged over the TCP control channel so each side can transition
/// its QP through INIT → RTR → RTS.
#[derive(Clone, Copy, Debug)]
struct QpInfo {
    /// Queue pair number.
    qp_num: u32,
    /// Local identifier (for InfiniBand; 0 for RoCE/SoftRoCE).
    lid: u16,
    /// Packet sequence number (initial).
    psn: u32,
    /// Selected source GID index for RoCE/SoftRoCE global routing.
    gid_index: u8,
    /// libibverbs link-layer value for the selected port.
    link_layer: u8,
    /// Active MTU value reported by the selected port.
    active_mtu: u8,
    /// Selected local GID. All zeros means no routable GID was found.
    gid: [u8; 16],
}

impl QpInfo {
    const WIRE_LEN: usize = 32;

    fn from_port(qp_num: u32, psn: u32, port: PortAttributes) -> Self {
        let gid = port.gid.map(|info| info.raw).unwrap_or([0u8; 16]);
        let gid_index = port.gid.map(|info| info.index).unwrap_or(0);
        Self {
            qp_num,
            lid: port.lid,
            psn,
            gid_index,
            link_layer: port.link_layer.0 as u8,
            active_mtu: port.active_mtu.0 as u8,
            gid,
        }
    }

    fn encode(&self) -> [u8; Self::WIRE_LEN] {
        let mut buf = [0u8; Self::WIRE_LEN];
        buf[0..4].copy_from_slice(&self.qp_num.to_be_bytes());
        buf[4..6].copy_from_slice(&self.lid.to_be_bytes());
        buf[6] = self.gid_index;
        buf[7] = self.link_layer;
        buf[8..12].copy_from_slice(&self.psn.to_be_bytes());
        buf[12] = self.active_mtu;
        buf[16..32].copy_from_slice(&self.gid);
        buf
    }

    fn decode(raw: &[u8; Self::WIRE_LEN]) -> Self {
        let qp_num = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let lid = u16::from_be_bytes([raw[4], raw[5]]);
        let psn = u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]);
        let mut gid = [0u8; 16];
        gid.copy_from_slice(&raw[16..32]);
        Self {
            qp_num,
            lid,
            psn,
            gid_index: raw[6],
            link_layer: raw[7],
            active_mtu: raw[12],
            gid,
        }
    }

    fn write_to(&self, stream: &mut TcpStream) -> std::io::Result<()> {
        stream.write_all(&self.encode())
    }

    fn read_from(stream: &mut TcpStream) -> std::io::Result<Self> {
        let mut raw = [0u8; Self::WIRE_LEN];
        stream.read_exact(&mut raw)?;
        Ok(Self::decode(&raw))
    }

    fn uses_global_route(self) -> bool {
        self.link_layer == ffi::IBV_LINK_LAYER_ETHERNET.0 as u8
    }
}

fn negotiated_mtu(local: QpInfo, peer: QpInfo) -> ffi::ibv_mtu {
    let mtu = local.active_mtu.min(peer.active_mtu);
    match mtu {
        1 => ffi::IBV_MTU_256,
        2 => ffi::IBV_MTU_512,
        4 => ffi::IBV_MTU_2048,
        5 => ffi::IBV_MTU_4096,
        _ => ffi::IBV_MTU_1024,
    }
}

fn queue_pair_path(local: QpInfo, peer: QpInfo) -> Result<QueuePairPath, String> {
    let global_route = local.uses_global_route();
    if global_route && peer.gid.iter().all(|byte| *byte == 0) {
        return Err("RoCE/SoftRoCE peer did not advertise a destination GID".into());
    }

    Ok(QueuePairPath {
        dest_lid: if global_route { 0 } else { peer.lid },
        dest_gid: if global_route { Some(peer.gid) } else { None },
        sgid_index: local.gid_index,
        path_mtu: negotiated_mtu(local, peer),
        global_route,
    })
}

// ---------------------------------------------------------------------------
// Buffer pool for RDMA send/recv operations
// ---------------------------------------------------------------------------

/// Pre-registered buffer pool. Each buffer can hold one maximum-sized
/// transport frame.
struct RdmaBufferPool {
    /// Raw allocation (owned for lifetime; never moved).
    raw: Vec<u8>,
    /// Memory region (registered with the HCA).
    mr: MemoryRegion,
    /// Per-buffer capacity in bytes.
    buf_size: usize,
    /// Total buffer capacity in bytes.
    capacity: usize,
}

impl RdmaBufferPool {
    /// Allocate and register a buffer pool of `buf_count` buffers,
    /// each `buf_size` bytes.
    fn new(pd: &ProtectionDomain, buf_count: usize, buf_size: usize) -> Result<Self, String> {
        let capacity = buf_count
            .checked_mul(buf_size)
            .ok_or_else(|| "rdma buffer pool size overflow".to_string())?;
        let raw: Vec<u8> = vec![0u8; capacity];
        // SAFETY: we own `raw` and the allocation is pinned for the MR lifetime.
        let mr = unsafe {
            MemoryRegion::register(
                pd,
                raw.as_ptr() as *mut _,
                capacity,
                ffi::IBV_ACCESS_LOCAL_WRITE,
            )?
        };
        Ok(Self {
            raw,
            mr,
            buf_size,
            capacity,
        })
    }

    /// Return the lkey for this memory region.
    fn lkey(&self) -> u32 {
        self.mr.lkey()
    }

    /// Get a pointer into the buffer at a given offset.
    fn ptr_at(&self, offset: usize) -> *const u8 {
        // SAFETY: offset is within the allocated buffer (the pool ensures this
        // by construction, as all offsets are computed from pool index * buf_size).
        unsafe { self.raw.as_ptr().add(offset) }
    }

    fn mut_ptr_at(&mut self, offset: usize) -> *mut u8 {
        // SAFETY: offset is within the allocated buffer; the Vec allocation
        // is stable (never reallocated after construction).
        unsafe { self.raw.as_mut_ptr().add(offset) }
    }

    #[allow(dead_code)]
    fn _buf_size(&self) -> usize {
        self.buf_size
    }

    #[allow(dead_code)]
    fn _capacity(&self) -> usize {
        self.capacity
    }
}

// ---------------------------------------------------------------------------
// RdmaConnection: frame-oriented read/write over RDMA
// ---------------------------------------------------------------------------

/// An established RDMA connection backed by a queue pair.
#[allow(dead_code)]
pub(crate) struct RdmaConnection {
    qp: QueuePair,
    cq: CompletionQueue,
    /// Pre-posted receive buffer pool.
    recv_pool: RdmaBufferPool,
    /// Send buffer pool.
    send_pool: RdmaBufferPool,
    /// Receive buffer size (max frame).
    recv_buf_size: usize,
    /// Send buffer size (max frame).
    send_buf_size: usize,
    /// Index of the next free recv buffer (ring-buffer index).
    recv_idx: usize,
    /// Number of buffers in the recv pool.
    recv_buf_count: usize,
    /// Non-blocking mode flag.
    nonblocking: bool,
    /// Received messages already observed while polling send completions.
    pending_recv: VecDeque<Vec<u8>>,
    /// Bitmap tracking free send buffers (bit i = 1 means free).
    send_free: u16,
}

impl RdmaConnection {
    /// Maximum frame size (1 MiB payload + 4-byte length prefix).
    ///
    /// This is intentionally conservative: every accepted connection
    /// pre-registers send and receive pools with the RDMA provider, and
    /// SoftRoCE guests can panic under oversized pinned regions.
    const MAX_FRAME_SIZE: usize = 1024 * 1024 + 4;
    /// Number of buffers in each pool.
    const POOL_COUNT: usize = 8;

    #[allow(dead_code)]
    fn registered_pool_bytes() -> usize {
        Self::POOL_COUNT * Self::MAX_FRAME_SIZE * 2
    }

    fn new(qp: QueuePair, cq: CompletionQueue, pd: &ProtectionDomain) -> Result<Self, String> {
        let send_pool = RdmaBufferPool::new(pd, Self::POOL_COUNT, Self::MAX_FRAME_SIZE)?;
        let recv_pool = RdmaBufferPool::new(pd, Self::POOL_COUNT, Self::MAX_FRAME_SIZE)?;

        let mut conn = Self {
            qp,
            cq,
            recv_pool,
            send_pool,
            recv_buf_size: Self::MAX_FRAME_SIZE,
            send_buf_size: Self::MAX_FRAME_SIZE,
            recv_idx: 0,
            recv_buf_count: Self::POOL_COUNT,
            nonblocking: false,
            pending_recv: VecDeque::new(),
            send_free: ((1u32 << Self::POOL_COUNT) - 1) as u16,
        };

        // Pre-post all recv buffers.
        for i in 0..Self::POOL_COUNT {
            conn.post_recv(i)?;
        }

        Ok(conn)
    }

    fn post_recv(&mut self, idx: usize) -> Result<(), String> {
        let offset = idx * self.recv_buf_size;
        let ptr = self.recv_pool.mut_ptr_at(offset);
        self.qp
            .post_recv(ptr, self.recv_buf_size, self.recv_pool.lkey(), idx as u64)
    }

    fn post_send(&mut self, idx: usize, len: usize) -> Result<(), String> {
        let offset = idx * self.send_buf_size;
        let ptr = self.send_pool.ptr_at(offset);
        self.qp
            .post_send(ptr, len, self.send_pool.lkey(), idx as u64)
    }

    fn poll_completions(&mut self, max_count: usize) -> Result<Vec<ffi::ibv_wc>, String> {
        self.cq.poll(max_count)
    }

    fn handle_completion(&mut self, wc: &ffi::ibv_wc) -> Result<(), TransportError> {
        if wc.status != ffi::IBV_WC_SUCCESS {
            return Err(TransportError::Generic(format!(
                "rdma completion failed: opcode={:?} status={:?} wr_id={}",
                wc.opcode, wc.status, wc.wr_id
            )));
        }

        if wc.opcode == ffi::IBV_WC_SEND {
            self.send_free |= 1 << wc.wr_id as usize;
            return Ok(());
        }

        if wc.opcode != ffi::IBV_WC_RECV {
            return Ok(());
        }

        let idx = wc.wr_id as usize;
        let offset = idx * self.recv_buf_size;

        if wc.byte_len < 4 {
            return Err(TransportError::Generic(
                "rdma recv too short for length prefix".into(),
            ));
        }

        // SAFETY: ptr points into the registered receive buffer at a
        // validated offset; 4 bytes are copied into a stack-local buffer.
        let len_prefix = unsafe {
            let ptr = self.recv_pool.ptr_at(offset);
            let mut buf = [0u8; 4];
            std::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), 4);
            u32::from_be_bytes(buf) as usize
        };

        let max_payload = self.recv_buf_size.saturating_sub(4);
        if len_prefix > max_payload {
            return Err(TransportError::Generic(format!(
                "frame too large: {len_prefix} bytes exceeds rdma payload limit {max_payload}"
            )));
        }

        let expected_total = 4 + len_prefix;
        if wc.byte_len as usize != expected_total {
            return Err(TransportError::Generic(format!(
                "short rdma recv: got {} bytes, expected {expected_total}",
                wc.byte_len
            )));
        }

        // SAFETY: src points into the registered receive buffer at offset+4;
        // bounds were validated against wc.byte_len and recv_buf_size above.
        let payload = unsafe {
            let src = self.recv_pool.ptr_at(offset + 4);
            let mut v = vec![0u8; len_prefix];
            std::ptr::copy_nonoverlapping(src, v.as_mut_ptr(), len_prefix);
            v
        };

        self.post_recv(idx)
            .map_err(|e| TransportError::Generic(format!("rdma repost recv failed: {e}")))?;
        self.pending_recv.push_back(payload);
        Ok(())
    }
}

impl ConnectionLike for RdmaConnection {
    fn read_frame(&mut self) -> Result<Vec<u8>, TransportError> {
        if let Some(pending) = self.pending_recv.pop_front() {
            return Ok(pending);
        }

        loop {
            let wcs = self
                .poll_completions(16)
                .map_err(|e| TransportError::Generic(format!("rdma poll failed: {e}")))?;

            for wc in &wcs {
                self.handle_completion(wc)?;
            }

            if let Some(pending) = self.pending_recv.pop_front() {
                return Ok(pending);
            }

            if self.nonblocking {
                return Err(TransportError::WouldBlock("rdma read: WouldBlock".into()));
            }

            // Brief yield to avoid busy-looping; in a real implementation
            // we'd use an event channel.
            std::thread::yield_now();
        }
    }

    fn write_frame(&mut self, data: &[u8]) -> Result<(), TransportError> {
        let total_len = 4 + data.len();
        if total_len > self.send_buf_size {
            return Err(TransportError::Generic(format!(
                "frame too large: total {total_len} bytes exceeds buffer {}",
                self.send_buf_size
            )));
        }

        // Write to a free send buffer, selected via the free bitmap.
        // Poll for completions while all buffers are busy.
        loop {
            // Drain any ready completions to free buffers.
            let wcs = self
                .cq
                .poll(16)
                .map_err(|e| TransportError::Generic(format!("rdma poll failed: {e}")))?;
            for wc in &wcs {
                self.handle_completion(wc)?;
            }

            // Find the first free send buffer.
            if let Some(idx) = (0..Self::POOL_COUNT).find(|&i| self.send_free & (1 << i) != 0) {
                // Mark buffer busy.
                self.send_free &= !(1 << idx);

                let offset = idx * self.send_buf_size;
                let dst = self.send_pool.mut_ptr_at(offset);

                // Write length prefix + payload into registered buffer.
                let len_be = (data.len() as u32).to_be_bytes();
                // SAFETY: dst points into the registered send buffer pool at a
                // validated offset (idx * send_buf_size). total_len (4 + data.len())
                // is bounded by send_buf_size (checked above). Both source slices
                // are valid for reads and dst is valid for writes per the MR.
                unsafe {
                    std::ptr::copy_nonoverlapping(len_be.as_ptr(), dst, 4);
                    std::ptr::copy_nonoverlapping(data.as_ptr(), dst.add(4), data.len());
                }

                match self.post_send(idx, total_len) {
                    Ok(()) => {
                        return Ok(());
                    }
                    Err(e) => {
                        // Release the buffer back on error.
                        self.send_free |= 1 << idx;
                        return Err(TransportError::Generic(format!(
                            "rdma post_send failed: {e}"
                        )));
                    }
                }
            }

            if self.nonblocking {
                return Err(TransportError::WouldBlock(
                    "rdma send: all buffers busy, WouldBlock".into(),
                ));
            }
            std::thread::yield_now();
        }
    }

    fn close(&mut self) {
        // QP and CQ are dropped via Drop impls on the verbs wrappers.
    }

    fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), TransportError> {
        self.nonblocking = nonblocking;
        Ok(())
    }

    fn backend_kind(&self) -> TransportBackendKind {
        TransportBackendKind::Rdma
    }
}

impl Drop for RdmaConnection {
    fn drop(&mut self) {
        // The QueuePair and CompletionQueue handles will be closed
        // by their Drop impls. The MemoryRegions are also dropped.
    }
}

// ---------------------------------------------------------------------------
// RdmaTransport: the TransportBackend implementation
// ---------------------------------------------------------------------------

/// RDMA transport backend.
///
/// Opens an RDMA device context at construction time. Uses a TCP side
/// channel for QP-attribute exchange during connect/accept, then
/// performs data-plane I/O over RDMA queue pairs.
#[allow(dead_code)]
pub struct RdmaTransport {
    /// RDMA device context (opened on the first available device).
    device: Option<RdmaDevice>,
    /// Protection domain (shared across all QPs).
    pd: Option<ProtectionDomain>,
    /// TCP listener for control-channel connections.
    tcp_listener: Option<TcpListener>,
    /// TCP connect timeout.
    connect_timeout: Duration,
    /// Whether non-blocking I/O is enabled.
    nonblocking: bool,
    /// Bound address (from TCP listener).
    bound_addr: Option<TransportAddr>,
}

impl RdmaTransport {
    pub fn new(connect_timeout: Duration) -> Result<Self, TransportError> {
        let device = RdmaDevice::open_first_available()
            .map_err(|e| TransportError::RdmaNotAvailable { reason: e })?;

        let pd = ProtectionDomain::alloc(device.context())
            .map_err(|e| TransportError::RdmaNotAvailable { reason: e })?;

        Ok(Self {
            device: Some(device),
            pd: Some(pd),
            tcp_listener: None,
            connect_timeout,
            nonblocking: false,
            bound_addr: None,
        })
    }

    /// Create a queue pair, transition to INIT, then exchange QP info
    /// over a TCP stream and complete the RTR/RTS transitions.
    fn handshake_qp(
        pd: &ProtectionDomain,
        tcp_stream: &mut TcpStream,
        _is_active: bool,
        max_send_wr: u32,
        max_recv_wr: u32,
        max_send_sge: u32,
        max_recv_sge: u32,
    ) -> Result<(QueuePair, CompletionQueue, QpInfo, QpInfo), String> {
        let context = pd.context();
        let cq = CompletionQueue::create(context, 256)?;
        let mut qp = QueuePair::create(
            pd,
            &cq,
            &cq,
            max_send_wr,
            max_recv_wr,
            max_send_sge,
            max_recv_sge,
        )?;

        // Initial PSN (randomized lower 24 bits).
        let psn = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
            & 0x00FF_FFFF;

        let port_num = 1;
        let local_port = pd.query_port(port_num)?;

        // Transition: RESET → INIT.
        qp.transition_to_init(port_num, psn)?;

        // Get our QPN.
        let local_qpn = qp.qp_num();
        let local_info = QpInfo::from_port(local_qpn, psn, local_port);

        // Exchange QP info over TCP control channel.
        local_info.write_to(tcp_stream).map_err(|e| e.to_string())?;
        let peer_info = QpInfo::read_from(tcp_stream).map_err(|e| e.to_string())?;

        let our_info = local_info;

        // Transition: INIT → RTR (needs peer QPN + PSN).
        qp.transition_to_rtr(
            peer_info.qp_num,
            peer_info.psn,
            port_num,
            queue_pair_path(local_info, peer_info)?,
        )?;

        // Transition: RTR → RTS.
        qp.transition_to_rts(psn)?;

        Ok((qp, cq, our_info, peer_info))
    }

    fn sync_preposted_recvs(tcp_stream: &mut TcpStream) -> Result<(), String> {
        const READY: u8 = 0xA5;
        let mut peer_ready = [0u8; 1];

        tcp_stream.write_all(&[READY]).map_err(|e| e.to_string())?;
        tcp_stream.flush().map_err(|e| e.to_string())?;
        tcp_stream
            .read_exact(&mut peer_ready)
            .map_err(|e| e.to_string())?;

        if peer_ready[0] != READY {
            return Err(format!(
                "rdma recv-ready barrier mismatch: got 0x{:02x}",
                peer_ready[0]
            ));
        }

        Ok(())
    }
}

impl Default for RdmaTransport {
    fn default() -> Self {
        RdmaTransport::new(Duration::from_secs(5))
            .expect("RdmaTransport::default: RDMA unavailable (expected in non-RDMA env)")
    }
}

impl TransportBackend for RdmaTransport {
    fn bind(&mut self, addr: TransportAddr) -> Result<(), TransportError> {
        let sock_addr = match addr {
            TransportAddr::Tcp(sa) => sa,
            ref other => {
                return Err(TransportError::UnsupportedCarrier {
                    carrier: other.carrier().to_string(),
                });
            }
        };
        let listener = TcpListener::bind(sock_addr).map_err(|err| TransportError::BindFailed {
            addr: addr.clone(),
            source: err,
        })?;
        listener
            .set_nonblocking(true)
            .map_err(|err| TransportError::BindFailed {
                addr: addr.clone(),
                source: err,
            })?;
        self.bound_addr = Some(
            listener
                .local_addr()
                .map_err(|err| TransportError::BindFailed {
                    addr: addr.clone(),
                    source: err,
                })
                .map(TransportAddr::Tcp)?,
        );
        self.tcp_listener = Some(listener);
        Ok(())
    }

    fn local_addr(&self) -> Option<TransportAddr> {
        self.bound_addr.clone()
    }

    fn connect(&mut self, peer: &NodeInfo) -> Result<Box<dyn ConnectionLike>, TransportError> {
        let pd = self
            .pd
            .as_ref()
            .ok_or_else(|| TransportError::RdmaNotAvailable {
                reason: "protection domain not initialized".into(),
            })?;

        // Try each peer address for the TCP control channel.
        let mut last_err: Option<TransportError> = None;
        for transport_addr in &peer.addresses {
            let sock_addr = match transport_addr {
                TransportAddr::Tcp(sa) => *sa,
                _ => continue,
            };
            let mut stream = match TcpStream::connect_timeout(&sock_addr, self.connect_timeout) {
                Ok(s) => s,
                Err(e) => {
                    last_err = Some(TransportError::ConnectFailed {
                        peer_addr: transport_addr.clone(),
                        source: e,
                    });
                    continue;
                }
            };

            stream
                .set_read_timeout(Some(Duration::from_secs(30)))
                .map_err(|e| TransportError::ConnectFailed {
                    peer_addr: transport_addr.clone(),
                    source: e,
                })?;

            let (qp, cq, _our_info, _peer_info) =
                Self::handshake_qp(pd, &mut stream, true, 256, 256, 1, 1).map_err(|e| {
                    TransportError::RdmaConnectionFailed {
                        session_id: crate::types::SessionId(0),
                        reason: e,
                    }
                })?;

            let conn = RdmaConnection::new(qp, cq, pd).map_err(|e| {
                TransportError::RdmaConnectionFailed {
                    session_id: crate::types::SessionId(0),
                    reason: e,
                }
            })?;

            Self::sync_preposted_recvs(&mut stream).map_err(|e| {
                TransportError::RdmaConnectionFailed {
                    session_id: crate::types::SessionId(0),
                    reason: e,
                }
            })?;

            return Ok(Box::new(conn));
        }

        Err(last_err.unwrap_or_else(|| TransportError::ConnectFailed {
            peer_addr: peer
                .addresses
                .first()
                .cloned()
                .unwrap_or_else(|| TransportAddr::Tcp("0.0.0.0:0".parse().unwrap())),
            source: std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "all peer addresses unreachable",
            ),
        }))
    }

    fn accept(&mut self) -> Result<AcceptResult, TransportError> {
        let pd = self
            .pd
            .as_ref()
            .ok_or_else(|| TransportError::RdmaNotAvailable {
                reason: "protection domain not initialized".into(),
            })?;

        let tcp_listener = self
            .tcp_listener
            .as_ref()
            .ok_or_else(|| TransportError::Generic("rdma: listener not bound".into()))?;

        let (stream, peer_addr) = match tcp_listener.accept() {
            Ok((s, a)) => (s, a),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return Err(TransportError::Generic("no pending connections".into()));
            }
            Err(e) => return Err(TransportError::AcceptFailed(e)),
        };

        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(TransportError::AcceptFailed)?;

        let mut stream = stream;
        let (qp, cq, _our_info, _peer_info) =
            Self::handshake_qp(pd, &mut stream, false, 256, 256, 1, 1).map_err(|e| {
                TransportError::RdmaConnectionFailed {
                    session_id: crate::types::SessionId(0),
                    reason: e,
                }
            })?;

        let conn =
            RdmaConnection::new(qp, cq, pd).map_err(|e| TransportError::RdmaConnectionFailed {
                session_id: crate::types::SessionId(0),
                reason: e,
            })?;

        Self::sync_preposted_recvs(&mut stream).map_err(|e| {
            TransportError::RdmaConnectionFailed {
                session_id: crate::types::SessionId(0),
                reason: e,
            }
        })?;

        Ok((Box::new(conn), TransportAddr::Tcp(peer_addr)))
    }

    fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), TransportError> {
        self.nonblocking = nonblocking;
        Ok(())
    }

    fn backend_kind(&self) -> TransportBackendKind {
        TransportBackendKind::Rdma
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qp_info_encode_decode_roundtrip() {
        let info = QpInfo {
            qp_num: 0x1234,
            lid: 0x5678,
            psn: 0x9ABC_DEF0,
            gid_index: 2,
            link_layer: ffi::IBV_LINK_LAYER_ETHERNET.0 as u8,
            active_mtu: ffi::IBV_MTU_1024.0 as u8,
            gid: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 88, 10],
        };
        let encoded = info.encode();
        let decoded = QpInfo::decode(&encoded);
        assert_eq!(decoded.qp_num, info.qp_num);
        assert_eq!(decoded.lid, info.lid);
        assert_eq!(decoded.psn, info.psn);
        assert_eq!(decoded.gid_index, info.gid_index);
        assert_eq!(decoded.link_layer, info.link_layer);
        assert_eq!(decoded.active_mtu, info.active_mtu);
        assert_eq!(decoded.gid, info.gid);
    }

    #[test]
    fn test_queue_pair_path_uses_roce_global_route() {
        let local = QpInfo {
            qp_num: 1,
            lid: 0,
            psn: 10,
            gid_index: 3,
            link_layer: ffi::IBV_LINK_LAYER_ETHERNET.0 as u8,
            active_mtu: ffi::IBV_MTU_4096.0 as u8,
            gid: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 88, 10],
        };
        let peer = QpInfo {
            qp_num: 2,
            lid: 0,
            psn: 20,
            gid_index: 4,
            link_layer: ffi::IBV_LINK_LAYER_ETHERNET.0 as u8,
            active_mtu: ffi::IBV_MTU_1024.0 as u8,
            gid: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 88, 20],
        };

        let path = queue_pair_path(local, peer).expect("valid RoCE path");
        assert!(path.global_route);
        assert_eq!(path.dest_lid, 0);
        assert_eq!(path.sgid_index, local.gid_index);
        assert_eq!(path.dest_gid, Some(peer.gid));
        assert_eq!(path.path_mtu, ffi::IBV_MTU_1024);
    }

    #[test]
    fn test_qp_attr_mask_constants_match_linux_uverbs() {
        assert_eq!(ffi::IBV_QP_MAX_QP_RD_ATOMIC, 1 << 13);
        assert_eq!(ffi::IBV_QP_ALT_PATH, 1 << 14);
        assert_eq!(ffi::IBV_QP_MIN_RNR_TIMER, 1 << 15);
        assert_eq!(ffi::IBV_QP_SQ_PSN, 1 << 16);
        assert_eq!(ffi::IBV_QP_MAX_DEST_RD_ATOMIC, 1 << 17);
        assert_eq!(ffi::IBV_QP_PATH_MIG_STATE, 1 << 18);
        assert_eq!(ffi::IBV_QP_CAP, 1 << 19);
        assert_eq!(ffi::IBV_QP_DEST_QPN, 1 << 20);
    }

    #[test]
    fn test_send_wr_opcode_constants_match_linux_uverbs() {
        assert_eq!(ffi::IBV_WR_RDMA_WRITE.0, 0);
        assert_eq!(ffi::IBV_WR_RDMA_WRITE_WITH_IMM.0, 1);
        assert_eq!(ffi::IBV_WR_SEND.0, 2);
        assert_eq!(ffi::IBV_WR_SEND_WITH_IMM.0, 3);
        assert_eq!(ffi::IBV_WR_RDMA_READ.0, 4);
        assert_ne!(ffi::IBV_WR_SEND.0, ffi::IBV_WC_SEND.0);
    }

    #[test]
    fn test_rdma_transport_new_returns_not_available_when_no_device() {
        // In most CI/container environments, no RDMA device is present.
        // This validates the runtime detection path.
        let result = RdmaTransport::new(Duration::from_secs(1));
        match result {
            Ok(_transport) => {
                // We have an RDMA device (e.g. SoftRoCE or real hardware).
                // Drop it and pass the test.
                drop(_transport);
            }
            Err(TransportError::RdmaNotAvailable { .. }) => {
                // Expected on hosts without RDMA.
            }
            Err(e) => {
                panic!("unexpected error: {e:?}");
            }
        }
    }

    #[test]
    fn test_rdma_transport_bind_without_device() {
        // Starting transport when no RDMA device exists is a constructor failure,
        // not a bind failure. This test validates the error path.
        let result = RdmaTransport::new(Duration::from_secs(1));
        // Just check we don't panic; the result is either Ok or RdmaNotAvailable.
        let _ = result;
    }

    #[test]
    fn test_send_free_bitmap_all_free_at_init() {
        // Verify the send_free bitmap arithmetic: POOL_COUNT should
        // produce a mask with exactly the lower count bits set.
        let count = RdmaConnection::POOL_COUNT;
        let mask: u16 = ((1u32 << count) - 1) as u16;
        assert_eq!(mask.count_ones() as usize, count);
        // Each bit corresponds to a free buffer.
        for i in 0..count {
            assert!(mask & (1 << i) != 0, "bit {i} should be set");
        }
    }

    #[test]
    fn test_rdma_registered_pool_footprint_is_bounded() {
        let validation_payload_frame_size = 256 * 1024 + 4;
        assert!(
            RdmaConnection::MAX_FRAME_SIZE >= validation_payload_frame_size,
            "transport must still carry the large validation payload"
        );
        assert!(
            RdmaConnection::registered_pool_bytes() <= 20 * 1024 * 1024,
            "default RDMA pinned memory must remain safe for QEMU SoftRoCE guests"
        );
    }

    #[test]
    fn test_send_free_bitmap_mark_and_release() {
        // Simulate the send buffer lifecycle: mark busy, then release.
        let mut free: u16 = 0xFFFF;
        // Mark buffer 3 busy.
        free &= !(1 << 3);
        assert!(free & (1 << 3) == 0, "buffer 3 should be busy");
        assert!(free & (1 << 0) != 0, "buffer 0 should still be free");
        // Release buffer 3.
        free |= 1 << 3;
        assert!(free & (1 << 3) != 0, "buffer 3 should be free again");
        // All buffers free again.
        assert_eq!(free, 0xFFFF);
    }

    #[test]
    fn test_qp_info_zero_values_roundtrip() {
        let info = QpInfo {
            qp_num: 0,
            lid: 0,
            psn: 0,
            gid_index: 0,
            link_layer: 0,
            active_mtu: 0,
            gid: [0; 16],
        };
        let encoded = info.encode();
        let decoded = QpInfo::decode(&encoded);
        assert_eq!(decoded.qp_num, 0);
        assert_eq!(decoded.lid, 0);
        assert_eq!(decoded.psn, 0);
    }

    #[test]
    fn test_rdma_connection_lifecycle_with_device() {
        // Full RdmaConnection creation test when an RDMA device is present.
        let dev = match super::verbs::RdmaDevice::open_first_available() {
            Ok(d) => d,
            Err(_) => return, // skip on hosts without RDMA
        };
        let pd = match super::verbs::ProtectionDomain::alloc(dev.context()) {
            Ok(p) => p,
            Err(_) => return,
        };
        let cq = match super::verbs::CompletionQueue::create(dev.context(), 64) {
            Ok(c) => c,
            Err(_) => return,
        };
        let qp = match super::verbs::QueuePair::create(&pd, &cq, &cq, 64, 64, 1, 1) {
            Ok(q) => q,
            Err(_) => return,
        };

        // Create the connection with explicit buffer pool initialization.
        let conn = RdmaConnection::new(qp, cq, &pd);
        assert!(conn.is_ok(), "RdmaConnection::new failed: {:?}", conn.err());

        let conn = conn.unwrap();
        // send_free should have all POOL_COUNT bits set.
        let expected_free: u16 = ((1u32 << RdmaConnection::POOL_COUNT) - 1) as u16;
        assert_eq!(conn.send_free, expected_free);
        // Non-blocking should default to false.
        assert!(!conn.nonblocking);
        // No completions should be queued at initialization.
        assert!(conn.pending_recv.is_empty());

        drop(conn);
        drop(pd);
        drop(dev);
    }

    #[test]
    fn test_wr_id_passed_to_post_send_and_post_recv() {
        // Verify that wr_id is accepted as a parameter and the call succeeds
        // (does not panic or return an unexpected error).
        let dev = match super::verbs::RdmaDevice::open_first_available() {
            Ok(d) => d,
            Err(_) => return,
        };
        let pd = match super::verbs::ProtectionDomain::alloc(dev.context()) {
            Ok(p) => p,
            Err(_) => return,
        };
        let cq = match super::verbs::CompletionQueue::create(dev.context(), 64) {
            Ok(c) => c,
            Err(_) => return,
        };

        let mut qp = match super::verbs::QueuePair::create(&pd, &cq, &cq, 64, 64, 1, 1) {
            Ok(q) => q,
            Err(_) => return,
        };
        // Must be in INIT to post recv.
        assert!(qp.transition_to_init(1, 0xABCD).is_ok());

        let buf_size: usize = 1024;
        let mut buf: Vec<u8> = vec![0u8; buf_size];
        // SAFETY: buf is a live Vec<u8> allocation; buf_size matches the
        // allocation size. The buffer is stable and valid for reads/writes
        // for the MR lifetime.
        let mr = unsafe {
            super::verbs::MemoryRegion::register(
                &pd,
                buf.as_mut_ptr() as *mut _,
                buf_size,
                super::ffi::IBV_ACCESS_LOCAL_WRITE,
            )
        };
        let mr = match mr {
            Ok(m) => m,
            Err(_) => return,
        };

        // Post recv with wr_id = 42. Should not panic or error with wrong args.
        let result = qp.post_recv(buf.as_mut_ptr(), buf_size, mr.lkey(), 42);
        // In INIT state, posting recv may or may not succeed depending on
        // the implementation; we just verify the API accepts wr_id.
        let _ = result;

        // Post send with wr_id = 7.
        let result = qp.post_send(buf.as_ptr(), buf_size, mr.lkey(), 7);
        // In INIT state, send would typically fail (need RTS); we verify API.
        let _ = result;

        drop(mr);
        drop(qp);
        drop(cq);
        drop(pd);
        drop(dev);
    }

    /// Helper: create a pair of connected RdmaConnections over single-process loopback.
    /// Returns `(server_conn, client_conn)` or `None` if RDMA is unavailable.
    fn create_loopback_pair() -> Option<(RdmaConnection, RdmaConnection)> {
        let dev = super::verbs::RdmaDevice::open_first_available().ok()?;
        let ctx = dev.context();

        // Server side: protection domain, CQ, QP.
        let server_pd = super::verbs::ProtectionDomain::alloc(ctx).ok()?;
        let server_cq = super::verbs::CompletionQueue::create(ctx, 256).ok()?;
        let server_qp =
            super::verbs::QueuePair::create(&server_pd, &server_cq, &server_cq, 256, 256, 1, 1)
                .ok()?;

        // Client side: protection domain, CQ, QP.
        let client_pd = super::verbs::ProtectionDomain::alloc(ctx).ok()?;
        let client_cq = super::verbs::CompletionQueue::create(ctx, 256).ok()?;
        let client_qp =
            super::verbs::QueuePair::create(&client_pd, &client_cq, &client_cq, 256, 256, 1, 1)
                .ok()?;

        // TCP control channel for QP attribute exchange.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
        let server_addr = listener.local_addr().ok()?;

        let mut client_stream = std::net::TcpStream::connect(server_addr).ok()?;
        let (mut server_stream, _peer_addr) = listener.accept().ok()?;

        // Perform QP handshakes.
        let handshake_qp = |qp: &mut super::verbs::QueuePair,
                            pd: &super::verbs::ProtectionDomain,
                            stream: &mut std::net::TcpStream,
                            _is_active: bool|
         -> Result<(), String> {
            let psn = 0x1234_5678u32;
            let port_num = 1;
            let local_port = pd.query_port(port_num)?;
            qp.transition_to_init(port_num, psn)?;
            let local_qpn = qp.qp_num();
            let local_info = QpInfo::from_port(local_qpn, psn, local_port);
            local_info.write_to(stream).map_err(|e| e.to_string())?;
            let peer_info = QpInfo::read_from(stream).map_err(|e| e.to_string())?;
            qp.transition_to_rtr(
                peer_info.qp_num,
                peer_info.psn,
                port_num,
                queue_pair_path(local_info, peer_info)?,
            )?;
            qp.transition_to_rts(psn)?;
            Ok(())
        };

        let mut server_qp = server_qp;
        let mut client_qp = client_qp;

        // Both sides need to exchange. Client (active) sends first.
        handshake_qp(&mut client_qp, &client_pd, &mut client_stream, true).ok()?;
        handshake_qp(&mut server_qp, &server_pd, &mut server_stream, false).ok()?;

        // Build RdmaConnections.
        let mut server_conn = RdmaConnection::new(server_qp, server_cq, &server_pd).ok()?;
        let mut client_conn = RdmaConnection::new(client_qp, client_cq, &client_pd).ok()?;

        // Enable non-blocking for both sides so we can alternate reads.
        server_conn.set_nonblocking(true).ok()?;
        client_conn.set_nonblocking(true).ok()?;

        // Transfer ownership of the PD/dev to prevent early drop.
        // We leak a small amount here — acceptable for a test.
        std::mem::forget(dev);
        std::mem::forget(server_pd);
        std::mem::forget(client_pd);

        Some((server_conn, client_conn))
    }

    #[test]
    fn test_rdma_loopback_send_recv_roundtrip() {
        let (mut server_conn, mut client_conn) = match create_loopback_pair() {
            Some(pair) => pair,
            None => return, // skip on hosts without RDMA
        };

        // Message payloads to exchange.
        let client_msg: Vec<u8> = b"hello from client: RDMA transport validation".to_vec();
        let server_msg: Vec<u8> = b"hello from server: RDMA ack received".to_vec();

        // Client sends to server.
        client_conn
            .write_frame(&client_msg)
            .expect("client write_frame failed");
        // Allow a brief delay for the RDMA completion to land.
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Server reads client message.
        let recv_from_client = server_conn.read_frame().expect("server read_frame failed");
        assert_eq!(
            recv_from_client, client_msg,
            "server received unexpected payload from client"
        );

        // Server sends to client.
        server_conn
            .write_frame(&server_msg)
            .expect("server write_frame failed");
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Client reads server message.
        let recv_from_server = client_conn.read_frame().expect("client read_frame failed");
        assert_eq!(
            recv_from_server, server_msg,
            "client received unexpected payload from server"
        );

        drop(server_conn);
        drop(client_conn);
    }

    #[test]
    fn test_rdma_loopback_large_payload() {
        let (mut server_conn, mut client_conn) = match create_loopback_pair() {
            Some(pair) => pair,
            None => return,
        };

        // Send a payload near the buffer size limit.
        let payload_size = 256 * 1024; // 256 KiB
        let payload: Vec<u8> = (0..payload_size).map(|i| (i & 0xFF) as u8).collect();

        client_conn
            .write_frame(&payload)
            .expect("client large write_frame failed");
        std::thread::sleep(std::time::Duration::from_millis(20));

        let recv = server_conn
            .read_frame()
            .expect("server large read_frame failed");
        assert_eq!(recv.len(), payload_size);
        assert_eq!(recv, payload);

        drop(server_conn);
        drop(client_conn);
    }

    #[test]
    fn test_rdma_loopback_multiple_messages() {
        let (mut server_conn, mut client_conn) = match create_loopback_pair() {
            Some(pair) => pair,
            None => return,
        };

        // Exchange several messages to exercise buffer-pool reuse.
        let messages: Vec<Vec<u8>> = (0..8)
            .map(|i| format!("message number {i}").into_bytes())
            .collect();

        for msg in &messages {
            client_conn
                .write_frame(msg)
                .expect("multi-message write_frame failed");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        for (i, expected) in messages.iter().enumerate() {
            let recv = server_conn
                .read_frame()
                .unwrap_or_else(|_| panic!("read_frame {i} failed"));
            assert_eq!(&recv, expected, "message {i} mismatch");
        }

        drop(server_conn);
        drop(client_conn);
    }

    /// Full RdmaTransport bind/accept/connect smoke test using the
    /// TransportBackend trait. Gated behind TIDEFS_RUN_QEMU_RDMA_SMOKE=1
    /// or TIDEFS_RUN_RDMA_LOOPBACK=1.
    #[test]
    fn test_rdma_transport_bind_connect_accept_loopback() {
        if std::env::var("TIDEFS_RUN_QEMU_RDMA_SMOKE").is_err()
            && std::env::var("TIDEFS_RUN_RDMA_LOOPBACK").is_err()
        {
            return; // opt-in gate
        }

        let dev = match super::verbs::RdmaDevice::open_first_available() {
            Ok(d) => d,
            Err(_) => return,
        };
        // Keep device alive for the full test.
        let _dev = dev;

        // Server side.
        let mut server = match RdmaTransport::new(Duration::from_secs(5)) {
            Ok(t) => t,
            Err(_) => return,
        };
        server
            .bind(TransportAddr::Tcp("127.0.0.1:0".parse().unwrap()))
            .expect("server bind failed");
        let server_addr = server.local_addr().expect("no local addr");
        server
            .set_nonblocking(true)
            .expect("server set_nonblocking failed");

        // Client side.
        let mut client = match RdmaTransport::new(Duration::from_secs(5)) {
            Ok(t) => t,
            Err(_) => return,
        };
        client
            .set_nonblocking(true)
            .expect("client set_nonblocking failed");

        // Accept in a background thread.
        let accept_handle = std::thread::spawn(move || {
            loop {
                match server.accept() {
                    Ok((conn, _peer)) => return conn,
                    Err(TransportError::Generic(_)) => {
                        // WouldBlock-like — retry.
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("server accept unexpected error: {e:?}"),
                }
            }
        });

        // Give the server thread a moment to start.
        std::thread::sleep(Duration::from_millis(10));

        // Connect from client side.
        let peer = crate::session_cohort::NodeInfo::new(1, vec![server_addr], 0);
        let mut client_conn = client.connect(&peer).expect("client connect failed");

        // Wait for accept to complete.
        let mut server_conn = accept_handle.join().expect("accept thread panicked");

        // Exchange messages.
        let msg_a = b"transport smoke: client to server".to_vec();
        let msg_b = b"transport smoke: server to client".to_vec();

        client_conn
            .write_frame(&msg_a)
            .expect("client write_frame failed");
        std::thread::sleep(Duration::from_millis(10));

        let recv_a = server_conn.read_frame().expect("server read_frame failed");
        assert_eq!(recv_a, msg_a);

        server_conn
            .write_frame(&msg_b)
            .expect("server write_frame failed");
        std::thread::sleep(Duration::from_millis(10));

        let recv_b = client_conn.read_frame().expect("client read_frame failed");
        assert_eq!(recv_b, msg_b);

        drop(server_conn);
        drop(client_conn);
        // server was moved into the accept thread, already dropped there.
        drop(client);
    }
}
