// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Transport outbound connection pool with shared TCP connection reuse
//! and idle eviction.
//!
//! ## Connection pool architecture
//!
//! The [`TcpConnectionPool`] holds established `TcpStream` connections keyed by
//! peer [`SocketAddr`]. It amortizes TCP handshake overhead across transport
//! sessions to the same peer, reducing socket pressure in multi-node
//! deployments.
//!
//! ### Lifecycle
//!
//! - **Checkout**: [`ConnectionPool::checkout`] returns a [`PooledConnection`]
//!   RAII handle when an idle connection exists for the peer. Returns `None`
//!   if the pool has no usable connection for that address.
//! - **Return**: On [`Drop`], a healthy [`PooledConnection`] returns its
//!   underlying `TcpStream` to the pool. Call [`PooledConnection::into_stream`]
//!   to take permanent ownership (skips return-to-pool). Call
//!   [`PooledConnection::mark_unhealthy`] to close the socket on drop instead
//!   of returning it.
//! - **Eviction**: A background task periodically evicts connections idle
//!   beyond `idle_timeout`, enforcing `max_per_peer` and `max_total` bounds.
//! - **Backpressure**: When `max_total` is reached, `checkout` still succeeds
//!   for existing pooled connections; new `checkin` calls may evict the
//!   stalest connection or drop the incoming stream.
//!
//! ### Integration
//!
//! Wired into [`connect_with_retry`](crate::connection_retry::connect_with_retry)
//! for pre-connect pool lookup, and into `ConnectionManager` disconnect/drain
//! for return-to-pool on session teardown.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::TcpStream;

// ---------------------------------------------------------------------------
// Pool configuration
// ---------------------------------------------------------------------------

/// Configuration for the outbound connection pool.
#[derive(Clone, Debug)]
pub struct PoolConfig {
    /// Maximum idle connections per peer address.
    pub max_per_peer: usize,
    /// Maximum total connections across all peers.
    pub max_total: usize,
    /// Duration after which an idle connection is evicted.
    pub idle_timeout: Duration,
    /// Interval at which the background eviction task runs.
    pub eviction_interval: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_per_peer: 4,
            max_total: 64,
            idle_timeout: Duration::from_secs(60),
            eviction_interval: Duration::from_secs(10),
        }
    }
}

// ---------------------------------------------------------------------------
// Pool entry
// ---------------------------------------------------------------------------

/// A single pooled TCP connection with bookkeeping metadata.
struct PoolEntry {
    stream: TcpStream,
    last_used: Instant,
    use_count: u64,
}

impl PoolEntry {
    fn new(stream: TcpStream) -> Self {
        let now = Instant::now();
        Self {
            stream,
            last_used: now,
            use_count: 0,
        }
    }

    fn idle_duration(&self, now: Instant) -> Duration {
        now.duration_since(self.last_used)
    }
}

// ---------------------------------------------------------------------------
// Pool statistics
// ---------------------------------------------------------------------------

/// Snapshot of pool statistics.
#[derive(Clone, Debug, Default)]
pub struct PoolStats {
    /// Total connections currently in the pool.
    pub total: usize,
    /// Number of distinct peer addresses with connections.
    pub active_peers: usize,
    /// Total successful checkouts since pool creation.
    pub total_checkouts: u64,
    /// Total checkins since pool creation.
    pub total_checkins: u64,
    /// Total connections evicted since pool creation.
    pub total_evictions: u64,
    /// Total connections dropped as unhealthy.
    pub total_unhealthy_drops: u64,
}

// ---------------------------------------------------------------------------
// Pool inner state (behind Arc<Mutex<>>)
// ---------------------------------------------------------------------------

struct PoolInner {
    config: PoolConfig,
    entries: HashMap<SocketAddr, Vec<PoolEntry>>,
    total: usize,
    stats: PoolStats,
}

impl PoolInner {
    fn new(config: PoolConfig) -> Self {
        Self {
            config,
            entries: HashMap::new(),
            total: 0,
            stats: PoolStats::default(),
        }
    }

    /// Try to remove and return a connection for `peer_addr`.
    /// Returns `None` if no idle connection exists.
    fn checkout(&mut self, peer_addr: SocketAddr) -> Option<PoolEntry> {
        let conns = self.entries.get_mut(&peer_addr)?;
        // Pick the freshest connection (shortest idle time).
        let now = Instant::now();
        let best_idx = conns
            .iter()
            .enumerate()
            .min_by_key(|(_, e)| e.idle_duration(now))
            .map(|(i, _)| i)?;

        let mut entry = conns.swap_remove(best_idx);
        self.total -= 1;
        self.stats.total_checkouts += 1;
        entry.use_count += 1;
        entry.last_used = now;

        if conns.is_empty() {
            self.entries.remove(&peer_addr);
        }

        Some(entry)
    }

    /// Return a connection to the pool.
    /// If `max_total` is exceeded, the stalest connection across all peers
    /// is evicted to make room, or the incoming stream is dropped.
    fn checkin(&mut self, peer_addr: SocketAddr, stream: TcpStream) {
        // If we're at capacity, try to evict the stalest connection.
        if self.total >= self.config.max_total && !self.evict_stalest() {
            // Couldn't evict; drop the incoming stream.
            return;
        }

        let conns = self.entries.entry(peer_addr).or_default();

        // Enforce per-peer limit.
        if conns.len() >= self.config.max_per_peer {
            // Remove the stalest connection for this peer.
            let now = Instant::now();
            if let Some(stalest_idx) = conns
                .iter()
                .enumerate()
                .max_by_key(|(_, e)| e.idle_duration(now))
                .map(|(i, _)| i)
            {
                conns.swap_remove(stalest_idx);
                self.total -= 1;
                self.stats.total_evictions += 1;
            }
        }

        conns.push(PoolEntry::new(stream));
        self.total += 1;
        self.stats.total_checkins += 1;
    }

    /// Evict the single stalest connection across all peers.
    /// Returns true if a connection was evicted.
    fn evict_stalest(&mut self) -> bool {
        let now = Instant::now();
        let mut stalest_key: Option<SocketAddr> = None;
        let mut stalest_idx: Option<usize> = None;
        let mut stalest_age = Duration::ZERO;

        for (addr, conns) in self.entries.iter() {
            for (i, entry) in conns.iter().enumerate() {
                let age = entry.idle_duration(now);
                if age > stalest_age {
                    stalest_age = age;
                    stalest_key = Some(*addr);
                    stalest_idx = Some(i);
                }
            }
        }

        if let (Some(addr), Some(idx)) = (stalest_key, stalest_idx) {
            if let Some(conns) = self.entries.get_mut(&addr) {
                conns.swap_remove(idx);
                self.total -= 1;
                self.stats.total_evictions += 1;
                if conns.is_empty() {
                    self.entries.remove(&addr);
                }
                return true;
            }
        }

        false
    }

    /// Evict connections idle beyond `idle_timeout`.
    fn evict_idle(&mut self) -> usize {
        let now = Instant::now();
        let max_idle = self.config.idle_timeout;
        let mut evicted = 0;
        let mut empty_addrs = Vec::new();

        for (addr, conns) in self.entries.iter_mut() {
            let before = conns.len();
            conns.retain(|e| e.idle_duration(now) < max_idle);
            let removed = before - conns.len();
            evicted += removed;
            self.total -= removed;
            if conns.is_empty() {
                empty_addrs.push(*addr);
            }
        }

        for addr in empty_addrs {
            self.entries.remove(&addr);
        }

        self.stats.total_evictions += evicted as u64;
        evicted
    }

    fn stats_snapshot(&self) -> PoolStats {
        let mut s = self.stats.clone();
        s.total = self.total;
        s.active_peers = self.entries.len();
        s
    }
}

// ---------------------------------------------------------------------------
// ConnectionPool
// ---------------------------------------------------------------------------

/// A thread-safe pool of established outbound TCP connections, keyed by peer
/// [`SocketAddr`].
///
/// Use [`checkout`](TcpConnectionPool::checkout) to obtain a pooled connection,
/// and either let the [`PooledConnection`] RAII handle return it on drop, or
/// call [`PooledConnection::into_stream`] to take permanent ownership.
///
/// # Example
///
/// ```ignore
/// let pool = TcpConnectionPool::new(PoolConfig::default());
/// pool.spawn_eviction_task();
///
/// // Check out a pooled connection for a peer.
/// if let Some(handle) = pool.checkout(peer_addr) {
///     let stream = handle.into_stream();
///     // use stream...
///     // pool.checkin(peer_addr, stream) to return it later
/// }
/// ```
#[derive(Clone)]
pub struct TcpConnectionPool {
    inner: Arc<Mutex<PoolInner>>,
}

impl TcpConnectionPool {
    /// Create a new connection pool with the given configuration.
    #[must_use]
    pub fn new(config: PoolConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(PoolInner::new(config))),
        }
    }

    /// Create a new pool with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(PoolConfig::default())
    }

    /// Try to check out a pooled connection for `peer_addr`.
    ///
    /// Returns a [`PooledConnection`] RAII handle if an idle connection exists,
    /// or `None` if the pool has no connection for that address.
    ///
    /// The caller can either:
    /// - Let the handle drop to return the stream to the pool.
    /// - Call [`PooledConnection::into_stream`] to take ownership.
    /// - Call [`PooledConnection::mark_unhealthy`] to close the socket on drop.
    pub fn checkout(&self, peer_addr: SocketAddr) -> Option<PooledConnection> {
        let mut inner = self.inner.lock().unwrap();
        inner.checkout(peer_addr).map(|entry| PooledConnection {
            stream: Some(entry.stream),
            peer_addr,
            pool: Arc::clone(&self.inner),
            healthy: true,
        })
    }

    /// Return a stream directly to the pool without using the RAII handle.
    ///
    /// Use this when you obtained a stream via
    /// [`PooledConnection::into_stream`] and later want to return it.
    pub fn checkin(&self, peer_addr: SocketAddr, stream: TcpStream) {
        let mut inner = self.inner.lock().unwrap();
        inner.checkin(peer_addr, stream);
    }

    /// Number of connections currently in the pool.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().total
    }

    /// Whether the pool is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of distinct peer addresses with connections.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.inner.lock().unwrap().entries.len()
    }

    /// Remove all connections for a specific peer address.
    ///
    /// Returns the number of connections removed.
    pub fn remove_peer(&self, peer_addr: SocketAddr) -> usize {
        let mut inner = self.inner.lock().unwrap();
        if let Some(conns) = inner.entries.remove(&peer_addr) {
            let count = conns.len();
            inner.total -= count;
            count
        } else {
            0
        }
    }

    /// Get a snapshot of pool statistics.
    #[must_use]
    pub fn stats(&self) -> PoolStats {
        self.inner.lock().unwrap().stats_snapshot()
    }

    /// Spawn a background task that periodically evicts idle connections.
    ///
    /// The task runs at the interval specified in
    /// [`PoolConfig::eviction_interval`] and removes connections idle beyond
    /// [`PoolConfig::idle_timeout`]. Returns a [`tokio::task::JoinHandle`]
    /// that can be aborted to stop eviction.
    pub fn spawn_eviction_task(&self) -> tokio::task::JoinHandle<()> {
        let pool = self.clone();
        let interval_dur = {
            let inner = self.inner.lock().unwrap();
            inner.config.eviction_interval
        };
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(interval_dur);
            // Skip the first immediate tick; wait for the first interval.
            interval.tick().await;
            loop {
                interval.tick().await;
                let mut inner = pool.inner.lock().unwrap();
                inner.evict_idle();
            }
        })
    }
}

// ---------------------------------------------------------------------------
// PooledConnection: RAII handle
// ---------------------------------------------------------------------------

/// RAII handle for a connection checked out from the [`ConnectionPool`].
///
/// On drop, if the connection is still healthy, it is returned to the pool.
/// Call [`into_stream`](PooledConnection::into_stream) to take permanent
/// ownership (skipping return-to-pool). Call
/// [`mark_unhealthy`](PooledConnection::mark_unhealthy) to close the socket
/// on drop instead of returning it.
pub struct PooledConnection {
    stream: Option<TcpStream>,
    peer_addr: SocketAddr,
    pool: Arc<Mutex<PoolInner>>,
    healthy: bool,
}

impl PooledConnection {
    /// Consume the handle and take ownership of the underlying `TcpStream`.
    /// The stream will not be returned to the pool.
    #[must_use]
    pub fn into_stream(mut self) -> TcpStream {
        self.stream
            .take()
            .expect("PooledConnection stream already taken")
    }

    /// Mark this connection as unhealthy. On drop, the socket will be closed
    /// instead of returned to the pool.
    pub fn mark_unhealthy(&mut self) {
        self.healthy = false;
    }

    /// Borrow the underlying stream. Returns `None` if the stream has been
    /// taken via [`into_stream`](Self::into_stream).
    #[must_use]
    pub fn stream(&self) -> Option<&TcpStream> {
        self.stream.as_ref()
    }

    /// Mutably borrow the underlying stream.
    #[must_use]
    pub fn stream_mut(&mut self) -> Option<&mut TcpStream> {
        self.stream.as_mut()
    }

    /// Returns the peer address this connection was pooled for.
    #[must_use]
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Whether this connection will be returned to the pool on drop.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.healthy
    }
}

impl Drop for PooledConnection {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.take() {
            if self.healthy {
                let mut inner = self.pool.lock().unwrap();
                inner.checkin(self.peer_addr, stream);
            } else {
                // Unhealthy: drop the stream, closing the socket.
                let mut inner = self.pool.lock().unwrap();
                inner.stats.total_unhealthy_drops += 1;
                drop(inner);
                drop(stream);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a connected TcpStream pair.
    fn connected_pair() -> (TcpStream, TcpStream) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let listen_addr = listener.local_addr().unwrap();
            let client = tokio::net::TcpStream::connect(listen_addr).await.unwrap();
            let (server, _) = listener.accept().await.unwrap();
            (client, server)
        })
    }

    // -----------------------------------------------------------------------
    // PoolConfig tests
    // -----------------------------------------------------------------------

    #[test]
    fn pool_config_defaults() {
        let cfg = PoolConfig::default();
        assert_eq!(cfg.max_per_peer, 4);
        assert_eq!(cfg.max_total, 64);
        assert_eq!(cfg.idle_timeout, Duration::from_secs(60));
        assert_eq!(cfg.eviction_interval, Duration::from_secs(10));
    }

    // -----------------------------------------------------------------------
    // Checkout / checkin lifecycle
    // -----------------------------------------------------------------------

    #[test]
    fn checkout_empty_pool_returns_none() {
        let pool = TcpConnectionPool::with_defaults();
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        assert!(pool.checkout(addr).is_none());
    }

    #[test]
    fn checkin_then_checkout_returns_connection() {
        // Test PoolInner directly since we need real TcpStream handles.
        let cfg = PoolConfig::default();
        let mut inner = PoolInner::new(cfg);
        let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();

        let (stream, _peer) = connected_pair();
        inner.checkin(addr, stream);
        assert_eq!(inner.total, 1);

        let entry = inner.checkout(addr);
        assert!(entry.is_some());
        assert_eq!(inner.total, 0);
    }

    #[test]
    fn checkout_returns_none_after_draining() {
        let cfg = PoolConfig::default();
        let mut inner = PoolInner::new(cfg);
        let addr: SocketAddr = "127.0.0.1:9002".parse().unwrap();

        let (stream, _peer) = connected_pair();
        inner.checkin(addr, stream);
        let _entry = inner.checkout(addr).unwrap();
        assert!(inner.checkout(addr).is_none());
    }

    // -----------------------------------------------------------------------
    // max_per_peer enforcement
    // -----------------------------------------------------------------------

    #[test]
    fn max_per_peer_enforced() {
        let cfg = PoolConfig {
            max_per_peer: 2,
            ..Default::default()
        };
        let mut inner = PoolInner::new(cfg);
        let addr: SocketAddr = "127.0.0.1:9003".parse().unwrap();

        for _ in 0..3 {
            let (stream, _peer) = connected_pair();
            inner.checkin(addr, stream);
        }

        let conns = inner.entries.get(&addr).map(|v| v.len()).unwrap_or(0);
        assert!(conns <= 2);
    }

    // -----------------------------------------------------------------------
    // max_total enforcement
    // -----------------------------------------------------------------------

    #[test]
    fn max_total_enforced() {
        let cfg = PoolConfig {
            max_total: 2,
            ..Default::default()
        };
        let mut inner = PoolInner::new(cfg);

        for port in 0..4 {
            let addr: SocketAddr = format!("127.0.0.1:{}", 9100 + port).parse().unwrap();
            let (stream, _peer) = connected_pair();
            inner.checkin(addr, stream);
        }

        assert!(inner.total <= 2);
    }

    // -----------------------------------------------------------------------
    // Eviction
    // -----------------------------------------------------------------------

    #[test]
    fn evict_idle_removes_stale_connections() {
        let cfg = PoolConfig {
            idle_timeout: Duration::from_millis(1),
            ..Default::default()
        };
        let mut inner = PoolInner::new(cfg);
        let addr: SocketAddr = "127.0.0.1:9105".parse().unwrap();

        let (stream, _peer) = connected_pair();
        inner.checkin(addr, stream);
        assert_eq!(inner.total, 1);

        // Backdate the entry so it appears idle.
        if let Some(conns) = inner.entries.get_mut(&addr) {
            for e in conns.iter_mut() {
                e.last_used = Instant::now() - Duration::from_secs(10);
            }
        }

        let evicted = inner.evict_idle();
        assert_eq!(evicted, 1);
        assert_eq!(inner.total, 0);
    }

    #[test]
    fn evict_idle_keeps_fresh_connections() {
        let cfg = PoolConfig::default();
        let mut inner = PoolInner::new(cfg);
        let addr: SocketAddr = "127.0.0.1:9106".parse().unwrap();

        let (stream, _peer) = connected_pair();
        inner.checkin(addr, stream);
        let evicted = inner.evict_idle();
        assert_eq!(evicted, 0);
        assert_eq!(inner.total, 1);
    }

    // -----------------------------------------------------------------------
    // Pool stats
    // -----------------------------------------------------------------------

    #[test]
    fn stats_tracks_operations() {
        let cfg = PoolConfig::default();
        let mut inner = PoolInner::new(cfg);
        let addr1: SocketAddr = "127.0.0.1:9107".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:9108".parse().unwrap();

        let (s1, _) = connected_pair();
        let (s2, _) = connected_pair();
        inner.checkin(addr1, s1);
        inner.checkin(addr2, s2);

        let stats = inner.stats_snapshot();
        assert_eq!(stats.total, 2);
        assert_eq!(stats.active_peers, 2);
        assert_eq!(stats.total_checkins, 2);
    }

    // -----------------------------------------------------------------------
    // remove_peer
    // -----------------------------------------------------------------------

    #[test]
    fn remove_peer_drops_connections() {
        let mut inner = PoolInner::new(PoolConfig::default());
        let addr: SocketAddr = "127.0.0.1:9109".parse().unwrap();

        for _ in 0..3 {
            let (stream, _peer) = connected_pair();
            inner.checkin(addr, stream);
        }

        // Simulate ConnectionPool::remove_peer
        let removed = if let Some(conns) = inner.entries.remove(&addr) {
            let count = conns.len();
            inner.total -= count;
            count
        } else {
            0
        };
        assert_eq!(removed, 3);
        assert_eq!(inner.total, 0);
    }

    // -----------------------------------------------------------------------
    // PooledConnection RAII
    // -----------------------------------------------------------------------

    #[test]
    fn pooled_connection_into_stream_prevents_return() {
        let pool = TcpConnectionPool::with_defaults();
        let addr: SocketAddr = "127.0.0.1:9110".parse().unwrap();

        let (stream, _peer) = connected_pair();
        pool.checkin(addr, stream);
        assert_eq!(pool.len(), 1);

        let handle = pool.checkout(addr).unwrap();
        let _stream = handle.into_stream(); // Takes ownership, no return.

        assert_eq!(pool.len(), 0);
        drop(_stream);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn pooled_connection_drop_returns_to_pool() {
        let pool = TcpConnectionPool::with_defaults();
        let addr: SocketAddr = "127.0.0.1:9111".parse().unwrap();

        let (stream, _peer) = connected_pair();
        pool.checkin(addr, stream);
        assert_eq!(pool.len(), 1);

        {
            let _handle = pool.checkout(addr).unwrap();
            assert_eq!(pool.len(), 0);
        }
        // Drop returns connection to pool.
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn pooled_connection_unhealthy_drop_closes() {
        let pool = TcpConnectionPool::with_defaults();
        let addr: SocketAddr = "127.0.0.1:9112".parse().unwrap();

        let (stream, _peer) = connected_pair();
        pool.checkin(addr, stream);
        assert_eq!(pool.len(), 1);

        {
            let mut handle = pool.checkout(addr).unwrap();
            handle.mark_unhealthy();
            assert_eq!(pool.len(), 0);
        }
        // Unhealthy handle: stream is closed, not returned.
        assert_eq!(pool.len(), 0);
    }

    // -----------------------------------------------------------------------
    // Multi-peer distribution
    // -----------------------------------------------------------------------

    #[test]
    fn multi_peer_distribution() {
        let mut inner = PoolInner::new(PoolConfig::default());

        for i in 0..3 {
            let addr: SocketAddr = format!("127.0.0.1:{}", 9120 + i).parse().unwrap();
            let (stream, _peer) = connected_pair();
            inner.checkin(addr, stream);
        }

        assert_eq!(inner.total, 3);
        assert_eq!(inner.entries.len(), 3);

        for i in 0..3 {
            let addr: SocketAddr = format!("127.0.0.1:{}", 9120 + i).parse().unwrap();
            assert!(inner.checkout(addr).is_some());
        }
        assert_eq!(inner.total, 0);
    }

    // -----------------------------------------------------------------------
    // Eviction task (tokio test)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn eviction_task_runs() {
        let cfg = PoolConfig {
            eviction_interval: Duration::from_millis(10),
            idle_timeout: Duration::from_millis(5),
            ..Default::default()
        };
        let pool = TcpConnectionPool::new(cfg);

        let addr: SocketAddr = "127.0.0.1:9130".parse().unwrap();
        let (stream, _peer) = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let la = l.local_addr().unwrap();
            let c = tokio::net::TcpStream::connect(la).await.unwrap();
            let (s, _) = l.accept().await.unwrap();
            (c, s)
        };
        pool.checkin(addr, stream);
        assert_eq!(pool.len(), 1);

        // Backdate the entry.
        {
            let mut inner = pool.inner.lock().unwrap();
            if let Some(conns) = inner.entries.get_mut(&addr) {
                for e in conns.iter_mut() {
                    e.last_used = Instant::now() - Duration::from_secs(10);
                }
            }
        }

        let handle = pool.spawn_eviction_task();

        // Wait for a couple of eviction cycles.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The stale connection should have been evicted.
        assert_eq!(pool.len(), 0);

        handle.abort();
    }

    // -----------------------------------------------------------------------
    // Stress: acquire cycle
    // -----------------------------------------------------------------------

    #[test]
    fn acquire_cycle_stress() {
        let pool = TcpConnectionPool::with_defaults();
        let addr: SocketAddr = "127.0.0.1:9140".parse().unwrap();

        // Pre-populate with connections.
        for _ in 0..8 {
            let (stream, _peer) = connected_pair();
            pool.checkin(addr, stream);
        }

        // Cycle checkout/checkin multiple times.
        for _ in 0..20 {
            if let Some(handle) = pool.checkout(addr) {
                let stream = handle.into_stream();
                pool.checkin(addr, stream);
            }
        }

        assert!(!pool.is_empty());
    }
}
