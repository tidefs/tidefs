//! Unified transport configuration surface for endpoint addresses,
//! timeouts, buffer sizes, keepalive parameters, and stream limits.
//!
//! This module provides the input contract for the connection lifecycle
//! state machine and eliminates scattered hardcoded constants across
//! `tidefs-transport`.  Every field is validated at build time; invalid
//! combinations are refused with a [`ConfigError`].
//!
//! # Example
//!
//! ```ignore
//! use std::net::SocketAddr;
//! use tidefs_transport::config::{
//!     TransportConfigBuilder, TransportEndpoint,
//! };
//!
//! let addr: SocketAddr = "192.168.1.10:9090".parse().unwrap();
//! let config = TransportConfigBuilder::default()
//!     .endpoint(TransportEndpoint::Tcp(addr))
//!     .connect_timeout_secs(10)
//!     .send_buffer_size(128 * 1024)
//!     .max_concurrent_streams(512)
//!     .build()
//!     .expect("valid config");
//! ```

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::flow_control::ReceiveWindowConfig;
use crate::receive_flow::ReceiveFlowConfig;
use crate::send_scheduler::SendSchedulerConfig;

// ---------------------------------------------------------------------------
// Placeholder endpoint type -- will be replaced by the canonical
// TransportAddr from #5787.  The variants are designed to be a
// straightforward substitution target.
// ---------------------------------------------------------------------------

/// Placeholder endpoint address.  Once #5787 lands, this will be replaced
/// by the canonical `TransportAddr` enum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportEndpoint {
    /// TCP socket address (host:port).
    Tcp(SocketAddr),
    /// RDMA address -- opaque string until the RDMA address type stabilises.
    Rdma(String),
    /// Unix domain socket path.
    Unix(PathBuf),
}

// ---------------------------------------------------------------------------
// Timeout configuration
// ---------------------------------------------------------------------------

/// Per-connection timeout parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimeoutConfig {
    /// Maximum time allowed for a TCP handshake to complete.
    pub connect_timeout: Duration,
    /// Time after which an idle connection (no data in either direction)
    /// is eligible for keepalive probing.
    pub idle_timeout: Duration,
    /// Maximum time to wait for a single read operation.
    pub read_timeout: Duration,
    /// Maximum time to wait for a single write operation.
    pub write_timeout: Duration,
}

// ---------------------------------------------------------------------------
// Buffer configuration
// ---------------------------------------------------------------------------

/// Per-connection buffer sizes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BufferConfig {
    /// Socket send buffer size in bytes (SO_SNDBUF).
    pub send_buffer_size: usize,
    /// Socket receive buffer size in bytes (SO_RCVBUF).
    pub recv_buffer_size: usize,
}

// ---------------------------------------------------------------------------
// Stream limits
// ---------------------------------------------------------------------------

/// Limits on multiplexed streams within a single transport connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamLimits {
    /// Maximum number of concurrent multiplexed streams.
    pub max_concurrent_streams: usize,
    /// Per-stream buffer capacity in bytes.
    pub per_stream_buffer: usize,
}

// ---------------------------------------------------------------------------
// Keepalive configuration
// ---------------------------------------------------------------------------

/// Keepalive heartbeat parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeepaliveConfig {
    /// Interval between keepalive probes when the connection is idle.
    pub interval: Duration,
    /// Maximum time to wait for a keepalive response before declaring
    /// a probe missed.
    pub timeout: Duration,
    /// Number of consecutive missed probes before the peer is declared
    /// dead.
    pub probe_count: u32,
}

// ---------------------------------------------------------------------------
// Aggregate transport configuration
// ---------------------------------------------------------------------------

/// Configuration for per-session response tracking with timeout expiry.
///
/// Controls how long a caller waits for a response to an in-flight request
/// and how frequently the background reaper scans for expired entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseTrackerConfig {
    /// Default per-request timeout. After this duration the pending response
    /// entry is removed and the caller receives a timeout error.
    pub default_timeout: Duration,
    /// Interval between background scans for expired response entries.
    pub reap_interval: Duration,
    /// Maximum number of concurrently pending responses.
    pub max_pending: Option<usize>,
}

impl Default for ResponseTrackerConfig {
    fn default() -> Self {
        Self {
            default_timeout: Duration::from_secs(30),
            reap_interval: Duration::from_secs(1),
            max_pending: Some(1024),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportConfig {
    endpoint: TransportEndpoint,
    timeouts: TimeoutConfig,
    buffers: BufferConfig,
    stream_limits: StreamLimits,
    /// Keepalive configuration. `None` disables connection-level keepalive
    /// (default — single-node local mounts should not run keepalive).
    keepalive: Option<KeepaliveConfig>,
    /// Receive-window flow control configuration.
    receive_window: ReceiveWindowConfig,
    /// Per-session send-priority scheduler configuration.
    send_scheduler: SendSchedulerConfig,
    /// Receive-side credit flow control configuration.
    receive_flow: ReceiveFlowConfig,
    /// Per-session response tracking with timeout expiry and background reaping.
    response_tracker: ResponseTrackerConfig,
}

impl TransportConfig {
    /// Endpoint address for this transport connection.
    pub fn endpoint(&self) -> &TransportEndpoint {
        &self.endpoint
    }

    /// Timeout parameters.
    pub fn timeouts(&self) -> &TimeoutConfig {
        &self.timeouts
    }

    /// Buffer sizes.
    pub fn buffers(&self) -> &BufferConfig {
        &self.buffers
    }

    /// Multiplexed stream limits.
    pub fn stream_limits(&self) -> &StreamLimits {
        &self.stream_limits
    }

    /// Keepalive heartbeat parameters.
    pub fn keepalive(&self) -> Option<&KeepaliveConfig> {
        self.keepalive.as_ref()
    }

    /// Receive-window flow control configuration.
    pub fn receive_window(&self) -> &ReceiveWindowConfig {
        &self.receive_window
    }

    /// Send-priority scheduler configuration.
    pub fn send_scheduler_config(&self) -> &SendSchedulerConfig {
        &self.send_scheduler
    }

    /// Receive-side credit flow control configuration.
    pub fn receive_flow(&self) -> &ReceiveFlowConfig {
        &self.receive_flow
    }

    /// Per-session response tracking configuration.
    pub fn response_tracker(&self) -> &ResponseTrackerConfig {
        &self.response_tracker
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.timeouts.connect_timeout.is_zero() {
            return Err(ConfigError::ZeroTimeout("connect_timeout"));
        }
        if self.timeouts.idle_timeout.is_zero() {
            return Err(ConfigError::ZeroTimeout("idle_timeout"));
        }
        if self.timeouts.read_timeout.is_zero() {
            return Err(ConfigError::ZeroTimeout("read_timeout"));
        }
        if self.timeouts.write_timeout.is_zero() {
            return Err(ConfigError::ZeroTimeout("write_timeout"));
        }

        if self.buffers.send_buffer_size == 0 {
            return Err(ConfigError::ZeroField("send_buffer_size"));
        }
        if self.buffers.recv_buffer_size == 0 {
            return Err(ConfigError::ZeroField("recv_buffer_size"));
        }

        if self.stream_limits.max_concurrent_streams == 0 {
            return Err(ConfigError::ZeroField("max_concurrent_streams"));
        }
        if self.stream_limits.per_stream_buffer == 0 {
            return Err(ConfigError::ZeroField("per_stream_buffer"));
        }

        if let Some(k) = self.keepalive.as_ref() {
            if k.interval.is_zero() {
                return Err(ConfigError::ZeroTimeout("keepalive_interval"));
            }
            if k.timeout.is_zero() {
                return Err(ConfigError::ZeroTimeout("keepalive_timeout"));
            }
            if k.probe_count == 0 {
                return Err(ConfigError::ZeroField("keepalive_probe_count"));
            }
            if k.timeout > k.interval {
                return Err(ConfigError::TimeoutExceedsIdle("keepalive_timeout"));
            }
        }

        if self.timeouts.read_timeout > self.timeouts.idle_timeout {
            return Err(ConfigError::TimeoutExceedsIdle("read_timeout"));
        }
        if self.timeouts.write_timeout > self.timeouts.idle_timeout {
            return Err(ConfigError::TimeoutExceedsIdle("write_timeout"));
        }

        let _ = &self.endpoint;
        if let Err(msg) = self.receive_window.validate() {
            return Err(ConfigError::Other(msg.to_string()));
        }
        if let Err(msg) = self.send_scheduler.validate() {
            return Err(ConfigError::Other(msg.to_string()));
        }
        if let Err(msg) = self.receive_flow.validate() {
            return Err(ConfigError::Other(msg.to_string()));
        }
        // Response tracker: validate non-zero fields.
        if self.response_tracker.default_timeout.is_zero() {
            return Err(ConfigError::ZeroTimeout("response_tracker.default_timeout"));
        }
        if self.response_tracker.reap_interval.is_zero() {
            return Err(ConfigError::ZeroTimeout("response_tracker.reap_interval"));
        }
        if let Some(mp) = self.response_tracker.max_pending {
            if mp == 0 {
                return Err(ConfigError::ZeroField("response_tracker.max_pending"));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ConfigError
// ---------------------------------------------------------------------------

/// Errors returned by [`TransportConfigBuilder::build`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// The named timeout field is zero.
    ZeroTimeout(&'static str),
    /// The named field (buffer size, stream count, etc.) is zero.
    ZeroField(&'static str),
    /// A timeout value exceeds the idle timeout ceiling.
    TimeoutExceedsIdle(&'static str),
    /// Generic configuration error.
    Other(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::ZeroTimeout(name) => {
                write!(f, "timeout field `{name}` must be non-zero")
            }
            ConfigError::ZeroField(name) => {
                write!(f, "field `{name}` must be non-zero")
            }
            ConfigError::TimeoutExceedsIdle(name) => {
                write!(f, "timeout `{name}` must not exceed idle_timeout")
            }
            ConfigError::Other(msg) => {
                write!(f, "config error: {msg}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

// ---------------------------------------------------------------------------
// Default configuration
// ---------------------------------------------------------------------------

/// Production-safe defaults.
fn default_endpoint() -> TransportEndpoint {
    TransportEndpoint::Tcp("127.0.0.1:9090".parse().unwrap())
}

fn default_timeouts() -> TimeoutConfig {
    TimeoutConfig {
        connect_timeout: Duration::from_secs(30),
        idle_timeout: Duration::from_secs(300),
        read_timeout: Duration::from_secs(30),
        write_timeout: Duration::from_secs(30),
    }
}

fn default_buffers() -> BufferConfig {
    BufferConfig {
        send_buffer_size: 64 * 1024,
        recv_buffer_size: 64 * 1024,
    }
}

fn default_stream_limits() -> StreamLimits {
    StreamLimits {
        max_concurrent_streams: 256,
        per_stream_buffer: 64 * 1024,
    }
}

fn default_receive_flow() -> ReceiveFlowConfig {
    ReceiveFlowConfig::default()
}

fn default_receive_window() -> ReceiveWindowConfig {
    ReceiveWindowConfig::default()
}

fn default_keepalive() -> Option<KeepaliveConfig> {
    // Keepalive is opt-in; disabled by default.
    // Enable via TransportConfigBuilder::with_keepalive().
    None
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            endpoint: default_endpoint(),
            timeouts: default_timeouts(),
            buffers: default_buffers(),
            stream_limits: default_stream_limits(),
            keepalive: default_keepalive(),
            receive_window: default_receive_window(),
            send_scheduler: SendSchedulerConfig::default(),
            receive_flow: default_receive_flow(),
            response_tracker: ResponseTrackerConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builds a validated [`TransportConfig`].
///
/// All fields start from production defaults (see
/// [`TransportConfig::default`]).  Chainable setters override individual
/// fields.  Call [`build`](Self::build) to validate and produce the final
/// configuration.
#[derive(Clone, Debug)]
pub struct TransportConfigBuilder {
    endpoint: TransportEndpoint,
    timeouts: TimeoutConfig,
    buffers: BufferConfig,
    stream_limits: StreamLimits,
    /// Keepalive configuration. `None` disables connection-level keepalive
    /// (default — single-node local mounts should not run keepalive).
    keepalive: Option<KeepaliveConfig>,
    receive_window: ReceiveWindowConfig,
    /// Per-session send-priority scheduler configuration.
    send_scheduler: SendSchedulerConfig,
    /// Receive-side credit flow control configuration.
    receive_flow: ReceiveFlowConfig,
    /// Per-session response tracking with timeout expiry and background reaping.
    response_tracker: ResponseTrackerConfig,
}

impl Default for TransportConfigBuilder {
    fn default() -> Self {
        Self {
            endpoint: default_endpoint(),
            timeouts: default_timeouts(),
            buffers: default_buffers(),
            stream_limits: default_stream_limits(),
            keepalive: default_keepalive(),
            receive_window: default_receive_window(),
            send_scheduler: SendSchedulerConfig::default(),
            receive_flow: default_receive_flow(),
            response_tracker: ResponseTrackerConfig::default(),
        }
    }
}

impl TransportConfigBuilder {
    /// Create a builder starting from an existing [`TransportConfig`].
    pub fn from_config(config: &TransportConfig) -> Self {
        Self {
            endpoint: config.endpoint.clone(),
            timeouts: config.timeouts.clone(),
            buffers: config.buffers.clone(),
            stream_limits: config.stream_limits.clone(),
            keepalive: config.keepalive.clone(),
            receive_window: config.receive_window.clone(),
            send_scheduler: config.send_scheduler.clone(),
            receive_flow: config.receive_flow.clone(),
            response_tracker: config.response_tracker.clone(),
        }
    }

    pub fn endpoint(mut self, e: TransportEndpoint) -> Self {
        self.endpoint = e;
        self
    }

    pub fn connect_timeout(mut self, d: Duration) -> Self {
        self.timeouts.connect_timeout = d;
        self
    }

    pub fn connect_timeout_secs(self, secs: u64) -> Self {
        self.connect_timeout(Duration::from_secs(secs))
    }

    pub fn idle_timeout(mut self, d: Duration) -> Self {
        self.timeouts.idle_timeout = d;
        self
    }

    pub fn idle_timeout_secs(self, secs: u64) -> Self {
        self.idle_timeout(Duration::from_secs(secs))
    }

    pub fn read_timeout(mut self, d: Duration) -> Self {
        self.timeouts.read_timeout = d;
        self
    }

    pub fn read_timeout_secs(self, secs: u64) -> Self {
        self.read_timeout(Duration::from_secs(secs))
    }

    pub fn write_timeout(mut self, d: Duration) -> Self {
        self.timeouts.write_timeout = d;
        self
    }

    pub fn write_timeout_secs(self, secs: u64) -> Self {
        self.write_timeout(Duration::from_secs(secs))
    }

    pub fn send_buffer_size(mut self, sz: usize) -> Self {
        self.buffers.send_buffer_size = sz;
        self
    }

    pub fn recv_buffer_size(mut self, sz: usize) -> Self {
        self.buffers.recv_buffer_size = sz;
        self
    }

    pub fn max_concurrent_streams(mut self, n: usize) -> Self {
        self.stream_limits.max_concurrent_streams = n;
        self
    }

    pub fn per_stream_buffer(mut self, sz: usize) -> Self {
        self.stream_limits.per_stream_buffer = sz;
        self
    }

    /// Enable keepalive with a specific configuration.
    pub fn with_keepalive(mut self, k: KeepaliveConfig) -> Self {
        self.keepalive = Some(k);
        self
    }

    /// Disable keepalive (default).
    pub fn without_keepalive(mut self) -> Self {
        self.keepalive = None;
        self
    }

    /// Set the send-priority scheduler configuration.
    pub fn with_send_scheduler(mut self, cfg: SendSchedulerConfig) -> Self {
        self.send_scheduler = cfg;
        self
    }

    /// Configure receive-side credit flow control.
    ///
    /// Controls how the receiver grants send credits to the remote
    /// sender and when it emits credit-refresh frames to prevent
    /// unbounded inbound buffer growth.
    pub fn with_receive_flow(mut self, cfg: ReceiveFlowConfig) -> Self {
        self.receive_flow = cfg;
        self
    }

    /// Set the per-session response tracking configuration.
    pub fn with_response_tracker(mut self, cfg: ResponseTrackerConfig) -> Self {
        self.response_tracker = cfg;
        self
    }

    /// Set the default per-request response timeout.
    pub fn response_timeout(mut self, d: Duration) -> Self {
        self.response_tracker.default_timeout = d;
        self
    }

    /// Set the background reap interval for expired response entries.
    pub fn response_reap_interval(mut self, d: Duration) -> Self {
        self.response_tracker.reap_interval = d;
        self
    }

    /// Set the maximum number of concurrently pending responses.
    pub fn max_pending_responses(mut self, n: usize) -> Self {
        self.response_tracker.max_pending = Some(n);
        self
    }

    pub fn keepalive_interval(mut self, d: Duration) -> Self {
        let mut k = self.keepalive.unwrap_or_else(|| KeepaliveConfig {
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            probe_count: 3,
        });
        k.interval = d;
        self.keepalive = Some(k);
        self
    }

    pub fn keepalive_interval_secs(self, secs: u64) -> Self {
        self.keepalive_interval(Duration::from_secs(secs))
    }

    pub fn keepalive_timeout(mut self, d: Duration) -> Self {
        let mut k = self.keepalive.unwrap_or_else(|| KeepaliveConfig {
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            probe_count: 3,
        });
        k.timeout = d;
        self.keepalive = Some(k);
        self
    }

    pub fn keepalive_timeout_secs(self, secs: u64) -> Self {
        self.keepalive_timeout(Duration::from_secs(secs))
    }

    pub fn keepalive_probe_count(mut self, n: u32) -> Self {
        let mut k = self.keepalive.unwrap_or_else(|| KeepaliveConfig {
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            probe_count: 3,
        });
        k.probe_count = n;
        self.keepalive = Some(k);
        self
    }

    /// Validate and produce a [`TransportConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if any field fails validation.
    pub fn build(self) -> Result<TransportConfig, ConfigError> {
        let config = TransportConfig {
            endpoint: self.endpoint,
            timeouts: self.timeouts,
            buffers: self.buffers,
            stream_limits: self.stream_limits,
            keepalive: self.keepalive,
            send_scheduler: self.send_scheduler,
            receive_window: self.receive_window,
            receive_flow: self.receive_flow,
            response_tracker: self.response_tracker,
        };
        config.validate()?;
        Ok(config)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn default_matches_builder_no_overrides() {
        let cfg = TransportConfig::default();
        let b = TransportConfigBuilder::default().build().unwrap();
        assert_eq!(cfg, b);
    }

    #[test]
    fn default_connect_timeout_is_30s() {
        assert_eq!(
            TransportConfig::default().timeouts.connect_timeout,
            Duration::from_secs(30)
        );
    }

    #[test]
    fn default_idle_timeout_is_300s() {
        assert_eq!(
            TransportConfig::default().timeouts.idle_timeout,
            Duration::from_secs(300)
        );
    }

    #[test]
    fn default_buffers_are_64k() {
        let cfg = TransportConfig::default();
        assert_eq!(cfg.buffers.send_buffer_size, 64 * 1024);
        assert_eq!(cfg.buffers.recv_buffer_size, 64 * 1024);
    }

    #[test]
    fn default_max_streams_is_256() {
        assert_eq!(
            TransportConfig::default()
                .stream_limits
                .max_concurrent_streams,
            256
        );
    }

    #[test]
    fn default_per_stream_buffer_is_64k() {
        assert_eq!(
            TransportConfig::default().stream_limits.per_stream_buffer,
            64 * 1024
        );
    }

    #[test]
    fn default_keepalive_is_disabled() {
        // Keepalive is opt-in; default config disables it.
        assert!(TransportConfig::default().keepalive().is_none());
    }

    #[test]
    fn with_keepalive_enables_and_sets_fields() {
        let cfg = TransportConfigBuilder::default()
            .with_keepalive(KeepaliveConfig {
                interval: Duration::from_secs(30),
                timeout: Duration::from_secs(5),
                probe_count: 3,
            })
            .build()
            .unwrap();
        let k = cfg.keepalive().unwrap();
        assert_eq!(k.interval, Duration::from_secs(30));
        assert_eq!(k.timeout, Duration::from_secs(5));
        assert_eq!(k.probe_count, 3);
    }

    #[test]
    fn without_keepalive_clears_config() {
        let cfg = TransportConfigBuilder::default()
            .with_keepalive(KeepaliveConfig {
                interval: Duration::from_secs(30),
                timeout: Duration::from_secs(5),
                probe_count: 3,
            })
            .without_keepalive()
            .build()
            .unwrap();
        assert!(cfg.keepalive().is_none());
    }

    #[test]
    fn builder_round_trip_all_fields() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
        let cfg = TransportConfigBuilder::default()
            .endpoint(TransportEndpoint::Tcp(addr))
            .connect_timeout_secs(10)
            .idle_timeout_secs(600)
            .read_timeout_secs(60)
            .write_timeout_secs(60)
            .send_buffer_size(128 * 1024)
            .recv_buffer_size(256 * 1024)
            .max_concurrent_streams(512)
            .per_stream_buffer(32 * 1024)
            .keepalive_interval_secs(15)
            .keepalive_timeout_secs(3)
            .keepalive_probe_count(5)
            .build()
            .unwrap();

        assert_eq!(*cfg.endpoint(), TransportEndpoint::Tcp(addr));
        assert_eq!(cfg.timeouts().connect_timeout, Duration::from_secs(10));
        assert_eq!(cfg.timeouts().idle_timeout, Duration::from_secs(600));
        assert_eq!(cfg.timeouts().read_timeout, Duration::from_secs(60));
        assert_eq!(cfg.timeouts().write_timeout, Duration::from_secs(60));
        assert_eq!(cfg.buffers().send_buffer_size, 128 * 1024);
        assert_eq!(cfg.buffers().recv_buffer_size, 256 * 1024);
        assert_eq!(cfg.stream_limits().max_concurrent_streams, 512);
        assert_eq!(cfg.stream_limits().per_stream_buffer, 32 * 1024);
        assert_eq!(cfg.keepalive().unwrap().interval, Duration::from_secs(15));
        assert_eq!(cfg.keepalive().unwrap().timeout, Duration::from_secs(3));
        assert_eq!(cfg.keepalive().unwrap().probe_count, 5);
    }

    #[test]
    fn reject_zero_connect_timeout() {
        let err = TransportConfigBuilder::default()
            .connect_timeout(Duration::ZERO)
            .build()
            .unwrap_err();
        assert_eq!(err, ConfigError::ZeroTimeout("connect_timeout"));
    }

    #[test]
    fn reject_zero_idle_timeout() {
        let err = TransportConfigBuilder::default()
            .idle_timeout(Duration::ZERO)
            .build()
            .unwrap_err();
        assert_eq!(err, ConfigError::ZeroTimeout("idle_timeout"));
    }

    #[test]
    fn reject_zero_read_timeout() {
        let err = TransportConfigBuilder::default()
            .read_timeout(Duration::ZERO)
            .build()
            .unwrap_err();
        assert_eq!(err, ConfigError::ZeroTimeout("read_timeout"));
    }

    #[test]
    fn reject_zero_write_timeout() {
        let err = TransportConfigBuilder::default()
            .write_timeout(Duration::ZERO)
            .build()
            .unwrap_err();
        assert_eq!(err, ConfigError::ZeroTimeout("write_timeout"));
    }

    #[test]
    fn reject_zero_send_buffer_size() {
        let err = TransportConfigBuilder::default()
            .send_buffer_size(0)
            .build()
            .unwrap_err();
        assert_eq!(err, ConfigError::ZeroField("send_buffer_size"));
    }

    #[test]
    fn reject_zero_recv_buffer_size() {
        let err = TransportConfigBuilder::default()
            .recv_buffer_size(0)
            .build()
            .unwrap_err();
        assert_eq!(err, ConfigError::ZeroField("recv_buffer_size"));
    }

    #[test]
    fn reject_zero_max_concurrent_streams() {
        let err = TransportConfigBuilder::default()
            .max_concurrent_streams(0)
            .build()
            .unwrap_err();
        assert_eq!(err, ConfigError::ZeroField("max_concurrent_streams"));
    }

    #[test]
    fn reject_zero_per_stream_buffer() {
        let err = TransportConfigBuilder::default()
            .per_stream_buffer(0)
            .build()
            .unwrap_err();
        assert_eq!(err, ConfigError::ZeroField("per_stream_buffer"));
    }

    #[test]
    fn reject_zero_keepalive_interval() {
        let err = TransportConfigBuilder::default()
            .keepalive_interval(Duration::ZERO)
            .build()
            .unwrap_err();
        assert_eq!(err, ConfigError::ZeroTimeout("keepalive_interval"));
    }

    #[test]
    fn reject_zero_keepalive_timeout() {
        let err = TransportConfigBuilder::default()
            .keepalive_timeout(Duration::ZERO)
            .build()
            .unwrap_err();
        assert_eq!(err, ConfigError::ZeroTimeout("keepalive_timeout"));
    }

    #[test]
    fn reject_zero_keepalive_probe_count() {
        let err = TransportConfigBuilder::default()
            .keepalive_probe_count(0)
            .build()
            .unwrap_err();
        assert_eq!(err, ConfigError::ZeroField("keepalive_probe_count"));
    }

    #[test]
    fn reject_read_timeout_exceeds_idle() {
        let err = TransportConfigBuilder::default()
            .idle_timeout_secs(10)
            .read_timeout_secs(20)
            .build()
            .unwrap_err();
        assert_eq!(err, ConfigError::TimeoutExceedsIdle("read_timeout"));
    }

    #[test]
    fn reject_write_timeout_exceeds_idle() {
        let err = TransportConfigBuilder::default()
            .idle_timeout_secs(10)
            .read_timeout_secs(5)
            .write_timeout_secs(20)
            .build()
            .unwrap_err();
        assert_eq!(err, ConfigError::TimeoutExceedsIdle("write_timeout"));
    }

    #[test]
    fn reject_keepalive_timeout_exceeds_interval() {
        let err = TransportConfigBuilder::default()
            .keepalive_interval_secs(5)
            .keepalive_timeout_secs(10)
            .build()
            .unwrap_err();
        assert_eq!(err, ConfigError::TimeoutExceedsIdle("keepalive_timeout"));
    }

    #[test]
    fn from_config_round_trip() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)), 9000);
        let original = TransportConfigBuilder::default()
            .endpoint(TransportEndpoint::Tcp(addr))
            .connect_timeout_secs(5)
            .build()
            .unwrap();
        let rebuilt = TransportConfigBuilder::from_config(&original)
            .build()
            .unwrap();
        assert_eq!(original, rebuilt);
    }

    #[test]
    fn accessors_match_inner() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), 7000);
        let cfg = TransportConfigBuilder::default()
            .endpoint(TransportEndpoint::Tcp(addr))
            .build()
            .unwrap();
        assert_eq!(*cfg.endpoint(), TransportEndpoint::Tcp(addr));
        assert_eq!(cfg.timeouts().connect_timeout, Duration::from_secs(30));
        assert_eq!(cfg.buffers().send_buffer_size, 64 * 1024);
    }

    #[test]
    fn unix_endpoint_round_trip() {
        let cfg = TransportConfigBuilder::default()
            .endpoint(TransportEndpoint::Unix(PathBuf::from("/tmp/tidefs.sock")))
            .build()
            .unwrap();
        assert_eq!(
            *cfg.endpoint(),
            TransportEndpoint::Unix(PathBuf::from("/tmp/tidefs.sock"))
        );
    }

    #[test]
    fn config_error_display_zero_timeout() {
        let e = ConfigError::ZeroTimeout("connect_timeout");
        assert!(e.to_string().contains("connect_timeout"));
    }

    #[test]
    fn config_error_display_zero_field() {
        let e = ConfigError::ZeroField("send_buffer_size");
        assert!(e.to_string().contains("send_buffer_size"));
    }

    #[test]
    fn config_error_display_timeout_exceeds_idle() {
        let e = ConfigError::TimeoutExceedsIdle("read_timeout");
        assert!(e.to_string().contains("read_timeout"));
        assert!(e.to_string().contains("idle_timeout"));
    }
}
