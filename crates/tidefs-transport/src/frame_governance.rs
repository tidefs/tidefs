// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Per-session frame-size governance for the transport layer.
//!
//! ## Governance model
//!
//! A [`FrameSizeGovernor`] enforces configurable byte caps on outbound message
//! payloads and inbound frame deserialization. The governor prevents
//! oversized allocations from buggy callers or malformed peer messages before
//! they consume memory or hit the wire.
//!
//! Two independent limits are enforced:
//!
//! - **Send payload cap** (`max_send_payload_bytes`): checked before the
//!   payload is framed and queued. A send exceeding the cap returns
//!   [`FrameSizeError::SendPayloadTooLarge`].
//! - **Receive frame cap** (`max_recv_frame_bytes`): checked after the frame
//!   length is decoded from the wire and before buffer allocation. A frame
//!   exceeding the cap returns [`FrameSizeError::RecvFrameTooLarge`].
//!
//! ## Per-class overrides
//!
//! The global [`FrameSizeConfig`] can carry per-[`SessionClass`] overrides via
//! `per_class`. When an override exists for the active session class, it
//! replaces the global defaults for that session. This allows bulk-transfer
//! sessions to have larger caps than control sessions, for example.
//!
//! ## Default limits
//!
//! | Limit | Default | Rationale |
//! |---|---|---|
//! | `max_send_payload_bytes` | 16 MiB | Matches `MAX_FRAME_BODY_BYTES`; large enough for state-transfer chunks |
//! | `max_recv_frame_bytes` | 16 MiB | Symmetric with send; prevents oversized inbound allocations |
//!
//! ## Error surface
//!
//! Both checks return [`FrameSizeError`], which implements `Display`, `Error`,
//! `Clone`, `Debug`, `PartialEq`, and `Eq` for ergonomic use in error
//! propagation and test assertions.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use tidefs_types_transport_session::SessionClass;

// ---------------------------------------------------------------------------
// FrameSizeError
// ---------------------------------------------------------------------------

/// Errors returned by frame-size governance checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameSizeError {
    /// The outbound payload exceeds the configured send cap.
    SendPayloadTooLarge {
        /// Configured maximum payload bytes for this session class.
        limit: usize,
        /// Actual payload length that was rejected.
        actual: usize,
    },
    /// The inbound frame exceeds the configured receive cap.
    RecvFrameTooLarge {
        /// Configured maximum frame bytes for this session class.
        limit: usize,
        /// Actual frame length that was rejected.
        actual: usize,
    },
}

impl fmt::Display for FrameSizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SendPayloadTooLarge { limit, actual } => {
                write!(
                    f,
                    "send payload too large: {actual} bytes exceeds limit of {limit} bytes"
                )
            }
            Self::RecvFrameTooLarge { limit, actual } => {
                write!(
                    f,
                    "recv frame too large: {actual} bytes exceeds limit of {limit} bytes"
                )
            }
        }
    }
}

impl std::error::Error for FrameSizeError {}

// ---------------------------------------------------------------------------
// FrameSizeConfig
// ---------------------------------------------------------------------------

/// Configuration for per-session frame-size governance.
///
/// Holds global send and receive byte caps plus optional per-[`SessionClass`]
/// overrides. When a per-class override exists, it takes precedence over the
/// global defaults for sessions of that class.
#[derive(Clone, Debug)]
pub struct FrameSizeConfig {
    /// Maximum payload bytes for outbound sends (default 16 MiB).
    pub max_send_payload_bytes: usize,
    /// Maximum frame bytes for inbound receives (default 16 MiB).
    pub max_recv_frame_bytes: usize,
    /// Per-session-class overrides. When present, the per-class value
    /// replaces the global default for sessions of that class.
    pub per_class: HashMap<SessionClass, ClassFrameSizeLimits>,
}

/// Per-class frame-size limits that override the global defaults.
#[derive(Clone, Debug, Default)]
pub struct ClassFrameSizeLimits {
    /// Maximum payload bytes for outbound sends on this session class.
    pub max_send_payload_bytes: Option<usize>,
    /// Maximum frame bytes for inbound receives on this session class.
    pub max_recv_frame_bytes: Option<usize>,
}

/// Default send payload cap: 16 MiB, matching `MAX_FRAME_BODY_BYTES`.
pub const DEFAULT_MAX_SEND_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

/// Default receive frame cap: 16 MiB.
pub const DEFAULT_MAX_RECV_FRAME_BYTES: usize = 16 * 1024 * 1024;

impl Default for FrameSizeConfig {
    fn default() -> Self {
        Self {
            max_send_payload_bytes: DEFAULT_MAX_SEND_PAYLOAD_BYTES,
            max_recv_frame_bytes: DEFAULT_MAX_RECV_FRAME_BYTES,
            per_class: HashMap::new(),
        }
    }
}

impl FrameSizeConfig {
    // ----------------------------------------------------------------
    // Builder helpers
    // ----------------------------------------------------------------

    /// Set the global maximum send payload bytes.
    #[must_use]
    pub fn with_max_send_payload_bytes(mut self, bytes: usize) -> Self {
        self.max_send_payload_bytes = bytes;
        self
    }

    /// Set the global maximum receive frame bytes.
    #[must_use]
    pub fn with_max_recv_frame_bytes(mut self, bytes: usize) -> Self {
        self.max_recv_frame_bytes = bytes;
        self
    }

    /// Override the send cap for a specific session class.
    #[must_use]
    pub fn with_class_send_override(mut self, sc: SessionClass, bytes: usize) -> Self {
        self.per_class.entry(sc).or_default().max_send_payload_bytes = Some(bytes);
        self
    }

    /// Override the receive cap for a specific session class.
    #[must_use]
    pub fn with_class_recv_override(mut self, sc: SessionClass, bytes: usize) -> Self {
        self.per_class.entry(sc).or_default().max_recv_frame_bytes = Some(bytes);
        self
    }

    // ----------------------------------------------------------------
    // Effective limit resolution
    // ----------------------------------------------------------------

    /// Return the effective send payload cap for the given session class,
    /// falling back to the global default when no per-class override exists.
    #[must_use]
    pub fn effective_send_limit(&self, sc: Option<SessionClass>) -> usize {
        sc.and_then(|s| {
            self.per_class
                .get(&s)
                .and_then(|l| l.max_send_payload_bytes)
        })
        .unwrap_or(self.max_send_payload_bytes)
    }

    /// Return the effective receive frame cap for the given session class,
    /// falling back to the global default when no per-class override exists.
    #[must_use]
    pub fn effective_recv_limit(&self, sc: Option<SessionClass>) -> usize {
        sc.and_then(|s| self.per_class.get(&s).and_then(|l| l.max_recv_frame_bytes))
            .unwrap_or(self.max_recv_frame_bytes)
    }
}

// ---------------------------------------------------------------------------
// FrameSizeGovernor
// ---------------------------------------------------------------------------

/// Per-session frame-size governor that enforces byte caps on sends and
/// receives.
///
/// Wraps an [`Arc`]`<`[`FrameSizeConfig`]`>` so the governor can be shared
/// between the send and receive halves of a session without cloning the
/// configuration. The governor is cheap to clone.
///
/// # Usage
///
/// ```ignore
/// let config = FrameSizeConfig::default();
/// let governor = FrameSizeGovernor::new(config);
///
/// // Before sending:
/// governor.check_send(session_class, payload.len())?;
///
/// // Before allocating for a received frame:
/// governor.check_recv(session_class, frame_len)?;
/// ```
#[derive(Clone, Debug)]
pub struct FrameSizeGovernor {
    config: Arc<FrameSizeConfig>,
}

impl FrameSizeGovernor {
    /// Create a new governor wrapping the given config.
    #[must_use]
    pub fn new(config: FrameSizeConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// Check whether an outbound payload of `payload_len` bytes is within
    /// the configured send cap for the given session class.
    ///
    /// # Errors
    ///
    /// Returns [`FrameSizeError::SendPayloadTooLarge`] if `payload_len`
    /// exceeds the effective send limit.
    pub fn check_send(
        &self,
        session_class: Option<SessionClass>,
        payload_len: usize,
    ) -> Result<(), FrameSizeError> {
        let limit = self.config.effective_send_limit(session_class);
        if payload_len > limit {
            return Err(FrameSizeError::SendPayloadTooLarge {
                limit,
                actual: payload_len,
            });
        }
        Ok(())
    }

    /// Check whether an inbound frame of `frame_len` bytes is within the
    /// configured receive cap for the given session class.
    ///
    /// # Errors
    ///
    /// Returns [`FrameSizeError::RecvFrameTooLarge`] if `frame_len` exceeds
    /// the effective receive limit.
    pub fn check_recv(
        &self,
        session_class: Option<SessionClass>,
        frame_len: usize,
    ) -> Result<(), FrameSizeError> {
        let limit = self.config.effective_recv_limit(session_class);
        if frame_len > limit {
            return Err(FrameSizeError::RecvFrameTooLarge {
                limit,
                actual: frame_len,
            });
        }
        Ok(())
    }

    /// Return the effective send payload cap for the given session class.
    #[must_use]
    pub fn send_limit(&self, session_class: Option<SessionClass>) -> usize {
        self.config.effective_send_limit(session_class)
    }

    /// Return the effective receive frame cap for the given session class.
    #[must_use]
    pub fn recv_limit(&self, session_class: Option<SessionClass>) -> usize {
        self.config.effective_recv_limit(session_class)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // FrameSizeConfig defaults
    // ---------------------------------------------------------------

    #[test]
    fn config_defaults() {
        let cfg = FrameSizeConfig::default();
        assert_eq!(cfg.max_send_payload_bytes, DEFAULT_MAX_SEND_PAYLOAD_BYTES);
        assert_eq!(cfg.max_recv_frame_bytes, DEFAULT_MAX_RECV_FRAME_BYTES);
        assert!(cfg.per_class.is_empty());
    }

    #[test]
    fn config_effective_limits_no_override() {
        let cfg = FrameSizeConfig::default();
        assert_eq!(
            cfg.effective_send_limit(None),
            DEFAULT_MAX_SEND_PAYLOAD_BYTES
        );
        assert_eq!(
            cfg.effective_send_limit(Some(SessionClass::Control)),
            DEFAULT_MAX_SEND_PAYLOAD_BYTES
        );
        assert_eq!(cfg.effective_recv_limit(None), DEFAULT_MAX_RECV_FRAME_BYTES);
        assert_eq!(
            cfg.effective_recv_limit(Some(SessionClass::TransferBulk)),
            DEFAULT_MAX_RECV_FRAME_BYTES
        );
    }

    // ---------------------------------------------------------------
    // Per-class overrides
    // ---------------------------------------------------------------

    #[test]
    fn config_per_class_send_override() {
        let cfg =
            FrameSizeConfig::default().with_class_send_override(SessionClass::Control, 1_000_000);

        assert_eq!(
            cfg.effective_send_limit(None),
            DEFAULT_MAX_SEND_PAYLOAD_BYTES
        );
        assert_eq!(
            cfg.effective_send_limit(Some(SessionClass::Control)),
            1_000_000
        );
        assert_eq!(
            cfg.effective_send_limit(Some(SessionClass::TransferBulk)),
            DEFAULT_MAX_SEND_PAYLOAD_BYTES
        );
    }

    #[test]
    fn config_per_class_recv_override() {
        let cfg = FrameSizeConfig::default()
            .with_class_recv_override(SessionClass::TransferBulk, 32 * 1024 * 1024);

        assert_eq!(cfg.effective_recv_limit(None), DEFAULT_MAX_RECV_FRAME_BYTES);
        assert_eq!(
            cfg.effective_recv_limit(Some(SessionClass::TransferBulk)),
            32 * 1024 * 1024
        );
        assert_eq!(
            cfg.effective_recv_limit(Some(SessionClass::Control)),
            DEFAULT_MAX_RECV_FRAME_BYTES
        );
    }

    #[test]
    fn config_per_class_both_overrides() {
        let cfg = FrameSizeConfig::default()
            .with_class_send_override(SessionClass::TransferBulk, 32 * 1024 * 1024)
            .with_class_recv_override(SessionClass::TransferBulk, 32 * 1024 * 1024);

        assert_eq!(
            cfg.effective_send_limit(Some(SessionClass::TransferBulk)),
            32 * 1024 * 1024
        );
        assert_eq!(
            cfg.effective_recv_limit(Some(SessionClass::TransferBulk)),
            32 * 1024 * 1024
        );
    }

    #[test]
    fn config_builder_methods() {
        let cfg = FrameSizeConfig::default()
            .with_max_send_payload_bytes(8 * 1024 * 1024)
            .with_max_recv_frame_bytes(8 * 1024 * 1024);

        assert_eq!(cfg.max_send_payload_bytes, 8 * 1024 * 1024);
        assert_eq!(cfg.max_recv_frame_bytes, 8 * 1024 * 1024);
    }

    // ---------------------------------------------------------------
    // FrameSizeGovernor: send checks
    // ---------------------------------------------------------------

    #[test]
    fn governor_send_within_limit() {
        let governor = FrameSizeGovernor::new(FrameSizeConfig::default());
        assert!(governor.check_send(None, 1024).is_ok());
        assert!(governor
            .check_send(None, DEFAULT_MAX_SEND_PAYLOAD_BYTES)
            .is_ok());
        // Exactly at limit is ok (payload_len <= limit)
        assert!(governor
            .check_send(Some(SessionClass::Control), DEFAULT_MAX_SEND_PAYLOAD_BYTES)
            .is_ok());
    }

    #[test]
    fn governor_send_exceeds_limit() {
        let governor = FrameSizeGovernor::new(FrameSizeConfig::default());
        let result = governor.check_send(None, DEFAULT_MAX_SEND_PAYLOAD_BYTES + 1);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            FrameSizeError::SendPayloadTooLarge {
                limit: DEFAULT_MAX_SEND_PAYLOAD_BYTES,
                actual: DEFAULT_MAX_SEND_PAYLOAD_BYTES + 1,
            }
        );
    }

    #[test]
    fn governor_send_respects_per_class_override() {
        let config =
            FrameSizeConfig::default().with_class_send_override(SessionClass::Control, 1024);
        let governor = FrameSizeGovernor::new(config);

        // Within Control's 1024 byte limit
        assert!(governor
            .check_send(Some(SessionClass::Control), 1024)
            .is_ok());
        // Exceeds Control's overridden limit
        let result = governor.check_send(Some(SessionClass::Control), 1025);
        assert_eq!(
            result.unwrap_err(),
            FrameSizeError::SendPayloadTooLarge {
                limit: 1024,
                actual: 1025,
            }
        );
        // TransferBulk still has global default
        assert!(governor
            .check_send(Some(SessionClass::TransferBulk), 1025)
            .is_ok());
    }

    // ---------------------------------------------------------------
    // FrameSizeGovernor: receive checks
    // ---------------------------------------------------------------

    #[test]
    fn governor_recv_within_limit() {
        let governor = FrameSizeGovernor::new(FrameSizeConfig::default());
        assert!(governor.check_recv(None, 1024).is_ok());
        assert!(governor
            .check_recv(None, DEFAULT_MAX_RECV_FRAME_BYTES)
            .is_ok());
    }

    #[test]
    fn governor_recv_exceeds_limit() {
        let governor = FrameSizeGovernor::new(FrameSizeConfig::default());
        let result = governor.check_recv(None, DEFAULT_MAX_RECV_FRAME_BYTES + 1);
        assert_eq!(
            result.unwrap_err(),
            FrameSizeError::RecvFrameTooLarge {
                limit: DEFAULT_MAX_RECV_FRAME_BYTES,
                actual: DEFAULT_MAX_RECV_FRAME_BYTES + 1,
            }
        );
    }

    #[test]
    fn governor_recv_respects_per_class_override() {
        let config =
            FrameSizeConfig::default().with_class_recv_override(SessionClass::Bootstrap, 4096);
        let governor = FrameSizeGovernor::new(config);

        assert!(governor
            .check_recv(Some(SessionClass::Bootstrap), 4096)
            .is_ok());
        let result = governor.check_recv(Some(SessionClass::Bootstrap), 4097);
        assert_eq!(
            result.unwrap_err(),
            FrameSizeError::RecvFrameTooLarge {
                limit: 4096,
                actual: 4097,
            }
        );
    }

    // ---------------------------------------------------------------
    // Zero-size semantics
    // ---------------------------------------------------------------

    #[test]
    fn governor_zero_size_payload_allowed() {
        let governor = FrameSizeGovernor::new(FrameSizeConfig::default());
        assert!(governor.check_send(None, 0).is_ok());
    }

    #[test]
    fn governor_zero_size_frame_allowed() {
        let governor = FrameSizeGovernor::new(FrameSizeConfig::default());
        assert!(governor.check_recv(None, 0).is_ok());
    }

    #[test]
    fn governor_zero_limit_rejects_all_nonzero() {
        let config = FrameSizeConfig::default().with_max_send_payload_bytes(0);
        let governor = FrameSizeGovernor::new(config);

        assert!(governor.check_send(None, 0).is_ok());
        let result = governor.check_send(None, 1);
        assert!(result.is_err());
    }

    // ---------------------------------------------------------------
    // FrameSizeError: Display and Error impl
    // ---------------------------------------------------------------

    #[test]
    fn error_display_send() {
        let e = FrameSizeError::SendPayloadTooLarge {
            limit: 100,
            actual: 200,
        };
        let s = e.to_string();
        assert!(s.contains("200"), "Display should contain actual: {s}");
        assert!(s.contains("100"), "Display should contain limit: {s}");
    }

    #[test]
    fn error_display_recv() {
        let e = FrameSizeError::RecvFrameTooLarge {
            limit: 100,
            actual: 200,
        };
        let s = e.to_string();
        assert!(s.contains("200"), "Display should contain actual: {s}");
        assert!(s.contains("100"), "Display should contain limit: {s}");
    }

    #[test]
    fn error_is_std_error() {
        let e = FrameSizeError::SendPayloadTooLarge {
            limit: 1,
            actual: 2,
        };
        let _: &dyn std::error::Error = &e;
    }

    // ---------------------------------------------------------------
    // FrameSizeGovernor: send_limit / recv_limit accessors
    // ---------------------------------------------------------------

    #[test]
    fn governor_limit_accessors() {
        let config = FrameSizeConfig::default()
            .with_class_send_override(SessionClass::Control, 512)
            .with_class_recv_override(SessionClass::Control, 1024);
        let governor = FrameSizeGovernor::new(config);

        assert_eq!(governor.send_limit(None), DEFAULT_MAX_SEND_PAYLOAD_BYTES);
        assert_eq!(governor.send_limit(Some(SessionClass::Control)), 512);
        assert_eq!(governor.recv_limit(None), DEFAULT_MAX_RECV_FRAME_BYTES);
        assert_eq!(governor.recv_limit(Some(SessionClass::Control)), 1024);
    }

    // ---------------------------------------------------------------
    // FrameSizeGovernor: clone and sharing
    // ---------------------------------------------------------------

    #[test]
    fn governor_clone_shares_config() {
        let governor = FrameSizeGovernor::new(FrameSizeConfig::default());
        let cloned = governor.clone();
        assert_eq!(
            governor.send_limit(Some(SessionClass::Control)),
            cloned.send_limit(Some(SessionClass::Control))
        );
    }

    #[test]
    fn governor_send_and_recv_independent() {
        let config = FrameSizeConfig::default()
            .with_max_send_payload_bytes(1024)
            .with_max_recv_frame_bytes(2048);
        let governor = FrameSizeGovernor::new(config);

        // Send rejects based on send limit
        assert!(governor.check_send(None, 1500).is_err());
        // Recv accepts what send rejects
        assert!(governor.check_recv(None, 1500).is_ok());
        // Recv rejects based on recv limit
        assert!(governor.check_recv(None, 2500).is_err());
    }

    // ---------------------------------------------------------------
    // Full matrix: all 6 SessionClass variants
    // ---------------------------------------------------------------

    #[test]
    fn governor_all_session_classes_no_override() {
        let governor = FrameSizeGovernor::new(FrameSizeConfig::default());
        let classes = [
            SessionClass::Bootstrap,
            SessionClass::Control,
            SessionClass::ReplicationMeta,
            SessionClass::TransferBulk,
            SessionClass::ShadowValidation,
            SessionClass::TransitionOrchestration,
        ];
        for &sc in &classes {
            assert!(
                governor.check_send(Some(sc), 1).is_ok(),
                "send should pass for {sc:?}"
            );
            assert!(
                governor.check_recv(Some(sc), 1).is_ok(),
                "recv should pass for {sc:?}"
            );
        }
    }

    #[test]
    fn config_per_class_override_does_not_affect_other_classes() {
        let cfg = FrameSizeConfig::default()
            .with_class_send_override(SessionClass::Bootstrap, 4096)
            .with_class_recv_override(SessionClass::Bootstrap, 4096);

        assert_eq!(
            cfg.effective_send_limit(Some(SessionClass::Bootstrap)),
            4096
        );
        assert_eq!(
            cfg.effective_recv_limit(Some(SessionClass::Bootstrap)),
            4096
        );

        for sc in &[
            SessionClass::Control,
            SessionClass::ReplicationMeta,
            SessionClass::TransferBulk,
            SessionClass::ShadowValidation,
            SessionClass::TransitionOrchestration,
        ] {
            assert_eq!(
                cfg.effective_send_limit(Some(*sc)),
                DEFAULT_MAX_SEND_PAYLOAD_BYTES,
                "send limit for {sc:?} should stay at default"
            );
            assert_eq!(
                cfg.effective_recv_limit(Some(*sc)),
                DEFAULT_MAX_RECV_FRAME_BYTES,
                "recv limit for {sc:?} should stay at default"
            );
        }
    }
}
