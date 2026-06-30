// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Transport message dispatch registry keyed by [`MessageFamily`].
//!
//! ## Purpose
//!
//! After the receive path decodes transport envelopes and demultiplexes
//! streams, the decoded message payload must be routed to the correct
//! subsystem handler (membership, leases, placement, state transfer, etc.).
//! This module provides a registry that maps each [`MessageFamily`] variant
//! to a boxed [`MessageHandler`], enabling the transport layer to route
//! messages to subsystem handlers without depending on those subsystems.
//!
//! ## Architecture
//!
//! ```text
//! DecodedMessage { family, payload }
//!   |
//!   v
//! MessageDispatch::dispatch(msg)
//!   |
//!   +-- lookup family -> Box<dyn MessageHandler>
//!   +-- handler.handle(msg)
//! ```
//!
//! ## Thread safety
//!
//! [`MessageDispatch`] uses an internal [`RwLock`] protecting the handler
//! table, so it can be shared as `Arc<MessageDispatch>` across tasks.
//! Registration acquires a write lock; dispatch acquires a read lock.
//!
//! ## Integration with the receive path
//!
//! The session receive loop calls [`MessageDispatch::dispatch()`] with the
//! decoded [`MessageFamily`] and payload. The registry looks up the handler
//! and delegates. If no handler is registered for the family,
//! [`DispatchError::NoHandlerRegistered`] is returned.

use std::collections::HashMap;
use std::fmt;
use std::sync::RwLock;

use crate::channel::ChannelId;
use crate::envelope::MessageFamily;
use crate::types::SessionId;
use crate::write_gate::WriteGate;
use tidefs_cluster::write_fence::{StaleFence, WriteFence};

// ---------------------------------------------------------------------------
// DecodedMessage
// ---------------------------------------------------------------------------

/// A decoded message received from the transport layer, carrying the
/// [`MessageFamily`] discriminant and the raw payload bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedMessage {
    /// Authenticated transport session that received this message, when known.
    pub session_id: Option<SessionId>,
    /// The multiplex channel ID, if this message was received on a specific channel.
    pub channel_id: Option<ChannelId>,
    /// The message family that classifies this message.
    pub family: MessageFamily,
    /// The raw payload bytes (opaque to the dispatch layer).
    pub payload: Vec<u8>,
}

impl DecodedMessage {
    /// Create a new decoded message.
    #[must_use]
    pub fn new(family: MessageFamily, payload: Vec<u8>) -> Self {
        Self {
            session_id: None,
            family,
            payload,
            channel_id: None,
        }
    }

    /// Create a decoded message associated with a specific channel.
    #[must_use]
    pub fn with_channel_id(family: MessageFamily, payload: Vec<u8>, channel_id: ChannelId) -> Self {
        Self {
            session_id: None,
            family,
            payload,
            channel_id: Some(channel_id),
        }
    }

    /// Attach the authenticated transport session that carried this message.
    #[must_use]
    pub fn with_session_id(mut self, session_id: SessionId) -> Self {
        self.session_id = Some(session_id);
        self
    }
}

// ---------------------------------------------------------------------------
// DispatchError
// ---------------------------------------------------------------------------

/// Errors that can occur during message dispatch.
#[derive(Debug)]
pub enum DispatchError {
    /// No handler is registered for the requested [`MessageFamily`].
    NoHandlerRegistered(MessageFamily),
    /// The registered handler returned an error.
    HandlerError(Box<dyn std::error::Error>),
    /// Write rejected: fence token is stale (prior lease holder).
    /// Returned when a message with a write-gated family arrives
    /// and the local node does not hold the active write fence.
    StaleFence(StaleFence),
}

use tracing;
impl fmt::Display for DispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoHandlerRegistered(family) => {
                write!(f, "no handler registered for message family: {family}")
            }
            Self::HandlerError(e) => write!(f, "handler error: {e}"),
            Self::StaleFence(sf) => write!(f, "stale write fence: {sf}"),
        }
    }
}

impl std::error::Error for DispatchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::HandlerError(e) => Some(e.as_ref()),
            Self::NoHandlerRegistered(_) => None,
            Self::StaleFence(sf) => Some(sf),
        }
    }
}

// ---------------------------------------------------------------------------
// MessageHandler trait
// ---------------------------------------------------------------------------

/// Trait for handling decoded transport messages keyed by [`MessageFamily`].
///
/// Implementors receive the full [`DecodedMessage`] (family + payload).
/// Implementations must be `Send + Sync` for concurrent registration.
pub trait MessageHandler: Send + Sync {
    /// Handle an incoming decoded message.
    ///
    /// # Errors
    ///
    /// Returns [`DispatchError::HandlerError`] if the handler cannot process
    /// the message (malformed payload, wrong state, etc.).
    fn handle(&self, msg: DecodedMessage) -> Result<(), DispatchError>;
}

// ---------------------------------------------------------------------------
// MessageDispatch
// ---------------------------------------------------------------------------

/// Registry-based dispatcher that routes decoded transport messages to
/// registered subsystem handlers based on [`MessageFamily`].
///
/// Handlers are stored in a [`HashMap`] keyed by [`MessageFamily`] inside
/// an [`RwLock`] for concurrent access. Registration acquires a write lock;
/// dispatch acquires a read lock.
///
/// This type is designed to be shared via `Arc<MessageDispatch>`.
pub struct MessageDispatch {
    handlers: RwLock<HashMap<MessageFamily, Box<dyn MessageHandler>>>,
    /// Optional write gate for single-writer fencing on the receive side.
    /// When configured, messages arriving on write-gated families
    /// (ReplicaTransferVerify, StateTransfer) are rejected if this
    /// node does not hold an active write fence.
    write_gate: Option<WriteGate>,
    /// Optional membership pre-dispatch handler for PublicationProgress.
    /// Checked before general family-handler lookup; enables membership
    /// messages to bypass the family-handler map.
    membership_handler: Option<Box<dyn MessageHandler>>,
}

impl MessageDispatch {
    /// Create a new empty message dispatch registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: RwLock::new(HashMap::new()),
            write_gate: None,
            membership_handler: None,
        }
    }

    /// Set the write gate for single-writer fencing on the receive side.
    ///
    /// When configured, messages arriving on write-gated families
    /// ([`MessageFamily::ReplicaTransferVerify`], [`MessageFamily::StateTransfer`])
    /// are rejected with [`DispatchError::StaleFence`] if this node does not
    /// hold an active write fence.
    pub fn with_write_gate(mut self, write_gate: WriteGate) -> Self {
        self.write_gate = Some(write_gate);
        self
    }

    /// Configure a dedicated membership inbound dispatch handler.
    ///
    /// When set, inbound `MessageFamily::PublicationProgress` messages are
    /// forwarded to this handler *before* the general family-handler map
    /// lookup. If the membership handler returns `Ok(())`, the message is
    /// considered consumed and the general lookup is skipped.
    #[must_use]
    pub fn with_membership_handler(mut self, handler: Box<dyn MessageHandler>) -> Self {
        self.membership_handler = Some(handler);
        self
    }

    /// Return true if the given [`MessageFamily`] requires write-fence
    /// authorization before dispatch.
    fn family_requires_write_fence(family: MessageFamily) -> bool {
        matches!(
            family,
            MessageFamily::ReplicaTransferVerify | MessageFamily::StateTransfer
        )
    }

    /// Register a handler for a given [`MessageFamily`].
    ///
    /// If a handler is already registered for this family, it is replaced.
    pub fn register(&self, family: MessageFamily, handler: Box<dyn MessageHandler>) {
        self.handlers.write().unwrap().insert(family, handler);
    }

    /// Remove the handler for a given [`MessageFamily`].
    ///
    /// Returns the removed handler, if any.
    pub fn unregister(&self, family: MessageFamily) -> Option<Box<dyn MessageHandler>> {
        self.handlers.write().unwrap().remove(&family)
    }

    /// Dispatch a decoded message to the handler registered for its family.
    ///
    /// Looks up the handler for `msg.family` and delegates to
    /// [`MessageHandler::handle`].
    ///
    /// # Errors
    ///
    /// Returns [`DispatchError::NoHandlerRegistered`] if no handler is
    /// registered for the message's family.
    pub fn dispatch(&self, msg: DecodedMessage) -> Result<(), DispatchError> {
        let family = msg.family;

        // Membership pre-dispatch: route PublicationProgress through the
        // dedicated membership handler before general family-map lookup.
        if family == MessageFamily::PublicationProgress {
            if let Some(ref handler) = self.membership_handler {
                return handler.handle(msg);
            }
        }

        // Single-writer fence check for write-gated families.
        if Self::family_requires_write_fence(family) {
            if let Some(ref gate) = self.write_gate {
                match gate.active_fence() {
                    None => {
                        return Err(DispatchError::StaleFence(StaleFence::new(
                            WriteFence::new(tidefs_membership_epoch::EpochId(0), 0),
                            WriteFence::new(tidefs_membership_epoch::EpochId(0), 0),
                        )));
                    }
                    Some(_active) => {
                        // Active fence exists; write messages are authorized.
                    }
                }
            }
            // If no write_gate is configured, writes pass through (backward compat).
        }

        let guard = self.handlers.read().unwrap();
        let handler = guard
            .get(&family)
            .ok_or(DispatchError::NoHandlerRegistered(family))?;

        handler.handle(msg)
    }

    /// Return whether a handler is registered for the given [`MessageFamily`].
    #[must_use]
    pub fn has_handler(&self, family: MessageFamily) -> bool {
        self.handlers.read().unwrap().contains_key(&family)
    }

    /// Return the number of registered handlers.
    #[must_use]
    pub fn handler_count(&self) -> usize {
        self.handlers.read().unwrap().len()
    }

    /// Return whether a membership pre-dispatch handler is configured.
    ///
    /// When true, `MessageFamily::PublicationProgress` messages are routed
    /// through the membership handler before family-map lookup.
    #[must_use]
    pub fn has_membership_handler(&self) -> bool {
        self.membership_handler.is_some()
    }

    /// Dispatch with warning-instrumented drop for unregistered families.
    ///
    /// If no handler is registered for `msg.family`, logs a `tracing::warn!`
    /// and returns silently (no silent drops).  If the handler itself errors,
    /// the error is logged via `tracing::warn!` as well.
    pub fn dispatch_or_warn(&self, msg: DecodedMessage) {
        let family = msg.family;
        match self.dispatch(msg) {
            Ok(()) => {}
            Err(DispatchError::NoHandlerRegistered(f)) => {
                tracing::warn!(
                    family = %f,
                    "no handler registered for message family -- message dropped"
                );
            }
            Err(e) => {
                tracing::warn!(
                    family = %family,
                    error = %e,
                    "dispatch handler returned error"
                );
            }
        }
    }
}

impl Default for MessageDispatch {
    fn default() -> Self {
        Self::new()
    }
}

// -- #[cfg(test)] registration helpers --------------------------

#[cfg(test)]
impl MessageDispatch {
    /// Register a test handler, returning `self` for chaining.
    pub fn with_test_handler(
        self,
        family: MessageFamily,
        handler: Box<dyn MessageHandler>,
    ) -> Self {
        self.register(family, handler);
        self
    }

    /// Bulk-register handlers, returning `self` for chaining.
    pub fn with_test_handlers(
        self,
        pairs: impl IntoIterator<Item = (MessageFamily, Box<dyn MessageHandler>)>,
    ) -> Self {
        for (family, handler) in pairs {
            self.register(family, handler);
        }
        self
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::sync::{Arc, Mutex};

    /// A shared call log for tracking handler invocations.
    #[derive(Clone, Default)]
    struct CallLog {
        calls: Arc<Mutex<Vec<DecodedMessage>>>,
    }

    impl CallLog {
        fn new() -> Self {
            Self::default()
        }

        fn push(&self, msg: DecodedMessage) {
            self.calls.lock().unwrap().push(msg);
        }

        fn count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }

        fn last(&self) -> Option<DecodedMessage> {
            self.calls.lock().unwrap().last().cloned()
        }
    }

    /// A test handler that records invocations to a shared [`CallLog`].
    struct RecordingHandler {
        log: CallLog,
        reject: Mutex<bool>,
    }

    impl RecordingHandler {
        fn new(log: CallLog) -> Self {
            Self {
                log,
                reject: Mutex::new(false),
            }
        }

        fn set_reject(&self, reject: bool) {
            *self.reject.lock().unwrap() = reject;
        }
    }

    impl MessageHandler for RecordingHandler {
        fn handle(&self, msg: DecodedMessage) -> Result<(), DispatchError> {
            if *self.reject.lock().unwrap() {
                return Err(DispatchError::HandlerError(
                    "test rejection".to_string().into(),
                ));
            }
            self.log.push(msg);
            Ok(())
        }
    }

    // -------------------------------------------------------------------
    // DecodedMessage tests
    // -------------------------------------------------------------------

    #[test]
    fn decoded_message_new() {
        let msg = DecodedMessage::new(MessageFamily::HelloClose, b"hello".to_vec());
        assert_eq!(msg.family, MessageFamily::HelloClose);
        assert_eq!(msg.payload, b"hello");
    }

    #[test]
    fn decoded_message_clone() {
        let msg = DecodedMessage::new(MessageFamily::StateTransfer, b"chunk".to_vec());
        let clone = msg.clone();
        assert_eq!(msg.family, clone.family);
        assert_eq!(msg.payload, clone.payload);
    }

    // -------------------------------------------------------------------
    // MessageDispatch tests
    // -------------------------------------------------------------------

    #[test]
    fn new_is_empty() {
        let d = MessageDispatch::new();
        assert_eq!(d.handler_count(), 0);
    }

    #[test]
    fn register_and_dispatch() {
        let d = MessageDispatch::new();
        let log = CallLog::new();
        let handler: Box<dyn MessageHandler> = Box::new(RecordingHandler::new(log.clone()));

        d.register(MessageFamily::StateTransfer, handler);
        assert_eq!(d.handler_count(), 1);
        assert!(d.has_handler(MessageFamily::StateTransfer));

        let msg = DecodedMessage::new(MessageFamily::StateTransfer, b"payload-1".to_vec());
        d.dispatch(msg).unwrap();

        assert_eq!(log.count(), 1);
        assert_eq!(log.last().unwrap().payload, b"payload-1");
    }

    #[test]
    fn dispatch_invokes_correct_handler() {
        let d = MessageDispatch::new();

        let log_st = CallLog::new();
        let log_hb = CallLog::new();
        let log_el = CallLog::new();

        d.register(
            MessageFamily::StateTransfer,
            Box::new(RecordingHandler::new(log_st.clone())),
        );
        d.register(
            MessageFamily::HeartbeatAck,
            Box::new(RecordingHandler::new(log_hb.clone())),
        );
        d.register(
            MessageFamily::ElectionControl,
            Box::new(RecordingHandler::new(log_el.clone())),
        );

        assert_eq!(d.handler_count(), 3);

        d.dispatch(DecodedMessage::new(
            MessageFamily::StateTransfer,
            b"st".to_vec(),
        ))
        .unwrap();
        d.dispatch(DecodedMessage::new(
            MessageFamily::HeartbeatAck,
            b"hb".to_vec(),
        ))
        .unwrap();
        d.dispatch(DecodedMessage::new(
            MessageFamily::ElectionControl,
            b"el".to_vec(),
        ))
        .unwrap();

        assert_eq!(log_st.count(), 1);
        assert_eq!(log_hb.count(), 1);
        assert_eq!(log_el.count(), 1);

        assert_eq!(log_st.last().unwrap().payload, b"st");
        assert_eq!(log_hb.last().unwrap().payload, b"hb");
        assert_eq!(log_el.last().unwrap().payload, b"el");
    }

    #[test]
    fn dispatch_no_handler_registered() {
        let d = MessageDispatch::new();
        let family = MessageFamily::LogSyncMetadata;
        let msg = DecodedMessage::new(family, b"data".to_vec());

        let result = d.dispatch(msg);
        assert!(
            matches!(result, Err(DispatchError::NoHandlerRegistered(f)) if f == family),
            "expected NoHandlerRegistered({family}), got: {result:?}"
        );
    }

    #[test]
    fn register_replaces_existing_handler() {
        let d = MessageDispatch::new();

        let log1 = CallLog::new();
        let log2 = CallLog::new();

        d.register(
            MessageFamily::HelloClose,
            Box::new(RecordingHandler::new(log1.clone())),
        );
        d.register(
            MessageFamily::HelloClose,
            Box::new(RecordingHandler::new(log2.clone())),
        );

        assert_eq!(d.handler_count(), 1);

        d.dispatch(DecodedMessage::new(
            MessageFamily::HelloClose,
            b"data".to_vec(),
        ))
        .unwrap();

        assert_eq!(log1.count(), 0, "replaced handler should not receive calls");
        assert_eq!(log2.count(), 1, "replacement handler should receive calls");
    }

    #[test]
    fn unregister_removes_handler() {
        let d = MessageDispatch::new();
        let log = CallLog::new();
        d.register(
            MessageFamily::PublicationProgress,
            Box::new(RecordingHandler::new(log)),
        );

        assert_eq!(d.handler_count(), 1);
        assert!(d.has_handler(MessageFamily::PublicationProgress));

        let removed = d.unregister(MessageFamily::PublicationProgress);
        assert!(removed.is_some());
        assert_eq!(d.handler_count(), 0);
        assert!(!d.has_handler(MessageFamily::PublicationProgress));

        let msg = DecodedMessage::new(MessageFamily::PublicationProgress, b"data".to_vec());
        let result = d.dispatch(msg);
        assert!(matches!(result, Err(DispatchError::NoHandlerRegistered(_))));
    }

    #[test]
    fn unregister_nonexistent_returns_none() {
        let d = MessageDispatch::new();
        let removed = d.unregister(MessageFamily::ShadowValidation);
        assert!(removed.is_none());
    }

    #[test]
    fn handler_error_propagates() {
        let d = MessageDispatch::new();
        let log = CallLog::new();
        let handler = RecordingHandler::new(log);
        handler.set_reject(true);
        d.register(MessageFamily::LeaseFenceDeadline, Box::new(handler));

        let msg = DecodedMessage::new(MessageFamily::LeaseFenceDeadline, b"lease".to_vec());
        let result = d.dispatch(msg);
        assert!(
            matches!(result, Err(DispatchError::HandlerError(_))),
            "expected HandlerError, got: {result:?}"
        );
    }

    #[test]
    fn dispatch_all_ten_families() {
        let d = MessageDispatch::new();

        for family in MessageFamily::all() {
            let log = CallLog::new();
            d.register(family, Box::new(RecordingHandler::new(log)));
        }

        assert_eq!(d.handler_count(), 10);

        for family in MessageFamily::all() {
            assert!(d.has_handler(family));
            d.dispatch(DecodedMessage::new(family, b"test".to_vec()))
                .unwrap();
        }
    }

    #[test]
    fn default_constructs_empty() {
        let d = MessageDispatch::default();
        assert_eq!(d.handler_count(), 0);
    }

    // -------------------------------------------------------------------
    // DispatchError tests
    // -------------------------------------------------------------------

    #[test]
    fn dispatch_error_display_no_handler_registered() {
        let e = DispatchError::NoHandlerRegistered(MessageFamily::StateTransfer);
        let s = format!("{e}");
        assert!(s.contains("no handler registered"));
        assert!(s.contains("m6.StateTransfer"));
    }

    #[test]
    fn dispatch_error_display_handler_error() {
        let inner: Box<dyn std::error::Error> = "something broke".to_string().into();
        let e = DispatchError::HandlerError(inner);
        let s = format!("{e}");
        assert!(s.contains("handler error"));
        assert!(s.contains("something broke"));
    }

    #[test]
    fn dispatch_error_source() {
        let inner: Box<dyn std::error::Error> = "boom".to_string().into();
        let e = DispatchError::HandlerError(inner);
        let src = e.source();
        assert!(src.is_some());
        assert_eq!(src.unwrap().to_string(), "boom");
    }

    #[test]
    fn dispatch_error_no_source_for_no_handler_registered() {
        let e = DispatchError::NoHandlerRegistered(MessageFamily::HelloClose);
        assert!(e.source().is_none());
    }

    #[test]
    fn has_handler_returns_false_for_unregistered() {
        let d = MessageDispatch::new();
        assert!(!d.has_handler(MessageFamily::ShadowValidation));
    }

    #[test]
    fn has_handler_returns_true_after_register() {
        let d = MessageDispatch::new();
        let log = CallLog::new();
        d.register(
            MessageFamily::ReplicaTransferVerify,
            Box::new(RecordingHandler::new(log)),
        );
        assert!(d.has_handler(MessageFamily::ReplicaTransferVerify));
    }

    #[test]
    fn has_handler_returns_false_after_unregister() {
        let d = MessageDispatch::new();
        let log = CallLog::new();
        d.register(
            MessageFamily::TransitionHoldResume,
            Box::new(RecordingHandler::new(log)),
        );
        d.unregister(MessageFamily::TransitionHoldResume);
        assert!(!d.has_handler(MessageFamily::TransitionHoldResume));
    }

    // ── Write gate integration tests ────────────────────────────

    #[test]
    fn write_gate_not_configured_allows_writes() {
        // Without a write gate, write-family messages dispatch normally.
        let d = MessageDispatch::new();
        let log = CallLog::new();
        d.register(
            MessageFamily::ReplicaTransferVerify,
            Box::new(RecordingHandler::new(log.clone())),
        );

        let msg = DecodedMessage::new(MessageFamily::ReplicaTransferVerify, b"write".to_vec());
        d.dispatch(msg).unwrap();
        assert_eq!(log.count(), 1);
    }

    #[test]
    fn write_gate_rejects_writes_without_active_fence() {
        // With a write gate but no active fence, write-family messages are rejected.
        let fence_auth = tidefs_cluster::write_fence::FenceAuthority::new();
        let validator = fence_auth.validator();
        let gate = WriteGate::new(validator);
        let d = MessageDispatch::new().with_write_gate(gate);

        let log = CallLog::new();
        d.register(
            MessageFamily::ReplicaTransferVerify,
            Box::new(RecordingHandler::new(log.clone())),
        );

        let msg = DecodedMessage::new(MessageFamily::ReplicaTransferVerify, b"write".to_vec());
        let result = d.dispatch(msg);
        assert!(
            matches!(result, Err(DispatchError::StaleFence(_))),
            "expected StaleFence, got: {result:?}"
        );
        assert_eq!(log.count(), 0, "handler should not have been called");
    }

    #[test]
    fn write_gate_allows_writes_with_active_fence() {
        // With an active fence, write-family messages dispatch normally.
        let fence_auth = tidefs_cluster::write_fence::FenceAuthority::new();
        let _ = fence_auth.issue_fence(tidefs_membership_epoch::EpochId(1));
        let validator = fence_auth.validator();
        let gate = WriteGate::new(validator);
        let d = MessageDispatch::new().with_write_gate(gate);

        let log = CallLog::new();
        d.register(
            MessageFamily::ReplicaTransferVerify,
            Box::new(RecordingHandler::new(log.clone())),
        );

        let msg = DecodedMessage::new(MessageFamily::ReplicaTransferVerify, b"write".to_vec());
        d.dispatch(msg).unwrap();
        assert_eq!(log.count(), 1);
    }

    #[test]
    fn write_gate_cleared_fence_rejects_writes() {
        // After clearing the fence, write-family messages are rejected again.
        let fence_auth = tidefs_cluster::write_fence::FenceAuthority::new();
        let _ = fence_auth.issue_fence(tidefs_membership_epoch::EpochId(1));
        let validator = fence_auth.validator();
        let gate = WriteGate::new(validator);
        let d = MessageDispatch::new().with_write_gate(gate);

        let log = CallLog::new();
        d.register(
            MessageFamily::StateTransfer,
            Box::new(RecordingHandler::new(log.clone())),
        );

        // Initially ok
        let msg1 = DecodedMessage::new(MessageFamily::StateTransfer, b"data1".to_vec());
        d.dispatch(msg1).unwrap();
        assert_eq!(log.count(), 1);

        // Clear the fence (simulating lease release)
        fence_auth.clear();
        let msg2 = DecodedMessage::new(MessageFamily::StateTransfer, b"data2".to_vec());
        let result = d.dispatch(msg2);
        assert!(matches!(result, Err(DispatchError::StaleFence(_))));
        assert_eq!(log.count(), 1, "second write should not reach handler");
    }

    #[test]
    fn write_gate_does_not_block_control_families() {
        // Control-plane families pass through even without a fence.
        let fence_auth = tidefs_cluster::write_fence::FenceAuthority::new();
        let validator = fence_auth.validator();
        let gate = WriteGate::new(validator);
        let d = MessageDispatch::new().with_write_gate(gate);

        let log = CallLog::new();
        d.register(
            MessageFamily::HeartbeatAck,
            Box::new(RecordingHandler::new(log.clone())),
        );

        // Heartbeat should pass through even with no active fence
        let msg = DecodedMessage::new(MessageFamily::HeartbeatAck, b"ping".to_vec());
        d.dispatch(msg).unwrap();
        assert_eq!(log.count(), 1);
    }

    #[test]
    fn family_requires_write_fence_only_gates_write_families() {
        // Verify the allowlist: only ReplicaTransferVerify and StateTransfer are gated.
        assert!(MessageDispatch::family_requires_write_fence(
            MessageFamily::ReplicaTransferVerify
        ));
        assert!(MessageDispatch::family_requires_write_fence(
            MessageFamily::StateTransfer
        ));

        // Control and metadata families are not gated
        assert!(!MessageDispatch::family_requires_write_fence(
            MessageFamily::HelloClose
        ));
        assert!(!MessageDispatch::family_requires_write_fence(
            MessageFamily::HeartbeatAck
        ));
        assert!(!MessageDispatch::family_requires_write_fence(
            MessageFamily::ElectionControl
        ));
        assert!(!MessageDispatch::family_requires_write_fence(
            MessageFamily::LeaseFenceDeadline
        ));
        assert!(!MessageDispatch::family_requires_write_fence(
            MessageFamily::PublicationProgress
        ));
        assert!(!MessageDispatch::family_requires_write_fence(
            MessageFamily::LogSyncMetadata
        ));
        assert!(!MessageDispatch::family_requires_write_fence(
            MessageFamily::ShadowValidation
        ));
        assert!(!MessageDispatch::family_requires_write_fence(
            MessageFamily::TransitionHoldResume
        ));
    }

    // -- dispatch_or_warn tests ---------------------------------

    #[test]
    fn dispatch_or_warn_no_handler_logs_warning() {
        let d = MessageDispatch::new();
        let msg = DecodedMessage::new(MessageFamily::ShadowValidation, b"ghost".to_vec());
        d.dispatch_or_warn(msg);
    }

    #[test]
    fn dispatch_or_warn_registered_handler_succeeds() {
        let d = MessageDispatch::new();
        let log = CallLog::new();
        d.register(
            MessageFamily::HeartbeatAck,
            Box::new(RecordingHandler::new(log.clone())),
        );
        let msg = DecodedMessage::new(MessageFamily::HeartbeatAck, b"ping".to_vec());
        d.dispatch_or_warn(msg);
        assert_eq!(log.count(), 1);
    }

    // -- cfg(test) builder helpers ------------------------------

    // -- membership handler pre-dispatch tests -----------------

    #[test]
    fn membership_handler_receives_publication_progress() {
        let log = CallLog::new();
        let membership_handler = Box::new(RecordingHandler::new(log.clone()));
        let d = MessageDispatch::new().with_membership_handler(membership_handler);

        assert!(d.has_membership_handler());
        assert_eq!(d.handler_count(), 0); // family-map is empty

        let msg = DecodedMessage::new(MessageFamily::PublicationProgress, b"m4-payload".to_vec());
        d.dispatch(msg).unwrap();
        assert_eq!(log.count(), 1);
        assert_eq!(log.last().unwrap().payload, b"m4-payload");
    }

    #[test]
    fn membership_handler_only_intercepts_publication_progress() {
        let log = CallLog::new();
        let membership_handler = Box::new(RecordingHandler::new(log.clone()));
        let general_log = CallLog::new();
        let general_handler = Box::new(RecordingHandler::new(general_log.clone()));

        let d = MessageDispatch::new()
            .with_membership_handler(membership_handler)
            .with_test_handler(MessageFamily::HeartbeatAck, general_handler);

        // HeartbeatAck should NOT go through membership handler
        let hb_msg = DecodedMessage::new(MessageFamily::HeartbeatAck, b"hb".to_vec());
        d.dispatch(hb_msg).unwrap();
        assert_eq!(
            log.count(),
            0,
            "membership handler should not see non-PublicationProgress"
        );
        assert_eq!(general_log.count(), 1);

        // PublicationProgress should go through membership handler, not general
        let pp_msg = DecodedMessage::new(MessageFamily::PublicationProgress, b"pp".to_vec());
        d.dispatch(pp_msg).unwrap();
        assert_eq!(log.count(), 1);
        assert_eq!(general_log.count(), 1, "general handler unchanged for PP");
    }

    #[test]
    fn membership_handler_falls_through_when_none() {
        // Without a membership handler, PublicationProgress uses the
        // normal family-map lookup.
        let general_log = CallLog::new();
        let general_handler = Box::new(RecordingHandler::new(general_log.clone()));

        let d = MessageDispatch::new()
            .with_test_handler(MessageFamily::PublicationProgress, general_handler);

        assert!(!d.has_membership_handler());

        let msg = DecodedMessage::new(MessageFamily::PublicationProgress, b"pp".to_vec());
        d.dispatch(msg).unwrap();
        assert_eq!(general_log.count(), 1);
    }

    #[test]
    fn membership_handler_error_propagates() {
        let log = CallLog::new();
        let handler = RecordingHandler::new(log);
        handler.set_reject(true);

        let d = MessageDispatch::new().with_membership_handler(Box::new(handler));

        let msg = DecodedMessage::new(MessageFamily::PublicationProgress, b"err".to_vec());
        let result = d.dispatch(msg);
        assert!(
            matches!(result, Err(DispatchError::HandlerError(_))),
            "expected HandlerError, got: {result:?}"
        );
    }

    #[test]
    fn test_builder_with_test_handler_chains() {
        let log = CallLog::new();
        let d = MessageDispatch::new().with_test_handler(
            MessageFamily::HelloClose,
            Box::new(RecordingHandler::new(log.clone())),
        );
        assert!(d.has_handler(MessageFamily::HelloClose));
        assert_eq!(d.handler_count(), 1);
    }
}
