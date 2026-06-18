// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Transport send-completion tracking: delivery-acknowledgement oneshot
//! handles that resolve after the framed message has been fully written
//! to the socket.
//!
//! This module is pure delivery signalling (tokio::sync::oneshot).
//! It has no security-semantic content.
//! Node-to-node security is handled at the transport/session boundary.
//!
//! ## Design
//!
//! ```text
//! Caller                          Pipeline
//!   |                                |
//!   +-- send_with_completion() ----> |
//!   |   returns SendCompletionToken  |
//!   |                                +-- enqueue frame + SendCompletion
//!   |                                +-- scheduler dequeues
//!   |                                +-- writev to socket
//!   |                                +-- resolve SendCompletion -> Written
//!   |                                |
//!   +-- await token ----------------+
//!   |   returns Written / WriteError / Cancelled
//! ```
//!
//! ## Integration
//!
//! `SendCompletion` is the sender half, held by the pipeline and resolved
//! after the framed message write completes (or fails). `SendCompletionToken`
//! is the receiver half, returned to the caller so they can `await` the
//! outcome. `CompletionDispatcher` collects completions for a batch of
//! dequeued messages and resolves them atomically after the writev call.
//!
//! ## Ordering guarantee
//!
//! Completions are resolved in the same order messages are dequeued from
//! the [`SendScheduler`](super::send_scheduler::SendScheduler), which is
//! priority-class weighted round-robin with starvation prevention. Within
//! a single priority class, completions respect FIFO submission order.

use tokio::sync::oneshot;

/// The result of waiting on a [`SendCompletionToken`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionOutcome {
    /// The framed message was fully written to the transport socket.
    Written,
    /// The write to the socket failed (connection broken, timeout, etc.).
    WriteError,
    /// The pipeline shut down before the message could be written, or
    /// the `SendCompletion` was dropped without being resolved.
    Cancelled,
}

/// Sender half of a send-completion oneshot pair, held by the outbound
/// send pipeline and resolved after the write completes.
///
/// Dropping this without calling a completion method signals `Cancelled`
/// to the corresponding [`SendCompletionToken`].
pub struct SendCompletion {
    tx: oneshot::Sender<CompletionOutcome>,
}

/// Receiver half of a send-completion oneshot pair, returned to the caller.
///
/// Callers `await` the token to learn whether their message was successfully
/// written to the transport socket or encountered an error.
pub struct SendCompletionToken {
    rx: oneshot::Receiver<CompletionOutcome>,
}

impl std::fmt::Debug for SendCompletion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendCompletion").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for SendCompletionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendCompletionToken")
            .finish_non_exhaustive()
    }
}

impl SendCompletion {
    /// Create a new completion pair.
    #[must_use]
    pub fn new() -> (Self, SendCompletionToken) {
        let (tx, rx) = oneshot::channel();
        (Self { tx }, SendCompletionToken { rx })
    }

    /// Signal that the message was successfully written to the socket.
    pub fn complete_written(self) {
        let _ = self.tx.send(CompletionOutcome::Written);
    }

    /// Signal that the write failed with a socket error.
    pub fn complete_error(self) {
        let _ = self.tx.send(CompletionOutcome::WriteError);
    }

    /// Signal that the pipeline cancelled the message before writing.
    pub fn complete_cancelled(self) {
        let _ = self.tx.send(CompletionOutcome::Cancelled);
    }
}

impl SendCompletionToken {
    /// Await the completion outcome.
    ///
    /// Returns `Cancelled` if the `SendCompletion` sender was dropped
    /// without being resolved (e.g. pipeline shut down uncleanly).
    pub async fn outcome(self) -> CompletionOutcome {
        self.rx.await.unwrap_or(CompletionOutcome::Cancelled)
    }
}

/// Collects [`SendCompletion`] values for a batch of dequeued messages
/// and resolves them atomically after the writev call completes.
///
/// # Drop behaviour
///
/// Any completions still pending when the dispatcher is dropped are
/// resolved as `Cancelled`. This ensures no completion leaks in error
/// paths that allocate a dispatcher but never write.
#[derive(Default)]
pub struct CompletionDispatcher {
    pending: Vec<SendCompletion>,
}

impl std::fmt::Debug for CompletionDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompletionDispatcher")
            .field("pending", &self.pending.len())
            .finish()
    }
}

impl CompletionDispatcher {
    /// Create an empty dispatcher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
        }
    }

    /// Add a completion to be resolved later.
    pub fn push(&mut self, completion: SendCompletion) {
        self.pending.push(completion);
    }

    /// Signal that all pending messages were successfully written.
    pub fn complete_all_written(&mut self) {
        for c in self.pending.drain(..) {
            c.complete_written();
        }
    }

    /// Signal that all pending messages failed with a write error.
    pub fn complete_all_error(&mut self) {
        for c in self.pending.drain(..) {
            c.complete_error();
        }
    }

    /// Signal that all pending messages were cancelled before writing.
    pub fn complete_all_cancelled(&mut self) {
        for c in self.pending.drain(..) {
            c.complete_cancelled();
        }
    }

    /// Return the number of pending completions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Return whether there are no pending completions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

impl Drop for CompletionDispatcher {
    fn drop(&mut self) {
        for c in self.pending.drain(..) {
            c.complete_cancelled();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn single_message_completion_written() {
        let (completion, token) = SendCompletion::new();
        completion.complete_written();
        assert_eq!(token.outcome().await, CompletionOutcome::Written);
    }

    #[tokio::test]
    async fn single_message_completion_error() {
        let (completion, token) = SendCompletion::new();
        completion.complete_error();
        assert_eq!(token.outcome().await, CompletionOutcome::WriteError);
    }

    #[tokio::test]
    async fn single_message_completion_cancelled() {
        let (completion, token) = SendCompletion::new();
        completion.complete_cancelled();
        assert_eq!(token.outcome().await, CompletionOutcome::Cancelled);
    }

    #[tokio::test]
    async fn drop_completion_is_cancelled() {
        let (completion, token) = SendCompletion::new();
        drop(completion);
        assert_eq!(token.outcome().await, CompletionOutcome::Cancelled);
    }

    #[tokio::test]
    async fn drop_token_does_not_block() {
        let (completion, _token) = SendCompletion::new();
        completion.complete_written();
    }

    #[test]
    fn dispatcher_empty_by_default() {
        let d = CompletionDispatcher::new();
        assert!(d.is_empty());
        assert_eq!(d.len(), 0);
    }

    #[test]
    fn dispatcher_push_increases_count() {
        let mut d = CompletionDispatcher::new();
        let (c1, _t1) = SendCompletion::new();
        let (c2, _t2) = SendCompletion::new();
        d.push(c1);
        d.push(c2);
        assert_eq!(d.len(), 2);
        assert!(!d.is_empty());
    }

    #[tokio::test]
    async fn dispatcher_complete_all_written_resolves_all() {
        let mut d = CompletionDispatcher::new();
        let (c1, t1) = SendCompletion::new();
        let (c2, t2) = SendCompletion::new();
        let (c3, t3) = SendCompletion::new();
        d.push(c1);
        d.push(c2);
        d.push(c3);
        d.complete_all_written();
        assert_eq!(t1.outcome().await, CompletionOutcome::Written);
        assert_eq!(t2.outcome().await, CompletionOutcome::Written);
        assert_eq!(t3.outcome().await, CompletionOutcome::Written);
        assert!(d.is_empty());
    }

    #[tokio::test]
    async fn dispatcher_complete_all_error_resolves_all() {
        let mut d = CompletionDispatcher::new();
        let (c1, t1) = SendCompletion::new();
        let (c2, t2) = SendCompletion::new();
        d.push(c1);
        d.push(c2);
        d.complete_all_error();
        assert_eq!(t1.outcome().await, CompletionOutcome::WriteError);
        assert_eq!(t2.outcome().await, CompletionOutcome::WriteError);
    }

    #[tokio::test]
    async fn dispatcher_complete_all_cancelled_resolves_all() {
        let mut d = CompletionDispatcher::new();
        let (c1, t1) = SendCompletion::new();
        d.push(c1);
        d.complete_all_cancelled();
        assert_eq!(t1.outcome().await, CompletionOutcome::Cancelled);
    }

    #[tokio::test]
    async fn dispatcher_drop_cancels_remaining() {
        let (c1, t1) = SendCompletion::new();
        let (c2, t2) = SendCompletion::new();
        {
            let mut d = CompletionDispatcher::new();
            d.push(c1);
            d.push(c2);
        }
        assert_eq!(t1.outcome().await, CompletionOutcome::Cancelled);
        assert_eq!(t2.outcome().await, CompletionOutcome::Cancelled);
    }
}
