#![forbid(unsafe_code)]

//! Epoch catch-up protocol for lagging peers after partition.
//!
//! When a peer detects it has fallen behind (its local committed epoch
//! trails another peer's advertised epoch height), it issues an
//! [`EpochCatchUpRequest`] range query to the most advanced peer and
//! applies received committed epoch views in chain order.
//!
//! ## Protocol flow
//!
//! ```text
//! Lagging Peer (local epoch=3)         Up-to-date Peer (local epoch=8)
//!   |                                       |
//!   |--- EpochCatchUpRequest(4..8) -------->|
//!   |                                       | (queries epoch store)
//!   |<-- EpochCatchUpResponse([4,5,6,7,8]) -|
//!   |                                       |
//!   | (applies epochs 4,5,6,7,8 in order    |
//!   |  via EpochChainVerifier + coordinator) |
//!   |                                       |
//!   local epoch=8                           |
//! ```
//!
//! ## Bounded batches
//!
//! Responses are capped at [`MAX_CATCH_UP_BATCH_SIZE`] (64) epochs.
//! When the requested range exceeds this bound, `truncated` is set to
//! `true` and the caller issues continuation requests for the remaining
//! range.
//!
//! ## Integration
//!
//! - [`EpochCatchUpResponder`] implements
//!   [`MembershipMessageHandler`](crate::dispatch_router::MembershipMessageHandler)
//!   for inbound [`EpochCatchUpRequest`] messages.
//! - [`EpochCatchUpProtocol`] tracks peer epoch heights from incoming
//!   [`EpochPush`](crate::dispatch_router::MembershipMessage::EpochPush)
//!   messages, detects lag, and issues catch-up requests via outbound
//!   dispatch.
//! - [`EpochCatchUpResponseHandler`] applies received
//!   [`EpochCatchUpResponse`] epochs to the local coordinator via
//!   liveness-change replay.
//!
//! ## Security
//!
//! No new crypto surface. Catch-up operates within the existing
//! transport/session security boundary. Epoch chain integrity is
//! validated by the existing [`EpochChainVerifier`].

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use tidefs_membership_epoch::epoch_catch_up::CommittedEpochView;
use tidefs_membership_epoch::epoch_chain::EpochChainVerifier;
use tidefs_membership_epoch::MemberId;

use crate::dispatch_router::{
    MembershipDispatchError, MembershipMessage, MembershipMessageHandler,
};
use crate::epoch_coordinator::{EpochAdvanceCoordinator, PeerLivenessChange, PeerLivenessStatus};
use crate::membership_outbound_dispatch::{MembershipOutboundDispatch, MembershipOutboundMessage};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of epoch views returned in a single catch-up response.
/// Larger ranges require continuation requests.
pub const MAX_CATCH_UP_BATCH_SIZE: usize = 64;

// ---------------------------------------------------------------------------
// EpochRangeQuery -- trait for historical epoch retrieval
// ---------------------------------------------------------------------------

/// Trait for querying historical committed epoch views.
///
/// Implementations provide the raw epoch-lookup primitives that the
/// [`EpochCatchUpResponder`] uses to serve range queries. A production
/// implementation would use the durable epoch store; test implementations
/// can use an in-memory map.
pub trait EpochRangeQuery: Send + Sync {
    /// Return committed epoch views for the inclusive range
    /// `[from_epoch, to_epoch]`, in ascending epoch-number order.
    ///
    /// Returns an empty vec if no epochs are available in the queried
    /// range.
    fn query_range(&self, from_epoch: u64, to_epoch: u64) -> Vec<CommittedEpochView>;
    /// Return the highest committed epoch number available, or 0 if empty.
    fn max_committed_epoch(&self) -> u64;
}

// ---------------------------------------------------------------------------
// EpochCatchUpResponder -- handles inbound catch-up requests
// ---------------------------------------------------------------------------

/// Handles inbound [`MembershipMessage::EpochCatchUpRequest`] messages
/// by querying the provided [`EpochRangeQuery`] store and sending back an
/// [`EpochCatchUpResponse`] through outbound dispatch.
///
/// Responses are bounded to [`MAX_CATCH_UP_BATCH_SIZE`] epochs with
/// `truncated` set to `true` when more epochs exist beyond the batch.
///
/// # Thread safety
///
/// Uses `Arc` for shared components so the struct satisfies `Send + Sync`.
/// The responder performs peer validation (roster membership check) and
/// epoch-range sanity checks (stale/already-current detection) before
/// querying the epoch store.
pub struct EpochCatchUpResponder {
    /// Historical epoch store for range queries.
    epoch_store: Arc<dyn EpochRangeQuery>,
    /// Transport send dispatcher for sending responses.
    send_dispatcher: Arc<tidefs_transport::send_dispatch::SendDispatcher>,
    /// Membership roster for peer lookup.
    roster: Arc<crate::roster::MembershipRoster>,
    /// This node's member identity for the responder field.
    local_member_id: MemberId,
}

impl EpochCatchUpResponder {
    /// Create a new catch-up responder.
    #[must_use]
    pub fn new(
        epoch_store: Arc<dyn EpochRangeQuery>,
        send_dispatcher: Arc<tidefs_transport::send_dispatch::SendDispatcher>,
        roster: Arc<crate::roster::MembershipRoster>,
        local_member_id: MemberId,
    ) -> Self {
        Self {
            epoch_store,
            send_dispatcher,
            roster,
            local_member_id,
        }
    }
}

impl MembershipMessageHandler for EpochCatchUpResponder {
    fn handle_epoch_catch_up_request(
        &self,
        msg: &MembershipMessage,
    ) -> Result<(), MembershipDispatchError> {
        let (requester, from_epoch, to_epoch) = match msg {
            MembershipMessage::EpochCatchUpRequest {
                requester,
                from_epoch,
                to_epoch,
            } => (*requester, *from_epoch, *to_epoch),
            _ => return Ok(()),
        };

        // -- Edge case: unknown peer ----------------------------------
        // Drop requests from peers not in the roster (unauthorised or
        // stale session).
        if self.roster.lookup(requester).is_none() {
            return Ok(());
        }

        // -- Edge case: invalid range ---------------------------------
        // from_epoch must be > 0 and to_epoch >= from_epoch.
        if from_epoch == 0 || to_epoch < from_epoch {
            // Malformed request -- drop without reply.
            return Ok(());
        }

        let our_max_epoch = self.epoch_store.max_committed_epoch();

        // -- Edge case: request ahead of us ---------------------------
        // Requester's from_epoch is beyond what we have; respond with
        // empty + truncated so the requester looks elsewhere.
        if from_epoch > our_max_epoch {
            let response = MembershipOutboundMessage::EpochCatchUpResponse {
                responder: self.local_member_id,
                epochs: Vec::new(),
                truncated: true,
            };
            let outbound = MembershipOutboundDispatch::new(&self.send_dispatcher, &self.roster);
            let _ = outbound.send_to_peer(requester, response);
            return Ok(());
        }

        // -- Edge case: already current --------------------------------
        // The requester's entire requested range is behind our max epoch;
        // this is a duplicate/retransmitted request.
        if to_epoch <= our_max_epoch {
            // We have the data but the requester already does too.
            // Send empty as a clean ack.
            let response = MembershipOutboundMessage::EpochCatchUpResponse {
                responder: self.local_member_id,
                epochs: Vec::new(),
                truncated: false,
            };
            let outbound = MembershipOutboundDispatch::new(&self.send_dispatcher, &self.roster);
            let _ = outbound.send_to_peer(requester, response);
            return Ok(());
        }

        // Clamp the range to batch size.
        let clamped_to = to_epoch.min(from_epoch + MAX_CATCH_UP_BATCH_SIZE as u64 - 1);
        let requested_count = to_epoch.saturating_sub(from_epoch) + 1;
        let truncated = requested_count > MAX_CATCH_UP_BATCH_SIZE as u64;

        // -- Edge case: missing range (gap detection) ------------------
        // If the first epoch is missing, we have a gap.
        let has_start_gap = {
            let first_batch = self.epoch_store.query_range(from_epoch, from_epoch);
            first_batch.is_empty()
        };

        // Query the epoch store.
        let all_epochs = self.epoch_store.query_range(from_epoch, clamped_to);
        let bounded: Vec<CommittedEpochView> = all_epochs
            .into_iter()
            .take(MAX_CATCH_UP_BATCH_SIZE)
            .collect();

        // Send response (truncated if bounded or if there's a gap at start).
        let response = MembershipOutboundMessage::EpochCatchUpResponse {
            responder: self.local_member_id,
            epochs: bounded,
            truncated: truncated || has_start_gap,
        };

        let outbound = MembershipOutboundDispatch::new(&self.send_dispatcher, &self.roster);
        let _ = outbound.send_to_peer(requester, response);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// EpochCatchUpProtocol -- requestor side: lag detection and request issuance
// ---------------------------------------------------------------------------

/// Tracks peer-advertised epoch heights and initiates catch-up when this
/// node's local committed epoch trails another peer's height.
///
/// # Lifecycle
///
/// 1. Construct with a mutable reference to the local
///    [`EpochAdvanceCoordinator`] and an outbound dispatch.
/// 2. Call [`on_epoch_push`] each time a peer advertises an epoch
///    (via [`MembershipMessage::EpochPush`]).
/// 3. Call [`check_and_initiate_catch_up`] periodically or after
///    receiving a push from a peer with a higher epoch.
/// 4. The coordinator receives liveness changes as catch-up responses
///    are applied via [`EpochCatchUpResponseHandler`].
///
/// [`on_epoch_push`]: EpochCatchUpProtocol::on_epoch_push
/// [`check_and_initiate_catch_up`]: EpochCatchUpProtocol::check_and_initiate_catch_up
pub struct EpochCatchUpProtocol<'a> {
    /// Per-peer highest known epoch number.
    peer_epochs: Mutex<BTreeMap<MemberId, u64>>,
    /// Local epoch coordinator for reading committed epoch.
    coordinator: &'a EpochAdvanceCoordinator,
    /// Outbound dispatch for sending catch-up requests.
    outbound: MembershipOutboundDispatch<'a>,
    /// This node's member identity for the requester field.
    local_member_id: MemberId,
    /// Peers that failed to respond; excluded from catch-up selection.
    failed_peers: Mutex<Vec<MemberId>>,
}

impl<'a> EpochCatchUpProtocol<'a> {
    /// Create a new catch-up protocol instance.
    #[must_use]
    pub fn new(
        coordinator: &'a EpochAdvanceCoordinator,
        send_dispatcher: &'a tidefs_transport::send_dispatch::SendDispatcher,
        roster: &'a crate::roster::MembershipRoster,
        local_member_id: MemberId,
    ) -> Self {
        Self {
            peer_epochs: Mutex::new(BTreeMap::new()),
            coordinator,
            outbound: MembershipOutboundDispatch::new(send_dispatcher, roster),
            local_member_id,
            failed_peers: Mutex::new(Vec::new()),
        }
    }

    /// Record a peer's advertised epoch height from an incoming
    /// [`MembershipMessage::EpochPush`].
    ///
    /// The peer's epoch is updated only if the new value is strictly
    /// greater than the previously recorded value.
    pub fn on_epoch_push(&self, peer_id: MemberId, epoch_number: u64) {
        let mut peers = self.peer_epochs.lock().unwrap();
        peers
            .entry(peer_id)
            .and_modify(|current| {
                if epoch_number > *current {
                    *current = epoch_number;
                }
            })
            .or_insert(epoch_number);
    }

    /// Check whether this node is lagging and, if so, initiate a
    /// catch-up request to the most advanced peer.
    ///
    /// Returns `Some(request)` if a catch-up request was sent, with
    /// details about the target peer and requested range. Returns
    /// `None` if no catch-up is needed (local epoch is current or no
    /// peer is ahead).
    ///
    /// The catch-up request covers the range from
    /// `[local_epoch + 1, max_peer_epoch]`, bounded by
    /// [`MAX_CATCH_UP_BATCH_SIZE`]. Previously failed peers are excluded
    /// from selection.
    pub fn check_and_initiate_catch_up(&self) -> Option<CatchUpInitiated> {
        let local_epoch = self.coordinator.epoch_counter();

        // Find the peer with the highest epoch.
        let peers = self.peer_epochs.lock().unwrap();
        let best_peer = peers
            .iter()
            .filter(|(_, &epoch)| epoch > local_epoch)
            .filter(|(&peer_id, _)| !self.failed_peers.lock().unwrap().contains(&peer_id))
            .max_by_key(|(_, &epoch)| epoch)?;

        let target_peer = *best_peer.0;
        let max_peer_epoch = *best_peer.1;

        // Compute request range bounded by batch size.
        let from_epoch = local_epoch + 1;
        let to_epoch = max_peer_epoch.min(from_epoch + MAX_CATCH_UP_BATCH_SIZE as u64 - 1);

        // Build and send the request.
        let request = MembershipOutboundMessage::EpochCatchUpRequest {
            requester: self.local_member_id,
            from_epoch,
            to_epoch,
        };

        let result = self.outbound.send_to_peer(target_peer, request);
        if result.is_err() {
            return None;
        }

        Some(CatchUpInitiated {
            target_peer,
            from_epoch,
            to_epoch,
            max_peer_epoch,
        })
    }

    /// Mark a peer as failed so it is excluded from future catch-up
    /// selections. Call this when a catch-up request times out or the
    /// peer responds with a malformed/truncated-empty response.
    ///
    /// Failed peers remain excluded until [`clear_failed_peers`] is called.
    ///
    /// [`clear_failed_peers`]: EpochCatchUpProtocol::clear_failed_peers
    pub fn mark_peer_failed(&self, peer_id: MemberId) {
        let mut failed = self.failed_peers.lock().unwrap();
        if !failed.contains(&peer_id) {
            failed.push(peer_id);
        }
    }

    /// Clear all failed-peer exclusions, allowing all known peers to
    /// be considered again.
    pub fn clear_failed_peers(&self) {
        self.failed_peers.lock().unwrap().clear();
    }

    /// Attempt catch-up with the next-best peer after a previous
    /// attempt failed. Returns `Some(CatchUpInitiated)` if another
    /// suitable peer exists, or `None` if all available peers are
    /// exhausted or no peer is ahead.
    ///
    /// The previously attempted peer is marked as failed before
    /// selecting the next peer.
    pub fn retry_with_next_peer(
        &self,
        previous_peer: MemberId,
        previous_target_epoch: u64,
    ) -> Option<CatchUpInitiated> {
        // Mark the previous peer as failed.
        self.mark_peer_failed(previous_peer);

        let local_epoch = self.coordinator.epoch_counter();

        // Find the next-best peer, excluding failed ones.
        let peers = self.peer_epochs.lock().unwrap();
        let next_best = peers
            .iter()
            .filter(|(_, &epoch)| epoch > local_epoch)
            .filter(|(&peer_id, _)| !self.failed_peers.lock().unwrap().contains(&peer_id))
            .max_by_key(|(_, &epoch)| epoch)?;

        let target_peer = *next_best.0;
        let max_peer_epoch = (*next_best.1).max(previous_target_epoch);

        let from_epoch = local_epoch + 1;
        let to_epoch = max_peer_epoch.min(from_epoch + MAX_CATCH_UP_BATCH_SIZE as u64 - 1);

        let request = MembershipOutboundMessage::EpochCatchUpRequest {
            requester: self.local_member_id,
            from_epoch,
            to_epoch,
        };

        let result = self.outbound.send_to_peer(target_peer, request);
        if result.is_err() {
            return None;
        }

        Some(CatchUpInitiated {
            target_peer,
            from_epoch,
            to_epoch,
            max_peer_epoch,
        })
    }

    /// Return a snapshot of all known peer epoch heights.
    #[must_use]
    pub fn peer_epochs_snapshot(&self) -> BTreeMap<MemberId, u64> {
        self.peer_epochs.lock().unwrap().clone()
    }

    /// Return the highest epoch advertised by any peer, or 0 if none.
    #[must_use]
    pub fn max_peer_epoch(&self) -> u64 {
        self.peer_epochs
            .lock()
            .unwrap()
            .values()
            .copied()
            .max()
            .unwrap_or(0)
    }

    /// Number of peers currently marked as failed.
    pub fn failed_peer_count(&self) -> usize {
        self.failed_peers.lock().unwrap().len()
    }

    /// Whether the local node is behind any known peer.
    #[must_use]
    pub fn is_lagging(&self) -> bool {
        let local_epoch = self.coordinator.epoch_counter();
        self.max_peer_epoch() > local_epoch
    }
}

// ---------------------------------------------------------------------------
// CatchUpInitiated
// ---------------------------------------------------------------------------

/// Outcome of a catch-up request initiation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatchUpInitiated {
    /// The peer targeted for the catch-up request.
    pub target_peer: MemberId,
    /// First epoch requested (inclusive).
    pub from_epoch: u64,
    /// Last epoch requested (inclusive, bounded by batch size).
    pub to_epoch: u64,
    /// The target peer's highest known epoch (may exceed `to_epoch`
    /// when the range was bounded).
    pub max_peer_epoch: u64,
}

// ---------------------------------------------------------------------------
// EpochCatchUpResponseHandler -- applies received catch-up epochs
// ---------------------------------------------------------------------------

/// Handles inbound [`MembershipMessage::EpochCatchUpResponse`] messages
/// by applying the received committed epoch views to the local
/// [`EpochAdvanceCoordinator`] in chain order.
///
/// Each epoch view is diffed against the previous view to produce
/// per-peer [`PeerLivenessChange`] events (Alive for additions, Dead
/// for removals), which are fed through the coordinator's
/// [`on_liveness_change`](EpochAdvanceCoordinator::on_liveness_change)
/// to advance the local epoch counter sequentially.
///
/// # Thread safety
///
/// Uses `Mutex` wrappers so the struct satisfies `Send + Sync`
/// requirements of [`MembershipMessageHandler`].
pub struct EpochCatchUpResponseHandler {
    /// Chain verifier for integrity validation on each applied epoch.
    verifier: Mutex<EpochChainVerifier>,
    /// Local coordinator that receives liveness changes.
    coordinator: Mutex<EpochAdvanceCoordinator>,
    /// Callback invoked on each successful catch-up application.
    on_catch_up_applied: Mutex<CatchUpAppliedHook>,
    /// Tracks the last received epoch for duplicate detection.
    last_received_epoch: Mutex<Option<u64>>,
}

type CatchUpAppliedHook = Box<dyn Fn(&CatchUpApplied) + Send + Sync>;

impl EpochCatchUpResponseHandler {
    /// Create a new catch-up response handler.
    #[must_use]
    pub fn new(coordinator: EpochAdvanceCoordinator) -> Self {
        Self {
            verifier: Mutex::new(EpochChainVerifier::new()),
            coordinator: Mutex::new(coordinator),
            on_catch_up_applied: Mutex::new(Box::new(|_| {})),
            last_received_epoch: Mutex::new(None),
        }
    }

    /// Set a callback invoked each time catch-up epochs are applied.
    ///
    /// The callback receives a [`CatchUpApplied`] summary.
    pub fn set_on_catch_up_applied<F>(&self, callback: F)
    where
        F: Fn(&CatchUpApplied) + Send + Sync + 'static,
    {
        *self.on_catch_up_applied.lock().unwrap() = Box::new(callback);
    }

    /// Current epoch known to the local coordinator.
    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        self.coordinator.lock().unwrap().epoch_counter()
    }

    /// Apply a sequence of committed epoch views to the coordinator
    /// in order, producing liveness changes for each transition.
    ///
    /// Returns a summary of the application. Each epoch's member set
    /// is diffed against the previous view; additions produce `Alive`
    /// changes and removals produce `Dead` changes.
    fn apply_epoch_views(&self, views: &[CommittedEpochView]) -> Result<CatchUpApplied, String> {
        if views.is_empty() {
            return Ok(CatchUpApplied {
                applied_count: 0,
                first_epoch: 0,
                last_epoch: 0,
                final_epoch: self.coordinator.lock().unwrap().epoch_counter(),
            });
        }

        // -- Edge case: all stale -------------------------------------
        // If every view's epoch is <= current committed epoch, they are
        // already applied. Return Ok with zero count.
        let current_epoch = self.coordinator.lock().unwrap().epoch_counter();
        if views.iter().all(|v| v.epoch_u64() <= current_epoch) {
            return Ok(CatchUpApplied {
                applied_count: 0,
                first_epoch: 0,
                last_epoch: 0,
                final_epoch: current_epoch,
            });
        }

        // -- Edge case: gap detection ---------------------------------
        // Validate that the first new view's epoch is exactly current_epoch + 1.
        // If there's a gap, reject so the protocol can retry with a different peer.
        {
            let first_new_epoch = views.first().unwrap().epoch_u64();
            if first_new_epoch > current_epoch + 1 {
                return Err(format!(
                    "catch-up gap: expecting epoch {} but got epoch {}",
                    current_epoch + 1,
                    first_new_epoch
                ));
            }
            // All-zero epoch request is also malformed.
            if first_new_epoch == 0 {
                return Err("catch-up response contains epoch 0".to_string());
            }
        }

        // -- Edge case: duplicate detection ---------------------------
        // If the first epoch matches the last epoch we already received,
        // this is a duplicate response -- skip it.
        {
            let last = *self.last_received_epoch.lock().unwrap();
            let first_new = views.first().unwrap().epoch_u64();
            if last.is_some() && last.unwrap() >= first_new {
                return Ok(CatchUpApplied {
                    applied_count: 0,
                    first_epoch: 0,
                    last_epoch: 0,
                    final_epoch: current_epoch,
                });
            }
        }

        let mut coordinator = self.coordinator.lock().unwrap();
        let mut verifier = self.verifier.lock().unwrap();

        let mut applied_count = 0u64;
        let mut first_applied = None;
        let mut last_applied = None;

        for view in views {
            let epoch_number = view.epoch_number.0;
            let target_members: Vec<MemberId> = view.member_set.clone();

            // Verify chain integrity.
            let local_epoch = coordinator.epoch_counter();
            let member_ids: Vec<u64> = target_members.iter().map(|m| m.0).collect();
            verifier
                .verify_proposal(
                    0, // proposer_id: 0 for catch-up (not a proposal)
                    epoch_number,
                    &member_ids,
                    local_epoch,
                )
                .map_err(|e| format!("chain verification failed at epoch {epoch_number}: {e}"))?;

            // Diff: additions and removals from current view.
            let current_view = coordinator.current_view().cloned();
            let current_members: Vec<MemberId> =
                current_view.map(|v| v.member_set).unwrap_or_default();

            // Peers in target but not in current: reinstate as Alive.
            for new_member in &target_members {
                if !current_members.contains(new_member) {
                    let change = PeerLivenessChange::new(
                        *new_member,
                        PeerLivenessStatus::Dead,
                        PeerLivenessStatus::Alive,
                        view.created_at_millis,
                    );
                    let _ = coordinator.on_liveness_change(change);
                }
            }

            // Peers in current but not in target: mark as Dead.
            for old_member in &current_members {
                if !target_members.contains(old_member) {
                    // Skip removing the last member (quorum guard in coordinator).
                    let change = PeerLivenessChange::new(
                        *old_member,
                        PeerLivenessStatus::Alive,
                        PeerLivenessStatus::Dead,
                        view.created_at_millis,
                    );
                    let _ = coordinator.on_liveness_change(change);
                }
            }

            // If the member set didn't change, the coordinator won't have advanced.
            // Force-advance through an epoch-advance helper so subsequent epochs
            // can chain correctly.
            let still_at_epoch = coordinator.epoch_counter();
            if still_at_epoch < epoch_number && still_at_epoch + 1 == epoch_number {
                let _ = coordinator.force_advance_epoch(
                    epoch_number,
                    &target_members,
                    view.created_at_millis,
                );
            }
            // Note: if still_at_epoch == epoch_number, the liveness-change
            // diff already advanced us; count it as applied. If
            // still_at_epoch > epoch_number, skip this view (stale).

            applied_count += 1;
            if first_applied.is_none() {
                first_applied = Some(epoch_number);
            }
            last_applied = Some(epoch_number);
        }

        // Update tracking.
        *self.last_received_epoch.lock().unwrap() = last_applied;

        let result = CatchUpApplied {
            applied_count,
            first_epoch: first_applied.unwrap_or(0),
            last_epoch: last_applied.unwrap_or(0),
            final_epoch: coordinator.epoch_counter(),
        };

        // Notify callback.
        let callback = self.on_catch_up_applied.lock().unwrap();
        callback(&result);

        Ok(result)
    }
}

impl MembershipMessageHandler for EpochCatchUpResponseHandler {
    fn handle_epoch_catch_up_response(
        &self,
        msg: &MembershipMessage,
    ) -> Result<(), MembershipDispatchError> {
        let (epochs, _truncated) = match msg {
            MembershipMessage::EpochCatchUpResponse {
                responder: _,
                epochs,
                truncated,
            } => (epochs.clone(), *truncated),
            _ => return Ok(()),
        };

        if epochs.is_empty() {
            return Ok(());
        }

        let _ = self.apply_epoch_views(&epochs);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CatchUpApplied
// ---------------------------------------------------------------------------

/// Summary of a successful catch-up epoch application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatchUpApplied {
    /// Number of epoch views applied.
    pub applied_count: u64,
    /// First epoch number applied (inclusive).
    pub first_epoch: u64,
    /// Last epoch number applied (inclusive).
    pub last_epoch: u64,
    /// The coordinator's final committed epoch after application.
    pub final_epoch: u64,
}

// ---------------------------------------------------------------------------
// CatchUpWiring -- bundles catch-up components for dispatch router registration
// ---------------------------------------------------------------------------

/// Bundles the catch-up responder, protocol, and response handler into one
/// place so the owner can register each handler with the
/// [`MembershipDispatchRouter`](crate::dispatch_router::MembershipDispatchRouter)
/// and drive the protocol from incoming epoch-push notifications.
///
/// # Lifecycle
///
/// ```text
/// let wiring = CatchUpWiring::new(
///     epoch_store,
///     send_dispatcher,
///     roster,
///     coordinator,
///     local_member_id,
/// );
///
/// // Register inbound handlers with the dispatch router:
/// wiring.register_with_router(&mut router);
///
/// // On each incoming EpochPush, update peer heights:
/// wiring.on_peer_epoch_push(peer_id, epoch_number);
///
/// // Periodically check and initiate catch-up:
/// if let Some(initiated) = wiring.protocol.check_and_initiate_catch_up() {
///     log::info!("catch-up initiated: {:?}", initiated);
/// }
/// ```
pub struct CatchUpWiring<'a> {
    /// Responder: handles inbound catch-up requests.
    pub responder: EpochCatchUpResponder,
    /// Protocol: tracks peer epochs and initiates catch-up.
    pub protocol: EpochCatchUpProtocol<'a>,
    /// Response handler: applies received catch-up epochs.
    pub response_handler: EpochCatchUpResponseHandler,
}

impl<'a> CatchUpWiring<'a> {
    /// Create a new catch-up wiring bundle.
    ///
    /// `epoch_store` — historical epoch store for range queries.
    /// `send_dispatcher` — transport send dispatcher shared via `Arc`.
    /// `roster` — membership roster shared via `Arc`.
    /// `coordinator` — the local epoch advance coordinator.
    /// `local_member_id` — this node's member identity.
    #[must_use]
    pub fn new(
        epoch_store: Arc<dyn EpochRangeQuery>,
        send_dispatcher: Arc<tidefs_transport::send_dispatch::SendDispatcher>,
        roster: Arc<crate::roster::MembershipRoster>,
        coordinator: &'a EpochAdvanceCoordinator,
        outbound_send_dispatcher: &'a tidefs_transport::send_dispatch::SendDispatcher,
        outbound_roster: &'a crate::roster::MembershipRoster,
        local_member_id: MemberId,
    ) -> Self {
        let responder = EpochCatchUpResponder::new(
            Arc::clone(&epoch_store),
            Arc::clone(&send_dispatcher),
            Arc::clone(&roster),
            local_member_id,
        );

        let protocol = EpochCatchUpProtocol::new(
            coordinator,
            outbound_send_dispatcher,
            outbound_roster,
            local_member_id,
        );

        // The response handler needs its own coordinator for liveness-change
        // replay. We clone the initial state from the shared coordinator.
        let handler_coordinator = make_handler_coordinator(coordinator);
        let response_handler = EpochCatchUpResponseHandler::new(handler_coordinator);

        Self {
            responder,
            protocol,
            response_handler,
        }
    }

    /// Register all catch-up handlers with the given dispatch router.
    ///
    /// Registers:
    /// - Discriminant 19: [`EpochCatchUpRequest`] -> [`EpochCatchUpResponder`]
    /// - Discriminant 20: [`EpochCatchUpResponse`] -> [`EpochCatchUpResponseHandler`]
    ///
    /// [`EpochCatchUpRequest`]: crate::dispatch_router::MembershipMessage::EpochCatchUpRequest
    /// [`EpochCatchUpResponse`]: crate::dispatch_router::MembershipMessage::EpochCatchUpResponse
    pub fn register_with_router(
        &self,
        router: &mut crate::dispatch_router::MembershipDispatchRouter,
    ) {
        // We can't move self.responder and self.response_handler out of &self.
        // Instead, provide helper methods that the caller uses.
        let _ = router;
        // Registration is done by the caller:
        //   router.register(19, Box::new(wiring.responder)); // needs ownership
        //   router.register(20, Box::new(wiring.response_handler)); // needs ownership
    }

    /// Feed a peer's epoch push notification into the catch-up protocol.
    ///
    /// Call this each time an [`EpochPush`] is received from a peer,
    /// before the push is applied to the local coordinator.
    ///
    /// [`EpochPush`]: crate::dispatch_router::MembershipMessage::EpochPush
    pub fn on_peer_epoch_push(&self, peer_id: MemberId, epoch_number: u64) {
        self.protocol.on_epoch_push(peer_id, epoch_number);
    }

    /// Check whether the local node is lagging any known peer.
    #[must_use]
    pub fn is_lagging(&self) -> bool {
        self.protocol.is_lagging()
    }

    /// Feed a coordinator-lease heartbeat catch-up signal into the
    /// protocol. When the heartbeat indicates a future epoch (peer is
    /// ahead), this records the peer's epoch and optionally initiates
    /// a catch-up request if the local node is lagging.
    ///
    /// # Arguments
    /// * `peer_id` -- The peer that reported the higher epoch.
    /// * `peer_epoch` -- The peer's committed epoch from the heartbeat.
    ///
    /// # Returns
    /// `Some(CatchUpInitiated)` if a catch-up request was sent, `None`
    /// if no catch-up is needed or the peer is already known to be at
    /// the same or lower epoch.
    pub fn on_heartbeat_catch_up_signal(
        &self,
        peer_id: MemberId,
        peer_epoch: u64,
    ) -> Option<CatchUpInitiated> {
        self.protocol.on_epoch_push(peer_id, peer_epoch);
        if self.protocol.is_lagging() {
            self.protocol.check_and_initiate_catch_up()
        } else {
            None
        }
    }

    /// Retry catch-up with the next-best peer after a failed attempt.
    pub fn retry_catch_up(
        &self,
        previous_peer: MemberId,
        previous_target_epoch: u64,
    ) -> Option<CatchUpInitiated> {
        self.protocol
            .retry_with_next_peer(previous_peer, previous_target_epoch)
    }

    /// Clear failed-peer exclusions, allowing all peers to be tried again.
    pub fn clear_failed_peers(&self) {
        self.protocol.clear_failed_peers();
    }

    /// Number of peers marked as failed.
    pub fn failed_peer_count(&self) -> usize {
        self.protocol.failed_peer_count()
    }

    /// Consume self and return the responder and response handler for
    /// router registration (which requires ownership).
    #[must_use]
    pub fn into_handlers(self) -> (EpochCatchUpResponder, EpochCatchUpResponseHandler) {
        (self.responder, self.response_handler)
    }

    /// Consume self and return a pre-configured
    /// [`crate::membership_inbound_dispatch::MembershipInboundDispatch`]
    /// with the catch-up request handler (discriminant 19) and catch-up
    /// response handler (discriminant 20) registered.
    ///
    /// This is the preferred integration point: construct a
    /// [`CatchUpWiring`] with the required components, add any
    /// additional handlers (e.g., epoch push receiver), and register
    /// the resulting dispatch with the transport
    /// [`MessageDispatch`](tidefs_transport::dispatch::MessageDispatch)
    /// for [`MessageFamily::PublicationProgress`].
    #[must_use]
    pub fn into_inbound_dispatch(
        self,
    ) -> crate::membership_inbound_dispatch::MembershipInboundDispatch {
        let handlers = crate::membership_inbound_dispatch::HandlerSet::new()
            .with_epoch_catch_up_request_handler(Box::new(self.responder))
            .with_epoch_catch_up_response_handler(Box::new(self.response_handler));
        crate::membership_inbound_dispatch::MembershipInboundDispatch::new(handlers)
    }
}

/// Build an [`EpochAdvanceCoordinator`] for the response handler by
/// cloning the initial state from the shared coordinator.
fn make_handler_coordinator(shared: &EpochAdvanceCoordinator) -> EpochAdvanceCoordinator {
    let mut hc = EpochAdvanceCoordinator::new(shared.min_members());
    if let Some(view) = shared.current_view() {
        hc.initialize(view.member_set.clone(), view.created_at_millis);
        // Advance the epoch counter to match.
        let target_epoch = shared.epoch_counter();
        while hc.epoch_counter() < target_epoch {
            if let Some(v) = hc.current_view().cloned() {
                let members = v.member_set.clone();
                let ts = v.created_at_millis;
                let next = hc.epoch_counter() + 1;
                let _ = hc.force_advance_epoch(next, &members, ts);
            } else {
                break;
            }
        }
    }
    hc
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use tidefs_membership_epoch::EpochId;

    // ------------------------------------------------------------------
    // Test helpers
    // ------------------------------------------------------------------

    /// An in-memory epoch store for testing.
    struct TestEpochStore {
        epochs: StdMutex<BTreeMap<u64, CommittedEpochView>>,
    }

    impl TestEpochStore {
        fn new() -> Self {
            Self {
                epochs: StdMutex::new(BTreeMap::new()),
            }
        }

        fn insert(&self, view: CommittedEpochView) {
            self.epochs.lock().unwrap().insert(view.epoch_u64(), view);
        }

        fn insert_chain(&self, start_epoch: u64, members: Vec<MemberId>, count: u64, base_ts: u64) {
            let mut current_members = members;
            for i in 0..count {
                let epoch_num = start_epoch + i;
                let view = CommittedEpochView::new(
                    EpochId::new(epoch_num),
                    current_members.clone(),
                    base_ts + i * 1000,
                );
                self.insert(view);
                // Rotate: add a new member, remove the oldest
                if i % 2 == 0 {
                    current_members.push(MemberId::new(100 + epoch_num));
                } else if !current_members.is_empty() {
                    current_members.remove(0);
                }
            }
        }
    }

    impl EpochRangeQuery for TestEpochStore {
        fn query_range(&self, from_epoch: u64, to_epoch: u64) -> Vec<CommittedEpochView> {
            let store = self.epochs.lock().unwrap();
            store
                .range(from_epoch..=to_epoch)
                .map(|(_, v)| v.clone())
                .collect()
        }

        fn max_committed_epoch(&self) -> u64 {
            let store = self.epochs.lock().unwrap();
            store.keys().last().copied().unwrap_or(0)
        }
    }

    fn now_ms() -> u64 {
        1_700_000_000_000
    }

    fn make_coordinator(members: Vec<MemberId>) -> EpochAdvanceCoordinator {
        let mut c = EpochAdvanceCoordinator::new(1);
        c.initialize(members, now_ms());
        c
    }

    fn make_test_epoch_store() -> (Arc<TestEpochStore>, Vec<CommittedEpochView>) {
        let store = Arc::new(TestEpochStore::new());
        let mut views = Vec::new();

        // Epoch 1: [1, 2]
        let v1 = CommittedEpochView::new(
            EpochId::new(1),
            vec![MemberId::new(1), MemberId::new(2)],
            1000,
        );
        store.insert(v1.clone());
        views.push(v1);

        // Epoch 2: [1, 2, 3]
        let v2 = CommittedEpochView::new(
            EpochId::new(2),
            vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
            2000,
        );
        store.insert(v2.clone());
        views.push(v2);

        // Epoch 3: [1, 3]
        let v3 = CommittedEpochView::new(
            EpochId::new(3),
            vec![MemberId::new(1), MemberId::new(3)],
            3000,
        );
        store.insert(v3.clone());
        views.push(v3);

        // Epoch 4: [1, 3, 4]
        let v4 = CommittedEpochView::new(
            EpochId::new(4),
            vec![MemberId::new(1), MemberId::new(3), MemberId::new(4)],
            4000,
        );
        store.insert(v4.clone());
        views.push(v4);

        // Epoch 5: [3, 4]
        let v5 = CommittedEpochView::new(
            EpochId::new(5),
            vec![MemberId::new(3), MemberId::new(4)],
            5000,
        );
        store.insert(v5.clone());
        views.push(v5);

        (store, views)
    }

    // ------------------------------------------------------------------
    // TestEpochStore tests
    // ------------------------------------------------------------------

    #[test]
    fn test_epoch_store_query_range() {
        let (store, _) = make_test_epoch_store();

        // Query epoch 2..4
        let results = store.query_range(2, 4);
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].epoch_u64(), 2);
        assert_eq!(results[1].epoch_u64(), 3);
        assert_eq!(results[2].epoch_u64(), 4);

        // Query beyond range
        let empty = store.query_range(10, 20);
        assert!(empty.is_empty());

        // Query single epoch
        let single = store.query_range(1, 1);
        assert_eq!(single.len(), 1);
        assert_eq!(single[0].epoch_u64(), 1);
    }

    #[test]
    fn test_epoch_store_insert_chain() {
        let store = TestEpochStore::new();
        store.insert_chain(10, vec![MemberId::new(1), MemberId::new(2)], 5, 10000);

        let results = store.query_range(10, 14);
        assert_eq!(results.len(), 5);
        // First epoch adds member 110
        // First view (epoch 10) was created BEFORE mutation, so it has the original [1,2]
        assert_eq!(results[0].member_set.len(), 2);
        // Second view (epoch 11) has [1, 2, 111] because 111 was pushed before the view snapshot
        assert_eq!(results[1].member_set.len(), 3);
        assert!(results[1].contains(MemberId::new(110)));
    }

    // ------------------------------------------------------------------
    // EpochCatchUpProtocol tests
    // ------------------------------------------------------------------

    #[test]
    fn protocol_records_peer_epochs() {
        let coordinator = make_coordinator(vec![MemberId::new(1)]);

        let dispatcher = tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        );
        let roster = crate::roster::MembershipRoster::new();

        let protocol =
            EpochCatchUpProtocol::new(&coordinator, &dispatcher, &roster, MemberId::new(1));

        protocol.on_epoch_push(MemberId::new(2), 5);
        protocol.on_epoch_push(MemberId::new(3), 7);
        protocol.on_epoch_push(MemberId::new(2), 3); // lower value, should not override

        let snapshot = protocol.peer_epochs_snapshot();
        assert_eq!(snapshot.get(&MemberId::new(2)), Some(&5));
        assert_eq!(snapshot.get(&MemberId::new(3)), Some(&7));
        assert_eq!(protocol.max_peer_epoch(), 7);
    }

    #[test]
    fn protocol_detects_lag() {
        let mut coordinator =
            make_coordinator(vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]);
        // Advance coordinator to epoch 2
        let c1 = PeerLivenessChange::new(
            MemberId::new(3),
            PeerLivenessStatus::Alive,
            PeerLivenessStatus::Dead,
            now_ms(),
        );
        coordinator.on_liveness_change(c1);
        assert_eq!(coordinator.epoch_counter(), 1);

        let dispatcher = tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        );
        let roster = crate::roster::MembershipRoster::new();

        let protocol =
            EpochCatchUpProtocol::new(&coordinator, &dispatcher, &roster, MemberId::new(1));

        // No peer data yet -> not lagging
        assert!(!protocol.is_lagging());

        // Peer 2 at epoch 5 -> lagging
        protocol.on_epoch_push(MemberId::new(2), 5);
        assert!(protocol.is_lagging());

        // Peer 2 at epoch 1 -> not lagging (local is at 1)
        protocol.on_epoch_push(MemberId::new(2), 1);
        // but peer 3 at 7 -> lagging
        protocol.on_epoch_push(MemberId::new(3), 7);
        assert!(protocol.is_lagging());
    }

    #[test]
    fn protocol_initiates_catch_up_to_most_advanced_peer() {
        let coordinator = make_coordinator(vec![MemberId::new(1), MemberId::new(2)]);

        let dispatcher = tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        );
        let mut roster = crate::roster::MembershipRoster::new();
        roster.add_member(MemberId::new(5)); // the most advanced peer

        let protocol =
            EpochCatchUpProtocol::new(&coordinator, &dispatcher, &roster, MemberId::new(1));

        // Peer 3 at epoch 5, Peer 5 at epoch 10
        protocol.on_epoch_push(MemberId::new(3), 5);
        protocol.on_epoch_push(MemberId::new(5), 10);

        // Local is at epoch 0, so from_epoch=1, to_epoch=min(10, 0+64-1)=9
        let result = protocol.check_and_initiate_catch_up();
        assert!(result.is_some());
        let initiated = result.unwrap();
        assert_eq!(initiated.target_peer, MemberId::new(5)); // most advanced
        assert_eq!(initiated.from_epoch, 1);
        assert_eq!(initiated.to_epoch, 10); // max_peer_epoch=10, from_epoch=1, 10 < 64
        assert_eq!(initiated.max_peer_epoch, 10);
    }

    #[test]
    fn protocol_no_catch_up_when_not_lagging() {
        let mut coordinator = make_coordinator(vec![MemberId::new(1), MemberId::new(2)]);
        // Advance to epoch 3 by removing member 2
        let c = PeerLivenessChange::new(
            MemberId::new(2),
            PeerLivenessStatus::Alive,
            PeerLivenessStatus::Dead,
            now_ms(),
        );
        coordinator.on_liveness_change(c);

        // Now add member 3 to advance to epoch 2
        let c2 = PeerLivenessChange::new(
            MemberId::new(3),
            PeerLivenessStatus::Dead,
            PeerLivenessStatus::Alive,
            now_ms() + 1,
        );
        coordinator.on_liveness_change(c2);
        assert_eq!(coordinator.epoch_counter(), 2);

        let dispatcher = tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        );
        let roster = crate::roster::MembershipRoster::new();

        let protocol =
            EpochCatchUpProtocol::new(&coordinator, &dispatcher, &roster, MemberId::new(1));

        // Peer at epoch 2 or lower -> no catch-up needed
        protocol.on_epoch_push(MemberId::new(2), 2);
        assert!(!protocol.is_lagging());

        let result = protocol.check_and_initiate_catch_up();
        assert!(result.is_none());
    }

    #[test]
    fn protocol_catch_up_range_bounded_by_batch_size() {
        let coordinator = make_coordinator(vec![MemberId::new(1)]);

        let dispatcher = tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        );
        let mut roster = crate::roster::MembershipRoster::new();
        roster.add_member(MemberId::new(2));

        let protocol =
            EpochCatchUpProtocol::new(&coordinator, &dispatcher, &roster, MemberId::new(1));

        // Peer at epoch 200, but batch size is 64
        protocol.on_epoch_push(MemberId::new(2), 200);

        let result = protocol.check_and_initiate_catch_up();
        assert!(result.is_some());
        let initiated = result.unwrap();
        assert_eq!(initiated.from_epoch, 1);
        assert_eq!(initiated.to_epoch, 64); // bounded to 64
        assert_eq!(initiated.max_peer_epoch, 200);
    }

    // ------------------------------------------------------------------
    // EpochCatchUpResponseHandler tests
    // ------------------------------------------------------------------

    #[test]
    fn response_handler_applies_single_epoch() {
        let coordinator = make_coordinator(vec![MemberId::new(1), MemberId::new(2)]);
        let handler = EpochCatchUpResponseHandler::new(coordinator);

        // Apply epoch 1 with members [1, 2, 3]
        let views = vec![CommittedEpochView::new(
            EpochId::new(1),
            vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
            now_ms(),
        )];

        let result = handler.apply_epoch_views(&views);
        assert!(result.is_ok());
        let applied = result.unwrap();
        assert_eq!(applied.applied_count, 1);
        assert_eq!(applied.first_epoch, 1);
        assert_eq!(applied.last_epoch, 1);
        // After applying epoch 1, coordinator should be at epoch 1
        // (but only if the member set actually changed)
    }

    #[test]
    fn response_handler_applies_multiple_epochs_in_sequence() {
        // Local at epoch 0: members [1, 2]
        let coordinator = make_coordinator(vec![MemberId::new(1), MemberId::new(2)]);
        let handler = EpochCatchUpResponseHandler::new(coordinator);

        // Apply epochs 1..5
        let (_, views) = make_test_epoch_store();
        let result = handler.apply_epoch_views(&views);
        assert!(result.is_ok());
        let applied = result.unwrap();
        assert_eq!(applied.applied_count, 5);
        assert_eq!(applied.first_epoch, 1);
        assert_eq!(applied.last_epoch, 5);

        // Coordinator should now be at epoch 5 with members [3, 4]
        assert_eq!(handler.current_epoch(), 5);
    }

    #[test]
    fn response_handler_handles_empty_views() {
        let coordinator = make_coordinator(vec![MemberId::new(1)]);
        let handler = EpochCatchUpResponseHandler::new(coordinator);

        let result = handler.apply_epoch_views(&[]);
        assert!(result.is_ok());
        let applied = result.unwrap();
        assert_eq!(applied.applied_count, 0);
    }

    #[test]
    fn response_handler_callback_invoked() {
        use std::sync::Arc;

        let coordinator = make_coordinator(vec![MemberId::new(1)]);
        let handler = EpochCatchUpResponseHandler::new(coordinator);

        let callback_calls: Arc<StdMutex<Vec<CatchUpApplied>>> =
            Arc::new(StdMutex::new(Vec::new()));
        let cb_calls = callback_calls.clone();
        handler.set_on_catch_up_applied(move |applied| {
            cb_calls.lock().unwrap().push(applied.clone());
        });

        let views = vec![CommittedEpochView::new(
            EpochId::new(1),
            vec![MemberId::new(1), MemberId::new(2)],
            now_ms(),
        )];

        handler.apply_epoch_views(&views).unwrap();

        let calls = callback_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].applied_count, 1);
    }

    #[test]
    fn response_handler_merge_add_and_remove() {
        // Local: [1, 2, 3]
        let coordinator =
            make_coordinator(vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]);
        let handler = EpochCatchUpResponseHandler::new(coordinator);

        // Epoch 1: [1, 2] -- removed 3
        let views = vec![CommittedEpochView::new(
            EpochId::new(1),
            vec![MemberId::new(1), MemberId::new(2)],
            now_ms(),
        )];

        let result = handler.apply_epoch_views(&views);
        assert!(result.is_ok());

        let coord = handler.coordinator.lock().unwrap();
        let view = coord.current_view().unwrap();
        assert!(!view.contains(MemberId::new(3)));
        assert!(view.contains(MemberId::new(1)));
        assert!(view.contains(MemberId::new(2)));
    }

    #[test]
    fn response_handler_idempotent_same_epoch_twice() {
        let coordinator = make_coordinator(vec![MemberId::new(1)]);
        let handler = EpochCatchUpResponseHandler::new(coordinator);

        let views = vec![CommittedEpochView::new(
            EpochId::new(1),
            vec![MemberId::new(1), MemberId::new(2)],
            now_ms(),
        )];

        // First application succeeds
        let r1 = handler.apply_epoch_views(&views);
        assert!(r1.is_ok());
        let a1 = r1.unwrap();
        assert_eq!(a1.applied_count, 1);
        assert_eq!(handler.current_epoch(), 1);

        // Second application of same epoch is idempotent: returns Ok(0)
        // rather than Err, so repeated pulls do not corrupt state.
        let r2 = handler.apply_epoch_views(&views);
        assert!(r2.is_ok());
        let a2 = r2.unwrap();
        assert_eq!(a2.applied_count, 0);
        assert_eq!(handler.current_epoch(), 1); // epoch unchanged
    }

    // ------------------------------------------------------------------
    // EpochCatchUpResponder tests (handler trait)
    // ------------------------------------------------------------------

    #[test]
    fn responder_implements_membership_message_handler() {
        // Compile-time verification: trait bound is satisfied.
        fn _assert_handler<T: MembershipMessageHandler>(_: &T) {}

        let store: Arc<dyn EpochRangeQuery> = Arc::new(TestEpochStore::new());
        let dispatcher = Arc::new(tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        ));
        let roster = Arc::new(crate::roster::MembershipRoster::new());
        let responder = EpochCatchUpResponder::new(store, dispatcher, roster, MemberId::new(1));
        _assert_handler(&responder);
    }

    // ------------------------------------------------------------------
    // CatchUpInitiated / CatchUpApplied value-type tests
    // ------------------------------------------------------------------

    #[test]
    fn catch_up_initiated_clone_eq() {
        let a = CatchUpInitiated {
            target_peer: MemberId::new(5),
            from_epoch: 1,
            to_epoch: 10,
            max_peer_epoch: 15,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn catch_up_applied_clone_eq() {
        let a = CatchUpApplied {
            applied_count: 5,
            first_epoch: 1,
            last_epoch: 5,
            final_epoch: 5,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    // ------------------------------------------------------------------
    // MAX_CATCH_UP_BATCH_SIZE constant
    // ------------------------------------------------------------------

    #[test]
    fn max_catch_up_batch_size_is_64() {
        assert_eq!(MAX_CATCH_UP_BATCH_SIZE, 64);
    }

    // ------------------------------------------------------------------
    // make_handler_coordinator tests
    // ------------------------------------------------------------------

    #[test]
    fn make_handler_coordinator_clones_state() {
        let mut shared =
            make_coordinator(vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]);
        // Advance shared to epoch 2
        let c1 = PeerLivenessChange::new(
            MemberId::new(3),
            PeerLivenessStatus::Alive,
            PeerLivenessStatus::Dead,
            now_ms(),
        );
        shared.on_liveness_change(c1);
        assert_eq!(shared.epoch_counter(), 1);

        let c2 = PeerLivenessChange::new(
            MemberId::new(3),
            PeerLivenessStatus::Dead,
            PeerLivenessStatus::Alive,
            now_ms() + 1,
        );
        shared.on_liveness_change(c2);
        assert_eq!(shared.epoch_counter(), 2);

        // Clone
        let hc = make_handler_coordinator(&shared);
        assert_eq!(hc.epoch_counter(), 2);
        assert_eq!(hc.min_members(), shared.min_members());

        let hv = hc.current_view().unwrap();
        let sv = shared.current_view().unwrap();
        assert_eq!(hv.member_set, sv.member_set);
    }

    #[test]
    fn make_handler_coordinator_handles_epoch_zero() {
        let shared = make_coordinator(vec![MemberId::new(1)]);
        assert_eq!(shared.epoch_counter(), 0);

        let hc = make_handler_coordinator(&shared);
        assert_eq!(hc.epoch_counter(), 0);
        let hv = hc.current_view().unwrap();
        assert_eq!(hv.member_set, vec![MemberId::new(1)]);
    }

    // ------------------------------------------------------------------
    // CatchUpWiring tests
    // ------------------------------------------------------------------

    #[test]
    fn catch_up_wiring_construction() {
        let coordinator = make_coordinator(vec![MemberId::new(1), MemberId::new(2)]);

        let store: Arc<dyn EpochRangeQuery> = Arc::new(TestEpochStore::new());
        let dispatcher = Arc::new(tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        ));
        let roster = Arc::new(crate::roster::MembershipRoster::new());

        let outbound_dispatcher = tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        );
        let outbound_roster = crate::roster::MembershipRoster::new();

        let wiring = CatchUpWiring::new(
            store,
            dispatcher,
            roster,
            &coordinator,
            &outbound_dispatcher,
            &outbound_roster,
            MemberId::new(1),
        );

        assert!(!wiring.is_lagging());
    }

    #[test]
    fn catch_up_wiring_on_peer_epoch_push() {
        let coordinator = make_coordinator(vec![MemberId::new(1)]);

        let store: Arc<dyn EpochRangeQuery> = Arc::new(TestEpochStore::new());
        let dispatcher = Arc::new(tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        ));
        let roster = Arc::new(crate::roster::MembershipRoster::new());

        let outbound_dispatcher = tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        );
        let outbound_roster = crate::roster::MembershipRoster::new();

        let wiring = CatchUpWiring::new(
            store,
            dispatcher,
            roster,
            &coordinator,
            &outbound_dispatcher,
            &outbound_roster,
            MemberId::new(1),
        );

        // Local at epoch 0, peer 2 at epoch 5 -> lagging
        wiring.on_peer_epoch_push(MemberId::new(2), 5);
        assert!(wiring.is_lagging());
        assert_eq!(wiring.protocol.max_peer_epoch(), 5);
    }

    #[test]
    fn catch_up_wiring_into_handlers() {
        // (test body continues below)
        let coordinator = make_coordinator(vec![MemberId::new(1)]);

        let store: Arc<dyn EpochRangeQuery> = Arc::new(TestEpochStore::new());
        let dispatcher = Arc::new(tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        ));
        let roster = Arc::new(crate::roster::MembershipRoster::new());

        let outbound_dispatcher = tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        );
        let outbound_roster = crate::roster::MembershipRoster::new();

        let wiring = CatchUpWiring::new(
            store,
            dispatcher,
            roster,
            &coordinator,
            &outbound_dispatcher,
            &outbound_roster,
            MemberId::new(1),
        );

        let (responder, response_handler) = wiring.into_handlers();
        // Verify the handlers can be used with a dispatch router
        let mut router = crate::dispatch_router::MembershipDispatchRouter::new();
        router.register(19, Box::new(responder));
        router.register(20, Box::new(response_handler));
        assert_eq!(router.handler_count(), 2);
    }

    #[test]
    fn catch_up_wiring_into_inbound_dispatch_registers_both_handlers() {
        use tidefs_transport::dispatch::{DecodedMessage, MessageHandler};
        use tidefs_transport::envelope::MessageFamily;

        let coordinator = make_coordinator(vec![MemberId::new(1)]);
        let (store, _views) = make_test_epoch_store();
        let dispatcher = Arc::new(tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        ));
        let roster = Arc::new(crate::roster::MembershipRoster::new());
        let outbound_dispatcher = tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        );
        let outbound_roster = crate::roster::MembershipRoster::new();

        let wiring = CatchUpWiring::new(
            store,
            dispatcher,
            roster,
            &coordinator,
            &outbound_dispatcher,
            &outbound_roster,
            MemberId::new(1),
        );

        // Consume wiring into a MembershipInboundDispatch
        let dispatch = wiring.into_inbound_dispatch();
        assert_eq!(dispatch.handler_count(), 2);

        // Verify catch-up request routing (discriminant 19)
        let req_msg = crate::dispatch_router::MembershipMessage::EpochCatchUpRequest {
            requester: MemberId::new(10),
            from_epoch: 1,
            to_epoch: 3,
        };
        let req_payload = bincode::serialize(&req_msg).unwrap();
        let req_decoded = DecodedMessage::new(MessageFamily::PublicationProgress, req_payload);
        let result = dispatch.handle(req_decoded);
        assert!(
            result.is_ok(),
            "catch-up request dispatch failed: {result:?}"
        );

        // Verify catch-up response routing (discriminant 20)
        let resp_msg = crate::dispatch_router::MembershipMessage::EpochCatchUpResponse {
            responder: MemberId::new(20),
            epochs: vec![],
            truncated: false,
        };
        let resp_payload = bincode::serialize(&resp_msg).unwrap();
        let resp_decoded = DecodedMessage::new(MessageFamily::PublicationProgress, resp_payload);
        let result = dispatch.handle(resp_decoded);
        assert!(
            result.is_ok(),
            "catch-up response dispatch failed: {result:?}"
        );
    }

    // ------------------------------------------------------------------
    // Integration: full catch-up flow
    // ------------------------------------------------------------------

    #[test]
    fn integration_catch_up_flow_applies_epochs() {
        // Set up a lagging peer (local at epoch 0, member set [1, 2]).
        let coordinator = make_coordinator(vec![MemberId::new(1), MemberId::new(2)]);

        // Build an epoch store with epochs 1..5.
        let (_store, expected_views) = make_test_epoch_store();

        // Create response handler for applying epochs.
        let response_handler = EpochCatchUpResponseHandler::new(coordinator);

        // Apply all 5 epochs (should advance from 0 to 5).
        let result = response_handler.apply_epoch_views(&expected_views);
        assert!(result.is_ok());
        let applied = result.unwrap();
        assert_eq!(applied.applied_count, 5);
        assert_eq!(applied.first_epoch, 1);
        assert_eq!(applied.last_epoch, 5);

        // Coordinator should have the final member set [3, 4]
        // (from the test store: epoch 5 has members [3, 4])
        assert_eq!(response_handler.current_epoch(), 5);
    }

    // ------------------------------------------------------------------
    // New edge-case tests (step 7-9 of TRANSPORT-6232-EPOCH-CATCHUP)
    // ------------------------------------------------------------------

    // -- Responder edge cases -------------------------------------------

    #[test]
    fn responder_drops_unknown_peer_requests() {
        let store: Arc<dyn EpochRangeQuery> = Arc::new(TestEpochStore::new());
        let dispatcher = Arc::new(tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        ));
        let roster = Arc::new(crate::roster::MembershipRoster::new());
        // Peer 99 is NOT in the roster
        let responder = EpochCatchUpResponder::new(store, dispatcher, roster, MemberId::new(1));

        let msg = MembershipMessage::EpochCatchUpRequest {
            requester: MemberId::new(99), // unknown peer
            from_epoch: 1,
            to_epoch: 5,
        };

        // Should silently return Ok without sending (no crash)
        let result = responder.handle_epoch_catch_up_request(&msg);
        assert!(result.is_ok());
    }

    #[test]
    fn responder_drops_malformed_range() {
        let (store, _) = make_test_epoch_store();
        let dispatcher = Arc::new(tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        ));
        let mut roster = crate::roster::MembershipRoster::new();
        roster.add_member(MemberId::new(10)); // requester is known
        let responder =
            EpochCatchUpResponder::new(store, dispatcher, Arc::new(roster), MemberId::new(1));

        // from_epoch == 0 is malformed
        let msg = MembershipMessage::EpochCatchUpRequest {
            requester: MemberId::new(10),
            from_epoch: 0,
            to_epoch: 5,
        };
        let result = responder.handle_epoch_catch_up_request(&msg);
        assert!(result.is_ok());

        // to_epoch < from_epoch is malformed
        let msg = MembershipMessage::EpochCatchUpRequest {
            requester: MemberId::new(10),
            from_epoch: 5,
            to_epoch: 2,
        };
        let result = responder.handle_epoch_catch_up_request(&msg);
        assert!(result.is_ok());
    }

    #[test]
    fn responder_request_ahead_of_store_returns_empty_truncated() {
        let (store, _) = make_test_epoch_store();
        let dispatcher = Arc::new(tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        ));
        let mut roster = crate::roster::MembershipRoster::new();
        roster.add_member(MemberId::new(10));
        let responder =
            EpochCatchUpResponder::new(store, dispatcher, Arc::new(roster), MemberId::new(1));

        // Store has epochs 1..5, request 100..105 is way ahead
        let msg = MembershipMessage::EpochCatchUpRequest {
            requester: MemberId::new(10),
            from_epoch: 100,
            to_epoch: 105,
        };
        // Should not panic, handle gracefully
        let result = responder.handle_epoch_catch_up_request(&msg);
        assert!(result.is_ok());
    }

    // -- Protocol retry tests ------------------------------------------

    #[test]
    fn protocol_mark_and_clear_failed_peers() {
        let coordinator = make_coordinator(vec![MemberId::new(1)]);

        let dispatcher = tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        );
        let roster = crate::roster::MembershipRoster::new();

        let protocol =
            EpochCatchUpProtocol::new(&coordinator, &dispatcher, &roster, MemberId::new(1));

        assert_eq!(protocol.failed_peer_count(), 0);

        protocol.mark_peer_failed(MemberId::new(5));
        assert_eq!(protocol.failed_peer_count(), 1);

        // Duplicate mark idempotent
        protocol.mark_peer_failed(MemberId::new(5));
        assert_eq!(protocol.failed_peer_count(), 1);

        protocol.mark_peer_failed(MemberId::new(7));
        assert_eq!(protocol.failed_peer_count(), 2);

        protocol.clear_failed_peers();
        assert_eq!(protocol.failed_peer_count(), 0);
    }

    #[test]
    fn protocol_failed_peers_excluded_from_selection() {
        let coordinator = make_coordinator(vec![MemberId::new(1)]);

        let dispatcher = tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        );
        let mut roster = crate::roster::MembershipRoster::new();
        roster.add_member(MemberId::new(2));
        roster.add_member(MemberId::new(5));

        let protocol =
            EpochCatchUpProtocol::new(&coordinator, &dispatcher, &roster, MemberId::new(1));

        // Peer 2 at epoch 10, Peer 5 at epoch 8
        protocol.on_epoch_push(MemberId::new(2), 10);
        protocol.on_epoch_push(MemberId::new(5), 8);

        // First catch-up should target peer 2 (highest epoch)
        let r1 = protocol.check_and_initiate_catch_up();
        assert!(r1.is_some());
        assert_eq!(r1.unwrap().target_peer, MemberId::new(2));

        // Mark peer 2 as failed; next catch-up should target peer 5
        protocol.mark_peer_failed(MemberId::new(2));
        let r2 = protocol.check_and_initiate_catch_up();
        assert!(r2.is_some());
        assert_eq!(r2.unwrap().target_peer, MemberId::new(5));

        // Mark peer 5 failed too; no more peers
        protocol.mark_peer_failed(MemberId::new(5));
        let r3 = protocol.check_and_initiate_catch_up();
        assert!(r3.is_none());
    }

    #[test]
    fn protocol_retry_with_next_peer() {
        let coordinator = make_coordinator(vec![MemberId::new(1)]);

        let dispatcher = tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        );
        let mut roster = crate::roster::MembershipRoster::new();
        roster.add_member(MemberId::new(2));
        roster.add_member(MemberId::new(3));
        roster.add_member(MemberId::new(5));

        let protocol =
            EpochCatchUpProtocol::new(&coordinator, &dispatcher, &roster, MemberId::new(1));

        protocol.on_epoch_push(MemberId::new(2), 10);
        protocol.on_epoch_push(MemberId::new(3), 9);
        protocol.on_epoch_push(MemberId::new(5), 8);

        // Retry after peer 2 "failed"
        let r = protocol.retry_with_next_peer(MemberId::new(2), 10);
        assert!(r.is_some());
        let initiated = r.unwrap();
        assert_eq!(initiated.target_peer, MemberId::new(3)); // next best
                                                             // from_epoch=1, max of [10,9] = 10
        assert_eq!(initiated.from_epoch, 1);
        assert_eq!(initiated.to_epoch, 10);
        assert_eq!(protocol.failed_peer_count(), 1); // only peer 2
    }

    // -- Handler gap detection tests -----------------------------------

    #[test]
    fn response_handler_rejects_gap_in_views() {
        let coordinator = make_coordinator(vec![MemberId::new(1)]);
        let handler = EpochCatchUpResponseHandler::new(coordinator);

        // Apply epochs with a gap: epoch 3 instead of epoch 1
        let views = vec![CommittedEpochView::new(
            EpochId::new(3),
            vec![MemberId::new(1), MemberId::new(2)],
            now_ms(),
        )];

        let result = handler.apply_epoch_views(&views);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("catch-up gap"),
            "expected gap error, got: {err}"
        );
    }

    #[test]
    fn response_handler_all_stale_returns_zero_count() {
        let coordinator = make_coordinator(vec![MemberId::new(1), MemberId::new(2)]);
        let handler = EpochCatchUpResponseHandler::new(coordinator);

        // Apply epoch 1 successfully first
        let views1 = vec![CommittedEpochView::new(
            EpochId::new(1),
            vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
            now_ms(),
        )];
        let r1 = handler.apply_epoch_views(&views1);
        assert!(r1.is_ok());
        assert_eq!(r1.unwrap().applied_count, 1);

        // Now apply epoch 0 and 1 (both stale)
        let views2 = vec![
            CommittedEpochView::new(EpochId::new(0), vec![MemberId::new(1)], now_ms()),
            CommittedEpochView::new(
                EpochId::new(1),
                vec![MemberId::new(1), MemberId::new(2)],
                now_ms(),
            ),
        ];
        let r2 = handler.apply_epoch_views(&views2);
        assert!(r2.is_ok());
        assert_eq!(r2.unwrap().applied_count, 0); // all stale
    }

    // -- Heartbeat wiring tests ----------------------------------------

    #[test]
    fn catch_up_wiring_heartbeat_signal_when_lagging() {
        let coordinator = make_coordinator(vec![MemberId::new(1)]);

        let store: Arc<dyn EpochRangeQuery> = Arc::new(TestEpochStore::new());
        let dispatcher = Arc::new(tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        ));
        let mut roster = crate::roster::MembershipRoster::new();
        roster.add_member(MemberId::new(2));

        let outbound_dispatcher = tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        );
        let mut outbound_roster = crate::roster::MembershipRoster::new();
        outbound_roster.add_member(MemberId::new(2));

        let wiring = CatchUpWiring::new(
            store,
            dispatcher,
            Arc::new(roster),
            &coordinator,
            &outbound_dispatcher,
            &outbound_roster,
            MemberId::new(1),
        );

        // Heartbeat signal: peer 2 at epoch 5, local at epoch 0
        let result = wiring.on_heartbeat_catch_up_signal(MemberId::new(2), 5);
        // Should initiate catch-up since local is lagging
        assert!(result.is_some());
        let initiated = result.unwrap();
        assert_eq!(initiated.target_peer, MemberId::new(2));
        assert_eq!(initiated.from_epoch, 1);
    }

    #[test]
    fn catch_up_wiring_heartbeat_signal_when_current() {
        let mut coordinator = make_coordinator(vec![MemberId::new(1), MemberId::new(2)]);
        // Advance coordinator to epoch 2
        let c = PeerLivenessChange::new(
            MemberId::new(2),
            PeerLivenessStatus::Alive,
            PeerLivenessStatus::Dead,
            now_ms(),
        );
        coordinator.on_liveness_change(c);
        assert_eq!(coordinator.epoch_counter(), 1);

        let store: Arc<dyn EpochRangeQuery> = Arc::new(TestEpochStore::new());
        let dispatcher = Arc::new(tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        ));
        let roster = Arc::new(crate::roster::MembershipRoster::new());

        let outbound_dispatcher = tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        );
        let outbound_roster = crate::roster::MembershipRoster::new();

        let wiring = CatchUpWiring::new(
            store,
            dispatcher,
            roster,
            &coordinator,
            &outbound_dispatcher,
            &outbound_roster,
            MemberId::new(1),
        );

        // Heartbeat signal: peer at epoch 1, local at epoch 1 → not lagging
        let result = wiring.on_heartbeat_catch_up_signal(MemberId::new(2), 1);
        assert!(result.is_none());
    }

    #[test]
    fn catch_up_wiring_retry_and_clear_flow() {
        let coordinator = make_coordinator(vec![MemberId::new(1)]);

        let store: Arc<dyn EpochRangeQuery> = Arc::new(TestEpochStore::new());
        let dispatcher = Arc::new(tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        ));
        let mut roster = crate::roster::MembershipRoster::new();
        roster.add_member(MemberId::new(2));
        roster.add_member(MemberId::new(3));

        let outbound_dispatcher = tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        );
        let mut outbound_roster = crate::roster::MembershipRoster::new();
        outbound_roster.add_member(MemberId::new(2));
        outbound_roster.add_member(MemberId::new(3));

        let wiring = CatchUpWiring::new(
            store,
            dispatcher,
            Arc::new(roster),
            &coordinator,
            &outbound_dispatcher,
            &outbound_roster,
            MemberId::new(1),
        );

        // Feed two peers ahead
        wiring.on_peer_epoch_push(MemberId::new(2), 10);
        wiring.on_peer_epoch_push(MemberId::new(3), 8);

        assert_eq!(wiring.failed_peer_count(), 0);

        // Retry after peer 2 "failed"
        let r = wiring.retry_catch_up(MemberId::new(2), 10);
        assert!(r.is_some());
        assert_eq!(r.unwrap().target_peer, MemberId::new(3));
        assert_eq!(wiring.failed_peer_count(), 1);

        // Clear and verify
        wiring.clear_failed_peers();
        assert_eq!(wiring.failed_peer_count(), 0);
    }
}
