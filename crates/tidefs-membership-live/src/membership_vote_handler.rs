// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Member-side roster change proposal validation and vote generation.
//!
//! [`MembershipVoteHandler`] validates incoming [`RosterChangeProposal`]
//! messages from the coordinator and produces [`RosterChangeVote`]
//! accept/reject responses. It checks:
//!
//! 1. The proposal's coordinator matches the expected coordinator.
//! 2. The proposal's current_epoch matches the member's current epoch.
//! 3. The add/remove sets are logically valid (no duplicate joins,
//!    no removal of non-members).
//!
//! Valid proposals receive an accept vote; invalid proposals receive
//! a reject vote with a reason code.

use crate::dispatch_router::MembershipDispatchError;
use crate::membership_outbound_dispatch::MembershipOutboundMessage;
use std::sync::Arc;
use tidefs_membership_epoch::roster_validation::{self, RosterChangeProposal};
use tidefs_membership_epoch::MemberId;
use tidefs_membership_types::RosterChangeVote;

/// Callback type for delivering proposal votes to the coordinator.
pub type MembershipVoteSender = Arc<
    dyn Fn(MemberId, MembershipOutboundMessage) -> Result<(), MembershipDispatchError>
        + Send
        + Sync,
>;

// ---------------------------------------------------------------------------
// VoteValidationOutcome
// ---------------------------------------------------------------------------

/// Result of validating a roster change proposal on the member side.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VoteValidationOutcome {
    /// The proposal is valid; the member accepts.
    Accept,
    /// The proposal is invalid; rejected with a reason.
    Reject {
        /// Machine-readable rejection reason code.
        reason: RejectReason,
        /// Human-readable detail.
        detail: String,
    },
}

/// Structured rejection reason codes for roster change proposals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectReason {
    /// The coordinator proposing the change is not the expected coordinator.
    WrongCoordinator,
    /// The proposal's epoch does not match the member's current epoch.
    EpochMismatch,
    /// The proposal contains a duplicate join (peer already in roster).
    DuplicateJoin,
    /// The proposal tries to remove a member not in the roster.
    RemoveNonMember,
    /// The proposal would remove the last member.
    RemoveLastMember,
    /// The proposal is empty (no adds, no removes).
    EmptyProposal,
    /// A peer appears in both add and remove sets.
    AddAndRemoveSamePeer,
    /// The proposal contains duplicate entries within add or remove sets.
    DuplicateEntry,
    /// Unknown or unspecified rejection.
    Other,
}

impl RejectReason {
    /// Human-readable label for this reason.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::WrongCoordinator => "wrong_coordinator",
            Self::EpochMismatch => "epoch_mismatch",
            Self::DuplicateJoin => "duplicate_join",
            Self::RemoveNonMember => "remove_non_member",
            Self::RemoveLastMember => "remove_last_member",
            Self::EmptyProposal => "empty_proposal",
            Self::AddAndRemoveSamePeer => "add_and_remove_same_peer",
            Self::DuplicateEntry => "duplicate_entry",
            Self::Other => "other",
        }
    }
}

// ---------------------------------------------------------------------------
// MembershipVoteConfig
// ---------------------------------------------------------------------------

/// Configuration for the vote handler.
#[derive(Clone, Debug)]
pub struct MembershipVoteConfig {
    /// The member's own node identity.
    pub my_member_id: MemberId,
    /// The expected coordinator (lowest MemberId in the roster).
    pub expected_coordinator: Option<MemberId>,
    /// The current committed epoch.
    pub current_epoch: u64,
    /// The current member set (sorted, deduplicated).
    pub current_members: Vec<u64>,
}

// ---------------------------------------------------------------------------
// MembershipVoteHandler
// ---------------------------------------------------------------------------

/// Validates roster change proposals from the coordinator and produces votes.
///
/// This handler is registered in the membership inbound dispatch to
/// process incoming proposal messages. It validates the proposal against
/// the local membership state and returns an accept or reject vote
/// that the member sends back to the coordinator.
#[derive(Clone, Debug)]
pub struct MembershipVoteHandler {
    config: Arc<std::sync::RwLock<MembershipVoteConfig>>,
}

impl MembershipVoteHandler {
    /// Create a new vote handler with the given configuration.
    #[must_use]
    pub fn new(config: MembershipVoteConfig) -> Self {
        Self {
            config: Arc::new(std::sync::RwLock::new(config)),
        }
    }

    /// Update the vote handler's configuration.
    pub fn update_config(&self, config: MembershipVoteConfig) {
        if let Ok(mut guard) = self.config.write() {
            *guard = config;
        }
    }

    /// Read the current configuration.
    fn read_config(&self) -> MembershipVoteConfig {
        self.config.read().map(|g| g.clone()).unwrap_or_else(|e| {
            // Poisoned lock: recover with the inner value.

            e.into_inner().clone()
        })
    }

    /// Validate a roster change proposal and produce a vote.
    ///
    /// Returns a `RosterChangeVote` with `accepted: true` for valid
    /// proposals, or `accepted: false` with a rejection reason.
    #[must_use]
    pub fn validate_and_vote(
        &self,
        proposal: &tidefs_membership_types::RosterChangeProposal,
    ) -> RosterChangeVote {
        let config = self.read_config();
        let outcome = self.validate_proposal(proposal, &config);

        match outcome {
            VoteValidationOutcome::Accept => RosterChangeVote {
                proposal_id: proposal.proposal_id,
                voter_id: config.my_member_id.0,
                accepted: true,
                reject_reason: None,
                voted_at_millis: 0, // caller sets real timestamp
            },
            VoteValidationOutcome::Reject { reason, detail } => RosterChangeVote {
                proposal_id: proposal.proposal_id,
                voter_id: config.my_member_id.0,
                accepted: false,
                reject_reason: Some(format!("{}: {}", reason.label(), detail)),
                voted_at_millis: 0,
            },
        }
    }

    /// Validate a proposal against the current membership state.
    fn validate_proposal(
        &self,
        proposal: &tidefs_membership_types::RosterChangeProposal,
        config: &MembershipVoteConfig,
    ) -> VoteValidationOutcome {
        // 1. Check coordinator matches expected.
        if let Some(expected_coord) = config.expected_coordinator {
            if proposal.coordinator_id != expected_coord.0 {
                return VoteValidationOutcome::Reject {
                    reason: RejectReason::WrongCoordinator,
                    detail: format!(
                        "expected coordinator {}, got {}",
                        expected_coord.0, proposal.coordinator_id
                    ),
                };
            }
        }

        // 2. Check epoch matches.
        if proposal.current_epoch != config.current_epoch {
            return VoteValidationOutcome::Reject {
                reason: RejectReason::EpochMismatch,
                detail: format!(
                    "proposal epoch {} != member epoch {}",
                    proposal.current_epoch, config.current_epoch
                ),
            };
        }

        // 3. Run the existing well-formedness validation.
        let delta = RosterChangeProposal {
            added: proposal.added.clone(),
            removed: proposal.removed.clone(),
        };

        match roster_validation::validate_roster_change(&delta, &config.current_members) {
            Ok(()) => VoteValidationOutcome::Accept,
            Err(errors) => {
                // Map the first validation error to a rejection reason.
                let first = &errors[0];
                let reason = match first.rule {
                    roster_validation::RosterChangeValidationRule::AddPeerPresent => {
                        RejectReason::DuplicateJoin
                    }
                    roster_validation::RosterChangeValidationRule::RemoveAbsentPeer => {
                        RejectReason::RemoveNonMember
                    }
                    roster_validation::RosterChangeValidationRule::RemoveLastMember => {
                        RejectReason::RemoveLastMember
                    }
                    roster_validation::RosterChangeValidationRule::EmptyProposal => {
                        RejectReason::EmptyProposal
                    }
                    roster_validation::RosterChangeValidationRule::DuplicateEntry => {
                        RejectReason::DuplicateEntry
                    }
                    roster_validation::RosterChangeValidationRule::AddAndRemoveSamePeer => {
                        RejectReason::AddAndRemoveSamePeer
                    }
                };
                let detail = format!(
                    "validation failed: {} error(s); first: {:?} (peer {:?})",
                    errors.len(),
                    first.rule,
                    first.peer_id,
                );
                VoteValidationOutcome::Reject { reason, detail }
            }
        }
    }

    /// Create a `MembershipMessageHandler` that validates proposals and sends
    /// votes back through `send_vote`.
    ///
    /// If `send_vote` is `None`, proposal handling fails closed with a
    /// [`MembershipDispatchError::HandlerError`] that names the missing vote
    /// delivery path instead of validating and silently dropping the vote.
    #[must_use]
    pub fn into_handler(
        self,
        send_vote: Option<MembershipVoteSender>,
    ) -> Box<dyn crate::dispatch_router::MembershipMessageHandler> {
        Box::new(VoteDispatchAdapter::new(self, send_vote))
    }
}

// ---------------------------------------------------------------------------
// VoteDispatchAdapter — bridges MembershipVoteHandler to the dispatch trait
// ---------------------------------------------------------------------------

/// Adapter that bridges [`MembershipVoteHandler`] to the
/// [`MembershipMessageHandler`] dispatch trait.
///
/// On receiving a `ProposalSubmission`, validates the proposal, constructs a
/// [`MembershipOutboundMessage::ProposalAck`], and sends it back to the
/// coordinator through the configured vote sender. Missing or failed vote
/// delivery is reported as a handler error so callers cannot mistake a lost
/// vote for successful proposal handling.

struct VoteDispatchAdapter {
    handler: MembershipVoteHandler,
    send_vote: Option<MembershipVoteSender>,
}

impl VoteDispatchAdapter {
    fn new(handler: MembershipVoteHandler, send_vote: Option<MembershipVoteSender>) -> Self {
        Self { handler, send_vote }
    }

    fn vote_delivery_error(
        reason: &str,
        proposer: MemberId,
        vote: &RosterChangeVote,
        proposal_hash: &[u8; 32],
    ) -> MembershipDispatchError {
        MembershipDispatchError::HandlerError(format!(
            "proposal vote delivery {reason}: target={}, responder={}, proposal_id={}, accepted={}, proposal_hash={:?}",
            proposer.0, vote.voter_id, vote.proposal_id, vote.accepted, proposal_hash
        ))
    }
}

impl crate::dispatch_router::MembershipMessageHandler for VoteDispatchAdapter {
    fn handle_proposal_submission(
        &self,
        msg: &crate::dispatch_router::MembershipMessage,
    ) -> Result<(), crate::dispatch_router::MembershipDispatchError> {
        // Extract the proposal fields from the MembershipMessage.
        if let crate::dispatch_router::MembershipMessage::ProposalSubmission {
            proposer,
            current_epoch,
            proposed_epoch: _,
            delta,
            resulting_members: _,
            proposal_hash,
            submitted_at_millis,
            catalog_delta_bytes: _,
        } = msg
        {
            // Convert MembershipDelta to added/removed sets for validation.
            // NodeSuspected doesn't change roster; skip without voting.
            let (added, removed): (Vec<u64>, Vec<u64>) = match delta {
                tidefs_membership_epoch::epoch_proposal::MembershipDelta::NodeJoined(id) => {
                    (vec![*id], vec![])
                }
                tidefs_membership_epoch::epoch_proposal::MembershipDelta::NodeDrained(id)
                | tidefs_membership_epoch::epoch_proposal::MembershipDelta::NodeFailed(id) => {
                    (vec![], vec![*id])
                }
                tidefs_membership_epoch::epoch_proposal::MembershipDelta::NodeSuspected(_) => {
                    return Ok(());
                }
            };

            let proposal = tidefs_membership_types::RosterChangeProposal {
                proposal_id: *submitted_at_millis,
                coordinator_id: proposer.0,
                current_epoch: *current_epoch,
                added,
                removed,
                created_at_millis: *submitted_at_millis,
            };

            let vote = self.handler.validate_and_vote(&proposal);

            let ack_msg = MembershipOutboundMessage::ProposalAck {
                responder: MemberId::new(vote.voter_id),
                proposal_hash: *proposal_hash,
                accepted: vote.accepted,
                reject_reason: vote.reject_reason.clone(),
                acked_at_millis: vote.voted_at_millis,
            };

            let Some(ref sender) = self.send_vote else {
                return Err(Self::vote_delivery_error(
                    "unavailable",
                    *proposer,
                    &vote,
                    proposal_hash,
                ));
            };

            sender(*proposer, ack_msg).map_err(|err| {
                Self::vote_delivery_error(
                    &format!("failed: {err}"),
                    *proposer,
                    &vote,
                    proposal_hash,
                )
            })?;
        } else {
            return Err(MembershipDispatchError::HandlerError(
                "VoteDispatchAdapter received non-ProposalSubmission message".to_string(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch_router::{MembershipDispatchError, MembershipMessage};
    use std::sync::{Arc, Mutex};
    use tidefs_membership_epoch::epoch_proposal::MembershipDelta;
    use tidefs_membership_epoch::MemberId;

    fn cfg(my_id: u64, coordinator: u64, epoch: u64, members: Vec<u64>) -> MembershipVoteConfig {
        MembershipVoteConfig {
            my_member_id: MemberId::new(my_id),
            expected_coordinator: Some(MemberId::new(coordinator)),
            current_epoch: epoch,
            current_members: members,
        }
    }

    fn proposal(
        id: u64,
        coordinator: u64,
        epoch: u64,
        added: Vec<u64>,
        removed: Vec<u64>,
    ) -> tidefs_membership_types::RosterChangeProposal {
        tidefs_membership_types::RosterChangeProposal {
            proposal_id: id,
            coordinator_id: coordinator,
            current_epoch: epoch,
            added,
            removed,
            created_at_millis: 1000,
        }
    }

    fn proposal_submission(delta: MembershipDelta) -> MembershipMessage {
        MembershipMessage::ProposalSubmission {
            proposer: MemberId::new(1),
            current_epoch: 5,
            proposed_epoch: 6,
            delta,
            resulting_members: vec![1, 2, 3, 4],
            proposal_hash: [8u8; 32],
            submitted_at_millis: 1000,
            catalog_delta_bytes: None,
        }
    }

    // ── Valid proposals ─────────────────────────────────────────

    #[test]
    fn valid_join_proposal_accepted() {
        let handler = MembershipVoteHandler::new(cfg(2, 1, 5, vec![1, 2, 3]));
        let p = proposal(1, 1, 5, vec![4], vec![]);

        let vote = handler.validate_and_vote(&p);
        assert!(vote.accepted);
        assert_eq!(vote.proposal_id, 1);
        assert_eq!(vote.voter_id, 2);
        assert!(vote.reject_reason.is_none());
    }

    #[test]
    fn valid_leave_proposal_accepted() {
        let handler = MembershipVoteHandler::new(cfg(2, 1, 5, vec![1, 2, 3]));
        let p = proposal(1, 1, 5, vec![], vec![3]);

        let vote = handler.validate_and_vote(&p);
        assert!(vote.accepted, "valid leave should be accepted");
    }

    #[test]
    fn valid_add_and_remove_accepted() {
        let handler = MembershipVoteHandler::new(cfg(2, 1, 5, vec![1, 2, 3]));
        let p = proposal(1, 1, 5, vec![4], vec![3]);

        let vote = handler.validate_and_vote(&p);
        assert!(vote.accepted);
    }

    // ── Wrong coordinator ───────────────────────────────────────

    #[test]
    fn wrong_coordinator_rejected() {
        let handler = MembershipVoteHandler::new(cfg(2, 1, 5, vec![1, 2, 3]));
        let p = proposal(1, 99, 5, vec![4], vec![]);

        let vote = handler.validate_and_vote(&p);
        assert!(!vote.accepted);
        assert!(vote.reject_reason.unwrap().contains("wrong_coordinator"));
    }

    #[test]
    fn no_expected_coordinator_skips_check() {
        let mut config = cfg(2, 1, 5, vec![1, 2, 3]);
        config.expected_coordinator = None;
        let handler = MembershipVoteHandler::new(config);
        let p = proposal(1, 99, 5, vec![4], vec![]);

        // No expected coordinator, so this is accepted (epoch and roster validation pass).
        let vote = handler.validate_and_vote(&p);
        assert!(vote.accepted);
    }

    // ── Epoch mismatch ──────────────────────────────────────────

    #[test]
    fn epoch_mismatch_rejected() {
        let handler = MembershipVoteHandler::new(cfg(2, 1, 5, vec![1, 2, 3]));
        let p = proposal(1, 1, 99, vec![4], vec![]);

        let vote = handler.validate_and_vote(&p);
        assert!(!vote.accepted);
        assert!(vote.reject_reason.unwrap().contains("epoch_mismatch"));
    }

    // ── Duplicate join ──────────────────────────────────────────

    #[test]
    fn duplicate_join_rejected() {
        let handler = MembershipVoteHandler::new(cfg(2, 1, 5, vec![1, 2, 3]));
        let p = proposal(1, 1, 5, vec![2], vec![]); // 2 is already a member

        let vote = handler.validate_and_vote(&p);
        assert!(!vote.accepted);
        assert!(vote.reject_reason.unwrap().contains("duplicate_join"));
    }

    // ── Remove non-member ───────────────────────────────────────

    #[test]
    fn remove_non_member_rejected() {
        let handler = MembershipVoteHandler::new(cfg(2, 1, 5, vec![1, 2, 3]));
        let p = proposal(1, 1, 5, vec![], vec![99]); // 99 not in roster

        let vote = handler.validate_and_vote(&p);
        assert!(!vote.accepted);
        assert!(vote.reject_reason.unwrap().contains("remove_non_member"));
    }

    // ── Remove last member ──────────────────────────────────────

    #[test]
    fn remove_last_member_rejected() {
        let handler = MembershipVoteHandler::new(cfg(1, 1, 5, vec![1]));
        let p = proposal(1, 1, 5, vec![], vec![1]);

        let vote = handler.validate_and_vote(&p);
        assert!(!vote.accepted);
        assert!(vote.reject_reason.unwrap().contains("remove_last_member"));
    }

    // ── VoteDispatchAdapter integration smoke ──────────────────

    #[test]
    fn adapter_sends_accept_vote_to_coordinator() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sender: MembershipVoteSender = {
            let sent = Arc::clone(&sent);
            Arc::new(move |target, message| {
                sent.lock().unwrap().push((target, message));
                Ok(())
            })
        };

        let handler =
            MembershipVoteHandler::new(cfg(2, 1, 5, vec![1, 2, 3])).into_handler(Some(sender));
        handler
            .handle_proposal_submission(&proposal_submission(MembershipDelta::NodeJoined(4)))
            .expect("valid proposal vote should be delivered");

        let sent = sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, MemberId::new(1));
        match &sent[0].1 {
            MembershipOutboundMessage::ProposalAck {
                responder,
                proposal_hash,
                accepted,
                reject_reason,
                ..
            } => {
                assert_eq!(*responder, MemberId::new(2));
                assert_eq!(*proposal_hash, [8u8; 32]);
                assert!(*accepted);
                assert!(reject_reason.is_none());
            }
            other => panic!("expected proposal ack, got {other:?}"),
        }
    }

    #[test]
    fn adapter_produces_reject_for_invalid_proposal() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sender: MembershipVoteSender = {
            let sent = Arc::clone(&sent);
            Arc::new(move |target, message| {
                sent.lock().unwrap().push((target, message));
                Ok(())
            })
        };

        let handler =
            MembershipVoteHandler::new(cfg(2, 1, 5, vec![1, 2, 3])).into_handler(Some(sender));
        handler
            .handle_proposal_submission(&proposal_submission(MembershipDelta::NodeJoined(2)))
            .expect("invalid proposal should still deliver a reject vote");

        let sent = sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        match &sent[0].1 {
            MembershipOutboundMessage::ProposalAck {
                accepted,
                reject_reason,
                ..
            } => {
                assert!(!accepted);
                assert!(reject_reason
                    .as_deref()
                    .unwrap_or_default()
                    .contains("duplicate_join"));
            }
            other => panic!("expected proposal ack, got {other:?}"),
        }
    }

    #[test]
    fn adapter_fails_closed_without_vote_sender() {
        let handler = MembershipVoteHandler::new(cfg(2, 1, 5, vec![1, 2, 3])).into_handler(None);
        let err = handler
            .handle_proposal_submission(&proposal_submission(MembershipDelta::NodeJoined(4)))
            .expect_err("missing vote sender must fail closed");

        match err {
            MembershipDispatchError::HandlerError(detail) => {
                assert!(detail.contains("proposal vote delivery unavailable"));
                assert!(detail.contains("target=1"));
                assert!(detail.contains("responder=2"));
                assert!(detail.contains("accepted=true"));
            }
            other => panic!("expected handler error, got {other:?}"),
        }
    }

    #[test]
    fn adapter_propagates_vote_sender_failure() {
        let sender: MembershipVoteSender = Arc::new(|_, _| {
            Err(MembershipDispatchError::HandlerError(
                "transport send refused".to_string(),
            ))
        });
        let handler =
            MembershipVoteHandler::new(cfg(2, 1, 5, vec![1, 2, 3])).into_handler(Some(sender));
        let err = handler
            .handle_proposal_submission(&proposal_submission(MembershipDelta::NodeJoined(4)))
            .expect_err("vote sender failure must fail proposal handling");

        match err {
            MembershipDispatchError::HandlerError(detail) => {
                assert!(detail.contains("proposal vote delivery failed"));
                assert!(detail.contains("transport send refused"));
                assert!(detail.contains("target=1"));
                assert!(detail.contains("responder=2"));
            }
            other => panic!("expected handler error, got {other:?}"),
        }
    }

    // ── Config update ───────────────────────────────────────────

    #[test]
    fn config_update_changes_behavior() {
        let handler = MembershipVoteHandler::new(cfg(2, 1, 5, vec![1, 2, 3]));

        // Epoch 5 is valid.
        let p = proposal(1, 1, 5, vec![4], vec![]);
        assert!(handler.validate_and_vote(&p).accepted);

        // Update config to epoch 6; same proposal now rejected.
        handler.update_config(cfg(2, 1, 6, vec![1, 2, 3]));
        assert!(!handler.validate_and_vote(&p).accepted);
    }
}
