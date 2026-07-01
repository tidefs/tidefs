// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// Source-owned witness set mechanism: quorum-based claim verification,
// witness selection, and receipt integration.
//
// Design rule Rule 8: "Witnesses independently verify critical placements."
// Source-owned witness completion law: "Witnesses must observe and verify transfer completion
// before a replica is considered live."

pub mod ack_tracker;
pub mod codec;
pub mod config;
pub mod health;
pub mod heartbeat;
pub mod persistence;
pub mod quorum;
pub mod selection;
pub mod state_machine;
pub mod types;
pub mod verification;
pub mod vote_round;
pub mod witness_set;

pub use ack_tracker::{AckTracker, SnapshotEntry, WitnessSetSnapshot};
pub use codec::{CodecError, WitnessEntryCodec, WitnessSetCodec};
pub use config::{MembershipQuorum, WitnessMember, WitnessSetConfig};
pub use health::{HealthEvent, WitnessHealth};
pub use heartbeat::{
    HeartbeatConfig, HeartbeatEpoch, HeartbeatProtocol, NodeFailureEvent, NodeHeartbeatState,
};
pub use quorum::{MembershipAction, QuorumEvaluator};
pub use selection::select_witnesses;
pub use state_machine::{Transition, TransitionError, WitnessState, WitnessStateMachine};
pub use types::*;
pub use verification::{sign_witness_record, verify_witness_record, verify_witness_set};
pub use vote_round::{RoundIdGenerator, VoteOutcome, VoteRound};
// Note: witness_set::WitnessSet is accessed via `witness_set::WitnessSet` to
// avoid name collision with types::WitnessSet. QuorumThreshold is re-exported
// because it's used by QuorumEvaluator and by consumers.
pub use persistence::{PersistError, PersistedWitnessConfig};
pub use witness_set::{QuorumSelection, QuorumThreshold};
