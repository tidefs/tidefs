use crate::coordinator_lease::{CoordinatorHeartbeatRequest, CoordinatorLease, LeaseStatus};
use crate::epoch_coordinator::{EpochCommitSubscriber, EpochView};
use crate::epoch_fence::MembershipEpochFence;
use crate::epoch_transition::*;
use crate::event_bridge::*;
use crate::failure_detector::*;
use crate::fencing_watchdog::{FencingAction, FencingWatchdog};
use crate::gossip_batcher::{GossipBatcher, GossipBatcherConfig, GossipUpdate};
use crate::heartbeat::*;
use crate::join_response::JoinResponseDispatcher;
use crate::membership_outbound_dispatch::{MembershipOutboundDispatch, MembershipOutboundMessage};
use crate::peer_address_registry::PeerAddressRegistry;
use crate::peer_health::PeerHealthTracker;
use crate::roster::*;
use crate::roster_notify::RosterNotifier;
use crate::roster_sync::RosterStateSync;
use crate::send_gate::MembershipSendGate;
use crate::suspicion_accumulator::SuspicionEvent;
use crate::types::*;
use ed25519_dalek::{Keypair, PublicKey};
use rand::rngs::OsRng;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use tidefs_membership_epoch::checkpoint::CheckpointManager;
use tidefs_membership_epoch::incarnation::IncarnationTracker;
use tidefs_membership_epoch::snapshot::{EpochSnapshotStore, TransportAddress};
use tidefs_membership_epoch::transition_journal::MembershipTransitionJournal;
use tidefs_membership_epoch::{ConfigClass, EpochId, HealthClass, MemberClass, MemberId};
use tidefs_membership_types::Incarnation;
use tidefs_membership_types::PeerHealthConfig;
use tidefs_transport::addr::TransportAddr;
use tidefs_transport::peer_manager::{self, MembershipEventSink};
use tidefs_transport::send_dispatch::SendDispatcher;

use crate::capability_view::MembershipCapabilityView;
use crate::departure_initiator::{DepartureInitiator, DepartureInitiatorConfig};
use crate::epoch_coordinator::{EpochAdvanceCoordinator, PeerLivenessChange, PeerLivenessStatus};
use crate::join_handler::JoinHandler;
use crate::peer_eviction::{EvictionCallback, EvictionExecutor};
use crate::peer_unreachable::{PeerUnreachableConfig, PeerUnreachableTracker};
use crate::proposal_commit::{ProposalCommitPipeline, ProposalSequencer};
use crate::session_binding::SessionBindingTable;
use crate::transport_bridge::MembershipTransportBridge;
use crate::transport_session_manager::TransportBridgeManager;
use tidefs_membership_epoch::roster_constraints::RosterConstraints;
use tidefs_membership_types::departure::DepartureResponse;
use tidefs_transport::connection_registry::ConnectionRegistry;
use tidefs_transport::Transport;

// ---------------------------------------------------------------------------
// MembershipRuntime: the live membership service
// ---------------------------------------------------------------------------

/// The live membership runtime drives SWIM failure detection, epoch transitions,
/// and cohort population for the distributed TideFS cluster.
///
/// ## Lifecycle
///
/// 1. Bootstrap: initial members are registered from config
/// 2. Heartbeat loop: per-peer SWIM pings drive failure detection
/// 3. Epoch transitions: on member join/leave/fail, a 3-phase quorum commit
///    transitions the epoch
/// 4. Continuous: the runtime lives for the process lifetime
pub struct MembershipRuntime {
    pub config: MembershipConfig,
    /// Failure detector: per-peer health tracking
    pub detector: FailureDetector,
    /// Epoch transition engine
    pub epoch_engine: EpochTransitionEngine,
    /// This node's identity
    pub my_id: MemberId,
    /// Signing key for this node
    pub signing_key: Keypair,
    /// Known verifying keys: member_id → PublicKey
    pub verifying_keys: BTreeMap<MemberId, PublicKey>,
    /// Pending epoch transitions we are waiting for
    pub pending_transition: Option<PendingTransition>,
    /// Callbacks on epoch transitions
    #[allow(clippy::type_complexity)]
    transition_callbacks: Vec<Box<dyn Fn(&AppliedTransition) + Send>>,
    /// Ticks since start
    tick_count: u64,
    /// Forced fencing watchdog for unresponsive node detection
    pub fencing: FencingWatchdog,
    /// Current placement map version from the transport layer (0 = none).
    placement_version: u64,
    /// Newest nonzero placement map version observed from each known peer.
    peer_placement_versions: BTreeMap<MemberId, u64>,
    /// Epoch fence for stale-proposer and fenced-peer rejection.
    pub epoch_fence: Option<Arc<MembershipEpochFence>>,
    /// Gossip batcher for disseminating suspicion and membership events.
    pub gossip_batcher: GossipBatcher,
    /// Heartbeat transmitter: periodically sends HealthReport messages
    pub heartbeat_tx: HeartbeatTransmitter,
    /// Deadline-based liveness tracker for heartbeat protocol
    pub heartbeat_tracker: PeerLivenessTracker,
    /// Session-disconnect-driven peer unreachability tracker.
    pub unreachable_tracker: PeerUnreachableTracker,
    /// Whether we are in bootstrap mode
    /// Event publisher for membership state-change notifications
    pub event_publisher: MembershipEventPublisher,
    /// Authoritative membership roster with BLAKE3-verified snapshots
    pub roster: MembershipRoster,
    /// Transport peer manager for membership-driven session lifecycle.
    pub peer_manager: Option<peer_manager::PeerManagerHandle>,
    /// Epoch advance coordinator bridging liveness detection to committed
    /// epoch views. When set via wire_eviction_executor(), dead-peer
    /// removals trigger transport connection teardown through the
    /// registered EvictionExecutor subscriber.
    pub epoch_coordinator: Option<EpochAdvanceCoordinator>,
    /// Transport send dispatcher for outbound membership protocol messages.
    ///
    /// Shared behind an `Arc` so the runtime can construct
    /// [`MembershipOutboundDispatch`] and [`RosterNotifier`] on the fly
    /// without self-referential borrows. Set via [`set_send_dispatcher`].
    pub send_dispatcher: Option<Arc<SendDispatcher>>,
    /// Peer address registry shared with outbound dispatch and roster sync.
    ///
    /// When set, the runtime populates it from incoming roster snapshots
    /// and uses it when building outgoing snapshots for joining peers.
    pub peer_address_registry: Option<Arc<PeerAddressRegistry>>,
    /// Outbound membership roster send gate for transport-layer enforcement.
    ///
    /// Created at construction time and kept current via
    /// EpochCommitSubscriber registration in wire_eviction_executor.
    /// Callers attach it to a Transport via set_send_gate so every
    /// outbound send is checked against the committed roster.
    pub send_gate: Option<Arc<MembershipSendGate>>,
    /// Coordinator transition journal for crash-recovery replay.
    ///
    /// Records in-flight join and leave transitions with prepare-commit
    /// lifecycle. Replayed on coordinator promotion to resolve pending
    /// transitions.
    pub transition_journal: Arc<Mutex<MembershipTransitionJournal>>,
    /// Coordinator epoch lease preventing split-brain during partitions.
    ///
    /// Activated on coordinator promotion, deactivated on stepdown.
    /// Tick-driven heartbeat renewal confirms majority connectivity.
    pub coordinator_lease: CoordinatorLease,
    pub peer_health: PeerHealthTracker,
    /// Monotonic coordinator incarnation tracker. Incremented on each
    /// coordinator promotion; validates inbound messages against current
    /// incarnation to reject stale commands from deposed coordinators.
    pub incarnation_tracker: IncarnationTracker,
    /// Coordinator-side join-request validator with roster-constraint
    /// and incarnation-aware stale-message rejection (#6244).
    pub join_handler: JoinHandler,
    pub proposal_commit_pipeline: ProposalCommitPipeline,
    /// Optional checkpoint manager for bounded-replay crash recovery.
    ///
    /// When set, the runtime creates a checkpoint after each
    /// quorum-confirmed epoch advancement so that on restart only
    /// post-checkpoint transition journal entries need replaying.
    pub checkpoint_mgr: Option<CheckpointManager>,
    /// Roster-scoped capability view for placement and transport selection.
    ///
    /// Populated from join-request peer capabilities and CapabilityUpdate
    /// messages. Placement planners and transport carrier selection query
    /// this view for per-peer operational capabilities.
    pub capability_view: Arc<Mutex<MembershipCapabilityView>>,
    bootstrapping: bool,
    /// Whether the transition journal should be replayed in the next tick.
    journal_needs_replay: bool,
    /// Peer-side departure initiator for voluntary coordinated departure.
    pub departure_initiator: Option<DepartureInitiator>,
    /// Tracks whether we held the coordinator role in the previous tick,
    /// so we can increment incarnation on coordinator promotion.
    had_coordinator_role: bool,
}

/// Error returned by [`MembershipRuntime::apply_roster_snapshot`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotError {
    /// The provided message is not a RosterSnapshot variant.
    NotASnapshot,
    /// The snapshot epoch is older than the local committed epoch.
    StaleEpoch {
        snapshot_epoch: EpochId,
        local_epoch: EpochId,
    },
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotASnapshot => write!(f, "message is not a roster snapshot"),
            Self::StaleEpoch {
                snapshot_epoch,
                local_epoch,
            } => {
                write!(
                    f,
                    "stale snapshot epoch {snapshot_epoch:?} < local epoch {local_epoch:?}",
                )
            }
        }
    }
}

impl std::error::Error for SnapshotError {}

pub struct PendingTransition {
    pub proposal_id: u64,
    pub proposal: EpochTransitionProposal,
    pub my_accept: Option<EpochTransitionAccept>,
    pub accepts_received: usize,
    pub required_accepts: usize,
}

/// Result of applying a peer-advertised placement version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerPlacementVersionObservation {
    pub peer: MemberId,
    pub advertised_version: u64,
    pub previous_version: Option<u64>,
    pub recorded_version: Option<u64>,
    pub accepted: bool,
}

/// Snapshot of local placement-version convergence against observed peers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlacementVersionConvergence {
    pub local_version: u64,
    pub max_peer_version: u64,
    pub peer_versions: BTreeMap<MemberId, u64>,
    pub peers_ahead: Vec<MemberId>,
    pub peers_behind: Vec<MemberId>,
}

impl PlacementVersionConvergence {
    #[must_use]
    pub fn local_is_stale(&self) -> bool {
        self.max_peer_version > self.local_version
    }

    #[must_use]
    pub fn all_observed_peers_converged(&self) -> bool {
        !self.local_is_stale() && self.peers_behind.is_empty()
    }
}

impl MembershipRuntime {
    /// Create a new membership runtime.
    pub fn new(
        config: MembershipConfig,
        my_id: MemberId,
        my_member_class: MemberClass,
        my_failure_domain: u64,
    ) -> Self {
        let mut csprng = OsRng;
        let signing_key = Keypair::generate(&mut csprng);
        let verifying_key = signing_key.public;

        let epoch_engine = EpochTransitionEngine::new(EpochId::new(1));
        let mut detector = FailureDetector::new(config.clone(), Keypair::generate(&mut csprng));

        // Register self
        detector.register_peer(my_id, my_member_class, my_failure_domain, EpochId::new(1));

        let mut verifying_keys = BTreeMap::new();
        verifying_keys.insert(my_id, verifying_key);

        let mut slf = Self {
            config,
            detector,
            epoch_engine,
            my_id,
            signing_key,
            verifying_keys,
            pending_transition: None,
            transition_callbacks: Vec::new(),
            tick_count: 0,
            fencing: FencingWatchdog::new(),
            placement_version: 0,
            peer_placement_versions: BTreeMap::new(),
            epoch_fence: None,
            bootstrapping: true,
            event_publisher: MembershipEventPublisher::new(),
            roster: MembershipRoster::new(),
            peer_manager: None,
            epoch_coordinator: None,
            send_dispatcher: None,
            peer_address_registry: None,
            send_gate: Some(Arc::new(MembershipSendGate::new(Arc::new(
                std::sync::RwLock::new(std::collections::BTreeSet::new()),
            )))),
            gossip_batcher: GossipBatcher::new(
                GossipBatcherConfig::default(),
                Box::new(now_millis),
                my_id,
            ),
            heartbeat_tx: HeartbeatTransmitter::new(HeartbeatConfig::default(), my_id),
            heartbeat_tracker: PeerLivenessTracker::new(HeartbeatConfig::default()),
            unreachable_tracker: PeerUnreachableTracker::new(PeerUnreachableConfig::default()),
            transition_journal: Arc::new(Mutex::new(MembershipTransitionJournal::new())),
            coordinator_lease: CoordinatorLease::new(
                crate::coordinator_lease::CoordinatorLeaseConfig::default(),
                my_id,
            ),
            peer_health: PeerHealthTracker::new(PeerHealthConfig::default()),
            incarnation_tracker: IncarnationTracker::genesis(),
            join_handler: JoinHandler::new(
                my_id,
                false,
                vec![my_id],
                RosterConstraints::default(),
                IncarnationTracker::genesis(),
            ),
            proposal_commit_pipeline: ProposalCommitPipeline::with_defaults(
                Arc::new(ProposalSequencer::new()),
                IncarnationTracker::genesis(),
                my_id,
            ),
            checkpoint_mgr: None,
            capability_view: Arc::new(Mutex::new(MembershipCapabilityView::new())),
            journal_needs_replay: true,
            departure_initiator: None,
            had_coordinator_role: false,
        };
        // Register self in the roster so consumers always see the local node.
        slf.roster.add_member(my_id);
        slf.heartbeat_tracker.register_peer(my_id);
        slf.unreachable_tracker.register_peer(my_id, 0);
        slf
    }

    /// Set the transport peer manager for membership-driven session lifecycle.
    pub fn set_peer_manager(&mut self, pm: peer_manager::PeerManagerHandle) {
        self.peer_manager = Some(pm);
    }

    /// Set the transport send dispatcher for outbound membership messages.
    ///
    /// Once set, [`add_peer`] will broadcast [`PeerJoined`] notifications
    /// to all connected cluster members via the [`RosterNotifier`].
    pub fn set_send_dispatcher(&mut self, sd: Arc<SendDispatcher>) {
        self.send_dispatcher = Some(sd);
    }

    /// Set the peer address registry shared with roster sync.
    ///
    /// The registry is used when building outgoing roster snapshots
    /// to resolve transport addresses for each member, and when applying
    /// incoming snapshots to populate address entries for known peers.
    pub fn set_peer_address_registry(&mut self, reg: Arc<PeerAddressRegistry>) {
        self.peer_address_registry = Some(reg);
    }

    /// Set the checkpoint store for bounded-replay crash recovery.
    ///
    /// After this call, the runtime creates a membership epoch checkpoint
    /// on every quorum-confirmed epoch advancement so that on restart only
    /// post-checkpoint transition journal entries need replaying.
    pub fn set_checkpoint_store(&mut self, store: Box<dyn EpochSnapshotStore>) {
        self.checkpoint_mgr = Some(CheckpointManager::new(store));
    }

    /// Load membership state from a checkpoint store and transition journal.
    ///
    /// On restart, this constructor loads the latest epoch checkpoint and
    /// replays committed transition journal entries after the checkpoint
    /// epoch, seeding the runtime with the reconstructed roster, epoch,
    /// and incarnation.  The checkpoint store is retained for ongoing
    /// checkpoint creation on future epoch advancements.
    ///
    /// When no checkpoint exists (first start) and the journal is empty,
    /// the runtime starts from epoch 1 with only the local node registered.
    pub fn load_from_checkpoint_store(
        store: Box<dyn EpochSnapshotStore>,
        journal: MembershipTransitionJournal,
        config: MembershipConfig,
        my_id: MemberId,
        my_member_class: MemberClass,
        my_failure_domain: u64,
    ) -> Self {
        let mut csprng = OsRng;
        let signing_key = Keypair::generate(&mut csprng);
        let verifying_key = signing_key.public;

        let mut verifying_keys = BTreeMap::new();
        verifying_keys.insert(my_id, verifying_key);

        let checkpoint_mgr = CheckpointManager::new(store);

        // Load the latest checkpoint snapshot to recover per-member transport
        // addresses. These are registered in the peer address registry so
        // outbound dispatch and transport session establishment can resolve
        // peer endpoints immediately after restart.
        let loaded_snapshot: Option<tidefs_membership_epoch::snapshot::MembershipEpochSnapshot> =
            checkpoint_mgr.latest_checkpoint().ok().flatten();

        let address_registry = {
            let reg = PeerAddressRegistry::new();
            if let Some(ref snap) = loaded_snapshot {
                for (member_id, transport_addr) in &snap.roster {
                    // Convert the checkpoint's TransportAddress string to a
                    // TransportAddr by prepending the TCP scheme.  Addresses
                    // in the snapshot are host:port pairs; the transport
                    // layer expects URI-form addresses.
                    let uri = format!("tcp://{}", transport_addr.address);
                    if let Ok(addr) = uri.parse::<TransportAddr>() {
                        reg.register(*member_id, vec![addr]);
                    }
                }
            }
            reg
        };

        // Try to recover the roster from the latest checkpoint + journal.
        let recovered =
            tidefs_membership_epoch::snapshot::recover_roster(checkpoint_mgr.store(), &journal);

        let (start_epoch, start_members, start_incarnation) = match recovered {
            Ok(rr) => (rr.epoch, rr.member_ids, rr.incarnation),
            Err(tidefs_membership_epoch::snapshot::EpochSnapshotError::NoState) => {
                // Genesis: no snapshot and empty journal.
                (EpochId::new(1), vec![my_id], Incarnation::ZERO)
            }
            Err(_e) => {
                // Storage or decode error: fall back to genesis.
                (EpochId::new(1), vec![my_id], Incarnation::ZERO)
            }
        };

        let epoch_engine = EpochTransitionEngine::new(start_epoch);
        let mut detector = FailureDetector::new(config.clone(), Keypair::generate(&mut csprng));

        // Register all recovered members in the failure detector.
        for &mid in &start_members {
            detector.register_peer(mid, my_member_class, my_failure_domain, start_epoch);
        }

        let mut slf = Self {
            config,
            detector,
            epoch_engine,
            my_id,
            signing_key,
            verifying_keys,
            pending_transition: None,
            transition_callbacks: Vec::new(),
            tick_count: 0,
            fencing: FencingWatchdog::new(),
            placement_version: 0,
            peer_placement_versions: BTreeMap::new(),
            epoch_fence: None,
            bootstrapping: start_members.len() <= 1,
            event_publisher: MembershipEventPublisher::new(),
            roster: MembershipRoster::new(),
            peer_manager: None,
            epoch_coordinator: None,
            send_dispatcher: None,
            peer_address_registry: Some(Arc::new(address_registry)),
            send_gate: Some(Arc::new(MembershipSendGate::new(Arc::new(
                std::sync::RwLock::new(std::collections::BTreeSet::new()),
            )))),
            gossip_batcher: GossipBatcher::new(
                GossipBatcherConfig::default(),
                Box::new(now_millis),
                my_id,
            ),
            heartbeat_tx: HeartbeatTransmitter::new(HeartbeatConfig::default(), my_id),
            heartbeat_tracker: PeerLivenessTracker::new(HeartbeatConfig::default()),
            unreachable_tracker: PeerUnreachableTracker::new(PeerUnreachableConfig::default()),
            transition_journal: Arc::new(Mutex::new(journal)),
            coordinator_lease: CoordinatorLease::new(
                crate::coordinator_lease::CoordinatorLeaseConfig::default(),
                my_id,
            ),
            peer_health: PeerHealthTracker::new(PeerHealthConfig::default()),
            incarnation_tracker: IncarnationTracker::new(start_incarnation),
            join_handler: JoinHandler::new(
                my_id,
                false,
                start_members.clone(),
                RosterConstraints::default(),
                IncarnationTracker::new(start_incarnation),
            ),
            proposal_commit_pipeline: ProposalCommitPipeline::with_defaults(
                Arc::new(ProposalSequencer::new()),
                IncarnationTracker::new(start_incarnation),
                my_id,
            ),
            checkpoint_mgr: Some(checkpoint_mgr),
            capability_view: Arc::new(Mutex::new(MembershipCapabilityView::new())),
            journal_needs_replay: false,
            departure_initiator: None,
            had_coordinator_role: false,
        };

        // Populate the roster with recovered members.
        for &mid in &start_members {
            slf.roster.add_member(mid);
            slf.heartbeat_tracker.register_peer(mid);
            slf.unreachable_tracker.register_peer(mid, 0);
        }

        slf
    }

    /// Initiate a voluntary coordinated departure for this peer.
    ///
    /// Creates a [`DepartureInitiator`] state machine and returns the
    /// [`MembershipOutboundMessage::DepartureRequest`] to send to the
    /// coordinator. The departure proceeds through the initiator state
    /// machine as responses and epoch advances arrive via
    /// [`handle_departure_response`].
    ///
    /// Panics if a departure initiator is already active.
    #[must_use]
    pub fn initiate_departure(
        &mut self,
        reason: tidefs_membership_types::departure::DepartureReason,
        _now_millis: u64,
    ) -> MembershipOutboundMessage {
        assert!(
            self.departure_initiator.is_none(),
            "departure already in progress"
        );
        let request_epoch = self.epoch_engine.current_epoch().0;
        let nonce = self.tick_count;
        let config = DepartureInitiatorConfig::default();
        let initiator = DepartureInitiator::initiate(self.my_id.0, request_epoch, nonce, config);
        let msg = MembershipOutboundMessage::DepartureRequest {
            peer_id: self.my_id.0,
            reason,
            request_epoch,
            nonce,
        };
        self.departure_initiator = Some(initiator);
        msg
    }

    /// Handle an inbound departure response from the coordinator.
    ///
    /// Routes the response to the active [`DepartureInitiator`] state
    /// machine. Returns `true` if the departure has reached a terminal
    /// state (committed or aborted).
    pub fn handle_departure_response(&mut self, response: &DepartureResponse) -> bool {
        let initiator = match self.departure_initiator.as_mut() {
            Some(init) => init,
            None => return false,
        };
        if initiator.on_response(response).is_ok() && initiator.is_terminal() {
            return true;
        }
        initiator.is_terminal()
    }

    /// Wire the eviction executor into the live membership runtime.
    ///
    /// Constructs an [`EpochAdvanceCoordinator`] initialized with the current
    /// member set from the roster, builds an [`EvictionExecutor`] with the
    /// supplied transport-level resources (`connection_registry`,
    /// `session_bindings`, `callback`), and registers it as a subscriber.
    ///
    /// After this call, committed epoch removals of dead peers
    /// automatically trigger transport connection teardown and session
    /// cleanup through the [`EvictionCallback`].
    ///
    /// Call this once during startup, after initial peers have been
    /// registered and transport resources are available.
    pub fn wire_eviction_executor(
        &mut self,
        connection_registry: Arc<ConnectionRegistry>,
        session_bindings: Arc<Mutex<SessionBindingTable>>,
        callback: EvictionCallback,
    ) {
        // Collect current members from the roster for coordinator initialization.
        let members: Vec<MemberId> = self.roster.snapshot().iter().map(|(id, _)| *id).collect();

        let mut coordinator = EpochAdvanceCoordinator::new(1);
        let now = now_millis();
        coordinator.initialize(members.clone(), now);

        let initial_roster: BTreeSet<MemberId> = members.into_iter().collect();
        let executor = EvictionExecutor::new(
            session_bindings,
            connection_registry,
            callback,
            initial_roster,
        );

        coordinator.subscribe(Box::new(executor));

        // Subscribe the outbound send gate so it stays current on every
        // epoch change, rejecting sends to departed peers at the transport
        // level without manual roster maintenance.
        if let Some(ref gate) = self.send_gate {
            struct SendGateSubscriber {
                gate: Arc<MembershipSendGate>,
            }
            impl EpochCommitSubscriber for SendGateSubscriber {
                fn on_epoch_committed(&self, view: &EpochView) {
                    self.gate.on_epoch_committed(view);
                }
            }
            coordinator.subscribe(Box::new(SendGateSubscriber {
                gate: Arc::clone(gate),
            }));
        }

        self.epoch_coordinator = Some(coordinator);
    }

    /// Return a clone of the outbound send gate for attachment to a
    /// Transport or MembershipTransport.
    ///
    /// The gate is kept current via EpochCommitSubscriber registration
    /// in wire_eviction_executor. Callers call
    /// Transport::set_send_gate(Some(gate)) to enable roster-gated sends.
    #[must_use]
    pub fn send_gate(&self) -> Option<Arc<MembershipSendGate>> {
        self.send_gate.clone()
    }

    /// Whether the eviction executor has been wired into this runtime.
    ///
    /// Returns `true` after [`wire_eviction_executor`] has been called.
    #[must_use]
    pub fn has_eviction_wired(&self) -> bool {
        self.epoch_coordinator.is_some()
    }

    /// Wire the membership transport bridge so that roster additions
    /// trigger proactive transport session establishment and roster
    /// removals trigger session teardown.
    ///
    /// Creates a TransportBridgeManager wrapping the given transport,
    /// constructs a MembershipTransportBridge subscribed to the epoch
    /// coordinator, and sets the initial member set from the current
    /// roster. If the epoch coordinator has not been created yet (e.g.
    /// called before wire_eviction_executor), one is created now.
    ///
    /// Call this once during startup, after initial peers have been
    /// registered and the transport is bound.
    pub fn wire_membership_transport_bridge(
        &mut self,
        transport: Arc<Mutex<Transport>>,
        address_registry: Arc<tidefs_transport::peer_address_registry::PeerAddressRegistry>,
    ) {
        let initial_members: BTreeSet<MemberId> =
            self.roster.snapshot().iter().map(|(id, _)| *id).collect();

        let coordinator = self.epoch_coordinator.get_or_insert_with(|| {
            let mut coord = EpochAdvanceCoordinator::new(1);
            let members: Vec<MemberId> = initial_members.iter().copied().collect();
            coord.initialize(members, now_millis());
            coord
        });

        let manager = Box::new(TransportBridgeManager::new(transport));
        let bridge = MembershipTransportBridge::new(manager, address_registry);
        bridge.set_initial_member_set(&initial_members);

        coordinator.subscribe(Box::new(bridge));
    }

    /// Register a verification key for a member.
    pub fn register_key(&mut self, member_id: MemberId, key: PublicKey) {
        self.verifying_keys.insert(member_id, key);
    }

    /// Register a peer from bootstrap or join.
    pub fn add_peer(
        &mut self,
        member_id: MemberId,
        member_class: MemberClass,
        failure_domain: u64,
    ) {
        let epoch = self.epoch_engine.current_epoch();
        self.detector
            .register_peer(member_id, member_class, failure_domain, epoch);
        // Register with the fencing watchdog for liveness tracking
        self.fencing.record_healthy(member_id, now_millis());
        // Publish MemberJoined event for new peers (skip self)
        if member_id != self.my_id {
            let incarnation = self.epoch_engine.current_epoch().0;
            let event = MembershipEvent::member_joined(member_id, incarnation);
            self.event_publisher.publish(&event);
            // Update roster: remove-and-re-add for any existing member that is
            // not Active (Left, Suspected, Failed) so they re-enter as Active.
            // New members (None) and already-Active members are idempotent.
            if let Some(state) = self.roster.lookup(member_id) {
                if state != RosterState::Active {
                    self.roster.remove_member(member_id);
                }
            }
            self.roster.add_member(member_id);
            self.heartbeat_tracker.register_peer(member_id);
            self.unreachable_tracker
                .register_peer(member_id, now_millis());
        }
        // Notify peer manager of joined node
        if let Some(ref pm) = self.peer_manager {
            let _ =
                pm.lock()
                    .unwrap()
                    .on_membership_event(peer_manager::MembershipEvent::NodeJoined {
                        node_id: member_id.0,
                    });
        }
        // Notify epoch advance coordinator of new live peer (if wired).
        if let Some(ref mut coord) = self.epoch_coordinator {
            let change = PeerLivenessChange::new(
                member_id,
                PeerLivenessStatus::Dead,
                PeerLivenessStatus::Alive,
                now_millis(),
            );
            let _ = coord.on_liveness_change(change);
        }
        // Broadcast peer-joined notification to all active connected members.
        if let Some(ref sd) = self.send_dispatcher {
            let dispatch = MembershipOutboundDispatch::new(sd, &self.roster);
            let notifier = RosterNotifier::new(&dispatch, &self.roster);
            let roster_epoch = self.epoch_engine.current_epoch();
            let result = notifier.notify_peer_joined(member_id, roster_epoch);
            // Partial failures are expected (unreachable peers); log if
            // no peer received the notification.
            if result.all_failed() {
                // All sends failed: the joining peer may be the only
                // active member, or the transport layer is down.
                // This is not an error — the roster already tracks the peer.
            }

            // Send join-response to the joining peer so they learn their assigned
            // MemberId and current epoch, completing the join handshake.
            let join_dispatcher = JoinResponseDispatcher::new(&dispatch);
            let _ = join_dispatcher.send_acceptance(
                member_id,
                roster_epoch,
                self.incarnation_tracker.current(),
            );
        }
        self.maybe_send_roster_snapshot(member_id);
    }

    /// Register a joining peer (Learner class).
    pub fn add_joining_peer(&mut self, member_id: MemberId, failure_domain: u64) {
        self.add_peer(member_id, MemberClass::Learner, failure_domain);
        self.detector.mark_joining(member_id);
    }

    /// Apply an incoming roster snapshot received from an existing member.
    ///
    /// Populates the local roster and peer address registry from the
    /// snapshot data so the joining peer can participate in membership
    /// decisions immediately without external bootstrap.
    ///
    /// # Edge cases
    ///
    /// - **Stale snapshots**: Snapshots with an epoch older than the local
    ///   committed epoch are rejected to prevent regression.
    /// - **Duplicate application**: Re-applying the same snapshot is
    ///   idempotent: existing members are not re-added and addresses are
    ///   merged.
    /// - **Self in snapshot**: The local member id is skipped during
    ///   roster merge since it is already registered at bootstrap.
    pub fn apply_roster_snapshot(
        &mut self,
        snapshot: &crate::dispatch_router::MembershipMessage,
    ) -> Result<(), SnapshotError> {
        let (_originator, roster_epoch, entries) = match snapshot {
            crate::dispatch_router::MembershipMessage::RosterSnapshot {
                originator,
                roster_epoch,
                entries,
            } => (*originator, *roster_epoch, entries),
            _ => {
                return Err(SnapshotError::NotASnapshot);
            }
        };

        // Reject stale snapshots.
        let local_epoch = self.epoch_engine.current_epoch();
        if roster_epoch < local_epoch {
            return Err(SnapshotError::StaleEpoch {
                snapshot_epoch: roster_epoch,
                local_epoch,
            });
        }

        // Merge each entry into the local state.
        for entry in entries {
            let member_id = entry.member_id;

            // Skip self — already registered at bootstrap.
            if member_id == self.my_id {
                continue;
            }

            // Add to roster (idempotent: re-adds non-Active members).
            let existing = self.roster.lookup(member_id);
            if let Some(state) = existing {
                if state != entry.state() {
                    let _ = self.roster.transition_state(member_id, entry.state());
                }
                // Already-Active members stay; non-Active get re-added.
                if state != crate::roster::RosterState::Active
                    && entry.state() == crate::roster::RosterState::Active
                {
                    self.roster.remove_member(member_id);
                    self.roster.add_member(member_id);
                }
            } else {
                self.roster.add_member(member_id);
            }

            // Populate peer address registry.
            if let Some(ref reg) = self.peer_address_registry {
                let addrs = entry.parsed_addresses();
                if !addrs.is_empty() {
                    reg.register(member_id, addrs);
                }
            }

            // Register in heartbeat tracker for liveness.
            self.heartbeat_tracker.register_peer(member_id);

            // Populate capability view from roster entry capabilities.
            if let Some(ref caps) = entry.capabilities {
                let mut view = self
                    .capability_view
                    .lock()
                    .expect("capability view lock poisoned");
                view.insert(member_id, caps.clone());
            }
        }

        Ok(())
    }

    /// Send a roster snapshot to a newly joined peer.
    ///
    /// Called after the peer-join notification broadcast so the joining
    /// peer receives the full current roster state.
    pub fn send_roster_snapshot_to_joiner(
        &self,
        joining_peer_id: MemberId,
    ) -> Result<(), crate::membership_outbound_dispatch::OutboundDispatchError> {
        let sd = match &self.send_dispatcher {
            Some(sd) => sd,
            None => return Ok(()),
        };
        let reg = match &self.peer_address_registry {
            Some(reg) => reg,
            None => return Ok(()),
        };

        let dispatch = MembershipOutboundDispatch::new(sd, &self.roster);
        let sync = RosterStateSync::new(&dispatch, &self.roster, reg, self.my_id);
        let roster_epoch = self.epoch_engine.current_epoch();
        sync.on_peer_joined(joining_peer_id, roster_epoch)
    }

    /// Wire the roster snapshot send into the add_peer path for foreign peers.
    ///
    /// Called automatically by [`add_peer`] when a foreign peer joins and
    /// both the send dispatcher and address registry are available.
    fn maybe_send_roster_snapshot(&self, joining_peer_id: MemberId) {
        if joining_peer_id == self.my_id {
            return;
        }
        if self.send_dispatcher.is_none() || self.peer_address_registry.is_none() {
            return;
        }
        let _ = self.send_roster_snapshot_to_joiner(joining_peer_id);
    }

    /// Notify the unreachable tracker that a transport session has been
    /// established for the given peer.
    ///
    /// Called from the [`RosterSessionHandle`] bridge when the transport
    /// layer reports a session as ready.
    pub fn notify_session_connected(&mut self, peer_id: MemberId) {
        self.unreachable_tracker
            .on_session_connected(peer_id, now_millis());
    }

    /// Notify the unreachable tracker that a transport session has been
    /// lost for the given peer.
    ///
    /// Called from the [`RosterSessionHandle`] bridge when the transport
    /// layer reports a session as lost.
    pub fn notify_session_disconnected(&mut self, peer_id: MemberId) {
        self.unreachable_tracker
            .on_session_disconnected(peer_id, now_millis());
    }

    /// Record a received HealthReport heartbeat from a peer.
    /// Resets the peer's deadline timer in the heartbeat tracker.
    pub fn receive_health_report(&mut self, member_id: MemberId) {
        self.heartbeat_tracker.record_heartbeat(member_id);
        self.peer_health.on_heartbeat_response(member_id);
    }

    /// Register a callback for epoch transitions.
    pub fn on_transition<F: Fn(&AppliedTransition) + Send + 'static>(&mut self, callback: F) {
        self.transition_callbacks.push(Box::new(callback));
    }

    /// Tick the peer health tracker: synchronise with the current roster,
    /// feed heartbeat liveness data from the heartbeat tracker, advance the
    /// Healthy→Suspect→Failed state machine, and initiate epoch transitions
    /// for peers that have newly reached Failed status.
    ///
    /// Called from [`tick`] after the heartbeat liveness step.
    fn tick_health(
        &mut self,
        now: u64,
        active_members: &[MemberId],
        coordinator_id: Option<MemberId>,
    ) {
        // Synchronise tracked peers with the current roster.
        self.peer_health.sync_roster(active_members, self.my_id);

        // Feed heartbeat liveness status into the peer health tracker.
        for &member_id in active_members {
            if member_id == self.my_id {
                continue;
            }
            match self.heartbeat_tracker.status(member_id) {
                Some(LivenessStatus::Alive) => {
                    self.peer_health.on_heartbeat_response(member_id);
                }
                Some(LivenessStatus::Suspected) | Some(LivenessStatus::Failed) => {
                    self.peer_health.on_heartbeat_miss(member_id);
                }
                None => {
                    self.peer_health.on_heartbeat_miss(member_id);
                }
            }
        }

        // Advance the state machine and collect eviction candidates.
        let eviction_candidates = self
            .peer_health
            .tick(now, coordinator_id, active_members.len());

        // For each eviction candidate, initiate an epoch transition
        // through the existing quorum-confirmed roster change path.
        for peer_id in &eviction_candidates {
            if self.pending_transition.is_some() {
                break;
            }
            self.initiate_epoch_transition(
                vec![],
                vec![*peer_id],
                TransitionReason::FailureDetected,
                vec![],
                None,
            );
        }
    }

    pub fn tick(&mut self) -> RuntimeTickResult {
        self.tick_count += 1;
        let now = now_millis();

        let mut result = RuntimeTickResult::default();

        // Replay transition journal if we are the coordinator and
        // it has not been replayed yet since promotion.
        if self.journal_needs_replay && self.send_dispatcher.is_some() {
            let members: Vec<tidefs_membership_epoch::MemberId> = self
                .roster
                .snapshot()
                .iter()
                .filter(|(_, state)| *state == RosterState::Active)
                .map(|(id, _)| *id)
                .collect();
            let is_coordinator = members
                .iter()
                .min()
                .copied()
                .map(|c| c == self.my_id)
                .unwrap_or(false);
            if is_coordinator {
                // Increment incarnation on first detection of coordinator role
                // (promotion). This closes the split-brain window where a
                // deposed coordinator could issue stale commands.
                if !self.had_coordinator_role {
                    self.incarnation_tracker.increment();
                }
                self.had_coordinator_role = true;
                self.replay_transition_journal();
                // Activate coordinator lease on promotion if not already active.
                if !self.coordinator_lease.is_active() {
                    self.coordinator_lease.activate();
                }
            } else {
                self.had_coordinator_role = false;
                self.journal_needs_replay = false;
                // Deactivate lease if we're no longer coordinator.
                if self.coordinator_lease.is_active() {
                    self.coordinator_lease.deactivate();
                }
            }
        }

        // Sync JoinHandler state from current runtime state (#6244).
        {
            let active_members: Vec<MemberId> = self
                .roster
                .snapshot()
                .iter()
                .filter(|(_, state)| *state == RosterState::Active)
                .map(|(id, _)| *id)
                .collect();
            let is_coordinator = active_members
                .iter()
                .min()
                .copied()
                .map(|c| c == self.my_id)
                .unwrap_or(false);
            self.join_handler.set_coordinator(is_coordinator);
            self.join_handler.set_roster(active_members);
            self.join_handler
                .set_incarnation_tracker(self.incarnation_tracker.clone());
        }

        // Coordinator lease tick: if active, send heartbeats and evaluate quorum.
        if self.coordinator_lease.is_active() {
            let roster_members: Vec<MemberId> = self
                .roster
                .snapshot()
                .iter()
                .filter(|(_, state)| *state == RosterState::Active)
                .map(|(id, _)| *id)
                .collect();
            let (requests, status) = self.coordinator_lease.tick(now, &roster_members);
            result.coordinator_heartbeat_requests = requests.clone();
            // Convert heartbeat requests to outbound messages for transport dispatch.
            let epoch = self.epoch_engine.current_epoch();
            for req in &requests {
                result.heartbeat_outbound.push((
                    req.target_member_id,
                    MembershipOutboundMessage::CoordinatorHeartbeat {
                        epoch,
                        coordinator_id: req.coordinator_id,
                        lease_nonce: req.nonce,
                    },
                ));
            }
            if status == LeaseStatus::Lost {
                result.coordinator_lease_lost = true;
                self.coordinator_lease.deactivate();
            }
        }

        // 1. Send pings
        let pings = self
            .detector
            .tick_pings(self.my_id, &self.signing_key, &self.verifying_keys);
        result.pings_sent = pings.len();
        result.outbound_pings = pings;

        // 1b. Transmit heartbeat HealthReport messages to all known peers
        let peer_ids: Vec<MemberId> = self
            .roster
            .snapshot()
            .iter()
            .filter(|(_, state)| *state == RosterState::Active)
            .map(|(id, _)| *id)
            .collect();
        let heartbeat_msgs = self.heartbeat_tx.tick(&peer_ids, now);
        result.heartbeat_outbound.extend(heartbeat_msgs);

        // 2. Check timeouts → suspicions
        let mut new_suspicions = self.detector.tick_timeouts();
        // 2b. Check relay timeouts → additional suspicions
        let relay_suspicions = self.detector.tick_relay_timeouts();
        new_suspicions.extend(relay_suspicions);
        result.new_suspicions = new_suspicions.len();
        // 2c. Tick suspicion accumulator: apply validation decay and drain events.
        let acc_events = self.detector.tick_accumulator();
        result.accumulator_events = acc_events.len();

        // 2d. Convert accumulator events to gossip updates and enqueue.
        for event in &acc_events {
            match event {
                SuspicionEvent::MemberSuspected { member, .. } => {
                    let record = SuspicionRecord::new(
                        *member,
                        self.my_id,
                        now,
                        SuspicionSource::DirectTimeout,
                    );
                    self.gossip_batcher
                        .enqueue(*member, GossipUpdate::SuspicionChange(record));
                }
                SuspicionEvent::MemberFailed { member, .. } => {
                    let record = SuspicionRecord::new(
                        *member,
                        self.my_id,
                        now,
                        SuspicionSource::IndirectAllTimeout,
                    );
                    self.gossip_batcher
                        .enqueue(*member, GossipUpdate::SuspicionChange(record));
                }
                SuspicionEvent::SuspicionCleared { member } => {
                    let delta = MembershipDelta {
                        member_id: *member,
                        kind: MembershipDeltaKind::Cleared,
                    };
                    self.gossip_batcher
                        .enqueue(*member, GossipUpdate::MembershipDelta(delta));
                }
            }
        }
        // 2e. Flush gossip batches periodically (every tick for now).
        let (flushed, _dropped) = self.gossip_batcher.flush();
        result.gossip_batches_flushed = flushed.len();

        // Publish MemberSuspected events
        let epoch_u64 = self.epoch_engine.current_epoch().0;
        for suspicion in &new_suspicions {
            let event = MembershipEvent::member_suspected(suspicion.subject, epoch_u64);
            self.event_publisher.publish(&event);
            // Update roster: transition to Suspected (ignore errors for non-existent members)
            let _ = self
                .roster
                .transition_state(suspicion.subject, RosterState::Suspected);
        }

        // 2.5 Forced fencing watchdog: check for nodes unresponsive beyond
        // fence_timeout_ms and trigger forced fencing + epoch transition.
        if self.pending_transition.is_none() {
            let peers: Vec<(MemberId, HealthClass, u64)> = self
                .detector
                .all_peers()
                .map(|p| (p.member_id, p.health, p.last_ack_millis))
                .filter(|(id, _, _)| *id != self.my_id)
                .collect();

            let current_epoch = self.epoch_engine.current_epoch().0;
            let action = self.fencing.tick(&peers, now, current_epoch);

            if let FencingAction::FenceNode {
                node_id,
                fence_token,
                trigger: _trigger,
            } = action
            {
                // Build validation from the failure detector
                let validation: Vec<SuspicionRecord> = self
                    .detector
                    .emitted_suspicions
                    .iter()
                    .filter(|s| s.subject == node_id)
                    .copied()
                    .collect();

                self.initiate_epoch_transition(
                    vec![],
                    vec![node_id],
                    TransitionReason::FailureDetected,
                    validation,
                    Some(fence_token),
                );
                // Notify peer manager of failed node (fencing path)
                if let Some(ref pm) = self.peer_manager {
                    let _ = pm.lock().unwrap().on_membership_event(
                        peer_manager::MembershipEvent::NodeFailed { node_id: node_id.0 },
                    );
                }
                result.epoch_transition_initiated = true;
                self.epoch_engine.cancel_proposals_from_fenced_peer(node_id);
            }
        }

        // 3. Handle pending transition
        if let Some(ref pending) = self.pending_transition {
            // Check if we've received enough accepts to commit
            if pending.accepts_received >= pending.required_accepts {
                // If we're the proposer, commit
                if pending.proposal.proposer == self.my_id {
                    if let Ok(commit) = self
                        .epoch_engine
                        .commit(pending.proposal_id, &self.signing_key)
                    {
                        let applied = AppliedTransition {
                            from_epoch: pending.proposal.from_epoch,
                            to_epoch: commit.new_epoch,
                            reason: pending.proposal.reason,
                            members_added: pending.proposal.members_added.clone(),
                            members_removed: pending.proposal.members_removed.clone(),
                            committed_at_millis: commit.committed_at_millis,
                        };
                        result.epoch_transitioned = true;
                        result.new_epoch = Some(commit.new_epoch);
                        self.fire_transition_callbacks(&applied);
                        self.pending_transition = None;
                    }
                }
            }
        }

        // 4. Check for dead members that haven't triggered a transition yet
        if self.pending_transition.is_none() {
            let dead_members: Vec<MemberId> = self
                .detector
                .all_peers()
                .filter(|p| p.health == HealthClass::Down && p.is_voter())
                .map(|p| p.member_id)
                .collect();

            if !dead_members.is_empty() {
                let is_member_dead_recently = |m: &MemberId| -> bool {
                    self.detector
                        .get_peer(*m)
                        .map(|p| {
                            p.suspect_since_millis > 0
                                && now.saturating_sub(p.suspect_since_millis)
                                    < self.config.suspicion_window_ms * 2
                        })
                        .unwrap_or(false)
                };

                let recent_dead: Vec<MemberId> = dead_members
                    .into_iter()
                    .filter(is_member_dead_recently)
                    .collect();

                if !recent_dead.is_empty() {
                    let validation: Vec<SuspicionRecord> = self
                        .detector
                        .emitted_suspicions
                        .iter()
                        .filter(|s| recent_dead.contains(&s.subject))
                        .copied()
                        .collect();

                    if !validation.is_empty() {
                        self.initiate_epoch_transition(
                            vec![],
                            recent_dead.clone(),
                            TransitionReason::FailureDetected,
                            validation,
                            None,
                        );
                        result.epoch_transition_initiated = true;
                    }
                }
            }
        }

        // 5. Done bootstrapping once we've ticked a few times
        // Publish MemberFailed events for all down peers
        {
            let epoch_u64 = self.epoch_engine.current_epoch().0;
            let down_members: Vec<MemberId> = self
                .detector
                .all_peers()
                .filter(|p| p.health == HealthClass::Down && p.member_id != self.my_id)
                .map(|p| p.member_id)
                .collect();
            for &member_id in &down_members {
                let event = MembershipEvent::member_failed(member_id, epoch_u64);
                self.event_publisher.publish(&event);
                // Notify peer manager of failed node
                if let Some(ref pm) = self.peer_manager {
                    let _ = pm.lock().unwrap().on_membership_event(
                        peer_manager::MembershipEvent::NodeFailed {
                            node_id: member_id.0,
                        },
                    );
                }
                // Update roster: transition to Failed
                let _ = self.roster.transition_state(member_id, RosterState::Failed);
            }
        }
        if self.bootstrapping && self.tick_count > 10 {
            self.bootstrapping = false;
        }

        // 5. Heartbeat liveness tracking: check deadlines, emit events
        let heartbeat_events = self.heartbeat_tracker.tick();
        for event in &heartbeat_events {
            self.event_publisher.publish(event);
        }

        // 5b. Session-disconnect-driven unreachability tracking: tick and
        //     feed PeerLivenessChange events into the epoch advance coordinator.
        {
            let now = now_millis();
            let unreachable_changes = self.unreachable_tracker.tick(now);
            if let Some(ref mut coord) = self.epoch_coordinator {
                for change in &unreachable_changes {
                    let _ = coord.on_liveness_change(change.clone());
                }
            }
            // Publish MemberFailed events for newly-unreachable peers.
            let epoch_u64 = self.epoch_engine.current_epoch().0;
            for change in &unreachable_changes {
                let event = MembershipEvent::member_failed(change.member_id, epoch_u64);
                self.event_publisher.publish(&event);
                // Notify peer manager of the unreachable node.
                if let Some(ref pm) = self.peer_manager {
                    let _ = pm.lock().unwrap().on_membership_event(
                        peer_manager::MembershipEvent::NodeFailed {
                            node_id: change.member_id.0,
                        },
                    );
                }
            }
        }
        // 6. Feed heartbeat-driven MemberFailed events into the epoch advance
        //    coordinator so the eviction executor triggers transport teardown.
        if let Some(ref mut coord) = self.epoch_coordinator {
            for event in &heartbeat_events {
                if let MembershipEvent::MemberFailed { member_id, .. } = event {
                    let change = PeerLivenessChange::new(
                        *member_id,
                        PeerLivenessStatus::Alive,
                        PeerLivenessStatus::Dead,
                        now,
                    );
                    let _ = coord.on_liveness_change(change);
                }
            }
        }

        // 7. Departure initiator cleanup: clear terminal-state initiators.
        if self
            .departure_initiator
            .as_ref()
            .is_some_and(|i| i.is_terminal())
        {
            self.departure_initiator = None;
        }

        // 8. Peer health tracking: advance the Healthy→Suspect→Failed state machine
        //    and initiate eviction proposals for newly-Failed peers.
        {
            let active_members: Vec<MemberId> = self
                .roster
                .snapshot()
                .iter()
                .filter(|(_, state)| *state == RosterState::Active)
                .map(|(id, _)| *id)
                .collect();
            let coordinator = active_members
                .iter()
                .min()
                .copied()
                .filter(|c| *c == self.my_id);
            self.tick_health(now, &active_members, coordinator);
        }

        result
    }

    /// Initiate an epoch transition (Phase 1: Propose).
    pub fn initiate_epoch_transition(
        &mut self,
        members_added: Vec<MemberId>,
        members_removed: Vec<MemberId>,
        reason: TransitionReason,
        validation: Vec<SuspicionRecord>,
        fence_token: Option<tidefs_node_drain::FenceToken>,
    ) {
        let proposal = self
            .epoch_engine
            .propose(EpochTransitionProposalRequest::new(
                self.my_id,
                members_added,
                members_removed,
                reason,
                validation,
                fence_token,
                &self.signing_key,
            ));

        let alive_voters = self.detector.alive_voters();
        let required = (alive_voters.len() / 2) + 1;

        // Auto-accept our own proposal
        if let Ok(accept) =
            self.epoch_engine
                .accept(&proposal, self.my_id, &alive_voters, &self.signing_key)
        {
            self.pending_transition = Some(PendingTransition {
                proposal_id: proposal.proposal_id,
                proposal,
                my_accept: Some(accept),
                accepts_received: 1,
                required_accepts: required,
            });
        } else {
            self.pending_transition = Some(PendingTransition {
                proposal_id: proposal.proposal_id,
                proposal,
                my_accept: None,
                accepts_received: 0,
                required_accepts: required,
            });
        }
    }

    /// Process an ack from another node.
    pub fn process_ack(&mut self, ack: &SwimAck) -> Result<AckResult, FailureDetectorError> {
        self.detector.process_ack(ack, &self.verifying_keys)
    }

    /// Receive and process an epoch transition proposal from another node.
    pub fn receive_proposal(
        &mut self,
        proposal: &EpochTransitionProposal,
    ) -> Result<(), TransitionError> {
        let alive = self.detector.alive_members();
        if let Some(ref fence) = self.epoch_fence {
            self.epoch_engine.validate_proposal_against_fence(
                proposal,
                &self.verifying_keys,
                &alive,
                &self.detector,
                fence,
            )?;
        } else {
            self.epoch_engine.validate_proposal(
                proposal,
                &self.verifying_keys,
                &alive,
                &self.detector,
            )?;
        }

        // Auto-accept if valid
        let alive_voters = self.detector.alive_voters();
        let accept =
            self.epoch_engine
                .accept(proposal, self.my_id, &alive_voters, &self.signing_key)?;

        // Track this as pending if we're not the proposer
        if proposal.proposer != self.my_id {
            let required = (alive_voters.len() / 2) + 1;
            self.pending_transition = Some(PendingTransition {
                proposal_id: proposal.proposal_id,
                proposal: proposal.clone(),
                my_accept: Some(accept),
                accepts_received: 1,
                required_accepts: required,
            });
        }

        Ok(())
    }

    /// Receive an accept for a pending proposal.
    pub fn receive_accept(
        &mut self,
        accept: EpochTransitionAccept,
    ) -> Result<AcceptanceStatus, TransitionError> {
        let status = self
            .epoch_engine
            .record_accept(accept, &self.verifying_keys)?;

        if let AcceptanceStatus::QuorumReached { .. } = &status {
            if let Some(ref mut pending) = self.pending_transition {
                pending.accepts_received = self.epoch_engine.accepts_count(pending.proposal_id);
            }
        }

        if let Some(ref mut pending) = self.pending_transition {
            match &status {
                AcceptanceStatus::Pending {
                    accepts_count,
                    required,
                } => {
                    pending.accepts_received = *accepts_count;
                    pending.required_accepts = *required;
                }
                AcceptanceStatus::QuorumReached {
                    accepts_count,
                    required,
                } => {
                    pending.accepts_received = *accepts_count;
                    pending.required_accepts = *required;
                }
                _ => {}
            }
        }

        Ok(status)
    }

    /// Receive a commit and apply the epoch transition.
    pub fn receive_commit(
        &mut self,
        commit: &EpochTransitionCommit,
    ) -> Result<AppliedTransition, TransitionError> {
        let applied =
            self.epoch_engine
                .receive_commit(commit, &self.verifying_keys, &mut self.detector)?;

        self.fire_transition_callbacks(&applied);
        self.pending_transition = None;

        Ok(applied)
    }

    fn fire_transition_callbacks(&mut self, transition: &AppliedTransition) {
        for cb in &self.transition_callbacks {
            cb(transition);
        }
        // Notify peer manager of epoch transition
        if let Some(ref pm) = self.peer_manager {
            let _ = pm.lock().unwrap().on_membership_event(
                peer_manager::MembershipEvent::EpochTransition {
                    new_epoch: transition.to_epoch.0,
                },
            );
        }
        // Create a membership epoch checkpoint for bounded-replay crash
        // recovery on every quorum-confirmed epoch advancement.
        if let Some(ref mut mgr) = self.checkpoint_mgr {
            let coordinator = self
                .roster
                .snapshot()
                .iter()
                .filter(|(_, state)| *state == RosterState::Active)
                .map(|(id, _)| *id)
                .min()
                .unwrap_or(self.my_id);
            let incarnation = self.incarnation_tracker.current();
            let roster: Vec<(MemberId, TransportAddress)> = self
                .roster
                .snapshot()
                .iter()
                .filter(|(_, state)| *state == RosterState::Active)
                .map(|(id, _)| {
                    let addr = self
                        .peer_address_registry
                        .as_ref()
                        .and_then(|reg| reg.resolve_first(*id))
                        .map(|a| TransportAddress::new(a.to_string()))
                        .unwrap_or_else(|| TransportAddress::new(""));
                    (*id, addr)
                })
                .collect();
            let _ = mgr.create_checkpoint(transition.to_epoch, coordinator, incarnation, roster);
        }
    }

    /// Get the current epoch.
    pub fn current_epoch(&self) -> EpochId {
        self.epoch_engine.current_epoch()
    }

    /// Get the current config class.
    pub fn config_class(&self) -> ConfigClass {
        self.epoch_engine.config_class()
    }
    /// Set the current placement map version for this runtime.
    ///
    /// The storage-node service calls this whenever the
    /// `PlacementVersionTracker` advances, so that [`view()`] carries
    /// the correct placement version for rebalance consistency.
    pub fn set_placement_version(&mut self, version: u64) {
        self.placement_version = version;
    }

    /// Return the current placement map version (0 = none).
    #[must_use]
    pub fn placement_version(&self) -> u64 {
        self.placement_version
    }

    /// Return the newest nonzero placement version observed from a peer.
    #[must_use]
    pub fn peer_placement_version(&self, peer: MemberId) -> Option<u64> {
        self.peer_placement_versions.get(&peer).copied()
    }

    /// Record a peer-advertised placement version without moving backward.
    pub fn observe_peer_placement_version(
        &mut self,
        peer: MemberId,
        advertised_version: u64,
    ) -> PeerPlacementVersionObservation {
        let previous_version = self.peer_placement_versions.get(&peer).copied();

        if peer == self.my_id || advertised_version == 0 || !self.detector.has_peer(peer) {
            return PeerPlacementVersionObservation {
                peer,
                advertised_version,
                previous_version,
                recorded_version: previous_version,
                accepted: false,
            };
        }

        if previous_version.is_some_and(|previous| advertised_version < previous) {
            return PeerPlacementVersionObservation {
                peer,
                advertised_version,
                previous_version,
                recorded_version: previous_version,
                accepted: false,
            };
        }

        self.peer_placement_versions
            .insert(peer, advertised_version);

        PeerPlacementVersionObservation {
            peer,
            advertised_version,
            previous_version,
            recorded_version: Some(advertised_version),
            accepted: true,
        }
    }

    /// Record the placement version advertised by a received membership view.
    pub fn observe_membership_view_placement_version(
        &mut self,
        view: &MembershipView,
    ) -> PeerPlacementVersionObservation {
        self.observe_peer_placement_version(view.local_member, view.placement_version)
    }

    /// Return local-vs-peer placement-version convergence state.
    #[must_use]
    pub fn placement_version_convergence(&self) -> PlacementVersionConvergence {
        let mut peers_ahead = Vec::new();
        let mut peers_behind = Vec::new();
        let mut max_peer_version = 0;

        for (&peer, &version) in &self.peer_placement_versions {
            max_peer_version = max_peer_version.max(version);
            if version > self.placement_version {
                peers_ahead.push(peer);
            } else if version < self.placement_version {
                peers_behind.push(peer);
            }
        }

        PlacementVersionConvergence {
            local_version: self.placement_version,
            max_peer_version,
            peer_versions: self.peer_placement_versions.clone(),
            peers_ahead,
            peers_behind,
        }
    }

    /// Return an immutable snapshot of the current membership state.
    pub fn view(&self) -> MembershipView {
        MembershipView {
            epoch: self.current_epoch(),
            config_class: self.config_class(),
            local_member: self.my_id,
            placement_version: self.placement_version,
            nodes: self
                .detector
                .all_peers()
                .map(|peer| MembershipViewNode {
                    member_id: peer.member_id,
                    member_class: peer.member_class,
                    health: peer.health,
                    epoch: peer.epoch,
                    failure_domain: peer.failure_domain,
                    joining: peer.joining,
                    draining: peer.draining,
                })
                .collect(),
        }
    }

    /// Get alive voter count.
    pub fn alive_voter_count(&self) -> usize {
        self.detector.alive_voters().len()
    }

    /// Whether quorum is lost.
    pub fn quorum_lost(&self) -> bool {
        self.detector.quorum_lost()
    }

    /// Whether we are bootstrapping.
    pub fn is_bootstrapping(&self) -> bool {
        self.bootstrapping
    }

    /// Get the verifying key for a member.
    pub fn get_verifying_key(&self, member_id: MemberId) -> Option<&PublicKey> {
        self.verifying_keys.get(&member_id)
    }

    /// Promote a learner to voter.
    pub fn promote_to_voter(&mut self, member_id: MemberId) {
        self.detector.promote_to_voter(member_id);
    }

    /// Announce the start of a graceful drain for a peer.
    ///
    /// Unlike [`drain_peer`](Self::drain_peer) which immediately marks the
    /// node as Left, this method emits a `MemberDraining` event so that
    /// subscribers (transport, epoch transition) can begin graceful
    /// degradation without tearing down sessions.  State transfer and
    /// final teardown happen between this call and the eventual
    /// [`drain_peer`](Self::drain_peer) / [`complete_drain_peer`](Self::complete_drain_peer).
    pub fn start_drain_peer(&mut self, member_id: MemberId) {
        // Mark the failure detector as draining (keeps liveness tracking
        // but prevents new work assignment).
        self.detector.mark_draining(member_id);
        // Publish MemberDraining event for subscribers.
        let incarnation = self.epoch_engine.current_epoch().0;
        let event = MembershipEvent::member_draining(member_id, incarnation);
        self.event_publisher.publish(&event);
        // Notify transport peer manager to transition to Draining state.
        if let Some(ref pm) = self.peer_manager {
            let _ = pm.lock().unwrap().on_membership_event(
                peer_manager::MembershipEvent::NodeDraining {
                    node_id: member_id.0,
                },
            );
        }
        // Register with fencing watchdog for drain timeout tracking.
        self.fencing.start_drain(member_id);
    }

    /// Complete a graceful drain by removing the peer from the roster
    /// and emitting `MemberDrained` followed by `MemberLeft`.
    ///
    /// Call this after state transfer finishes and the epoch gate
    /// commits the membership transition.
    pub fn complete_drain_peer(&mut self, member_id: MemberId) {
        let incarnation = self.epoch_engine.current_epoch().0;
        // Publish MemberDrained — the drain protocol is finished.
        let drained_event = MembershipEvent::member_drained(member_id, incarnation);
        self.event_publisher.publish(&drained_event);
        // Publish MemberLeft for consumers that use the simpler model.
        let left_event = MembershipEvent::member_left(member_id, incarnation);
        self.event_publisher.publish(&left_event);
        // Update roster: transition to Left.
        let _ = self.roster.transition_state(member_id, RosterState::Left);
        // Notify peer manager of final departure.
        if let Some(ref pm) = self.peer_manager {
            let _ =
                pm.lock()
                    .unwrap()
                    .on_membership_event(peer_manager::MembershipEvent::NodeLeft {
                        node_id: member_id.0,
                    });
        }
    }

    /// Start draining a peer (convenience wrapper that combines
    /// `start_drain_peer` + immediate completion for callers that
    /// do not need the full staged drain protocol).
    pub fn drain_peer(&mut self, member_id: MemberId) {
        self.detector.mark_draining(member_id);
        // Publish MemberLeft event
        {
            let incarnation = self.epoch_engine.current_epoch().0;
            let event = MembershipEvent::member_left(member_id, incarnation);
            self.event_publisher.publish(&event);
            // Update roster: transition to Left
            let _ = self.roster.transition_state(member_id, RosterState::Left);
            // Notify peer manager of graceful node departure
            if let Some(ref pm) = self.peer_manager {
                let _ = pm.lock().unwrap().on_membership_event(
                    peer_manager::MembershipEvent::NodeLeft {
                        node_id: member_id.0,
                    },
                );
            }
        }
        self.fencing.start_drain(member_id);
    }

    /// Return a BLAKE3-verified point-in-time snapshot of the membership roster.
    ///
    /// Consumers such as the epoch transition state machine and transport peer
    /// manager use this to obtain a consistent membership view.
    pub fn roster_snapshot(&self) -> RosterSnapshot {
        self.roster.snapshot()
    }

    /// Manually fence a node (operator command).
    pub fn fence_node(&mut self, node_id: MemberId) -> Result<(), tidefs_node_drain::FencingError> {
        let current_epoch = self.epoch_engine.current_epoch().0;
        self.fencing.manual_fence(node_id, current_epoch)?;
        Ok(())
    }

    /// Validate a fence token presented by a node attempting to rejoin.
    pub fn validate_fence_token(
        &self,
        node_id: MemberId,
        presented: tidefs_node_drain::FenceToken,
    ) -> Result<(), tidefs_node_drain::FencingError> {
        self.fencing.validate_fence_token(node_id, presented)
    }

    /// Clear a node's fenced status after successful catch-up rejoin.
    pub fn clear_fence(
        &mut self,
        node_id: MemberId,
        presented: tidefs_node_drain::FenceToken,
    ) -> Result<(), tidefs_node_drain::FencingError> {
        self.fencing.clear_fence(node_id, presented)
    }

    /// Replay the transition journal on coordinator promotion.
    ///
    /// Committed transitions are re-broadcast via outbound dispatch to
    /// ensure all members converge. Prepared transitions are aborted so
    /// the new coordinator starts with a clean slate. Idempotent: can be
    /// called multiple times safely.
    fn replay_transition_journal(&mut self) {
        let Some(ref sd) = self.send_dispatcher else {
            return;
        };
        let dispatch = MembershipOutboundDispatch::new(sd, &self.roster);
        let _result = crate::coordinator_promotion::replay_transition_journal(
            &self.transition_journal,
            &dispatch,
            &self.roster,
            30_000,
            self.incarnation_tracker.current(),
        );
        self.journal_needs_replay = false;
    }
}

#[derive(Default, Debug)]
pub struct RuntimeTickResult {
    pub pings_sent: usize,
    pub outbound_pings: Vec<(MemberId, SwimPing)>,
    pub new_suspicions: usize,
    pub accumulator_events: usize,
    pub gossip_batches_flushed: usize,
    pub epoch_transitioned: bool,
    pub new_epoch: Option<EpochId>,
    pub epoch_transition_initiated: bool,
    pub heartbeat_outbound: Vec<(MemberId, MembershipOutboundMessage)>,
    /// Coordinator lease heartbeat requests to send via outbound dispatch.
    pub coordinator_heartbeat_requests: Vec<CoordinatorHeartbeatRequest>,
    /// Whether the coordinator lease was lost this tick (stepdown needed).
    pub coordinator_lease_lost: bool,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_runtime(id: u64, class: MemberClass) -> MembershipRuntime {
        MembershipRuntime::new(
            MembershipConfig {
                ping_interval_ms: 50,
                ping_timeout_ms: 200,
                suspicion_window_ms: 500,
                indirect_ping_count: 2,
                min_voters_for_quorum: 2,
                max_failed_pings_before_suspect: 3,
            },
            MemberId::new(id),
            class,
            id,
        )
    }

    #[test]
    fn test_runtime_creation_and_self_registration() {
        let rt = make_runtime(1, MemberClass::Voter);
        assert_eq!(rt.current_epoch(), EpochId::new(1));
        assert!(rt.detector.has_peer(MemberId::new(1)));
        assert_eq!(rt.alive_voter_count(), 1);
        assert!(rt.quorum_lost());
    }

    #[test]
    fn test_view_is_immutable_snapshot() {
        let mut rt = make_runtime(1, MemberClass::Voter);
        rt.add_peer(MemberId::new(2), MemberClass::Learner, 42);

        let view = rt.view();
        rt.promote_to_voter(MemberId::new(2));

        let captured_peer = view
            .nodes
            .iter()
            .find(|node| node.member_id == MemberId::new(2))
            .expect("captured peer");
        assert_eq!(view.epoch, EpochId::new(1));
        assert_eq!(captured_peer.member_class, MemberClass::Learner);
        assert_eq!(captured_peer.failure_domain, 42);
    }

    #[test]
    fn placement_version_observation_tracks_known_peers_monotonically() {
        let mut rt = make_runtime(1, MemberClass::Voter);
        rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);

        let accepted = rt.observe_peer_placement_version(MemberId::new(2), 4);
        assert!(accepted.accepted);
        assert_eq!(accepted.previous_version, None);
        assert_eq!(accepted.recorded_version, Some(4));
        assert_eq!(rt.peer_placement_version(MemberId::new(2)), Some(4));

        let stale = rt.observe_peer_placement_version(MemberId::new(2), 3);
        assert!(!stale.accepted);
        assert_eq!(stale.previous_version, Some(4));
        assert_eq!(stale.recorded_version, Some(4));
        assert_eq!(rt.peer_placement_version(MemberId::new(2)), Some(4));

        let equal = rt.observe_peer_placement_version(MemberId::new(2), 4);
        assert!(equal.accepted);
        assert_eq!(equal.previous_version, Some(4));
        assert_eq!(equal.recorded_version, Some(4));
    }

    #[test]
    fn placement_version_observation_ignores_self_unknown_and_zero_views() {
        let mut rt = make_runtime(1, MemberClass::Voter);
        rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);

        let self_observation = rt.observe_peer_placement_version(MemberId::new(1), 7);
        assert!(!self_observation.accepted);
        assert_eq!(rt.peer_placement_version(MemberId::new(1)), None);

        let unknown = rt.observe_peer_placement_version(MemberId::new(3), 7);
        assert!(!unknown.accepted);
        assert_eq!(rt.peer_placement_version(MemberId::new(3)), None);

        let zero = rt.observe_peer_placement_version(MemberId::new(2), 0);
        assert!(!zero.accepted);
        assert_eq!(rt.peer_placement_version(MemberId::new(2)), None);
    }

    #[test]
    fn membership_view_observation_reports_local_staleness() {
        let mut rt = make_runtime(1, MemberClass::Voter);
        rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);
        rt.set_placement_version(8);
        let view = MembershipView {
            epoch: EpochId::new(1),
            config_class: ConfigClass::Normal,
            local_member: MemberId::new(2),
            nodes: Vec::new(),
            placement_version: 10,
        };

        let observed = rt.observe_membership_view_placement_version(&view);
        assert!(observed.accepted);

        let convergence = rt.placement_version_convergence();
        assert_eq!(convergence.local_version, 8);
        assert_eq!(convergence.max_peer_version, 10);
        assert_eq!(convergence.peers_ahead, vec![MemberId::new(2)]);
        assert!(convergence.local_is_stale());
        assert!(!convergence.all_observed_peers_converged());

        rt.set_placement_version(10);
        let convergence = rt.placement_version_convergence();
        assert!(!convergence.local_is_stale());
        assert!(convergence.all_observed_peers_converged());
    }

    #[test]
    fn test_tick_generates_signed_peer_ping() {
        let mut rt = make_runtime(1, MemberClass::Voter);
        rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);
        rt.detector
            .get_peer_mut(MemberId::new(2))
            .expect("peer")
            .last_ack_millis = 0;

        let result = rt.tick();
        assert_eq!(result.pings_sent, 1);

        let (_, ping) = result.outbound_pings.first().expect("outbound ping");
        assert_eq!(ping.pinger, MemberId::new(1));
        assert_eq!(ping.ping_target, MemberId::new(2));
        assert!(ping.verify(rt.get_verifying_key(MemberId::new(1)).expect("self key")));
    }

    #[test]
    fn test_add_peer_and_detect_failure() {
        let mut rt = make_runtime(1, MemberClass::Voter);
        rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);
        rt.add_peer(MemberId::new(3), MemberClass::Voter, 3);

        assert_eq!(rt.detector.peer_count(), 3);

        // Tick a few times — initially all are alive
        for _ in 0..3 {
            rt.tick();
        }
        assert_eq!(rt.detector.alive_voters().len(), 3);
        assert!(!rt.quorum_lost());
    }

    #[test]
    fn test_quorum_lost_when_majority_down() {
        let mut rt = make_runtime(1, MemberClass::Voter);
        rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);
        rt.add_peer(MemberId::new(3), MemberClass::Voter, 3);

        // Manually mark peers 2 and 3 as down
        rt.detector.get_peer_mut(MemberId::new(2)).unwrap().health = HealthClass::Down;
        rt.detector.get_peer_mut(MemberId::new(3)).unwrap().health = HealthClass::Down;

        assert!(rt.quorum_lost());
    }

    #[test]
    fn test_epoch_transition_on_failure_detection() {
        let mut rt = make_runtime(1, MemberClass::Voter);
        rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);
        rt.add_peer(MemberId::new(3), MemberClass::Voter, 3);

        // Generate keys for all peers
        let kp2 = {
            let mut csprng = OsRng;
            Keypair::generate(&mut csprng)
        };
        let kp3 = {
            let mut csprng = OsRng;
            Keypair::generate(&mut csprng)
        };
        rt.register_key(MemberId::new(2), kp2.public);
        rt.register_key(MemberId::new(3), kp3.public);

        // Manually advance peers to suspect → down
        rt.detector.get_peer_mut(MemberId::new(2)).unwrap().health = HealthClass::Down;
        rt.detector
            .get_peer_mut(MemberId::new(2))
            .unwrap()
            .suspect_since_millis = now_millis();

        // Emit a suspicion
        let suspicion = SuspicionRecord::new(
            MemberId::new(2),
            MemberId::new(1),
            now_millis(),
            SuspicionSource::DirectTimeout,
        );
        rt.detector.emitted_suspicions.push(suspicion);

        // Tick should initiate epoch transition
        let result = rt.tick();
        assert!(result.epoch_transition_initiated);
        assert!(rt.pending_transition.is_some());
    }

    #[test]
    fn test_member_add_flow() {
        let mut rt = make_runtime(1, MemberClass::Voter);
        rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);

        // New node joins as Learner
        let new_id = MemberId::new(4);
        let new_kp = {
            let mut csprng = OsRng;
            Keypair::generate(&mut csprng)
        };
        rt.register_key(new_id, new_kp.public);
        rt.add_joining_peer(new_id, 4);

        assert!(rt.detector.has_peer(new_id));
        let peer = rt.detector.get_peer(new_id).unwrap();
        assert_eq!(peer.member_class, MemberClass::Learner);
        assert!(peer.joining);

        // Promote to Voter
        rt.promote_to_voter(new_id);
        let peer = rt.detector.get_peer(new_id).unwrap();
        assert_eq!(peer.member_class, MemberClass::Voter);
        assert!(!peer.joining);
    }

    #[test]
    fn test_drain_peer() {
        let mut rt = make_runtime(1, MemberClass::Voter);
        rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);

        rt.drain_peer(MemberId::new(2));
        let peer = rt.detector.get_peer(MemberId::new(2)).unwrap();
        assert!(peer.draining);
        assert_eq!(peer.member_class, MemberClass::DataOnly);
    }

    #[test]
    fn test_witness_only_not_affecting_quorum() {
        let mut rt = make_runtime(1, MemberClass::Voter);
        rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);
        rt.add_peer(MemberId::new(3), MemberClass::WitnessOnly, 3);

        // 2 voters alive, 1 witness — quorum should be maintained
        assert_eq!(rt.alive_voter_count(), 2);
        assert!(!rt.quorum_lost());

        // Mark witness as down — shouldn't affect quorum
        rt.detector.get_peer_mut(MemberId::new(3)).unwrap().health = HealthClass::Down;
        assert_eq!(rt.alive_voter_count(), 2);
        assert!(!rt.quorum_lost());
    }

    #[test]
    fn test_quarantined_excluded_from_voters() {
        let mut rt = make_runtime(1, MemberClass::Voter);
        rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);
        rt.add_peer(MemberId::new(3), MemberClass::Quarantined, 3);

        // Quarantined members don't count as voters
        assert_eq!(rt.alive_voter_count(), 2);
    }

    #[test]
    fn test_swim_ping_sign_and_verify() {
        let kp = {
            let mut csprng = OsRng;
            Keypair::generate(&mut csprng)
        };

        let mut ping = SwimPing {
            pinger: MemberId::new(1),
            ping_target: MemberId::new(2),
            seq_no: 1,
            pinger_epoch: EpochId::new(1),
            pinger_epoch_receipt: 0,
            sent_at_millis: now_millis(),
            indirect_via: vec![MemberId::new(3)],
            signature: Vec::new(),
        };
        ping.sign(&kp);
        assert!(ping.verify(&kp.public));
    }

    #[test]
    fn test_swim_ack_sign_and_verify() {
        let kp = {
            let mut csprng = OsRng;
            Keypair::generate(&mut csprng)
        };

        let mut ack = SwimAck {
            ping_seq_no: 1,
            acker: MemberId::new(2),
            acker_epoch: EpochId::new(1),
            acker_epoch_receipt: 0,
            suspicion_list: vec![],
            membership_delta: vec![],
            acked_at_millis: now_millis(),
            signature: Vec::new(),
        };
        ack.sign(&kp);
        assert!(ack.verify(&kp.public));
    }

    #[test]
    fn test_epoch_transition_proposal_sign_verify() {
        let kp = {
            let mut csprng = OsRng;
            Keypair::generate(&mut csprng)
        };

        let mut prop = EpochTransitionProposal {
            proposal_id: 1,
            proposer: MemberId::new(1),
            from_epoch: EpochId::new(1),
            to_epoch: EpochId::new(2),
            members_added: vec![],
            members_removed: vec![MemberId::new(3)],
            reason: TransitionReason::FailureDetected,
            validation: vec![],
            proposed_at_millis: now_millis(),
            fence_token: None,
            proposer_signature: Vec::new(),
        };
        prop.sign(&kp);
        assert!(prop.verify(&kp.public));
    }

    // Peer manager integration tests — membership-live → transport bridge
    // -----------------------------------------------------------------------

    #[test]
    fn pm_node_joined_on_add_peer() {
        let mut rt = make_runtime(1, MemberClass::Voter);
        let pm = tidefs_transport::peer_manager::new_peer_manager_handle();
        rt.set_peer_manager(pm.clone());

        rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);

        let pm = pm.lock().unwrap();
        assert_eq!(
            pm.peer_state(2),
            Some(tidefs_transport::peer_manager::PeerState::Connecting),
            "add_peer should transition peer to Connecting"
        );
    }

    #[test]
    fn pm_node_left_on_drain_peer() {
        let mut rt = make_runtime(1, MemberClass::Voter);
        let pm = tidefs_transport::peer_manager::new_peer_manager_handle();
        rt.set_peer_manager(pm.clone());

        rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);
        // Establish session so peer is Connected before draining
        pm.lock()
            .unwrap()
            .establish_session(2, tidefs_transport::types::SessionId(42))
            .unwrap();

        rt.drain_peer(MemberId::new(2));

        let pm = pm.lock().unwrap();
        assert_eq!(
            pm.peer_state(2),
            Some(tidefs_transport::peer_manager::PeerState::Draining),
            "drain_peer should notify peer manager of graceful departure"
        );
    }

    #[test]
    fn pm_node_failed_on_dead_member_detection() {
        let mut rt = make_runtime(1, MemberClass::Voter);
        let pm = tidefs_transport::peer_manager::new_peer_manager_handle();
        rt.set_peer_manager(pm.clone());

        rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);

        // Establish session so peer is Connected
        pm.lock()
            .unwrap()
            .establish_session(2, tidefs_transport::types::SessionId(42))
            .unwrap();

        // Mark peer as Down with recent suspicion → dead member path
        rt.detector.get_peer_mut(MemberId::new(2)).unwrap().health = HealthClass::Down;
        rt.detector
            .get_peer_mut(MemberId::new(2))
            .unwrap()
            .suspect_since_millis = now_millis();

        let suspicion = SuspicionRecord::new(
            MemberId::new(2),
            MemberId::new(1),
            now_millis(),
            SuspicionSource::DirectTimeout,
        );
        rt.detector.emitted_suspicions.push(suspicion);

        // Tick triggers dead-member detection → NodeFailed notification
        rt.tick();

        let pm = pm.lock().unwrap();
        assert_eq!(
            pm.peer_state(2),
            Some(tidefs_transport::peer_manager::PeerState::Disconnected),
            "dead member detection should notify peer manager with NodeFailed"
        );
        assert_eq!(pm.peer_session(2), None);
    }

    #[test]
    fn pm_epoch_transition_notifies_on_epoch_change() {
        let mut rt = make_runtime(1, MemberClass::Voter);
        let pm = tidefs_transport::peer_manager::new_peer_manager_handle();
        rt.set_peer_manager(pm.clone());

        // Set voter count to 1 so a single accept reaches quorum
        rt.epoch_engine.set_voter_count(1);

        // Mark self as Down (unusual but works for testing the epoch path)
        // Actually, we need a peer to remove. Let's add a peer and mark it as Down.
        rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);
        let kp2 = {
            let mut csprng = OsRng;
            Keypair::generate(&mut csprng)
        };
        rt.register_key(MemberId::new(2), kp2.public);

        // Mark peer 2 as Down with suspicion
        rt.detector.get_peer_mut(MemberId::new(2)).unwrap().health = HealthClass::Down;
        rt.detector
            .get_peer_mut(MemberId::new(2))
            .unwrap()
            .suspect_since_millis = now_millis();
        rt.detector.emitted_suspicions.push(SuspicionRecord::new(
            MemberId::new(2),
            MemberId::new(1),
            now_millis(),
            SuspicionSource::DirectTimeout,
        ));

        // First tick: proposes the epoch transition (alive_voters=1, required=1)
        let result = rt.tick();
        assert!(result.epoch_transition_initiated);

        // Second tick: commits because voter_count=1 → required=1 ≥ 1 accept
        let result2 = rt.tick();
        assert!(
            result2.epoch_transitioned,
            "second tick should commit: {result2:?}"
        );

        let pm = pm.lock().unwrap();
        assert!(pm.current_epoch() > 0, "epoch={}", pm.current_epoch());
    }

    #[test]
    fn pm_no_notification_when_not_set() {
        let mut rt = make_runtime(1, MemberClass::Voter);
        // Peer manager is NOT set — operations should not panic
        rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);
        rt.drain_peer(MemberId::new(2));
        // Should reach here without panic
        assert!(rt.detector.has_peer(MemberId::new(2)));
    }

    #[test]
    fn pm_multiple_peers_lifecycle() {
        let mut rt = make_runtime(1, MemberClass::Voter);
        let pm = tidefs_transport::peer_manager::new_peer_manager_handle();
        rt.set_peer_manager(pm.clone());

        // Join 3 peers
        for id in 2..=4 {
            rt.add_peer(MemberId::new(id), MemberClass::Voter, id);
        }

        {
            let pm = pm.lock().unwrap();
            assert_eq!(pm.peer_count(), 3);
            for id in 2..=4 {
                assert_eq!(
                    pm.peer_state(id),
                    Some(tidefs_transport::peer_manager::PeerState::Connecting)
                );
            }
        }

        // Drain peer 2
        pm.lock()
            .unwrap()
            .establish_session(2, tidefs_transport::types::SessionId(10))
            .unwrap();
        rt.drain_peer(MemberId::new(2));

        // Fail peer 3 via dead-member path
        pm.lock()
            .unwrap()
            .establish_session(3, tidefs_transport::types::SessionId(20))
            .unwrap();
        rt.detector.get_peer_mut(MemberId::new(3)).unwrap().health = HealthClass::Down;
        rt.detector
            .get_peer_mut(MemberId::new(3))
            .unwrap()
            .suspect_since_millis = now_millis();
        rt.detector.emitted_suspicions.push(SuspicionRecord::new(
            MemberId::new(3),
            MemberId::new(1),
            now_millis(),
            SuspicionSource::DirectTimeout,
        ));
        rt.tick();

        // Establish peer 4
        pm.lock()
            .unwrap()
            .establish_session(4, tidefs_transport::types::SessionId(30))
            .unwrap();

        let pm = pm.lock().unwrap();
        assert_eq!(
            pm.peer_state(2),
            Some(tidefs_transport::peer_manager::PeerState::Draining)
        );
        assert_eq!(
            pm.peer_state(3),
            Some(tidefs_transport::peer_manager::PeerState::Disconnected)
        );
        assert_eq!(
            pm.peer_state(4),
            Some(tidefs_transport::peer_manager::PeerState::Connected)
        );
    }

    // ------------------------------------------------------------------
    // Eviction executor production wiring tests
    // ------------------------------------------------------------------

    /// Full production-path test: wire eviction executor, simulate a dead
    /// peer via the coordinator, and verify the transport teardown callback
    /// is invoked with the correct peer and Close action.
    #[test]
    fn eviction_executor_wired_into_runtime_triggers_teardown_on_dead_peer() {
        use crate::session_binding::{PeerSessionBinding, SessionBindingTable, SessionId};
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        use tidefs_transport::connection_registry::{ConnectionId, ConnectionRegistry};
        use tidefs_transport::peer_admission::AdmittedPeer;

        let mut rt = make_runtime(1, MemberClass::Voter);

        // Register two peers.
        rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);
        rt.add_peer(MemberId::new(3), MemberClass::Voter, 3);

        // Prepare transport-level resources.
        let registry = Arc::new(ConnectionRegistry::new());
        let bindings = Arc::new(Mutex::new(SessionBindingTable::new()));

        let ep2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 8000);
        let ep3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 8001);

        // Register peers in the connection registry and session bindings.
        for (peer_id, ep) in [(2u64, ep2), (3u64, ep3)] {
            let admitted = AdmittedPeer::new(peer_id, 1);
            registry
                .insert(&admitted, ConnectionId::new(peer_id * 10), ep)
                .unwrap();
            let mut bt = bindings.lock().unwrap();
            bt.insert(PeerSessionBinding::new(
                peer_id,
                MemberId::new(peer_id),
                SessionId::new(peer_id * 100),
                tidefs_membership_epoch::EpochId::new(1),
            ));
        }

        // Record eviction callbacks.
        let calls = Arc::new(Mutex::new(Vec::new()));
        let calls_clone = Arc::clone(&calls);

        rt.wire_eviction_executor(
            Arc::clone(&registry),
            Arc::clone(&bindings),
            Box::new(move |addr, action| {
                calls_clone.lock().unwrap().push((addr, action));
            }),
        );

        assert!(rt.has_eviction_wired());

        // Simulate peer 2 becoming dead via the heartbeat tracker path:
        // feed a MemberFailed event through the coordinator by directly
        // triggering a liveness change, which is what the tick() path
        // does when heartbeat deadlines expire.
        let coord = rt.epoch_coordinator.as_mut().unwrap();
        let change = crate::epoch_coordinator::PeerLivenessChange::new(
            MemberId::new(2),
            crate::epoch_coordinator::PeerLivenessStatus::Alive,
            crate::epoch_coordinator::PeerLivenessStatus::Dead,
            crate::types::now_millis(),
        );
        let committed = coord.on_liveness_change(change);
        assert!(
            committed.is_some(),
            "should produce a new epoch view removing peer 2"
        );

        let view = committed.unwrap();
        assert!(
            !view.contains(MemberId::new(2)),
            "peer 2 should be removed from the view"
        );
        assert!(view.contains(MemberId::new(3)), "peer 3 should remain");

        // The eviction callback should have been invoked.
        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.len(), 1, "one peer should have been evicted");
        assert_eq!(recorded[0].0, ep2, "peer 2's endpoint should be evicted");
        assert_eq!(
            recorded[0].1,
            crate::peer_eviction::EvictionAction::Close,
            "dead peer should be closed immediately"
        );

        // Connection registry should no longer have peer 2.
        assert!(
            registry.get(2).is_none(),
            "peer 2 should be removed from registry"
        );
        // Peer 3 should still be there.
        assert!(
            registry.get(3).is_some(),
            "peer 3 should remain in registry"
        );

        // Session bindings for peer 2 should be cleared; peer 3's remain.
        {
            let bt = bindings.lock().unwrap();
            assert!(
                bt.get_by_peer(MemberId::new(2)).is_empty(),
                "peer 2's bindings should be released"
            );
            assert!(
                !bt.get_by_peer(MemberId::new(3)).is_empty(),
                "peer 3's bindings should remain"
            );
        }
    }

    /// Verify that wire_eviction_executor is idempotent-safe: calling it
    /// when the coordinator is already Some replaces it (new executor
    /// takes over). After replacement, the new callback receives events.
    #[test]
    fn wire_eviction_executor_replaces_previous_wiring() {
        use crate::session_binding::{PeerSessionBinding, SessionBindingTable, SessionId};
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        use tidefs_transport::connection_registry::ConnectionId;
        use tidefs_transport::connection_registry::ConnectionRegistry;
        use tidefs_transport::peer_admission::AdmittedPeer;

        let mut rt = make_runtime(1, MemberClass::Voter);
        rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);

        let registry = Arc::new(ConnectionRegistry::new());
        let bindings = Arc::new(Mutex::new(SessionBindingTable::new()));

        let ep = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 8000);
        let admitted = AdmittedPeer::new(2, 1);
        registry
            .insert(&admitted, ConnectionId::new(20), ep)
            .unwrap();
        bindings.lock().unwrap().insert(PeerSessionBinding::new(
            2,
            MemberId::new(2),
            SessionId::new(200),
            tidefs_membership_epoch::EpochId::new(1),
        ));

        // First wiring.
        let calls1 = Arc::new(Mutex::new(Vec::new()));
        let c1 = Arc::clone(&calls1);
        rt.wire_eviction_executor(
            Arc::clone(&registry),
            Arc::clone(&bindings),
            Box::new(move |addr, action| {
                c1.lock().unwrap().push((addr, action));
            }),
        );

        // Trigger eviction through the first wiring to clear the registry.
        {
            let coord = rt.epoch_coordinator.as_mut().unwrap();
            let change = crate::epoch_coordinator::PeerLivenessChange::new(
                MemberId::new(2),
                crate::epoch_coordinator::PeerLivenessStatus::Alive,
                crate::epoch_coordinator::PeerLivenessStatus::Dead,
                crate::types::now_millis(),
            );
            coord.on_liveness_change(change);
        }
        // First callback should have been invoked.
        assert_eq!(
            calls1.lock().unwrap().len(),
            1,
            "first callback should fire"
        );

        // Second wiring replaces the first.
        let calls2 = Arc::new(Mutex::new(Vec::new()));
        let c2 = Arc::clone(&calls2);

        // Re-register peer 2 in the registry (first eviction removed it).
        registry
            .insert(&admitted, ConnectionId::new(20), ep)
            .unwrap();
        bindings.lock().unwrap().insert(PeerSessionBinding::new(
            2,
            MemberId::new(2),
            SessionId::new(200),
            tidefs_membership_epoch::EpochId::new(1),
        ));

        rt.wire_eviction_executor(
            Arc::clone(&registry),
            Arc::clone(&bindings),
            Box::new(move |addr, action| {
                c2.lock().unwrap().push((addr, action));
            }),
        );

        // Trigger eviction.
        let coord = rt.epoch_coordinator.as_mut().unwrap();
        let change = crate::epoch_coordinator::PeerLivenessChange::new(
            MemberId::new(2),
            crate::epoch_coordinator::PeerLivenessStatus::Alive,
            crate::epoch_coordinator::PeerLivenessStatus::Dead,
            crate::types::now_millis(),
        );
        coord.on_liveness_change(change);

        // The second callback should have been invoked (calls1 already
        // verified above that the first wiring fired once).
        assert_eq!(
            calls2.lock().unwrap().len(),
            1,
            "second callback should fire after replacement"
        );
    }

    /// Verify that without wiring, the coordinator is None, and
    /// has_eviction_wired returns false.
    #[test]
    fn has_eviction_wired_returns_false_before_wiring() {
        let rt = make_runtime(1, MemberClass::Voter);
        assert!(!rt.has_eviction_wired());
        assert!(rt.epoch_coordinator.is_none());
    }

    // ------------------------------------------------------------------
    // send_gate tests (#6181)
    // ------------------------------------------------------------------

    #[test]
    fn send_gate_is_some_after_construction() {
        let rt = make_runtime(1, MemberClass::Voter);
        assert!(
            rt.send_gate.is_some(),
            "send_gate should be created at construction time"
        );
    }

    #[test]
    fn send_gate_accessor_returns_clone_of_same_arc() {
        let rt = make_runtime(1, MemberClass::Voter);
        let gate1 = rt.send_gate();
        let gate2 = rt.send_gate();
        assert!(gate1.is_some());
        assert!(gate2.is_some());
        assert!(std::sync::Arc::ptr_eq(
            gate1.as_ref().unwrap(),
            gate2.as_ref().unwrap(),
        ));
    }

    #[test]
    fn send_gate_rejects_before_any_epoch_commit() {
        let rt = make_runtime(1, MemberClass::Voter);
        let gate = rt.send_gate().unwrap();
        // No epoch committed yet -- roster is empty, gate rejects all.
        assert!(gate.check(1).is_err());
    }

    // ------------------------------------------------------------------
    // Coordinator lease + health heartbeat integration tests (#6209)
    // ------------------------------------------------------------------

    /// When the coordinator lease is active, heartbeat_outbound must
    /// contain both CoordinatorHeartbeat messages (from the lease tick)
    /// and HealthReport messages (from the health heartbeat tick).
    /// Verifies the fix for the overwrite bug where
    /// `result.heartbeat_outbound = heartbeat_msgs` erased the
    /// coordinator-lease heartbeats pushed earlier in the tick.
    #[test]
    fn coordinator_lease_heartbeats_survive_health_heartbeat_tick() {
        let mut rt = make_runtime(1, MemberClass::Voter);
        rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);

        // Activate coordinator lease directly so the tick path exercises it.
        rt.coordinator_lease.activate();

        let result = rt.tick();

        // Should have at least one CoordinatorHeartbeat for peer 2.
        let coordinator_count = result
            .heartbeat_outbound
            .iter()
            .filter(|(_, msg)| {
                matches!(msg, MembershipOutboundMessage::CoordinatorHeartbeat { .. })
            })
            .count();
        assert!(
            coordinator_count > 0,
            "expected CoordinatorHeartbeat messages, got {} total outbound",
            result.heartbeat_outbound.len()
        );

        // Should also have HealthReport messages from the health heartbeat tick.
        let health_count = result
            .heartbeat_outbound
            .iter()
            .filter(|(_, msg)| matches!(msg, MembershipOutboundMessage::HealthReport { .. }))
            .count();
        assert!(
            health_count > 0,
            "HealthReport count was {health_count}; coordinator lease overwrite may still exist"
        );

        assert!(!result.coordinator_lease_lost);
    }

    /// When the coordinator lease is NOT active, heartbeat_outbound
    /// should still contain HealthReport messages and must NOT contain
    /// any CoordinatorHeartbeat messages.
    #[test]
    fn health_heartbeats_present_without_coordinator_lease() {
        let mut rt = make_runtime(1, MemberClass::Voter);
        rt.add_peer(MemberId::new(2), MemberClass::Voter, 2);

        // Do NOT activate coordinator lease.
        assert!(!rt.coordinator_lease.is_active());

        let result = rt.tick();

        // Should have HealthReport messages.
        let health_count = result
            .heartbeat_outbound
            .iter()
            .filter(|(_, msg)| matches!(msg, MembershipOutboundMessage::HealthReport { .. }))
            .count();
        assert!(
            health_count > 0,
            "expected HealthReport messages, got {} total outbound",
            result.heartbeat_outbound.len()
        );

        // Must NOT have CoordinatorHeartbeat messages.
        let coordinator_count = result
            .heartbeat_outbound
            .iter()
            .filter(|(_, msg)| {
                matches!(msg, MembershipOutboundMessage::CoordinatorHeartbeat { .. })
            })
            .count();
        assert_eq!(
            coordinator_count, 0,
            "expected zero CoordinatorHeartbeat messages when lease is inactive"
        );
    }

    /// When the coordinator lease expires (lease duration elapsed with
    /// no renewal), the runtime tick must set coordinator_lease_lost
    /// and deactivate the lease. Uses a short-duration config and small
    /// sleeps so the test completes quickly.
    #[test]
    fn coordinator_lease_lost_sets_flag_and_deactivates() {
        let mut rt = make_runtime(1, MemberClass::Voter);
        // Replace with a short-duration lease for fast expiration.
        rt.coordinator_lease = crate::coordinator_lease::CoordinatorLease::new(
            crate::coordinator_lease::CoordinatorLeaseConfig::new(
                std::time::Duration::from_millis(10),
                std::time::Duration::from_millis(3),
            ),
            MemberId::new(1),
        );
        rt.coordinator_lease.activate();

        // Tick 1: starts a heartbeat round (self-ack).
        rt.tick();
        assert!(rt.coordinator_lease.is_active());

        // Wait past the tick_interval (heartbeat_interval/3 = 1ms) so
        // the next tick evaluates the round and renews the lease.
        std::thread::sleep(std::time::Duration::from_millis(2));
        rt.tick(); // evaluates Held (self-ack), renews
        assert!(rt.coordinator_lease.is_active());

        // Wait past the lease_duration (10ms) so the next tick detects
        // expiration.
        std::thread::sleep(std::time::Duration::from_millis(12));
        let result = rt.tick();

        assert!(
            result.coordinator_lease_lost,
            "coordinator_lease_lost should be true when lease expires"
        );
        assert!(
            !rt.coordinator_lease.is_active(),
            "lease should be deactivated after loss"
        );
    }
}
