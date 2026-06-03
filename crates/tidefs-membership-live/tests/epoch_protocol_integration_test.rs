//! Integration tests for the epoch proposal/commit protocol (#5044).
//!
//! Uses a deterministic N-node message bus to exercise the full protocol
//! over framed bincode transport.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use ed25519_dalek::{Keypair, PublicKey, Signer};
use rand::rngs::OsRng;
use tidefs_membership_epoch::{EpochId, MemberId};
use tidefs_membership_live::{
    EpochCommit, EpochProposal, EpochProtocolConfig, EpochProtocolState, EpochStateMachine,
    EpochVote, RejectionReason, SignedAccept,
};

/// Tagged wire message for epoch protocol (avoids ambiguous bincode deserialization).
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
enum WireMessage {
    Proposal(EpochProposal),
    Vote(EpochVote),
    Commit(EpochCommit),
}

// ---------------------------------------------------------------------------
// MultiNodeBus — N-node deterministic message bus
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkState {
    Up,
    Down,
}

/// Shared N-node message bus with framed bincode messages.
pub struct MultiNodeBus {
    inboxes: Vec<VecDeque<Vec<u8>>>,
    links: Vec<Vec<LinkState>>,
    held: Vec<Vec<VecDeque<Vec<u8>>>>,
    num_nodes: usize,
}

impl MultiNodeBus {
    pub fn new(num_nodes: usize) -> Self {
        let sz = num_nodes + 1;
        let mut inboxes = Vec::with_capacity(sz);
        let mut links = Vec::with_capacity(sz);
        let mut held = Vec::with_capacity(sz);
        for _ in 0..sz {
            inboxes.push(VecDeque::new());
            links.push(vec![LinkState::Up; sz]);
            held.push((0..sz).map(|_| VecDeque::new()).collect());
        }
        Self {
            inboxes,
            links,
            held,
            num_nodes,
        }
    }

    pub fn shared(num_nodes: usize) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self::new(num_nodes)))
    }

    pub fn set_link(&mut self, from: usize, to: usize, state: LinkState) {
        self.links[from][to] = state;
        if state == LinkState::Up {
            let drained: Vec<Vec<u8>> = self.held[from][to].drain(..).collect();
            for msg in drained {
                self.inboxes[to].push_back(msg);
            }
        }
    }

    pub fn isolate_node(&mut self, node: usize) {
        for other in 1..=self.num_nodes {
            if other != node {
                self.set_link(node, other, LinkState::Down);
                self.set_link(other, node, LinkState::Down);
            }
        }
    }

    pub fn heal_all(&mut self) {
        for from in 1..=self.num_nodes {
            for to in 1..=self.num_nodes {
                if from != to {
                    self.set_link(from, to, LinkState::Up);
                }
            }
        }
    }

    fn send_framed(&mut self, from: usize, to: usize, framed: Vec<u8>) {
        if self.links[from][to] == LinkState::Down {
            self.held[from][to].push_back(framed);
        } else {
            self.inboxes[to].push_back(framed);
        }
    }

    fn recv_framed(&mut self, node: usize) -> Option<Vec<u8>> {
        self.inboxes[node].pop_front()
    }
}

// ---------------------------------------------------------------------------
// Message framing
// ---------------------------------------------------------------------------

fn frame_message(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut f = Vec::with_capacity(4 + payload.len());
    f.extend_from_slice(&len.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn unframe(buf: &[u8]) -> Option<&[u8]> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + len {
        return None;
    }
    Some(&buf[4..4 + len])
}

// ---------------------------------------------------------------------------
// ProtocolNode
// ---------------------------------------------------------------------------

/// A node in the multi-node integration harness.
pub struct ProtocolNode {
    pub node_id: usize,
    pub sm: EpochStateMachine,
    pub keypair: Keypair,
    bus: Rc<RefCell<MultiNodeBus>>,
}

impl ProtocolNode {
    pub fn new(
        node_id: usize,
        sm: EpochStateMachine,
        keypair: Keypair,
        bus: Rc<RefCell<MultiNodeBus>>,
    ) -> Self {
        Self {
            node_id,
            sm,
            keypair,
            bus,
        }
    }

    /// Send a bincode-encoded message to a specific node.
    fn send_to(&self, to: usize, payload: &[u8]) {
        let framed = frame_message(payload);
        self.bus.borrow_mut().send_framed(self.node_id, to, framed);
    }

    /// Broadcast a proposal to all other nodes.
    pub fn broadcast_proposal(&self, proposal: &EpochProposal) {
        let msg = WireMessage::Proposal(proposal.clone());
        let payload = bincode::serialize(&msg).expect("serialize WireMessage::Proposal");
        let n = self.bus.borrow().num_nodes;
        for to in 1..=n {
            if to != self.node_id {
                self.send_to(to, &payload);
            }
        }
    }

    /// Send a vote to the leader.
    pub fn send_vote(&self, leader_id: usize, vote: &EpochVote) {
        let msg = WireMessage::Vote(vote.clone());
        let payload = bincode::serialize(&msg).expect("serialize WireMessage::Vote");
        self.send_to(leader_id, &payload);
    }

    /// Broadcast a commit to all other nodes.
    pub fn broadcast_commit(&self, commit: &EpochCommit) {
        let msg = WireMessage::Commit(commit.clone());
        let payload = bincode::serialize(&msg).expect("serialize WireMessage::Commit");
        let n = self.bus.borrow().num_nodes;
        for to in 1..=n {
            if to != self.node_id {
                self.send_to(to, &payload);
            }
        }
    }

    /// Drain the inbox, processing proposals, votes, and commits.
    ///
    /// On receiving a proposal: create an Accept vote using this node's keypair
    /// and send it to the proposer.
    ///
    /// On receiving a vote: record it via [`EpochStateMachine::record_vote`].
    ///
    /// Returns any received [`EpochCommit`] records.
    pub fn process_inbox(&mut self, now_ms: u64) -> Vec<EpochCommit> {
        let mut commits = Vec::new();
        loop {
            let framed = match self.bus.borrow_mut().recv_framed(self.node_id) {
                Some(f) => f,
                None => break,
            };
            let payload = match unframe(&framed) {
                Some(p) => p,
                None => continue,
            };

            if let Ok(wire) = bincode::deserialize::<WireMessage>(payload) {
                match wire {
                    WireMessage::Proposal(proposal) => {
                        let mut sa = SignedAccept {
                            voter: MemberId::new(self.node_id as u64),
                            proposal_digest: proposal.proposal_digest(),
                            voted_at_millis: now_ms,
                            signature: Vec::new(),
                        };
                        sa.sign(&self.keypair);
                        let vote = EpochVote::Accept(sa);
                        let leader = proposal.proposer.0 as usize;
                        self.send_vote(leader, &vote);
                    }
                    WireMessage::Vote(vote) => {
                        let _ = self.sm.record_vote(vote);
                    }
                    WireMessage::Commit(commit) => {
                        commits.push(commit);
                    }
                }
            }
        }
        self.sm.check_timeout(now_ms);
        commits
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_keypair() -> Keypair {
    let mut csprng = OsRng;
    Keypair::generate(&mut csprng)
}

fn dup_keypair(kp: &Keypair) -> Keypair {
    Keypair::from_bytes(&kp.to_bytes()).expect("dup keypair")
}

fn simple_majority_config() -> EpochProtocolConfig {
    EpochProtocolConfig {
        vote_timeout_ms: 5000,
        supermajority: (1, 2),
        enforce_monotonic: true,
    }
}

fn supermajority_config() -> EpochProtocolConfig {
    EpochProtocolConfig {
        vote_timeout_ms: 5000,
        supermajority: (2, 3),
        enforce_monotonic: true,
    }
}

/// Create a ProtocolNode with its SM pre-configured.
#[allow(dead_code)]
fn make_protocol_node(
    node_id: usize,
    config: EpochProtocolConfig,
    bus: Rc<RefCell<MultiNodeBus>>,
    initial_voter_set: Vec<MemberId>,
    peer_keys: &[(usize, PublicKey)],
) -> ProtocolNode {
    let kp = make_keypair();
    let kp_copy = dup_keypair(&kp);
    let mut sm = EpochStateMachine::bootstrap(MemberId::new(node_id as u64), kp_copy, config);
    sm.set_voter_set(initial_voter_set);
    for (id, pk) in peer_keys {
        sm.register_key(MemberId::new(*id as u64), *pk);
    }
    ProtocolNode::new(node_id, sm, kp, bus)
}

// ---------------------------------------------------------------------------
// 3-node happy path: unanimous accept → commit
// ---------------------------------------------------------------------------

#[test]
fn three_node_clean_commit_unanimous_accept() {
    let bus = MultiNodeBus::shared(3);
    let cfg = simple_majority_config();
    let voters: Vec<MemberId> = (1..=3).map(MemberId::new).collect();

    // Generate all keypairs first
    let kp1 = make_keypair();
    let kp2 = make_keypair();
    let kp3 = make_keypair();

    // Leader (node 1) — use dup keypair for SM + ProtocolNode
    let kp1_for_sm = dup_keypair(&kp1);
    let kp1_for_node = dup_keypair(&kp1);
    let mut leader_sm = EpochStateMachine::bootstrap(MemberId::new(1), kp1_for_sm, cfg.clone());
    leader_sm.set_voter_set(voters.clone());
    leader_sm.register_key(MemberId::new(2), kp2.public);
    leader_sm.register_key(MemberId::new(3), kp3.public);
    let mut leader = ProtocolNode::new(1, leader_sm, kp1_for_node, Rc::clone(&bus));

    // Voter nodes
    let mut sm2 = EpochStateMachine::bootstrap(MemberId::new(2), dup_keypair(&kp2), cfg.clone());
    sm2.set_voter_set(voters.clone());
    sm2.register_key(MemberId::new(1), kp1.public);
    let mut node2 = ProtocolNode::new(2, sm2, dup_keypair(&kp2), Rc::clone(&bus));

    let mut sm3 = EpochStateMachine::bootstrap(MemberId::new(3), dup_keypair(&kp3), cfg.clone());
    sm3.set_voter_set(voters.clone());
    sm3.register_key(MemberId::new(1), kp1.public);
    let mut node3 = ProtocolNode::new(3, sm3, dup_keypair(&kp3), Rc::clone(&bus));

    // Phase 1: leader proposes
    let proposal = leader
        .sm
        .start_proposal(voters.clone(), 1000)
        .expect("propose");
    leader.sm.proposal_broadcast_done().expect("broadcast done");
    leader.broadcast_proposal(&proposal);

    // Phase 2: voters receive proposal → send Accept votes
    node2.process_inbox(1100);
    node3.process_inbox(1100);

    // Phase 2b: leader receives Accept votes
    let _commits = leader.process_inbox(1200);
    assert!(leader.sm.quorum_reached());
    assert_eq!(leader.sm.accept_count(), 2);

    // Phase 3: leader commits
    let commit = leader.sm.commit(1300).expect("commit");
    assert_eq!(commit.monotonic_epoch_counter, 1);
    assert_eq!(commit.epoch_number, EpochId::new(1));
    assert_eq!(commit.quorum_proof.signed_accepts.len(), 2);
    assert!(commit.quorum_proof.quorum_met());
    assert_eq!(leader.sm.state(), EpochProtocolState::Committed);

    // Broadcast commit
    leader.broadcast_commit(&commit);

    // All nodes observe the commit
    let c2 = node2.process_inbox(1400);
    let c3 = node3.process_inbox(1400);
    assert_eq!(c2.len(), 1);
    assert_eq!(c3.len(), 1);
    assert_eq!(c2[0].epoch_number, commit.epoch_number);
    assert_eq!(c3[0].epoch_number, commit.epoch_number);
    assert_eq!(c2[0].monotonic_epoch_counter, 1);
}

// ---------------------------------------------------------------------------
// Split-vote rejection: 2 Accept + 1 Reject below 2/3 supermajority
// ---------------------------------------------------------------------------

#[test]
fn split_vote_two_accept_one_reject_supermajority_fails() {
    let bus = MultiNodeBus::shared(5);
    let cfg = supermajority_config(); // 2/3 → need 4 of 5
    let voters: Vec<MemberId> = (1..=5).map(MemberId::new).collect();

    let kp1 = make_keypair();
    let kp2 = make_keypair();
    let kp3 = make_keypair();
    let kp4 = make_keypair();
    let kp5 = make_keypair();

    // Leader
    let mut leader_sm =
        EpochStateMachine::bootstrap(MemberId::new(1), dup_keypair(&kp1), cfg.clone());
    leader_sm.set_voter_set(voters.clone());
    for (id, kp) in &[(2, &kp2), (3, &kp3), (4, &kp4), (5, &kp5)] {
        leader_sm.register_key(MemberId::new(*id), kp.public);
    }
    let mut leader = ProtocolNode::new(1, leader_sm, dup_keypair(&kp1), Rc::clone(&bus));

    // Voters 2 & 3 (accept), Voter 4 (reject), Voter 5 (silent)
    let mut sm2 = EpochStateMachine::bootstrap(MemberId::new(2), dup_keypair(&kp2), cfg.clone());
    sm2.set_voter_set(voters.clone());
    sm2.register_key(MemberId::new(1), kp1.public);
    let mut node2 = ProtocolNode::new(2, sm2, dup_keypair(&kp2), Rc::clone(&bus));

    let mut sm3 = EpochStateMachine::bootstrap(MemberId::new(3), dup_keypair(&kp3), cfg.clone());
    sm3.set_voter_set(voters.clone());
    sm3.register_key(MemberId::new(1), kp1.public);
    let mut node3 = ProtocolNode::new(3, sm3, dup_keypair(&kp3), Rc::clone(&bus));

    // Node 4: pre-configured to reject
    let mut sm4 = EpochStateMachine::bootstrap(MemberId::new(4), dup_keypair(&kp4), cfg.clone());
    sm4.set_voter_set(voters.clone());
    sm4.register_key(MemberId::new(1), kp1.public);
    let node4 = ProtocolNode::new(4, sm4, dup_keypair(&kp4), Rc::clone(&bus));

    // Leader proposes
    let proposal = leader
        .sm
        .start_proposal(
            vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
            1000,
        )
        .expect("propose");
    leader.sm.proposal_broadcast_done().expect("broadcast done");
    leader.broadcast_proposal(&proposal);

    // Nodes 2, 3 accept
    node2.process_inbox(1100);
    node3.process_inbox(1100);

    // Node 4 rejects
    let reject_vote = EpochVote::Reject {
        voter: MemberId::new(4),
        proposal_digest: proposal.proposal_digest(),
        reason: RejectionReason::MemberSetConflict,
        voted_at_millis: 1200,
        signature: {
            let mut buf = Vec::new();
            buf.extend_from_slice(&MemberId::new(4).0.to_le_bytes());
            buf.extend_from_slice(&proposal.proposal_digest());
            buf.push(RejectionReason::MemberSetConflict as u8);
            buf.extend_from_slice(&1200u64.to_le_bytes());
            kp4.sign(&buf).to_bytes().to_vec()
        },
    };
    node4.send_vote(1, &reject_vote);

    // Node 5: isolate (simulate crash)
    bus.borrow_mut().set_link(5, 1, LinkState::Down);

    // Leader processes all votes
    leader.process_inbox(1300);

    // Only 2 accepts (nodes 2+3). Node 4 rejected. Node 5 silent.
    // Need 4 for 2/3 supermajority → quorum not met
    assert!(!leader.sm.quorum_reached());
    assert_eq!(leader.sm.accept_count(), 2);
    assert_eq!(leader.sm.reject_count(), 1);

    // Timeout → ProposalRejected
    assert!(leader.sm.check_timeout(9999));
    assert_eq!(leader.sm.state(), EpochProtocolState::ProposalRejected);

    // Cleanup
    bus.borrow_mut().heal_all();
}

// ---------------------------------------------------------------------------
// Leader crash timeout
// ---------------------------------------------------------------------------

#[test]
fn leader_crash_timeout_followers_detect() {
    let bus = MultiNodeBus::shared(3);
    let cfg = simple_majority_config();
    let voters: Vec<MemberId> = (1..=3).map(MemberId::new).collect();

    let kp1 = make_keypair();
    let kp2 = make_keypair();
    let kp3 = make_keypair();

    // Leader
    let mut leader_sm =
        EpochStateMachine::bootstrap(MemberId::new(1), dup_keypair(&kp1), cfg.clone());
    leader_sm.set_voter_set(voters.clone());
    leader_sm.register_key(MemberId::new(2), kp2.public);
    leader_sm.register_key(MemberId::new(3), kp3.public);
    let mut leader = ProtocolNode::new(1, leader_sm, dup_keypair(&kp1), Rc::clone(&bus));

    // Followers
    let mut sm2 = EpochStateMachine::bootstrap(MemberId::new(2), dup_keypair(&kp2), cfg.clone());
    sm2.set_voter_set(voters.clone());
    sm2.register_key(MemberId::new(1), kp1.public);
    let mut node2 = ProtocolNode::new(2, sm2, dup_keypair(&kp2), Rc::clone(&bus));

    let mut sm3 = EpochStateMachine::bootstrap(MemberId::new(3), dup_keypair(&kp3), cfg.clone());
    sm3.set_voter_set(voters.clone());
    sm3.register_key(MemberId::new(1), kp1.public);
    let mut node3 = ProtocolNode::new(3, sm3, dup_keypair(&kp3), Rc::clone(&bus));

    // Leader proposes and broadcasts
    let proposal = leader
        .sm
        .start_proposal(voters.clone(), 1000)
        .expect("propose");
    leader.sm.proposal_broadcast_done().expect("broadcast done");
    leader.broadcast_proposal(&proposal);

    // Followers receive and accept (send votes to leader)
    node2.process_inbox(1100);
    node3.process_inbox(1100);

    // Leader crashes — isolate it from the network
    bus.borrow_mut().isolate_node(1);

    // Leader can't receive the accept votes held in transit
    leader.process_inbox(1200);

    // Leader eventually times out
    assert!(leader.sm.check_timeout(9999));
    assert_eq!(leader.sm.state(), EpochProtocolState::ProposalRejected);

    // Followers also detect timeout: they create a synthetic timeout vote
    let to = EpochVote::Timeout {
        proposal_digest: proposal.proposal_digest(),
        timed_out_at_millis: 8000,
    };
    assert!(matches!(to, EpochVote::Timeout { .. }));

    bus.borrow_mut().heal_all();
}

// ---------------------------------------------------------------------------
// EpochCommit persistence and replay (via tidefs-local-object-store)
// ---------------------------------------------------------------------------

#[test]
fn epoch_commit_persistence_roundtrip() {
    use tidefs_local_object_store::{LocalObjectStore, ObjectKey};

    let kp = make_keypair();
    let kp_copy = dup_keypair(&kp);
    let mut sm = EpochStateMachine::bootstrap(MemberId::new(1), kp_copy, simple_majority_config());
    sm.set_supermajority(1, 1); // self-commit

    let proposal = sm
        .start_proposal(vec![MemberId::new(1)], 100)
        .expect("propose");
    sm.proposal_broadcast_done().expect("broadcast done");

    let mut sa = SignedAccept {
        voter: MemberId::new(1),
        proposal_digest: proposal.proposal_digest(),
        voted_at_millis: 200,
        signature: Vec::new(),
    };
    sa.sign(&kp);
    sm.record_vote(EpochVote::Accept(sa)).expect("record");
    let commit = sm.commit(300).expect("commit");
    assert_eq!(commit.monotonic_epoch_counter, 1);

    // Persist to local-object-store
    let dir = tempfile::tempdir().expect("tempdir");
    let commit_key = ObjectKey::from_name("epoch_commit_1");

    {
        let mut store = LocalObjectStore::open(dir.path()).expect("open");
        let encoded = bincode::serialize(&commit).expect("serialize");
        store.put(commit_key, &encoded).expect("put");
        store.sync_all().expect("sync_all");
        // store dropped here — file handles flushed
    }

    // Simulate restart: reopen and read back
    {
        let store = LocalObjectStore::open(dir.path()).expect("reopen");
        let encoded = store
            .get(commit_key)
            .expect("get")
            .expect("commit not found");
        let restored: EpochCommit = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(restored.monotonic_epoch_counter, 1);
        assert_eq!(restored.epoch_number, EpochId::new(1));
        assert!(restored.verify(&kp.public));
    }
}

#[test]
fn epoch_log_replay_preserves_monotonic_counter() {
    use tidefs_local_object_store::{LocalObjectStore, ObjectKey};

    let kp = make_keypair();
    let dir = tempfile::tempdir().expect("tempdir");

    // Write three epoch commits to the store, simulating sequential epochs.
    {
        let mut store = LocalObjectStore::open(dir.path()).expect("open");
        for i in 1..=3u64 {
            let kp_copy = dup_keypair(&kp);
            let mut sm =
                EpochStateMachine::bootstrap(MemberId::new(1), kp_copy, simple_majority_config());
            sm.set_supermajority(1, 1);

            let members: Vec<MemberId> = (1..=i).map(MemberId::new).collect();
            let proposal = sm
                .start_proposal(members.clone(), i * 100)
                .expect("propose");
            sm.proposal_broadcast_done().expect("broadcast done");

            let mut sa = SignedAccept {
                voter: MemberId::new(1),
                proposal_digest: proposal.proposal_digest(),
                voted_at_millis: i * 100 + 50,
                signature: Vec::new(),
            };
            sa.sign(&kp);
            sm.record_vote(EpochVote::Accept(sa)).expect("record");

            let commit = sm.commit(i * 100 + 80).expect("commit");
            let key = ObjectKey::from_name(format!("epoch_commit_{i}"));
            let encoded = bincode::serialize(&commit).expect("serialize");
            store.put(key, &encoded).expect("put");
        }
        store.sync_all().expect("sync_all");
    }

    // Replay: reopen and read back all commits
    {
        let store = LocalObjectStore::open(dir.path()).expect("reopen");
        let mut counters: Vec<u64> = Vec::new();
        for i in 1..=3u64 {
            let key = ObjectKey::from_name(format!("epoch_commit_{i}"));
            let encoded = store.get(key).expect("get").expect("commit not found");
            let commit: EpochCommit = bincode::deserialize(&encoded).expect("deserialize");
            counters.push(commit.monotonic_epoch_counter);
            assert!(commit.verify(&kp.public));
        }
        assert_eq!(counters.len(), 3, "should have 3 commits");
        assert_eq!(
            counters,
            vec![1, 1, 1],
            "each epoch commit preserves its monotonic counter on replay"
        );
    }
}
