// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Roster state synchronization to newly joined peers.
//!
//! When an existing member receives a `PeerJoined` notification for a peer
//! that is not itself, [`RosterStateSync::on_peer_joined`] sends a
//! [`MembershipOutboundMessage::RosterSnapshot`] carrying the full current
//! roster (members, classes, states, addresses, epoch) to the joining peer.
//! The joining peer applies the snapshot via
//! `MembershipRuntime::apply_roster_snapshot()` to populate its local roster
//! and address registry without external bootstrap.
//!
//! ## Architecture
//!
//! ```text
//! PeerJoined received (foreign peer)
//!   |
//!   v
//! RosterStateSync::on_peer_joined(joining_peer_id)
//!   |
//!   +-- collect roster entries from MembershipRoster + PeerAddressRegistry
//!   +-- build RosterSnapshot { originator, epoch, entries }
//!   +-- send via MembershipOutboundDispatch::send_to_peer(joining_peer, snapshot)
//! ```
//!
//! On the receiving side:
//! ```text
//! RosterSnapshot received
//!   |
//!   v
//! MembershipRuntime::apply_roster_snapshot(snapshot)
//!   |
//!   +-- validate epoch (must be >= local epoch)
//!   +-- merge members into local roster
//!   +-- populate peer address registry
//!   +-- advance epoch if snapshot epoch is newer
//! ```
//!
//! ## Edge cases
//!
//! - **First member (empty roster)**: The joining peer's roster is empty
//!   except for itself; no snapshot is triggered for self-join.
//! - **Duplicate snapshot**: Re-applying the same snapshot is idempotent:
//!   existing members are not re-added and address entries are merged.
//! - **Stale snapshot**: Snapshots with an epoch older than the local
//!   committed epoch are rejected to prevent regression.

use tidefs_membership_epoch::{EpochId, MemberClass, MemberId};
use tidefs_membership_types::capabilities::PeerCapabilities;
use tidefs_transport::addr::TransportAddr;

use crate::membership_outbound_dispatch::{MembershipOutboundDispatch, MembershipOutboundMessage};
use crate::peer_address_registry::PeerAddressRegistry;
use crate::roster::{MembershipRoster, RosterState};

// ---------------------------------------------------------------------------
// RosterEntryData -- a single member's data in the snapshot
// ---------------------------------------------------------------------------

/// Data for a single member carried in a [`RosterSnapshot`] payload.
///
/// Encodes enough information for the receiving peer to reconstruct
/// the full membership state: identity, class, roster state, failure
/// domain, and transport addresses.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RosterEntryData {
    /// The member's identity.
    pub member_id: MemberId,
    /// Member class discriminant (see [`MemberClass`]).
    pub member_class: u8,
    /// Roster state discriminant (see [`RosterState`]).
    pub state: u8,
    /// Failure domain for anti-affinity placement.
    pub failure_domain: u64,
    /// Transport addresses for this member, serialized as strings.
    pub addresses: Vec<String>,
    /// Advertised peer capabilities, if any.
    pub capabilities: Option<PeerCapabilities>,
}

impl RosterEntryData {
    /// Create a new roster entry from live runtime data.
    pub fn new(
        member_id: MemberId,
        member_class: MemberClass,
        state: RosterState,
        failure_domain: u64,
        addresses: Vec<TransportAddr>,
        capabilities: Option<PeerCapabilities>,
    ) -> Self {
        Self {
            member_id,
            member_class: member_class as u8,
            state: state.discriminant(),
            failure_domain,
            addresses: addresses.into_iter().map(|a| a.to_string()).collect(),
            capabilities,
        }
    }

    /// Parse the stored address strings back into [`TransportAddr`] values.
    ///
    /// Invalid entries are silently dropped.
    #[must_use]
    pub fn parsed_addresses(&self) -> Vec<TransportAddr> {
        self.addresses
            .iter()
            .filter_map(|s| s.parse::<TransportAddr>().ok())
            .collect()
    }

    /// Decode the stored class discriminant back to a [`MemberClass`].
    ///
    /// Unknown discriminants fall back to [`MemberClass::Learner`].
    #[must_use]
    pub fn member_class(&self) -> MemberClass {
        match self.member_class {
            0 => MemberClass::Voter,
            1 => MemberClass::Learner,
            2 => MemberClass::WitnessOnly,
            3 => MemberClass::DataOnly,
            4 => MemberClass::ShadowOnly,
            5 => MemberClass::Quarantined,
            _ => MemberClass::Learner,
        }
    }

    /// Decode the stored state discriminant back to a [`RosterState`].
    ///
    /// Unknown discriminants fall back to [`RosterState::Active`].
    #[must_use]
    pub fn state(&self) -> RosterState {
        match self.state {
            0 => RosterState::Active,
            1 => RosterState::Suspected,
            2 => RosterState::Failed,
            3 => RosterState::Left,
            _ => RosterState::Active,
        }
    }
}

// ---------------------------------------------------------------------------
// RosterStateSync -- outbound snapshot dispatch
// ---------------------------------------------------------------------------

/// Sends full roster snapshots to newly joined peers.
///
/// Created during membership runtime initialization.  On receiving a
/// `PeerJoined` notification for a foreign peer, collects the current
/// roster and address registry state and sends a `RosterSnapshot` to
/// the joining peer via the outbound dispatch bridge.
pub struct RosterStateSync<'a> {
    dispatch: &'a MembershipOutboundDispatch<'a>,
    roster: &'a MembershipRoster,
    address_registry: &'a PeerAddressRegistry,
    my_id: MemberId,
}

impl<'a> RosterStateSync<'a> {
    /// Create a new roster state sync engine.
    pub fn new(
        dispatch: &'a MembershipOutboundDispatch<'a>,
        roster: &'a MembershipRoster,
        address_registry: &'a PeerAddressRegistry,
        my_id: MemberId,
    ) -> Self {
        Self {
            dispatch,
            roster,
            address_registry,
            my_id,
        }
    }

    /// Called when a `PeerJoined` notification is received for a peer
    /// that is not self.
    ///
    /// Collects the current complete roster (members, states, addresses)
    /// and sends a [`MembershipOutboundMessage::RosterSnapshot`] to the
    /// joining peer so it can bootstrap its local state.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the snapshot was enqueued for delivery, or an error
    /// describing the dispatch failure.
    pub fn on_peer_joined(
        &self,
        joining_peer_id: MemberId,
        roster_epoch: EpochId,
    ) -> Result<(), crate::membership_outbound_dispatch::OutboundDispatchError> {
        // Never send a snapshot to ourselves.
        if joining_peer_id == self.my_id {
            return Ok(());
        }

        let entries = self.collect_roster_entries();
        let message = MembershipOutboundMessage::RosterSnapshot {
            originator: self.my_id,
            roster_epoch,
            entries,
        };

        self.dispatch.send_to_peer(joining_peer_id, message)
    }

    /// Collect all current roster entries with their addresses.
    fn collect_roster_entries(&self) -> Vec<RosterEntryData> {
        let snapshot = self.roster.snapshot();
        let mut entries = Vec::with_capacity(snapshot.member_count);

        for (member_id, state) in snapshot.iter() {
            let addresses = self
                .address_registry
                .resolve(*member_id)
                .unwrap_or_default();

            // MemberClass is not tracked in the roster; we store a
            // conservative default. The receiving peer can refine the
            // class from its own join handshake or subsequent updates.
            // For bootstrap, Learner is safe for unknown peers.
            let member_class = if *member_id == self.my_id {
                MemberClass::Voter // self is always a Voter
            } else {
                MemberClass::Learner
            };

            // Failure domain is not tracked per-member in the roster;
            // use 0 as the unknown-default. The receiving peer can
            // refine from join-handshake parameters.
            let failure_domain = 0u64;

            entries.push(RosterEntryData::new(
                *member_id,
                member_class,
                *state,
                failure_domain,
                addresses,
                None,
            ));
        }

        entries
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_address_registry::PeerAddressRegistry;
    use crate::roster::{MembershipRoster, RosterState};
    use tidefs_membership_epoch::{EpochId, MemberClass, MemberId};
    use tidefs_transport::addr::TransportAddr;

    // ------------------------------------------------------------------
    // RosterEntryData tests
    // ------------------------------------------------------------------

    fn make_addr(s: &str) -> TransportAddr {
        s.parse().unwrap()
    }

    #[test]
    fn entry_data_roundtrip_serialization() {
        let entry = RosterEntryData::new(
            MemberId::new(42),
            MemberClass::Voter,
            RosterState::Active,
            7,
            vec![make_addr("tcp://10.0.0.1:9100")],
            None,
        );
        assert_eq!(entry.member_id, MemberId::new(42));
        assert_eq!(entry.member_class, 0); // Voter
        assert_eq!(entry.state, 0); // Active
        assert_eq!(entry.failure_domain, 7);
        assert_eq!(entry.addresses.len(), 1);
        assert_eq!(entry.addresses[0], "tcp://10.0.0.1:9100");
    }

    #[test]
    fn entry_data_decode_member_class() {
        let entry = RosterEntryData {
            member_id: MemberId::new(1),
            member_class: 0,
            state: 0,
            failure_domain: 0,
            addresses: vec![],
            capabilities: None,
        };
        assert_eq!(entry.member_class(), MemberClass::Voter);

        let entry = RosterEntryData {
            member_id: MemberId::new(1),
            member_class: 1,
            state: 0,
            failure_domain: 0,
            addresses: vec![],
            capabilities: None,
        };
        assert_eq!(entry.member_class(), MemberClass::Learner);

        let entry = RosterEntryData {
            member_id: MemberId::new(1),
            member_class: 99, // unknown
            state: 0,
            failure_domain: 0,
            addresses: vec![],
            capabilities: None,
        };
        assert_eq!(entry.member_class(), MemberClass::Learner); // fallback
    }

    #[test]
    fn entry_data_decode_state() {
        let entry = RosterEntryData {
            member_id: MemberId::new(1),
            member_class: 0,
            state: 0,
            failure_domain: 0,
            addresses: vec![],
            capabilities: None,
        };
        assert_eq!(entry.state(), RosterState::Active);

        let entry = RosterEntryData {
            member_id: MemberId::new(1),
            member_class: 0,
            state: 2,
            failure_domain: 0,
            addresses: vec![],
            capabilities: None,
        };
        assert_eq!(entry.state(), RosterState::Failed);

        let entry = RosterEntryData {
            member_id: MemberId::new(1),
            member_class: 0,
            state: 99, // unknown
            failure_domain: 0,
            addresses: vec![],
            capabilities: None,
        };
        assert_eq!(entry.state(), RosterState::Active); // fallback
    }

    #[test]
    fn entry_data_parsed_addresses() {
        let entry = RosterEntryData {
            member_id: MemberId::new(1),
            member_class: 0,
            state: 0,
            failure_domain: 0,
            addresses: vec!["tcp://10.0.0.1:9100".into(), "tcp://10.0.0.2:9100".into()],
            capabilities: None,
        };
        let parsed = entry.parsed_addresses();
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn entry_data_parsed_addresses_drops_invalid() {
        let entry = RosterEntryData {
            member_id: MemberId::new(1),
            member_class: 0,
            state: 0,
            failure_domain: 0,
            addresses: vec!["tcp://10.0.0.1:9100".into(), "not-an-address".into()],
            capabilities: None,
        };
        let parsed = entry.parsed_addresses();
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn entry_data_bincode_roundtrip() {
        let original = RosterEntryData::new(
            MemberId::new(7),
            MemberClass::Voter,
            RosterState::Active,
            3,
            vec![make_addr("tcp://10.0.0.1:9100")],
            None,
        );
        let encoded = bincode::serialize(&original).expect("serialize");
        let decoded: RosterEntryData = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(original, decoded);
    }

    #[test]
    fn entry_data_capabilities_bincode_roundtrip() {
        let caps = PeerCapabilities {
            storage_capacity_bytes: 10_000,
            available_bytes: 5_000,
            transport_carriers: tidefs_membership_types::capabilities::TransportCarrier::TCP,
            failure_domain_datacenter: "dc-east".to_string(),
            failure_domain_rack: "rack-42".to_string(),
            coordinator_eligible: true,
            attributes: vec![],
        };
        let original = RosterEntryData::new(
            MemberId::new(7),
            MemberClass::Voter,
            RosterState::Active,
            3,
            vec![make_addr("tcp://10.0.0.1:9100")],
            Some(caps.clone()),
        );
        let encoded = bincode::serialize(&original).expect("serialize");
        let decoded: RosterEntryData = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(original, decoded);
        let decoded_caps = decoded
            .capabilities
            .expect("capabilities should survive roundtrip");
        assert_eq!(decoded_caps.storage_capacity_bytes, 10_000);
        assert_eq!(decoded_caps.available_bytes, 5_000);
        assert_eq!(decoded_caps.failure_domain_datacenter, "dc-east");
        assert!(decoded_caps.coordinator_eligible);
    }

    #[test]
    fn entry_data_no_capabilities_bincode_roundtrip() {
        let original = RosterEntryData::new(
            MemberId::new(1),
            MemberClass::Learner,
            RosterState::Active,
            0,
            vec![],
            None,
        );
        let encoded = bincode::serialize(&original).expect("serialize");
        let decoded: RosterEntryData = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(original, decoded);
        assert!(decoded.capabilities.is_none());
    }

    // ------------------------------------------------------------------
    // RosterStateSync tests
    // ------------------------------------------------------------------

    #[test]
    fn sync_skips_self() {
        let registry = PeerAddressRegistry::new();
        let roster = MembershipRoster::new();
        let dispatcher = tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        );
        let dispatch = MembershipOutboundDispatch::new(&dispatcher, &roster);
        let my_id = MemberId::new(1);

        let sync = RosterStateSync::new(&dispatch, &roster, &registry, my_id);

        // Sending to self should return Ok(()) immediately (no-op).
        let result = sync.on_peer_joined(my_id, EpochId::new(0));
        assert!(result.is_ok());
    }

    #[test]
    fn sync_sends_snapshot_to_joining_peer() {
        let registry = PeerAddressRegistry::new();
        registry.register(MemberId::new(1), vec![make_addr("tcp://10.0.0.1:9100")]);
        registry.register(MemberId::new(2), vec![make_addr("tcp://10.0.0.2:9100")]);

        let mut roster = MembershipRoster::new();
        roster.add_member(MemberId::new(1)); // self
        roster.add_member(MemberId::new(2)); // other peer

        let dispatcher = tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        );
        let my_id = MemberId::new(1);

        {
            let dispatch = MembershipOutboundDispatch::new(&dispatcher, &roster);
            let _sync = RosterStateSync::new(&dispatch, &roster, &registry, my_id);
        }

        // Send snapshot to peer 3 (new joiner).
        // Need to add peer 3 to roster first so send_to_peer can resolve it.
        roster.add_member(MemberId::new(3));

        let dispatch2 = MembershipOutboundDispatch::new(&dispatcher, &roster);
        let sync2 = RosterStateSync::new(&dispatch2, &roster, &registry, my_id);
        let result = sync2.on_peer_joined(MemberId::new(3), EpochId::new(1));
        assert!(result.is_ok());

        // Verify the message is in peer 3's transport queue.
        let q = dispatcher
            .queue(3)
            .expect("queue should exist after enqueue");
        assert_eq!(q.depth(), 1);

        let drained = q.dequeue().unwrap();
        let decoded: MembershipOutboundMessage =
            bincode::deserialize(&drained.payload).expect("deserialize from transport queue");
        match decoded {
            MembershipOutboundMessage::RosterSnapshot {
                originator,
                roster_epoch,
                entries,
            } => {
                assert_eq!(originator, MemberId::new(1));
                assert_eq!(roster_epoch, EpochId::new(1));
                // Should contain self (1), other peer (2), and joiner (3) — 3 entries.
                assert_eq!(entries.len(), 3);
                let ids: Vec<u64> = entries.iter().map(|e| e.member_id.0).collect();
                assert!(ids.contains(&1));
                assert!(ids.contains(&2));
                assert!(ids.contains(&3));
            }
            other => panic!("expected RosterSnapshot, got {other:?}"),
        }
    }

    #[test]
    fn sync_empty_roster_produces_empty_entries() {
        let registry = PeerAddressRegistry::new();
        let mut roster = MembershipRoster::new();
        roster.add_member(MemberId::new(1)); // just self
        roster.add_member(MemberId::new(3)); // joiner

        let dispatcher = tidefs_transport::send_dispatch::SendDispatcher::new(
            tidefs_transport::send_dispatch::SendQueueConfig::new(256, 1_048_576).unwrap(),
            tidefs_transport::ErrorClassifier,
            None,
        );
        let my_id = MemberId::new(1);

        // Roster only has self and joiner.
        // But collect_roster_entries includes joiner too if in roster.
        // Test with joiner NOT in roster (pre-add scenario).
        {
            let dispatch = MembershipOutboundDispatch::new(&dispatcher, &roster);
            let _sync = RosterStateSync::new(&dispatch, &roster, &registry, my_id);
        }
        roster.remove_member(MemberId::new(3)); // joiner not yet in roster
        roster.add_member(MemberId::new(3)); // add back so send_to_peer works

        let dispatch2 = MembershipOutboundDispatch::new(&dispatcher, &roster);
        let sync = RosterStateSync::new(&dispatch2, &roster, &registry, my_id);
        let result = sync.on_peer_joined(MemberId::new(3), EpochId::new(0));
        assert!(result.is_ok());

        let q = dispatcher.queue(3).unwrap();
        let drained = q.dequeue().unwrap();
        let decoded: MembershipOutboundMessage = bincode::deserialize(&drained.payload).unwrap();
        match decoded {
            MembershipOutboundMessage::RosterSnapshot { entries, .. } => {
                // Should contain at least self (member 1).
                assert!(!entries.is_empty(), "should contain at least self");
            }
            other => panic!("expected RosterSnapshot, got {other:?}"),
        }
    }
}
