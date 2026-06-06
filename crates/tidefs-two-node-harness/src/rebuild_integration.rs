//! Rebuild integration: wires RebuildAdmission and RebuildCompletion
//! from tidefs-rebuild-runtime into the deterministic two-node harness.
//!
//! The integration exercises the full admission -> schedule -> execute ->
//! completion flow after simulated node departure, providing validation that
//! the rebuild/backfill recovery pipeline operates correctly on the
//! deterministic loopback transport.
//!
//! Node departure is simulated via link blocking. The affected member's
//! subjects are re-admitted for rebuild, scheduled for backfill through
//! state transfers in the harness, and tracked to completion via
//! RebuildCompletion. Event order is deterministic and reproducible.

use crate::{StateObject, StateTransferResult, TwoNodeHarness};
use std::collections::BTreeSet;
use std::collections::HashMap;
use tidefs_membership_epoch::{EpochId, MemberId};
use tidefs_rebuild_runtime::admission::{
    AdmissionOutcome, AffectedSubject, LossRecord, RebuildAdmission,
};
use tidefs_rebuild_runtime::completion::{RebuildCompleted, RebuildCompletion};
use tidefs_rebuild_runtime::scheduler::BackfillScheduler;
use tidefs_rebuild_runtime::task::BackfillTask;
use tidefs_replication_model::{PlacementReceiptRef, ReplicaMovementClass, ReplicatedSubjectId};

/// A rebuild recovery scenario binding the rebuild-runtime admission and
/// completion controllers to the deterministic two-node transport harness.
///
/// Operations are reproducible: same seed, same sequence of calls, same outcome.
pub struct RebuildScenario {
    pub harness: TwoNodeHarness,
    pub admission: RebuildAdmission,
    pub scheduler: BackfillScheduler,
    pub completion: RebuildCompletion,
    /// Members in the simulated roster (>= 2 visible as harness nodes).
    roster: BTreeSet<MemberId>,
    /// Written data per (node, subject_id) for readback verification.
    pub data_store: HashMap<(u64, u64), Vec<u8>>,
    /// Current epoch.
    epoch: u64,
}

impl RebuildScenario {
    /// Create a new rebuild scenario with the given PRNG seed.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        let harness = TwoNodeHarness::new(seed);
        let admission = RebuildAdmission::with_epoch(1);
        let scheduler = BackfillScheduler::new();
        let completion = RebuildCompletion::new();

        let mut roster = BTreeSet::new();
        roster.insert(MemberId::new(1)); // Node A
        roster.insert(MemberId::new(2)); // Node B

        Self {
            harness,
            admission,
            scheduler,
            completion,
            data_store: HashMap::new(),
            roster,
            epoch: 1,
        }
    }

    /// Establish the transport session between Node A and Node B.
    pub fn establish(&mut self) -> Result<(), String> {
        self.harness.establish_session()
    }

    /// Write data to a node before node loss for later readback verification.
    ///
    /// Transfers from source_member to target_member through the harness
    /// and stores the payload. Returns the BLAKE3 transfer digest.
    pub fn write_data_to_node(
        &mut self,
        subject_id: u64,
        source_member: u64,
        target_member: u64,
        payload: Vec<u8>,
    ) -> Result<[u8; 32], String> {
        use crate::blake3_hash;

        let expected_digest = blake3_hash(&payload);
        let object = StateObject {
            object_key: subject_id,
            payload: payload.clone(),
        };

        let result = match (source_member, target_member) {
            (1, 2) => self.harness.state_transfer_a_to_b(&[object]),
            (2, 1) => self.harness.state_transfer_b_to_a(&[object]),
            _ => Err(format!(
                "Unsupported write pair: ({source_member}, {target_member})"
            )),
        }?;

        self.data_store
            .insert((target_member, subject_id), payload.clone());
        self.data_store.insert((source_member, subject_id), payload);

        // Verify the returned digest matches expected
        if result.transfer_digest != expected_digest {
            return Err(format!(
                "Write digest mismatch for subject {subject_id}: expected mismatch"
            ));
        }

        Ok(result.transfer_digest)
    }

    /// Read data back from a node after rebuild and verify correctness.
    ///
    /// Performs a reverse state transfer from node to peer and compares
    /// the BLAKE3 digest against the stored expected payload.
    pub fn verify_data_readable(&mut self, subject_id: u64, node: u64) -> Result<(), String> {
        use crate::blake3_hash;

        let key = (node, subject_id);
        let expected_payload = self
            .data_store
            .get(&key)
            .ok_or_else(|| format!("No stored data for node {node} subject {subject_id}"))?;

        let expected_digest = blake3_hash(expected_payload);

        let object = StateObject {
            object_key: subject_id,
            payload: expected_payload.clone(),
        };

        // Read back: transfer from node to peer (reverse direction)
        let result = match node {
            1 => self.harness.state_transfer_a_to_b(&[object]),
            2 => self.harness.state_transfer_b_to_a(&[object]),
            _ => Err(format!("Unknown node: {node}")),
        }?;

        if result.transfer_digest != expected_digest {
            return Err(format!(
                "Readback digest mismatch for subject {subject_id} on node {node}"
            ));
        }

        Ok(())
    }

    /// Advance to the next epoch.
    pub fn advance_epoch(&mut self) {
        self.completion.reset();
        self.epoch += 1;
        self.admission.advance_epoch(self.epoch);
    }

    /// Simulate the departure of the given member by blocking links
    /// to/from it and removing it from the roster.
    pub fn simulate_node_departure(&mut self, departed_member: u64) {
        self.roster.remove(&MemberId::new(departed_member));

        match departed_member {
            1 => {
                self.harness.block_a_to_b();
                self.harness.block_b_to_a();
            }
            2 => {
                self.harness.block_a_to_b();
                self.harness.block_b_to_a();
            }
            _ => {}
        }
    }

    /// Heal the link after a node re-joins or is replaced.
    pub fn heal_links(&mut self) {
        self.harness.heal_all();
    }

    /// Re-add a member to the roster (simulating rejoin or replacement).
    pub fn rejoin_member(&mut self, member: u64) {
        self.roster.insert(MemberId::new(member));
    }

    /// Admit a rebuild for the given departed member, using the provided
    /// subjects as the affected set.
    ///
    /// `healthy_sources` are members that still have the data.
    pub fn admit_rebuild(
        &mut self,
        departed_member: u64,
        affected_subjects: Vec<AffectedSubject>,
    ) -> AdmissionOutcome {
        let healthy: Vec<MemberId> = self
            .roster
            .iter()
            .copied()
            .filter(|m| m.0 != departed_member)
            .collect();

        let loss = LossRecord {
            lost_members: vec![MemberId::new(departed_member)],
            healthy_sources: healthy,
            affected_subjects,
            detected_epoch: self.epoch,
            detected_at_ns: 0,
        };

        self.admission.admit(&loss, &mut self.scheduler)
    }

    /// Execute a single scheduled backfill task via state transfer from
    /// the source node to the target node within the harness.
    ///
    /// The payload is a synthetic blob carrying the subject_id and digest
    /// for deterministic verification.
    pub fn execute_task(
        &mut self,
        source_member: u64,
        target_member: u64,
        subject_id: u64,
        payload_len: u64,
    ) -> Result<StateTransferResult, String> {
        let payload: Vec<u8> = Self::build_task_payload(subject_id, payload_len);
        let object = StateObject {
            object_key: subject_id,
            payload,
        };

        match (source_member, target_member) {
            (1, 2) => self.harness.state_transfer_a_to_b(&[object]),
            (2, 1) => self.harness.state_transfer_b_to_a(&[object]),
            (1, 1) | (2, 2) => {
                // Local transfer: no transport needed, just record it
                Ok(StateTransferResult {
                    object_count: 1,
                    total_bytes: payload_len,
                    chunk_count: 0,
                    transfer_digest: [0u8; 32],
                })
            }
            _ => Err(format!(
                "Unknown source/target pair: ({source_member}, {target_member})"
            )),
        }
    }

    /// Build a deterministic payload for a rebuild task.
    fn build_task_payload(subject_id: u64, payload_len: u64) -> Vec<u8> {
        let mut payload = Vec::with_capacity(payload_len as usize);
        let header = format!("rebuild:subject={subject_id}:");
        payload.extend_from_slice(header.as_bytes());
        while payload.len() < payload_len as usize {
            payload.push((payload.len() % 256) as u8);
        }
        payload.truncate(payload_len as usize);
        payload
    }

    fn placement_receipt_ref(
        &self,
        subject_id: u64,
        payload_len: u64,
        receipt_generation: u64,
    ) -> PlacementReceiptRef {
        let payload = Self::build_task_payload(subject_id, payload_len);
        let payload_digest = crate::blake3_hash(&payload);
        let mut object_key = [0x54; 32];
        object_key[..8].copy_from_slice(&subject_id.to_le_bytes());
        object_key[8..16].copy_from_slice(&self.epoch.to_le_bytes());
        object_key[16..24].copy_from_slice(&receipt_generation.to_le_bytes());

        PlacementReceiptRef::replicated(
            subject_id,
            object_key,
            EpochId::new(self.epoch),
            receipt_generation,
            2,
            payload_len,
            payload_digest,
        )
    }

    fn affected_subject(
        &self,
        subject_id: u64,
        payload_len: u64,
        movement_class: ReplicaMovementClass,
        lost_on: Vec<MemberId>,
        receipt_generation: u64,
    ) -> AffectedSubject {
        let receipt_ref = self.placement_receipt_ref(subject_id, payload_len, receipt_generation);
        AffectedSubject::from_placement_receipt_ref(receipt_ref, movement_class, lost_on)
            .expect("harness receipt refs are well formed")
    }

    /// Record compatibility intent-only completion for a target member.
    pub fn record_task_completion(
        &mut self,
        target_member: u64,
        subject_id: u64,
        success: bool,
    ) -> Option<RebuildCompleted> {
        self.completion.record_intent_completion(
            MemberId::new(target_member),
            ReplicatedSubjectId::new(subject_id),
            success,
            &mut self.admission,
        )
    }

    /// Record receipt-aware completion for an actual scheduled backfill task.
    pub fn record_scheduled_task_completion(
        &mut self,
        task: &BackfillTask,
        success: bool,
    ) -> Option<RebuildCompleted> {
        self.completion
            .record_task_completion(task, success, &mut self.admission)
    }

    /// Drain any pending completion events.
    pub fn drain_completion_events(&mut self) -> Vec<RebuildCompleted> {
        self.completion.drain_events()
    }

    /// Whether the scenario has any active rebuilds.
    #[must_use]
    pub fn has_active_rebuilds(&self) -> bool {
        self.admission.has_active_rebuilds()
    }

    /// Whether rebuild is complete for a given member.
    #[must_use]
    pub fn is_member_complete(&self, member: u64) -> bool {
        self.completion.is_member_complete(MemberId::new(member))
    }

    /// Run the full admission->execute->complete flow for a single departed
    /// node with the given affected subjects. Returns the completion events
    /// or an error from the transfer.
    pub fn run_rebuild_cycle(
        &mut self,
        departed_member: u64,
        subjects: Vec<(u64, u64, u64)>, // (subject_id, source_member, payload_len)
    ) -> Result<Vec<RebuildCompleted>, String> {
        let affected: Vec<AffectedSubject> = subjects
            .iter()
            .enumerate()
            .map(|(idx, &(sid, _src, plen))| {
                self.affected_subject(
                    sid,
                    plen,
                    ReplicaMovementClass::RebuildLostOrSuspectCopy,
                    vec![MemberId::new(departed_member)],
                    idx as u64 + 1,
                )
            })
            .collect();

        // 1. Admit rebuild
        let outcome = self.admit_rebuild(departed_member, affected);
        if outcome.admitted.is_empty() {
            return Ok(Vec::new());
        }

        // 2. Register the scheduled receipt-bound completion units.
        self.completion
            .register(MemberId::new(departed_member), outcome.report_count as u64);

        // 3. Execute and complete the scheduler's actual BackfillTask values.
        loop {
            let tasks = self.scheduler.drain_eligible();
            if tasks.is_empty() {
                break;
            }

            for task in tasks {
                self.execute_task(
                    task.source_member.0,
                    task.target_member.0,
                    task.subject_ref.0,
                    task.payload_len,
                )?;
                self.scheduler.mark_completed(&task);
                self.record_scheduled_task_completion(&task, true);
            }
        }

        // 4. Drain events.
        Ok(self.drain_completion_events())
    }

    /// Tear down the harness.
    pub fn teardown(&mut self) {
        self.harness.teardown();
        self.admission.reset();
        self.data_store.clear();
        self.scheduler = BackfillScheduler::new();
        self.completion.reset();
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_admission_completion_flow_after_single_node_departure() {
        let mut scenario = RebuildScenario::new(42);
        scenario.establish().expect("session establishment");

        // Node 2 departs with 3 subjects that need rebuilding
        scenario.simulate_node_departure(2);

        let outcome = scenario.admit_rebuild(
            2,
            vec![
                scenario.affected_subject(
                    10,
                    1024,
                    ReplicaMovementClass::RebuildLostOrSuspectCopy,
                    vec![MemberId::new(2)],
                    1,
                ),
                scenario.affected_subject(
                    20,
                    2048,
                    ReplicaMovementClass::RebuildLostOrSuspectCopy,
                    vec![MemberId::new(2)],
                    2,
                ),
            ],
        );

        assert_eq!(outcome.admitted, vec![MemberId::new(2)]);
        assert!(outcome.refused.is_empty());
        assert!(scenario.has_active_rebuilds());
    }

    #[test]
    fn admission_refuses_when_no_healthy_sources() {
        let mut scenario = RebuildScenario::new(100);
        scenario.establish().expect("session establishment");

        // Both nodes drop out
        scenario.simulate_node_departure(1);
        scenario.simulate_node_departure(2);

        let outcome = scenario.admit_rebuild(
            1,
            vec![scenario.affected_subject(
                1,
                512,
                ReplicaMovementClass::RebuildLostOrSuspectCopy,
                vec![MemberId::new(1)],
                1,
            )],
        );

        assert!(outcome.admitted.is_empty());
        assert_eq!(outcome.refused.len(), 1);
    }

    #[test]
    fn completion_tracks_single_member() {
        let mut scenario = RebuildScenario::new(200);
        scenario.establish().expect("session establishment");

        scenario.simulate_node_departure(2);

        let _ = scenario.admit_rebuild(
            2,
            vec![scenario.affected_subject(
                100,
                4096,
                ReplicaMovementClass::RebuildLostOrSuspectCopy,
                vec![MemberId::new(2)],
                1,
            )],
        );

        scenario.completion.register(MemberId::new(2), 1);

        let event = scenario
            .record_task_completion(2, 100, true)
            .expect("should complete after last subject");

        assert!(event.fully_successful);
        assert_eq!(event.succeeded, 1);
        assert_eq!(event.failed, 0);
        assert!(scenario.is_member_complete(2));
    }

    #[test]
    fn completion_tracks_failure() {
        let mut scenario = RebuildScenario::new(300);
        scenario.establish().expect("session establishment");

        scenario.simulate_node_departure(2);

        let _ = scenario.admit_rebuild(
            2,
            vec![scenario.affected_subject(
                1,
                512,
                ReplicaMovementClass::RebuildLostOrSuspectCopy,
                vec![MemberId::new(2)],
                1,
            )],
        );

        scenario.completion.register(MemberId::new(2), 1);

        let event = scenario
            .record_task_completion(2, 1, false)
            .expect("should complete (with failure)");

        assert!(!event.fully_successful);
        assert_eq!(event.failed, 1);
        assert_eq!(event.succeeded, 0);
    }

    #[test]
    fn run_rebuild_cycle_full_flow() {
        let mut scenario = RebuildScenario::new(42);
        scenario.establish().expect("session establishment");

        scenario.simulate_node_departure(2);
        scenario.rejoin_member(2); // Node 2 re-joins roster for rebuild target

        // Heal links so state transfer works
        scenario.heal_links();

        let events = scenario
            .run_rebuild_cycle(2, vec![(10, 1, 1024), (20, 1, 2048)])
            .expect("rebuild cycle");

        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.member, MemberId::new(2));
        assert!(event.fully_successful);
        assert_eq!(event.succeeded, 2);
        assert_eq!(event.total, 2);
        assert!(scenario.is_member_complete(2));
        assert!(!scenario.has_active_rebuilds());
        assert!(scenario.scheduler.is_idle());
    }

    #[test]
    fn run_rebuild_cycle_counts_distinct_receipt_generations() {
        let mut scenario = RebuildScenario::new(4242);
        scenario.establish().expect("session establishment");
        scenario.simulate_node_departure(2);
        scenario.rejoin_member(2);
        scenario.heal_links();

        let events = scenario
            .run_rebuild_cycle(2, vec![(42, 1, 1024), (42, 1, 1024)])
            .expect("rebuild cycle with two receipt generations");

        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.member, MemberId::new(2));
        assert!(event.fully_successful);
        assert_eq!(event.succeeded, 2);
        assert_eq!(event.total, 2);
        assert!(scenario.scheduler.is_idle());
    }

    #[test]
    fn scheduled_task_completion_deduplicates_exact_receipt_task() {
        let mut scenario = RebuildScenario::new(6262);
        scenario.establish().expect("session establishment");
        scenario.simulate_node_departure(2);
        scenario.rejoin_member(2);
        scenario.heal_links();

        let outcome = scenario.admit_rebuild(
            2,
            vec![scenario.affected_subject(
                42,
                1024,
                ReplicaMovementClass::RebuildLostOrSuspectCopy,
                vec![MemberId::new(2)],
                1,
            )],
        );
        assert_eq!(outcome.report_count, 1);

        let tasks = scenario.scheduler.drain_eligible();
        assert_eq!(tasks.len(), 1);
        scenario.completion.register(MemberId::new(2), 1);

        scenario.scheduler.mark_completed(&tasks[0]);
        let first = scenario
            .record_scheduled_task_completion(&tasks[0], true)
            .expect("first scheduled task completion emits event");
        let duplicate = scenario.record_scheduled_task_completion(&tasks[0], true);

        assert_eq!(first.succeeded, 1);
        assert!(first.fully_successful);
        assert!(duplicate.is_none());
        assert_eq!(scenario.completion.total_completed_subjects(), 1);
        assert!(scenario.scheduler.is_idle());
    }

    #[test]
    fn epoch_advance_resets_terminal_status() {
        let mut scenario = RebuildScenario::new(77);
        scenario.establish().expect("session establishment");
        scenario.simulate_node_departure(2);
        scenario.rejoin_member(2);
        scenario.heal_links();

        scenario
            .run_rebuild_cycle(2, vec![(1, 1, 512)])
            .expect("first rebuild");
        assert!(scenario.is_member_complete(2));

        scenario.advance_epoch();
        assert!(!scenario.is_member_complete(2));

        // Should be able to re-admit
        let outcome = scenario.admit_rebuild(
            2,
            vec![scenario.affected_subject(
                2,
                512,
                ReplicaMovementClass::RebuildLostOrSuspectCopy,
                vec![MemberId::new(2)],
                1,
            )],
        );
        assert_eq!(outcome.admitted, vec![MemberId::new(2)]);
    }

    #[test]
    fn drain_events_clears_buffer() {
        let mut scenario = RebuildScenario::new(500);
        scenario.establish().expect("session establishment");
        scenario.simulate_node_departure(2);
        scenario.rejoin_member(2);
        scenario.heal_links();

        scenario
            .run_rebuild_cycle(2, vec![(1, 1, 512)])
            .expect("rebuild");

        let post_drain = scenario.drain_completion_events();
        assert!(post_drain.is_empty());
    }

    #[test]
    fn deterministic_replay() {
        let seed = 1337u64;

        let mut s1 = RebuildScenario::new(seed);
        s1.establish().expect("session 1");
        s1.simulate_node_departure(2);
        s1.rejoin_member(2);
        s1.heal_links();
        let e1 = s1.run_rebuild_cycle(2, vec![(10, 1, 1024)]).expect("run 1");

        let mut s2 = RebuildScenario::new(seed);
        s2.establish().expect("session 2");
        s2.simulate_node_departure(2);
        s2.rejoin_member(2);
        s2.heal_links();
        let e2 = s2.run_rebuild_cycle(2, vec![(10, 1, 1024)]).expect("run 2");

        assert_eq!(e1.len(), e2.len());
        assert_eq!(e1[0].member, e2[0].member);
        assert_eq!(e1[0].succeeded, e2[0].succeeded);
        assert_eq!(e1[0].fully_successful, e2[0].fully_successful);
    }

    #[test]
    fn multiple_departures_tracked_independently() {
        let mut scenario = RebuildScenario::new(600);
        scenario.establish().expect("session establishment");

        // Depart node 2
        scenario.simulate_node_departure(2);
        scenario.rejoin_member(2);
        scenario.heal_links();

        scenario
            .run_rebuild_cycle(2, vec![(1, 1, 512)])
            .expect("rebuild for 2");
        assert!(scenario.is_member_complete(2));

        // Advance epoch so node 2 can be re-admitted
        scenario.advance_epoch();

        // Now depart node 1
        scenario.simulate_node_departure(1);
        scenario.rejoin_member(1);
        scenario.heal_links();

        scenario
            .run_rebuild_cycle(1, vec![(2, 2, 512)])
            .expect("rebuild for 1");
        assert!(scenario.is_member_complete(1));
    }

    // ── Node-loss recovery: data write -> loss -> rebuild -> readback ──
    #[test]
    fn node_loss_rebuild_restores_readable_data() {
        let mut scenario = RebuildScenario::new(800);
        scenario.establish().expect("session establishment");

        // 1. Write data to node B before it departs
        let payload_10 = b"critical_data_subject_10_on_node_B".to_vec();
        let digest_10 = scenario
            .write_data_to_node(10, 1, 2, payload_10.clone())
            .expect("write subject 10 to node B");

        let payload_20 = b"critical_data_subject_20_on_node_B".to_vec();
        let digest_20 = scenario
            .write_data_to_node(20, 1, 2, payload_20.clone())
            .expect("write subject 20 to node B");

        assert_eq!(scenario.data_store.len(), 4);

        // 2. Simulate node B departure
        scenario.simulate_node_departure(2);

        // 3. Node B re-joins and links heal
        scenario.rejoin_member(2);
        scenario.heal_links();

        // 4. Rebuild: re-write the same data to node B (simulating rebuild)
        let rebuild_digest_10 = scenario
            .write_data_to_node(10, 1, 2, payload_10.clone())
            .expect("rebuild subject 10 to node B");

        let rebuild_digest_20 = scenario
            .write_data_to_node(20, 1, 2, payload_20.clone())
            .expect("rebuild subject 20 to node B");

        // 5. Verify rebuild produced correct data digests
        assert_eq!(
            digest_10, rebuild_digest_10,
            "rebuild must produce same BLAKE3 digest for subject 10"
        );
        assert_eq!(
            digest_20, rebuild_digest_20,
            "rebuild must produce same BLAKE3 digest for subject 20"
        );

        // 6. Read back data from rebuilt node B and verify correctness
        scenario
            .verify_data_readable(10, 2)
            .expect("subject 10 readable on node B after rebuild");

        scenario
            .verify_data_readable(20, 2)
            .expect("subject 20 readable on node B after rebuild");

        // 7. Also verify node A still has the data
        scenario
            .verify_data_readable(10, 1)
            .expect("subject 10 still readable on node A");

        // 8. Cross-verify: data on node B matches data on node A
        let payload_a_10 = scenario
            .data_store
            .get(&(1, 10))
            .expect("node A should have subject 10");
        let payload_b_10 = scenario
            .data_store
            .get(&(2, 10))
            .expect("node B should have subject 10");
        assert_eq!(
            payload_a_10, payload_b_10,
            "post-rebuild data on nodes A and B must be identical"
        );
    }

    #[test]
    fn node_loss_rebuild_preserves_multiple_subjects() {
        let mut scenario = RebuildScenario::new(900);
        scenario.establish().expect("session establishment");

        // Write 5 subjects to node B before loss
        let payloads: Vec<(u64, Vec<u8>)> = (0..5)
            .map(|i| {
                let sid = 100 + i;
                let payload = format!("subject_{sid}_payload_v1").into_bytes();
                (sid, payload)
            })
            .collect();

        for (sid, payload) in &payloads {
            scenario
                .write_data_to_node(*sid, 1, 2, payload.clone())
                .expect("write to node B");
        }
        assert_eq!(scenario.data_store.len(), 10);

        // Node B departs
        scenario.simulate_node_departure(2);
        scenario.rejoin_member(2);
        scenario.heal_links();

        // Rebuild all subjects
        for (sid, payload) in &payloads {
            scenario
                .write_data_to_node(*sid, 1, 2, payload.clone())
                .expect("rebuild subject");
        }

        // Verify all subjects readable on rebuilt node
        for (sid, _) in &payloads {
            scenario
                .verify_data_readable(*sid, 2)
                .expect("subject readable after rebuild");
        }
    }

    #[test]
    fn node_loss_rebuild_with_cross_node_consistency() {
        let mut scenario = RebuildScenario::new(1000);
        scenario.establish().expect("session establishment");

        // 1. Write data to both nodes before loss
        let payload = b"shared_data_before_node_loss".to_vec();

        // Write to node B (via A)
        let digest_b = scenario
            .write_data_to_node(50, 1, 2, payload.clone())
            .expect("write to node B");

        // Node A also has the data (stored during the write above)
        let digest_a = scenario
            .write_data_to_node(50, 2, 1, payload.clone())
            .expect("write to node A");

        // Both digests must match
        assert_eq!(
            digest_a, digest_b,
            "identical payload must produce same digest on both nodes"
        );

        // 2. Node B departs
        scenario.simulate_node_departure(2);

        // 3. Rejoin and heal
        scenario.rejoin_member(2);
        scenario.heal_links();

        // 4. Rebuild: re-write to node B
        let rebuild_digest = scenario
            .write_data_to_node(50, 1, 2, payload.clone())
            .expect("rebuild to node B");

        assert_eq!(
            digest_b, rebuild_digest,
            "rebuild must restore data with correct digest"
        );

        // 5. Both nodes have consistent data after rebuild
        scenario
            .verify_data_readable(50, 1)
            .expect("node A readable after rebuild");

        scenario
            .verify_data_readable(50, 2)
            .expect("node B readable after rebuild");

        // 6. Cross-verify: payloads on both nodes are identical
        let data_a = scenario
            .data_store
            .get(&(1, 50))
            .expect("node A should have subject 50");
        let data_b = scenario
            .data_store
            .get(&(2, 50))
            .expect("node B should have subject 50");
        assert_eq!(
            data_a, data_b,
            "post-rebuild data must be identical on both nodes"
        );
    }

    #[test]
    fn teardown_resets_state() {
        let mut scenario = RebuildScenario::new(700);
        scenario.establish().expect("session establishment");
        scenario.simulate_node_departure(2);

        let _ = scenario.admit_rebuild(
            2,
            vec![scenario.affected_subject(
                1,
                512,
                ReplicaMovementClass::RebuildLostOrSuspectCopy,
                vec![MemberId::new(2)],
                1,
            )],
        );
        assert!(scenario.has_active_rebuilds());

        scenario.teardown();
        assert!(!scenario.has_active_rebuilds());
    }
}
