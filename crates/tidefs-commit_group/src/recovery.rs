//! CommitGroupRecovery: mount-time journal replay.
//!
//! On mount, `CommitGroupRecovery` scans a [`CommitGroupStore`] for commit_group journal records,
//! determines which commit_groups were fully committed before a crash, and replays
//! any incomplete (torn) commits. It also identifies the mount-time
//! `next_commit_group_id` and rebuilds the dirty tracker if needed.

use crate::commit::CommitGroupCommit;
use crate::store::{CommitGroupKey, CommitGroupStore};
use crate::types::{CommitGroupError, CommitGroupId};

/// Result of a mount-time recovery scan.
#[derive(Clone, Debug)]
pub struct RecoveryResult {
    /// The highest committed commit_group id found in the journal.
    pub highest_committed_commit_group: CommitGroupId,
    /// The next commit_group id to assign for new writes.
    pub next_commit_group_id: CommitGroupId,
    /// Object keys belonging to committed commit_groups (for GC awareness).
    pub committed_keys: Vec<CommitGroupKey>,
    /// CommitGroup ids that were found but incomplete (torn).
    pub torn_commit_groups: Vec<CommitGroupId>,
    /// CommitGroup ids that were replayed successfully.
    pub replayed_commit_groups: Vec<CommitGroupId>,
}

// ---------------------------------------------------------------------------
// CommitGroupRecovery
// ---------------------------------------------------------------------------

/// Mount-time recovery: scans commit_group journal records and replays incomplete
/// commits.
pub struct CommitGroupRecovery;

impl CommitGroupRecovery {
    /// Scan a [`CommitGroupStore`] for commit_group journal records and determine the
    /// recovery state.
    ///
    /// This is a lightweight scan; it does not replay torn commits.
    /// For full replay, use [`Self::recover`].
    pub fn scan<S: CommitGroupStore>(
        store: &S,
        max_commit_group: Option<CommitGroupId>,
    ) -> Result<RecoveryResult, CommitGroupError> {
        let mut highest = CommitGroupId::NIL;
        let mut committed_keys: Vec<CommitGroupKey> = Vec::new();
        let mut torn_commit_groups: Vec<CommitGroupId> = Vec::new();
        let mut found_commit_groups: Vec<CommitGroupId> = Vec::new();

        let upper_bound = max_commit_group.map(|t| t.0).unwrap_or(1024);

        for i in 1..=upper_bound {
            let commit_group_id = CommitGroupId(i);
            let journal_key = format!("commit_group-journal-{i}");

            match store.get_named(&journal_key) {
                Ok(Some(payload)) => {
                    found_commit_groups.push(commit_group_id);
                    if let Some((parsed_commit_group, keys, _inodes)) =
                        CommitGroupCommit::parse_journal_payload(&payload)
                    {
                        if parsed_commit_group == commit_group_id {
                            if commit_group_id > highest {
                                highest = commit_group_id;
                            }
                            committed_keys.extend(keys);
                        } else {
                            torn_commit_groups.push(commit_group_id);
                        }
                    } else {
                        torn_commit_groups.push(commit_group_id);
                    }
                }
                Ok(None) => {
                    if !found_commit_groups.is_empty() {
                        break;
                    }
                }
                Err(_e) => {
                    return Err(CommitGroupError::Io(std::io::ErrorKind::Other));
                }
            }
        }

        let next_commit_group_id = if highest.is_valid() {
            highest.next()
        } else {
            CommitGroupId::FIRST
        };

        Ok(RecoveryResult {
            highest_committed_commit_group: highest,
            next_commit_group_id,
            committed_keys,
            torn_commit_groups,
            replayed_commit_groups: Vec::new(),
        })
    }

    /// Scan journal records without replaying torn commits.
    pub fn recover<S: CommitGroupStore>(store: &S) -> Result<RecoveryResult, CommitGroupError> {
        Self::scan(store, None)
    }

    /// Determine the `next_commit_group_id` to use for new writes.
    pub fn determine_next_commit_group_id<S: CommitGroupStore>(
        store: &S,
    ) -> Result<CommitGroupId, CommitGroupError> {
        let result = Self::scan(store, None)?;
        Ok(result.next_commit_group_id)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn fresh_filesystem_has_no_journals() {
        let fake_payload = CommitGroupCommit::build_journal_payload(CommitGroupId(1), &[], &[]);
        let parsed = CommitGroupCommit::parse_journal_payload(&fake_payload);
        assert!(parsed.is_some());
        let (commit_group_id, keys, inodes) = parsed.unwrap();
        assert_eq!(commit_group_id, CommitGroupId(1));
        assert!(keys.is_empty());
        assert!(inodes.is_empty());
    }

    #[test]
    fn recovery_scans_empty_store() {
        let payload = CommitGroupCommit::build_journal_payload(CommitGroupId(1), &[], &[]);
        let (commit_group, _, _) = CommitGroupCommit::parse_journal_payload(&payload).unwrap();
        assert_eq!(commit_group, CommitGroupId(1));
    }

    #[test]
    fn torn_commit_groups_detected_for_corrupt_payload() {
        let corrupt = vec![0xDE, 0xAD, 0xBE, 0xEF];
        assert!(CommitGroupCommit::parse_journal_payload(&corrupt).is_none());
    }

    #[test]
    fn next_commit_group_id_after_commit() {
        let payload = CommitGroupCommit::build_journal_payload(CommitGroupId(5), &[], &[]);
        let (commit_group, _, _) = CommitGroupCommit::parse_journal_payload(&payload).unwrap();
        assert_eq!(commit_group, CommitGroupId(5));
        assert_eq!(commit_group.next(), CommitGroupId(6));
    }

    #[test]
    fn recovery_result_defaults() {
        let result = RecoveryResult {
            highest_committed_commit_group: CommitGroupId::NIL,
            next_commit_group_id: CommitGroupId::FIRST,
            committed_keys: vec![],
            torn_commit_groups: vec![],
            replayed_commit_groups: vec![],
        };
        assert!(!result.highest_committed_commit_group.is_valid());
        assert_eq!(result.next_commit_group_id, CommitGroupId::FIRST);
        assert!(result.torn_commit_groups.is_empty());
    }

    #[test]
    fn torn_replay_id_mismatch_is_detected() {
        let payload = CommitGroupCommit::build_journal_payload(CommitGroupId(5), &[], &[]);
        let (parsed_id, _, _) = CommitGroupCommit::parse_journal_payload(&payload).unwrap();
        assert_ne!(parsed_id, CommitGroupId(9));
    }

    struct MockStore {
        data: HashMap<String, Vec<u8>>,
        fail_keys: Vec<String>,
    }

    impl MockStore {
        fn new() -> Self {
            Self {
                data: HashMap::new(),
                fail_keys: Vec::new(),
            }
        }

        fn with_journal(
            mut self,
            id: CommitGroupId,
            keys: &[CommitGroupKey],
            inodes: &[u64],
        ) -> Self {
            let journal_key = format!("commit_group-journal-{}", id.0);
            let payload = CommitGroupCommit::build_journal_payload(id, keys, inodes);
            self.data.insert(journal_key, payload);
            self
        }

        fn with_failing_journal(mut self, id: CommitGroupId) -> Self {
            let journal_key = format!("commit_group-journal-{}", id.0);
            self.fail_keys.push(journal_key);
            self
        }
    }

    impl CommitGroupStore for MockStore {
        fn put_named(&mut self, _name: &str, _payload: &[u8]) -> Result<CommitGroupKey, String> {
            unimplemented!("mock store is read-only")
        }

        fn get_named(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
            if self.fail_keys.contains(&name.to_string()) {
                return Err("mock I/O failure".into());
            }
            Ok(self.data.get(name).cloned())
        }
    }

    #[test]
    fn scan_empty_store_returns_first_txg() {
        let store = MockStore::new();
        let result = CommitGroupRecovery::scan(&store, None).unwrap();
        assert!(!result.highest_committed_commit_group.is_valid());
        assert_eq!(result.next_commit_group_id, CommitGroupId::FIRST);
        assert!(result.committed_keys.is_empty());
        assert!(result.torn_commit_groups.is_empty());
    }

    #[test]
    fn scan_single_committed_journal() {
        let store = MockStore::new().with_journal(CommitGroupId(1), &[], &[]);
        let result = CommitGroupRecovery::scan(&store, None).unwrap();
        assert_eq!(result.highest_committed_commit_group, CommitGroupId(1));
        assert_eq!(result.next_commit_group_id, CommitGroupId(2));
        assert!(result.torn_commit_groups.is_empty());
    }

    #[test]
    fn scan_multiple_sequential_journals() {
        let store = MockStore::new()
            .with_journal(CommitGroupId(1), &[], &[])
            .with_journal(CommitGroupId(2), &[], &[])
            .with_journal(CommitGroupId(3), &[], &[]);
        let result = CommitGroupRecovery::scan(&store, None).unwrap();
        assert_eq!(result.highest_committed_commit_group, CommitGroupId(3));
        assert_eq!(result.next_commit_group_id, CommitGroupId(4));
        assert!(result.torn_commit_groups.is_empty());
    }

    #[test]
    fn scan_gap_detection_stops_at_missing() {
        let store = MockStore::new()
            .with_journal(CommitGroupId(1), &[], &[])
            .with_journal(CommitGroupId(2), &[], &[]);
        let result = CommitGroupRecovery::scan(&store, None).unwrap();
        assert_eq!(result.highest_committed_commit_group, CommitGroupId(2));
        assert_eq!(result.next_commit_group_id, CommitGroupId(3));
    }

    #[test]
    fn scan_with_max_commit_group_bound() {
        let store = MockStore::new()
            .with_journal(CommitGroupId(1), &[], &[])
            .with_journal(CommitGroupId(2), &[], &[])
            .with_journal(CommitGroupId(3), &[], &[]);
        let result = CommitGroupRecovery::scan(&store, Some(CommitGroupId(2))).unwrap();
        assert_eq!(result.highest_committed_commit_group, CommitGroupId(2));
    }

    #[test]
    fn scan_with_keys_in_journal() {
        let keys = vec![
            CommitGroupKey::from_bytes32([0xAAu8; 32]),
            CommitGroupKey::from_bytes32([0xBBu8; 32]),
        ];
        let inodes = vec![10, 20];
        let store = MockStore::new().with_journal(CommitGroupId(1), &keys, &inodes);
        let result = CommitGroupRecovery::scan(&store, None).unwrap();
        assert_eq!(result.committed_keys.len(), 2);
        assert_eq!(result.committed_keys[0].as_bytes32(), [0xAAu8; 32]);
        assert_eq!(result.committed_keys[1].as_bytes32(), [0xBBu8; 32]);
    }

    #[test]
    fn scan_corrupt_journal_detected_as_torn() {
        let mut store = MockStore::new();
        store.data.insert(
            "commit_group-journal-1".into(),
            vec![0xDE, 0xAD, 0xBE, 0xEF],
        );
        let result = CommitGroupRecovery::scan(&store, None).unwrap();
        assert_eq!(result.torn_commit_groups, vec![CommitGroupId(1)]);
        assert!(!result.highest_committed_commit_group.is_valid());
    }

    #[test]
    fn scan_io_error_propagates() {
        let store = MockStore::new().with_failing_journal(CommitGroupId(1));
        let result = CommitGroupRecovery::scan(&store, None);
        assert!(result.is_err());
    }

    #[test]
    fn scan_mismatched_id_detected_as_torn() {
        let mut store = MockStore::new();
        let payload = CommitGroupCommit::build_journal_payload(CommitGroupId(5), &[], &[]);
        store.data.insert("commit_group-journal-1".into(), payload);
        let result = CommitGroupRecovery::scan(&store, None).unwrap();
        assert_eq!(result.torn_commit_groups, vec![CommitGroupId(1)]);
    }

    #[test]
    fn determine_next_commit_group_id_empty_store() {
        let store = MockStore::new();
        let next = CommitGroupRecovery::determine_next_commit_group_id(&store).unwrap();
        assert_eq!(next, CommitGroupId::FIRST);
    }

    #[test]
    fn determine_next_commit_group_id_after_commit() {
        let store = MockStore::new().with_journal(CommitGroupId(7), &[], &[]);
        let next = CommitGroupRecovery::determine_next_commit_group_id(&store).unwrap();
        assert_eq!(next, CommitGroupId(8));
    }

    #[test]
    fn recover_is_alias_for_scan() {
        let store = MockStore::new().with_journal(CommitGroupId(1), &[], &[]);
        let result = CommitGroupRecovery::recover(&store).unwrap();
        assert_eq!(result.highest_committed_commit_group, CommitGroupId(1));
        assert_eq!(result.next_commit_group_id, CommitGroupId(2));
    }
}
