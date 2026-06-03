use super::*;

#[test]
fn reconstruction_task_encode_decode_roundtrip_full_object() {
    let task = ReconstructionTask::new_full(42, vec![10, 20], vec![30], 1);
    let encoded = task.encode();
    let (decoded, bytes_read) = ReconstructionTask::decode(&encoded).unwrap();
    assert_eq!(bytes_read, encoded.len());
    assert_eq!(decoded, task);
}

#[test]
fn reconstruction_task_encode_decode_roundtrip_with_range() {
    let task = ReconstructionTask {
        object_id: 100,
        source_nodes: vec![1, 2, 3],
        target_nodes: vec![4],
        data_range: Some((0, 4096)),
        priority: 3,
    };
    let encoded = task.encode();
    let (decoded, bytes_read) = ReconstructionTask::decode(&encoded).unwrap();
    assert_eq!(bytes_read, encoded.len());
    assert_eq!(decoded, task);
}

#[test]
fn reconstruction_task_has_viable_sources() {
    let with = ReconstructionTask::new_full(1, vec![10], vec![], 0);
    assert!(with.has_viable_sources());
    let without = ReconstructionTask::new_full(1, vec![], vec![10], 0);
    assert!(!without.has_viable_sources());
}

#[test]
fn reconstruction_task_target_count() {
    let task = ReconstructionTask::new_full(1, vec![10], vec![20, 30], 0);
    assert_eq!(task.target_count(), 2);
}

#[test]
fn rebuild_plan_seal_verify_roundtrip() {
    let tasks = vec![
        ReconstructionTask::new_full(1, vec![10], vec![20], 0),
        ReconstructionTask::new_full(2, vec![10], vec![30], 1),
    ];
    let plan = RebuildPlan::new(1, tasks, 1_000_000_000);
    let sealed = plan.seal();
    assert!(sealed.len() > 32);
    let decoded = RebuildPlan::verify_and_decode(&sealed).unwrap();
    assert_eq!(decoded, plan);
    assert_eq!(decoded.task_count(), 2);
    assert_eq!(decoded.total_target_replicas(), 2);
}

#[test]
fn rebuild_plan_seal_verify_empty() {
    let plan = RebuildPlan::new(7, vec![], 500_000_000);
    assert!(plan.is_empty());
    let sealed = plan.seal();
    let decoded = RebuildPlan::verify_and_decode(&sealed).unwrap();
    assert_eq!(decoded, plan);
    assert!(decoded.is_empty());
}

#[test]
fn rebuild_plan_verify_integrity_pass() {
    let plan = RebuildPlan::new(
        1,
        vec![ReconstructionTask::new_full(42, vec![1], vec![2], 0)],
        0,
    );
    let sealed = plan.seal();
    assert!(RebuildPlan::verify_integrity(&sealed));
}

#[test]
fn rebuild_plan_verify_integrity_tampered() {
    let plan = RebuildPlan::new(
        1,
        vec![ReconstructionTask::new_full(42, vec![1], vec![2], 0)],
        0,
    );
    let mut sealed = plan.seal();
    sealed[40] ^= 0xFF;
    assert!(!RebuildPlan::verify_integrity(&sealed));
}

#[test]
fn rebuild_plan_verify_too_short() {
    assert!(!RebuildPlan::verify_integrity(&[]));
    assert!(!RebuildPlan::verify_integrity(&[0u8; 16]));
}

#[test]
fn rebuild_plan_verify_and_decode_tampered_fails() {
    let plan = RebuildPlan::new(
        1,
        vec![ReconstructionTask::new_full(42, vec![1], vec![2], 0)],
        0,
    );
    let mut sealed = plan.seal();
    sealed[50] ^= 0xFF;
    assert!(RebuildPlan::verify_and_decode(&sealed).is_err());
}

#[test]
fn rebuild_plan_seal_deterministic() {
    let tasks = vec![
        ReconstructionTask::new_full(10, vec![1], vec![2], 0),
        ReconstructionTask::new_full(20, vec![3], vec![4], 1),
    ];
    let plan = RebuildPlan::new(99, tasks, 123456789);
    let sealed1 = plan.seal();
    let sealed2 = plan.seal();
    assert_eq!(sealed1, sealed2);
}

#[test]
fn rebuild_plan_is_empty() {
    assert!(RebuildPlan::new(1, vec![], 0).is_empty());
    assert!(!RebuildPlan::new(
        1,
        vec![ReconstructionTask::new_full(1, vec![1], vec![2], 0),],
        0
    )
    .is_empty());
}

#[test]
fn rebuild_plan_total_target_replicas() {
    let tasks = vec![
        ReconstructionTask::new_full(1, vec![10], vec![20, 30], 0),
        ReconstructionTask::new_full(2, vec![11], vec![21], 0),
    ];
    let plan = RebuildPlan::new(1, tasks, 0);
    assert_eq!(plan.total_target_replicas(), 3);
}

#[test]
fn reconstruction_task_decode_corrupted() {
    assert!(ReconstructionTask::decode(&[0u8; 4]).is_err());
    let mut buf = vec![0u8; 8];
    buf.extend_from_slice(&5u32.to_le_bytes());
    buf.extend_from_slice(&[0u8; 4]);
    assert!(ReconstructionTask::decode(&buf).is_err());
}

#[test]
fn rebuild_plan_task_count() {
    let tasks = vec![
        ReconstructionTask::new_full(1, vec![1], vec![2], 0),
        ReconstructionTask::new_full(2, vec![3], vec![4], 0),
        ReconstructionTask::new_full(3, vec![5], vec![6], 0),
    ];
    let plan = RebuildPlan::new(1, tasks, 0);
    assert_eq!(plan.task_count(), 3);
}

#[test]
fn rebuild_plan_large_task_list() {
    let mut tasks = Vec::new();
    for i in 0..100 {
        tasks.push(ReconstructionTask::new_full(
            i as u64,
            vec![(i % 5) as u64 + 1],
            vec![(i % 3) as u64 + 10],
            (i % 4) as u8,
        ));
    }
    let plan = RebuildPlan::new(42, tasks, 1_000_000_000);
    assert_eq!(plan.task_count(), 100);
    let sealed = plan.seal();
    let decoded = RebuildPlan::verify_and_decode(&sealed).unwrap();
    assert_eq!(decoded, plan);
}

#[test]
fn reconstruction_task_with_range_verify() {
    let task = ReconstructionTask {
        object_id: 77,
        source_nodes: vec![1],
        target_nodes: vec![2, 3],
        data_range: Some((1024, 2048)),
        priority: 2,
    };
    let encoded = task.encode();
    let (decoded, _) = ReconstructionTask::decode(&encoded).unwrap();
    assert_eq!(decoded.data_range, Some((1024, 2048)));
}

#[test]
fn reconstruction_task_no_range() {
    let task = ReconstructionTask::new_full(5, vec![1], vec![2], 0);
    let encoded = task.encode();
    let (decoded, _) = ReconstructionTask::decode(&encoded).unwrap();
    assert_eq!(decoded.data_range, None);
}

#[test]
fn plan_seal_verify_many_tasks() {
    let tasks: Vec<_> = (0..50)
        .map(|i| ReconstructionTask::new_full(i, vec![i + 1], vec![i + 100], (i % 5) as u8))
        .collect();
    let plan = RebuildPlan::new(1, tasks, 0);
    let decoded = RebuildPlan::verify_and_decode(&plan.seal()).unwrap();
    assert_eq!(decoded, plan);
}
