# Receive merge-planner lineage pointer

This file is intentionally no longer a maintained design roadmap. It remains
only as a narrow lineage pointer because current source comments cite this path
for the receive merge-planner taxonomy and manual conflict-resolution surface.

Current authority lives in:

- `docs/RECEIVE_STREAM_MERGE_POLICY.md` for the default fail-closed receive
  policy and non-empty-target boundary.
- `crates/tidefs-local-filesystem/src/receive_merge_planner.rs`,
  `crates/tidefs-local-filesystem/src/receive_persistence.rs`,
  `crates/tidefs-local-filesystem/src/encoding.rs`, and the public receive
  entry points for implemented merge-planner behavior.
- `apps/tidefsctl/src/commands/merge.rs` for the operator conflict-inventory
  resolution surface.
- GitHub issue and PR lineage for the design and implementation slices:
  #704, #770/#1140, #774/#1225, and #773/#1230.
- `validation/claims.toml`, `docs/CLAIMS_GATE_POLICY.md`, and generated
  `docs/CLAIM_REGISTRY.md` for snapshot, send/receive, reclaim, distributed,
  and successor/comparator product-admission boundaries.

Legacy section map for source citations:

- Former section 1, the five-axis conflict taxonomy, is now represented by the
  conflict inventory types in `encoding.rs` and the classifier in
  `receive_merge_planner.rs`.
- Former section 5.1 item 4, in-receive merge-plan execution, is now
  represented by `receive_persistence.rs`, receive entry-point plumbing, and
  PR #1230.
- Former section 5.1 item 5, the manual conflict-resolution surface, is now
  represented by `apps/tidefsctl/src/commands/merge.rs` and PR #1225.

Non-claims:

- This pointer does not define new receive behavior, new stream formats, or a
  current roadmap.
- It does not by itself relax the fail-closed receive policy; only current
  source and validated tests do that for the implemented merge-plan path.
- It does not validate snapshot/send/receive/reclaim admission, distributed
  receive, cross-pool trust, production readiness, release readiness, or
  OpenZFS/Ceph successor or comparator wording.

Do not grow this file back into a design record. Put durable receive authority
in current source, current receive authority docs, `validation/claims.toml`,
live GitHub issues, and pull-request history.
