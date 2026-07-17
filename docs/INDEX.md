# Documentation Index

Start here for active project authority:

1. `README.md`
2. `AGENTS.md`
3. `CONTRIBUTING.md`
4. `docs/GITHUB_CI.md`
5. `docs/CLAIMS_GATE_POLICY.md`
6. `docs/REVIEW_TODO_POLICY.md`
7. `docs/REVIEW_TODO_REGISTER.md`
8. `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`
9. `docs/INDEX.md`

Read `docs/LICENSING.md`, `docs/TEST_SIGNAL_POLICY.md`,
`docs/UNRELEASED_AUTHORITY_POLICY.md`, and
`docs/CONTROL_FORMAT_AND_JSON_POLICY.md` when a change touches those surfaces.
Managed-worker host docs may impose local process constraints, but they are not
public product policy or prerequisite reading for ordinary contributors.

Preview orientation:

- `docs/PREVIEW_USER_MANUAL.md` gives preview-only mount notes and limitations.

This preview file is not product-admission, POSIX-complete, release, or
per-operation status authorities.

The remaining documents are design/reference material unless this index and
`docs/DOCUMENTATION_AUTHORITY_REGISTER.md` classify a narrower current scope.
Imported design files, issue-era implementation plans, old status matrices,
coordination packets, and closeout snapshots are historical input by default;
old maturity/status labels, Forgejo references, phase-completion wording, or
canonical-design wording inside those files does not make them current
authority.
Broad reference/status files are not mandatory first-read authority unless
live issue and repository-doc state explicitly reclassify them.

Release readiness boundary and evidence inputs:

- `docs/RELEASE_READINESS_VERDICT_CONTRACT.md` is the whole-product
  release-readiness verdict boundary.
- `docs/RELEASE_CANDIDATE_EVIDENCE_CONTRACT.md` describes the
  release-candidate evidence index as a gate input.
- `docs/CLAIM_REGISTRY.md` is generated from `validation/claims.toml` and
  records the registry-backed product-admission gates and claim ids that bound
  successor/comparator wording.
- The current performance-gate implementation lives under
  `crates/tidefs-validation/src/performance_gate/`.
- `docs/GITHUB_CI.md` describes standing CI and release-candidate workflow
  behavior.
- `docs/CLAIMS_GATE_POLICY.md` defines publishing-facing claim guardrails,
  successor/comparator wording boundaries, and individual claim validation.
- `docs/DOCUMENTATION_AUTHORITY_REGISTER.md` defines TFR-019 document
  classification and consolidation rules.
- `docs/UNRELEASED_AUTHORITY_POLICY.md` defines the unreleased-surface
  authority and compatibility guardrail.
- `docs/CONTROL_FORMAT_AND_JSON_POLICY.md` defines the JSON and control-format
  guardrail for operator surfaces, wire/control paths, durable records, and
  evidence artifacts.

The evidence inputs, generated product-admission gates, gate-local receipts,
CI artifacts, and claims-gate results listed here do not combine into a
product-admission decision on their own.

Current authority families:

- Namespace, version, and transform boundaries:
  `docs/INODE_NAMESPACE_AUTHORITY.md`,
  `docs/TIMESTAMP_GENERATION_AUTHORITY.md`,
  `docs/CONTENT_OBJECT_VERSION_AUTHORITY.md`,
  `docs/SEND_RECEIVE_VERSION_AUTHORITY.md`,
  `docs/TRANSFORM_PIPELINE_AUTHORITY.md`, and
  `docs/MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY.md`.
- Capacity, cache, and durability: `docs/CAPACITY_ACCOUNTING_AUTHORITY.md`,
  `docs/PAGE_CACHE_WRITEBACK_AUTHORITY.md`, and
  `docs/PAGE_CACHE_INVALIDATION_AUTHORITY.md`.
- Storage lifecycle and maintenance:
  `docs/POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md`,
  `docs/DEVICE_LIFECYCLE_REMANENCE_AUTHORITY.md`,
  `docs/SNAPSHOT_CLONE_DEADLIST_AUTHORITY.md`,
  `docs/SCRUB_IDENTITY_AUTHORITY.md`, and
  `docs/BACKGROUND_SERVICE_FRAMEWORK_DESIGN.md`.
- Kernel and mounted-path boundaries: `docs/KERNEL_RESIDENCY_AUTHORITY.md`,
  `docs/KERNEL_RESIDENT_POOL_ENGINE_ARCHITECTURE.md`, and
  `docs/FUSE_ADAPTER_CONTRACT_ASSUMPTIONS.md`.
- Transport and distributed records: `docs/TRANSPORT_CLUSTER_AUTHORITY.md`,
  `docs/CROSS_REPLICA_SCRUB_COMPARISON_DESIGN.md`, and
  `docs/LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md`.
- Storage intent and receipts: `docs/STORAGE_INTENT_POLICY_AUTHORITY.md`,
  `docs/STORAGE_INTENT_SERVICE_OBJECTIVE_DESIGN.md`,
  and `docs/STORAGE_INTENT_RESULT_REFUSAL_EVIDENCE_DESIGN.md`.
- Operator, block, and API surfaces: `docs/OPERATOR_UAPI_AUTHORITY.md`,
  `docs/OPERATOR_PRODUCT_SURFACE_DECISION.md`, `docs/REQUEST_CONTRACT.md`,
  `docs/PREVIEW_UAPI_ABI_BOUNDARY_OW202.md`,
  `docs/BLOCK_VOLUME_UBLK_STARTED_EXPORT_ADMISSION_BOUNDARY_ISSUE_341.md`,
  `docs/CONTROL_FORMAT_AND_JSON_POLICY.md`, and
  `docs/TRACE_ORACLE_ARTIFACT_SCHEMA.md`.
- Validation, CI, and workspace policy: `CONTRIBUTING.md`,
  `docs/GITHUB_CI.md`, `docs/TEST_SIGNAL_POLICY.md`,
  `docs/XFSTESTS_DISPATCH_CONTRACT.md`,
  `docs/workspace-package-classification.md`, and
  `docs/CLAIMS_GATE_POLICY.md`.

Do not infer current behavior from a document merely because it exists under
`docs/` or uses old authority language. Cite the source-backed authority,
claims registry, validation evidence, or live GitHub issue/PR state for the
specific behavior being discussed.
