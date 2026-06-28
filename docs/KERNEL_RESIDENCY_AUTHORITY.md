# Kernel Residency Authority

Maturity: current authority decision for TFR-009 and GitHub issue #1288.

Decision id: `tfr-009.kernel_residency_authority.v1`.

This document records the authority boundary for kernel-resident TideFS
storage behavior. It does not implement kernel runtime behavior, update claim
registry state, or replace
`docs/KERNEL_RESIDENT_POOL_ENGINE_ARCHITECTURE.md`. The architecture document
remains the target-architecture spec and evidence-tier map. This document
decides what TideFS may claim today, what remains explicitly non-claimed, and
which follow-up slices must land before the authority can strengthen.

## Decision

Kernel residency is a tiered authority boundary, not a terminal product claim.

TideFS may currently claim bounded, evidence-scoped kernel residency for these
surfaces only:

- missing or implicit kernel pool authority fails closed before synthetic
  root, statfs, VFS, or block I/O authority is presented;
- the POSIX kernel module has a bounded engine-backed mount bring-up path for
  an explicit pool member, with in-kernel label/committed-root selection,
  mounted superblock state, pool-backed statfs, and the mounted operation rows
  that current Linux 7.0 QEMU evidence supports;
- the first mounted POSIX operation slice still uses a small fixed in-kernel
  namespace/data table and committed-root publication mirror, so it is
  bring-up evidence rather than final storage-engine authority;
- the `tidefs-block-kmod` crate is daemon-independent and has a
  production-shaped pool-backed entrypoint that must refuse registration when
  that backend is absent, but current block-kmod bring-up is not a full
  block-volume product claim;
- `kernel.teardown.no_work_after.v1` has source/model evidence plus an
  accepted T5 mounted-kernel-vfs cutover/teardown artifact from issue #1186 /
  PR #1463, while the claim remains blocked because no accepted T6
  full-kernel/no-daemon teardown and recovery artifact is registered.

All stronger wording is a non-claim until the matching tier evidence lands and
the claim gate records it. In particular, no source-only, cargo-only,
Kbuild-only, module-load-only, fixed-table-only, in-memory-backend-only, or
shim-local-storage path can claim production kernel-resident storage authority.

## Authority Boundary

The final target remains one `KernelPoolCore` per imported pool, consumed by
the POSIX VFS and block-volume front-ends. That target is defined by
`docs/KERNEL_RESIDENT_POOL_ENGINE_ARCHITECTURE.md`.

For present authority, the boundary is narrower:

| Surface | Current authority | Non-claim | Upgrade gate |
|---|---|---|---|
| Authority refusal | Unbound/bootstrap POSIX mounts must fail before root/statfs synthesis. | Refusal is not mounted storage, read/write, xfstests, block I/O, crash/remount, or no-daemon evidence. | None for the refusal claim; any mounted claim needs a higher-tier runtime row. |
| POSIX VFS mounted bring-up | Explicit pool-member mount, engine-backed superblock state, pool-backed statfs, and current mounted rows supported by Linux 7.0 QEMU evidence. | The fixed in-kernel namespace/data table is not the final object/extent/intent-log engine. | Replace table readback with committed-root object/extent/inode/intent replay, then prove focused mounted-kernel rows. |
| Page cache and writeback | Kernel page-cache paths are projections that must consume TFR-008 authority. | This document does not claim dirty lifecycle, writeback durability, mmap coherency, direct-I/O reconciliation, or fsync/syncfs completeness. | `docs/PAGE_CACHE_WRITEBACK_AUTHORITY.md` and `docs/PAGE_CACHE_INVALIDATION_AUTHORITY.md` implementation plus mounted runtime and claim-gate evidence. |
| Block-kmod | Daemon-independent crate and product-shaped pool-backed entrypoint/fail-closed behavior. | No full block-volume product claim, no self-stacking authority, no production in-memory backend, and no broad queue_rq read/write/flush/discard claim. | Real kernel block-I/O artifacts through the shared pool core and later block-volume claim review. |
| Teardown and cutover | Source/model cutover authority from #825 / PR #1189, plus accepted T5 mounted-kernel cutover/teardown evidence from #1186 / PR #1463. | No full-kernel/no-daemon teardown or recovery claim. | Accepted T6 full-kernel/no-daemon teardown and recovery artifact, then claims-gate review. |
| Operator UAPI | `tidefsctl` and future kernel UAPI clients may configure or inspect through declared public surfaces. | Operator tools are not a storage authority and do not prove kernelspace readiness or production ABI freeze. | `docs/OPERATOR_UAPI_AUTHORITY.md` plus issue-scoped runtime wiring and ABI review. |
| Transport and cluster | No TFR-009 kernel residency claim depends on transport/cluster runtime today. | No distributed, RDMA, clustered cache, or kernel transport authority is implied. | `docs/TRANSPORT_CLUSTER_AUTHORITY.md` and future kernel transport issues if a resident transport service is admitted. |
| Full-kernel/no-daemon | Not claimed. | No daemonless storage parity, production kernel-resident storage authority, or full-kernel block-volume/filesystem product claim. | T6 evidence proving VFS, block, recovery, writeback, placement, reserve, and admission operate without required support daemons. |

## Evidence Reviewed

This decision reviewed the evidence named by issue #1288:

- `docs/REVIEW_TODO_REGISTER.md` TFR-008, TFR-009, TFR-010, TFR-011,
  TFR-017, TFR-018, and TFR-019 notes.
- `docs/KERNEL_RESIDENT_POOL_ENGINE_ARCHITECTURE.md`, which remains the target
  architecture and evidence-tier map.
- `docs/KERNEL_TEARDOWN_RUNTIME_EVIDENCE_DECISION.md`, whose T5/T6 model is
  still the teardown tiering vocabulary even though #1186 / PR #1463 has since
  accepted the T5 mounted-kernel cutover/teardown artifact.
- `docs/KERNEL_MODULE_FAMILY_MATRIX_ROLLOUT_ORDER_P7-01.md`, especially the
  full-kernel residency invariant and rollout-order constraints.
- `docs/PAGE_CACHE_WRITEBACK_AUTHORITY.md` and
  `docs/PAGE_CACHE_INVALIDATION_AUTHORITY.md`, which own TFR-008 dirty data,
  writeback, mmap, and invalidation boundaries that kernel residency must
  consume rather than redefine.
- `docs/STD_NO_STD_KERNEL_USERSPACE_BOUNDARY_RULES_P1-02.md`, as historical
  input for environment-boundary rules; current authority classification stays
  with `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.
- `crates/tidefs-kmod-posix-vfs/README.md` and
  `crates/tidefs-block-kmod/README.md`, including mount tiers, daemon
  independence, fixed-table bring-up, xfstests caveats, block-kmod QEMU
  evidence requirements, and block-kmod production-backend refusal.
- `validation/claims.toml` and `docs/CLAIM_REGISTRY.md`, especially the
  blocked `kernel.teardown.no_work_after.v1` and
  `local.vfs.page_cache_writeback_authority.v1` claim rows.
- Live issue #1186 and PR #1463, which closed on 2026-06-27 with accepted T5
  mounted-kernel-vfs cutover/teardown evidence and no T6 claim-registry
  upgrade.
- Live issue #825 and PR #1189, which closed on 2026-06-23 by establishing
  `tidefs-kernel-cutover-runtime` as current source/model authority and
  leaving mounted runtime evidence to #1186.
- `docs/VFS_BLOCK_INTEGRATION_KERNEL_UAPI_LAW_P7-04.md` was referenced by the
  kernel architecture and rollout docs but is absent in this checkout. This
  decision therefore does not derive a new VFS/block UAPI law from that file.

## Alternatives Considered

Promote `docs/KERNEL_RESIDENT_POOL_ENGINE_ARCHITECTURE.md` as the TFR-009
authority decision.

: Rejected. That document is the right target-architecture spec and tier map,
  but it intentionally does not decide the present authority boundary,
  non-claims, or follow-up issue map required by TFR-009.

Treat current engine-backed POSIX mount and block-kmod daemon independence as
full kernel-resident storage authority.

: Rejected. The POSIX path still has fixed-table bring-up state and the block
  path still requires shared pool-core queue_rq evidence before a full block
  product claim. The evidence proves useful slices, not storage parity.

Split final authority into independent POSIX and block stores.

: Rejected for the target architecture. POSIX VFS and block-volume front-ends
  must converge on one pool core, transaction/replay frontier, capacity model,
  pin/drain broker, worker registry, and teardown protocol. They may be
  validated in separate rows, but they must not become separate stores.

## T5/T6 Claim Upgrade Model

TideFS uses the claim tiers in `docs/CLAIMS_GATE_POLICY.md` and the teardown
model in `docs/KERNEL_TEARDOWN_RUNTIME_EVIDENCE_DECISION.md`.

| Tier | What it can upgrade | Required evidence before upgrade |
|---|---|---|
| Source/model, cargo-unit, Kbuild, or QEMU module load | Source invariants, schemas, crate boundaries, buildability, and module-load mechanics. | Matched source/model artifacts or build artifacts. These tiers never prove mounted kernel storage behavior by themselves. |
| T5 `mounted-kernel-vfs` | The exact mounted POSIX VFS behavior exercised by the artifact. | Product module loaded in Linux 7.0 QEMU or equivalent self-hosted kernel workflow, explicit pool member, mounted `-t tidefs` path, source ref/SHA, logs/artifacts, and claim-specific observations. #1186 / PR #1463 satisfies this for mounted cutover/teardown only. |
| T5 `kernel-block-io` | The exact kernel block-device behavior exercised by the artifact. | Registered `/dev/tidefs*` product block device, `queue_rq` read/write/flush/discard path through the shared pool core, source ref/SHA, logs/artifacts, and block claim observations. |
| T5 crash/remount | The exact committed-root/replay recovery behavior exercised by the artifact. | Forced-shutdown or crash/remount artifact showing committed-root and replay-cursor survival for the claimed path. |
| T6 `full-kernel-no-daemon` | Final daemonless storage residency for the claim scope. | T5 VFS/block/recovery/writeback prerequisites, no required FUSE daemon, ublk daemon, policy/control daemon, transport helper, or usermode worker for normal mounted operation, plus T6 no-daemon artifacts and claims-gate review. |

Kernel cutover and teardown claims follow the same ladder: #825 / PR #1189 is
source/model authority, #1186 / PR #1463 is accepted T5 mounted-kernel cutover
and teardown evidence, and T6 remains blocked until a no-daemon teardown and
recovery artifact is accepted and the claim registry is reviewed.

## Composition Rules

TFR-008 page-cache/writeback authority composes underneath kernel residency.
Kernel page-cache callbacks, writeback workers, mmap faults, fsync/syncfs, and
direct-I/O reconciliation are projections of the dirty-data authority in
`docs/PAGE_CACHE_WRITEBACK_AUTHORITY.md` and the stale-generation authority in
`docs/PAGE_CACHE_INVALIDATION_AUTHORITY.md`.

TFR-011 operator UAPI composes beside kernel residency. Operator commands and
future kernel UAPI clients may select, configure, inspect, and collect
evidence, but they are not storage authorities and cannot replace mounted
kernel runtime evidence.

TFR-017 transport and cluster authority composes outside this decision. A
future kernel transport or resident cluster service must consume
`docs/TRANSPORT_CLUSTER_AUTHORITY.md`; TFR-009 does not create a distributed
storage or RDMA claim.

The POSIX VFS and block-volume modules compose as front-ends to one future
`KernelPoolCore`. They may have separate T5 rows, but a full-kernel/no-daemon
claim requires both front-ends, recovery, writeback, placement, reserve, and
admission to operate through the resident pool core without required support
daemons.

## Explicit Non-Claims

This authority decision preserves these non-claims:

- no production kernel-resident storage authority;
- no daemonless storage parity;
- no full-kernel block-volume product claim;
- no final object/extent/intent-log engine from the fixed in-kernel
  namespace/data table;
- no page-cache/writeback or mmap durability authority beyond the TFR-008
  documents and current blocked claim state;
- no broad kernel-mode xfstests coverage beyond rows that current evidence
  explicitly supports;
- no crash/remount, replay, or recovery claim from basic mount or fixed-table
  readback;
- no distributed, RDMA, cluster, or kernel transport authority;
- no production kernel UAPI or ABI freeze;
- no OpenZFS/Ceph-class, production-ready, or release-ready product claim.

## Follow-Up Issue Map

The rows below are the implementation slices that should be tracked after this
decision. Rows marked blocked must not be admitted until their prerequisite
clears and the new GitHub issue records a non-overlapping expected write set.

| Slice | Primary expected write set | Status after this decision | Boundary |
|---|---|---|---|
| Kernel pool-core committed-root replay and object/extent import | `crates/tidefs-kernel-storage-io/**`, `crates/tidefs-vfs-engine/src/pool_core.rs`, focused mount/replay bridge files under `crates/tidefs-kmod-posix-vfs/src/` | Required first implementation slice after #1288. | Replaces fixed-table storage authority with committed-root object/extent/inode/intent replay. Does not own page-cache/writeback, block export, xfstests breadth, or claim-registry updates. |
| POSIX VFS operation coverage and mounted xfstests tranche | Focused VFS operation files under `crates/tidefs-kmod-posix-vfs/src/`, kernel VFS validation harness rows, and `docs/GITHUB_CI.md` only if dispatch docs change | Blocked until pool-core replay provides authoritative mounted state. | Owns operation-level mounted VFS behavior and xfstests evidence. Does not own block-kmod, page-cache/writeback authority, or claims registry. |
| Kernel page-cache, mmap, fsync, and writeback projection | Address-space/writeback/mmap/fsync files under `crates/tidefs-kmod-posix-vfs/src/`, kernel page-cache validation hooks, and focused runtime artifacts | Blocked on TFR-008 dirty lifecycle authority implementation and pool-core replay. | Consumes `PAGE_CACHE_WRITEBACK_AUTHORITY` and `PAGE_CACHE_INVALIDATION_AUTHORITY`; does not redefine durability authority. |
| Kernel block-volume export over shared pool core | `crates/tidefs-block-kmod/**`, block-facing shared pool-core adapter files, kernel block-I/O validation rows, and `docs/GITHUB_CI.md` only if dispatch docs change | Blocked until shared logical-volume pool-core operations are available. | Owns real queue_rq read/write/flush/discard through the resident pool core. Does not own POSIX VFS correctness or self-stacked pool admission. |
| Kernel crash/remount and replay evidence | Focused QEMU/Nix runtime row files, replay evidence artifacts, and kernel recovery validation docs | Blocked until committed-root replay and mounted operation coverage exist. | Owns crash/remount proof for claimed kernel paths. Does not claim full-kernel/no-daemon by itself. |
| T6 full-kernel/no-daemon storage residency | `nix/vm/kernel-no-daemon-*`, focused self-hosted workflow target/docs if needed, and no-daemon evidence artifacts | Blocked until T5 VFS, block, recovery, and writeback rows pass. | Proves normal mounted VFS/block/recovery/writeback/placement/reserve/admission without required support daemons. |
| Kernel-residency claim review | `validation/artifacts/kernel/**`, `validation/claims.toml`, generated `docs/CLAIM_REGISTRY.md`, and focused claim-validation tooling only | Blocked until the matching T5/T6 runtime artifacts exist. | Records accepted evidence and remaining blockers. Does not implement kernel runtime behavior. |

## Validation For This Decision

This issue is documentation/design work. Validation is bounded source/doc and
live issue/PR inspection plus `git diff --check`.

No local Cargo, rustc, clippy, Nix, QEMU, xfstests, RDMA, FUSE, ublk,
release-candidate, or broad GitHub Actions validation is required for this
authority decision.
