# POSIX Filesystem Adapter daemon topology (POSIX_FILESYSTEM_ADAPTER pre-preview continuity)

> TFR-019 authority classification: Historical input. See `docs/DOCUMENTATION_AUTHORITY_REGISTER.md`.

This imported document is historical design input for the human-named adapter
topology.


It records a production-depth `posix_filesystem_adapter` runtime and process
topology target.

The active production reading is now requirement-aligned: steady-state
production `posix_filesystem_adapter` residency is kernel-hosted, while any FUSE/userspace runtime

It answers the question:

**How does tidefs expose one lawful `posix_filesystem_adapter` projection runtime - with one
production residency family, one bounded bring-up mirror family, one kernel
mount/session state grammar, one worker/page-runtime binding law, one budget
split, and one restart/quarantine language - without letting mount helpers,
per-mount shell glue, FUSE wrappers, or leftover daemon process models become
hidden production sovereignty?**

See also:
- `docs/FUSE_REQUEST_WORKER_QUEUE_MODEL_P5-02.md`
- `docs/PAGE_CACHE_WRITEBACK_MMAP_INTEGRATION_P5-03.md`
- `docs/MEMORY_DOMAINS_ARENA_FAMILIES_OWNERSHIP_TOKEN_LAW_P4-01.md`
- `docs/POLICY_AUTHORITY_RUNTIME_SURFACE_P3-01.md`
- `docs/STORAGE_INTENT_POLICY_AUTHORITY.md`
- `docs/LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md`
- `docs/RECEIPT_RESPONSE_RUNTIME_EMISSION_PATH_P3-03.md`
- `docs/BUILD_PACKAGING_FEATURE_MATRIX_P1-04.md`
- `docs/END_TO_END_PRODUCTION_BLUEPRINT.md`
- `docs/AUTHORITATIVE_DATA_STRUCTURES_ALGORITHMS.md`

## 1. Core result

The production design now has one explicit family for live `posix_filesystem_adapter` runtime
deployment:

- one production kernel-resident runtime family:
  - **`service.posix_filesystem_adapter.runtime.kernel_resident.k0`**
- one bounded non-production FUSE / userspace mirror family:
  - **`service.posix_filesystem_adapter.runtime.lab_mirror.tidefs-posix-filesystem-adapter-daemon.l0`**
- one bounded mount-helper family:
  - **`helper.posix_filesystem_adapter.mount.mount_fuse_tidefs.h0`**
- three stable execution classes:
  - **`exec.posix_filesystem_adapter.kernel_runtime.k0`**
  - **`exec.posix_filesystem_adapter.mount_helper.p1`**
  - **`exec.posix_filesystem_adapter.session_mirror.l1`**
- seven stable thread-set classes, six phase classes, six restart verdict classes,
  ten required record families, and ten required algorithms
- one fixed runtime chain:
  - **mount intent -> admitted runtime class -> request/page-runtime binding -> publication / response bridge -> drain or recovery receipt**

This means tidefs is no longer allowed to say only:
- "there is some `posix_filesystem_adapter` daemon,"
- "xfstests can just use whatever helper works,"
- "the session model can be figured out later,"
- "FUSE bring-up is good enough to define production topology,"
- or "restart behavior can live in systemd or shell retry loops."

It must instead say:
- which production family owns steady-state `posix_filesystem_adapter` truth,
- which userspace/FUSE mirror is explicitly non-production,
- which helper contract is bounded to bring-up and mount-intent translation,
- which execution class owns request/runtime and page/writeback bindings,
- which budgets are global versus mount/session-local,
- and which restart/quarantine verdict proves how failure was handled.

The anti-regression rule is explicit:

script, page-cache sidecar, reply-copy helper, or future CLI convenience
entrypoint may become production authority unless it is bound to the declared
`posix_filesystem_adapter` runtime/helper/execution/budget/restart law fixed here. Any surviving
`tidefs-posix-filesystem-adapter-daemon` path is non-production by declaration and may not silently become
the steady-state production residency.**

## 2. Scope and boundaries

This document governs:

- the production kernel-resident `posix_filesystem_adapter` family and its single lawful runtime role,
- the bounded non-production FUSE/userspace mirror family,
- the transient mount-helper contract for `mount(8)` / xfstests / local mount orchestration,
- the binding from process classes to the already-settled `P5-02` worker/queue law and `P5-03` page/writeback/mmap law,
- global versus per-session budgets, including thread, FD, reply-byte, pin/loan, and restart-storm accounting,
- and crash, drain, restart, quarantine, and retirement behavior.

This document now consumes the explicit `P5-02` worker/queue law in `docs/FUSE_REQUEST_WORKER_QUEUE_MODEL_P5-02.md`, the explicit `P5-03` page-cache / writeback / mmap law in `docs/PAGE_CACHE_WRITEBACK_MMAP_INTEGRATION_P5-03.md`, the explicit `memory_arena_0` memory-domain / arena / ownership-token law in `docs/MEMORY_DOMAINS_ARENA_FAMILIES_OWNERSHIP_TOKEN_LAW_P4-01.md`, the explicit `governance_surface_0` authority-service law in `docs/POLICY_AUTHORITY_RUNTIME_SURFACE_P3-01.md`, current storage-intent and placement-receipt authority in `docs/STORAGE_INTENT_POLICY_AUTHORITY.md` and `docs/LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md`, the explicit `response_registry` receipt / response runtime emission law in `docs/RECEIPT_RESPONSE_RUNTIME_EMISSION_PATH_P3-03.md`, and the explicit `package_profile_catalog` build / packaging / activation law in `docs/BUILD_PACKAGING_FEATURE_MATRIX_P1-04.md`.

That boundary is deliberate.
`P5-01` closes the last remaining `L1` production-design blocker.
The design rule-family lineage, workspace-layout law, product-variant law,
UAPI mirror law, seam-map law, and deletion-law references in this imported
document are historical production-depth inputs. Current kernel and preview
UAPI authority is kept in the focused kernel residency and preview UAPI docs.
This historical topology input must not invent a second
`posix_filesystem_adapter` production runtime family, a second mount-helper
truth path, a one-big-process versus one-process-per-mount dialect split, a
page-runtime sidecar, or shell-local restart folklore outside the topology
declared here.

## 3. Repo anchor snapshot

The production law is grounded in real repo surfaces rather than pure future prose:


Production `P5-01` extends those anchors by fixing the runtime topology they must eventually share.
The current reference still proves feasibility, but any `tidefs-posix-filesystem-adapter-daemon`/FUSE path now counts only as a bounded bring-up mirror rather than the final production residency.

## 4. Metrics snapshot

| Metric | Count |
|---|---:|
| Logical runtime components | 8 |
| Stable process classes | 3 |
| Stable backend classes | 2 |
| Stable thread-set classes | 7 |
| Stable phase classes | 6 |
| Stable restart verdict classes | 6 |
| Required record families | 10 |
| Required algorithms | 10 |

## 5. Runtime family, helper, and execution-class law

### 5.1 One production family plus one bounded mirror

The production design now fixes exactly one production runtime family for live `posix_filesystem_adapter` truth:

- **`service.posix_filesystem_adapter.runtime.kernel_resident.k0`**

The bounded non-production mirror family is:

- **`service.posix_filesystem_adapter.runtime.lab_mirror.tidefs-posix-filesystem-adapter-daemon.l0`**

Tidefs is not allowed to grow:
- one separate mount daemon for xfstests,
- one separate page/writeback daemon,
- one separate reply-copy helper that owns completion truth,
- one sidecar process that bypasses the same restart and budget law,
- or one FUSE/userspace mirror that silently becomes the production host by packaging convention.

### 5.2 One transient mount-helper family

The production design now fixes exactly one bounded helper family:

- **`helper.posix_filesystem_adapter.mount.mount_fuse_tidefs.h0`**

This helper is intentionally narrow.
It may:
- parse `mount(8)` and xfstests argv/env,
- normalize them into one `PosixFilesystemAdapterMountIntentRecord`,
- wait for a ready or refusal receipt from the admitted runtime class,
- and then exit.

It may **not**:
- own long-lived production truth,
- keep page/writeback or reply-credit state after readiness,
- open a second back door to `policy_authority`,
- or become a hidden long-lived daemon just because the lab currently uses `--daemonize`.

### 5.3 Stable execution classes

| Execution class | Meaning | Production-admitted? | Owns live `/dev/fuse` session state? |
|---|---|---:|---:|
| `exec.posix_filesystem_adapter.kernel_runtime.k0` | kernel-resident runtime that owns steady-state `posix_filesystem_adapter` truth, request/runtime binding, page/writeback binding, and recovery receipts | yes | n/a |
| `exec.posix_filesystem_adapter.mount_helper.p1` | transient helper that translates `mount(8)` / xfstests / local CLI invocation into one admitted mount intent and waits for a ready/refusal receipt | no | no |

The process law is strict:

1. There is exactly one `p2` per live mount.
2. `p2` may be implemented as the same binary re-execed in session mode; it does not create a second public service family.
3. No two mounts share a `/dev/fuse` FD, session-handle table, dirty-window set, mmap region set, or reply-credit ledger.
4. `p0` may supervise many `p2` processes, but it may not collapse them into one hot-path megaprocess that lets one mount's crash kill another mount's request/runtime state.
5. `p1` exits after readiness or refusal; it is never the durable owner of a live mount.

### 5.4 Backend classes

The production design now distinguishes exactly two backend classes:

| Backend class | Meaning |
|---|---|
| `backend.posix_filesystem_adapter.devfuse.production.k0` | the production Linux 7.0 userspace backend with direct `/dev/fuse` ownership and full mount-helper continuity |

It may **not** silently redefine the production process topology.
The production daemon law is written against `k0`.

## 6. Canonical component split and thread-set law

### 6.1 Logical runtime components

The root-supervisor and session-runtime processes together contain exactly these logical components:

| Component | Host process | Purpose |
|---|---|---|
| `component.posix_filesystem_adapter.control_listener.g0` | `p0` | local control socket / helper entry, idempotency, and supervisor-visible policy checks |
| `component.posix_filesystem_adapter.mount_broker.g1` | `p0` | converts admitted mount intents into session-spawn capsules and returns ready/refusal receipts |
| `component.posix_filesystem_adapter.session_registry.g2` | `p0` | tracks live mounts, mount ids, session ids, backend class, and phase |
| `component.posix_filesystem_adapter.global_budget_guard.g3` | `p0` | tracks global session/thread/FD/restart budgets and can refuse new mounts |
| `component.posix_filesystem_adapter.session_supervisor.g4` | `p2` | owns mount-lifetime bootstrap, stop/drain transitions, and local fatal-error classification |
| `component.posix_filesystem_adapter.request_runtime.g5` | `p2` | the `P5-02` ingress/classify/queue/worker/reply runtime |
| `component.posix_filesystem_adapter.page_runtime.g6` | `p2` | the `P5-03` page/writeback/mmap/direct-I/O runtime |

### 6.2 Stable thread-set classes

Each live `p2` session process owns these stable thread-set classes:

| Thread-set class | Meaning |
|---|---|
| `tset.posix_filesystem_adapter.control.t0` | tiny control/refusal path for local supervisor messages that affect the session |
| `tset.posix_filesystem_adapter.mount_broker.t1` | bootstrap/ready pipe and early handoff work only |
| `tset.posix_filesystem_adapter.session_supervisor.t2` | mount/session phase transitions, stop trigger handling, fatal-stop coordination |
| `tset.posix_filesystem_adapter.request_runtime.t3` | expands into the canonical `P5-02` ingress readers, worker lanes, interrupt routing, and forget/release handling |
| `tset.posix_filesystem_adapter.reply_commit.t5` | small/bulk reply committers and reply-credit release |

The thread-set law is strict:

1. `t3` and `t4` live inside `p2`; they are not permitted to move into detached sidecars.
2. `t5` may not be absorbed back into ingress or workers; reply commit remains a separate lawful class from `P5-02`.
4. `p0` threads may refuse new mount admission, but they may not reorder a live session's `P5-02` or `P5-03` hot-path work.

## 7. Canonical session/process chain

### 7.1 Mount admission chain

The production runtime now fixes one mount/session chain:

1. `p1` parses `mount(8)` / xfstests / local CLI inputs and emits one `PosixFilesystemAdapterMountIntentRecord`.
2. `p1` sends that intent to `p0` over the local helper contract.
4. `p0` allocates a session id and spawns one `p2` session-runtime process.
5. `p2` opens or receives the live `/dev/fuse` FD, opens the pool/dataset, binds the backend class, and materializes `P5-02` plus `P5-03` thread sets.
6. `p2` completes `INIT` and emits one ready or refusal receipt.
7. `p0` relays the ready/refusal result to `p1`.
8. `p1` exits.

There is no lawful alternate chain in which `p1` remains the durable owner of the mount.

### 7.2 Session phases

The phase classes are now fixed:

| Phase class | Meaning |
|---|---|
| `phase.posix_filesystem_adapter.mount_requested.s0` | helper-normalized mount intent exists but no session-runtime process owns the live session yet |
| `phase.posix_filesystem_adapter.session_bootstrap.s1` | `p2` exists and is acquiring backend, pool/dataset, and session-local state |
| `phase.posix_filesystem_adapter.init_negotiated.s2` | live `/dev/fuse` ownership and `INIT` negotiation are complete, but steady-state traffic is not yet admitted |
| `phase.posix_filesystem_adapter.live.s3` | steady-state `P5-02` and `P5-03` work is live |
| `phase.posix_filesystem_adapter.draining.s4` | ingress is closed for stop/cutover/unmount/failover/pressure and the session is draining replies, dirty state, and loans |
| `phase.posix_filesystem_adapter.stopped_or_quarantined.s5` | no live traffic remains; the session is either fully retired or fenced pending restart/quarantine action |

Only `p2` may move a live session through `s1-s4`.
`p0` records and supervises the phase, but it does not own the hot-path state.

### 7.3 Stop and drain law

A live session must enter `s4` for:
- explicit unmount,
- operator stop,
- failover or cutover fence that affects the mounted scope,
- severe reserve/pressure trigger,
- repeated fatal runtime errors,
- or controlled package/upgrade transition.

Drain means, in order:
1. close ingress for newly admitted ordinary work,
2. classify or fail visible outstanding requests under `P5-02`,
4. commit or fail pending replies under `response_registry`,
5. emit stop or drain receipts,
6. and only then release the mount-lifetime state.

## 8. Global-budget and restart law

### 8.1 Global versus session budgets

The process law now separates two budget scopes:

- **session-local budget state** inside `p2`
  - request depth
  - reply bytes
  - dirty-window bytes
  - page loans / pin debt
  - lock-wait occupancy
  - session-maintenance backlog
- **global supervisor budget state** inside `p0`
  - live mount count
  - total session threads
  - total live FDs and mount resources
  - total pinned/loaned bytes visible at the session boundary
  - restart-storm counters
  - admission ceiling for new mounts

`p0` may refuse a new mount intent when the global budget says no.
It may **not** become the local queueing authority for a live session.
`p2` remains responsible for the already-settled `P5-02` and `P5-03` backpressure law inside one mount.

### 8.2 Restart verdict classes

The restart/quarantine verdict classes are now fixed:

| Verdict | Meaning |
|---|---|
| `verdict.posix_filesystem_adapter.restart.fast_auto.v0` | session may be restarted automatically with the same mount intent because live state was fully drain-safe or the crash occurred before steady-state admission |
| `verdict.posix_filesystem_adapter.restart.cold_auto.v1` | session may restart automatically, but only by rebuilding clean runtime mirrors and failing/forgetting all mount-local inflight work |
| `verdict.posix_filesystem_adapter.quarantine.v3` | session may not restart automatically; mount remains fenced and visible as quarantined until a higher-level law clears it |
| `verdict.posix_filesystem_adapter.operator_repair.v4` | operator or runbook action is required because policy, packaging, media, or repeated-crash conditions are outside safe automatic recovery |
| `verdict.posix_filesystem_adapter.retire_mount.v5` | explicit unmount/disable/retirement; no restart is attempted |

### 8.3 Restart rules

The restart law is strict:

1. A crash before `phase.posix_filesystem_adapter.live.s3` is a mount-start failure, not a hidden background retry loop.
2. A crash after `s3` must emit a `PosixFilesystemAdapterCrashIncidentRecord` and a restart verdict.
3. `v0` requires no ambiguous dirty-writeback, shared-dirty mmap, or reply-commit state.
4. `v1` is allowed only when durable truth is intact but mount-local runtime mirrors must be rebuilt.
5. `v2` is mandatory when `publication_pipeline`, `response_registry`, `P5-03`, or stop-receipt state is incomplete enough that the supervisor cannot prove restart safety immediately.
6. `v3` or `v4` are mandatory on repeated crash storms, mount-identity mismatch, unresolved reply ambiguity, unresolved page-loan / mmap drain ambiguity, or package/policy mismatch.
7. No shell-level daemonize loop, mount-helper retry, or systemd restart setting may bypass these verdict classes.

## 9. Canonical runtime/schema families

| Record | Purpose | Authority class |
|---|---|---|
| `PosixFilesystemAdapterDaemonTopologyRecord` | one authoritative declaration of the production kernel-resident family, any bounded non-production mirror, helper family, execution classes, backend classes, and bound package/unit refs | authoritative declaration |
| `PosixFilesystemAdapterProcessClassRecord` | declaration of one runtime/helper/mirror execution class, allowed thread sets, ownership ceilings, and forbidden truth scopes | authoritative declaration |
| `PosixFilesystemAdapterMountHelperContractRecord` | argv/env schema, ready/refusal signaling, timeout law, and allowed backend/mount-option set for the helper family | authoritative declaration |
| `PosixFilesystemAdapterMountIntentRecord` | normalized request to create, stop, or remount one `posix_filesystem_adapter` session at one mountpoint and dataset under one backend class | authoritative/runtime intent |
| `PosixFilesystemAdapterSessionProcessRecord` | live or recent per-mount session process with phase, backend class, FD ownership, and start/stop or crash linkage | runtime mirror |
| `PosixFilesystemAdapterSessionThreadSetRecord` | one thread-set class instance for one session process, including worker floors/ceilings and queue/page-runtime bindings | runtime mirror |
| `PosixFilesystemAdapterSessionBridgeBindingRecord` | binding from one session process to `policy_authority`, `publication_pipeline`, `response_registry`, stop routes, and observe surfaces without inventing a sidecar truth path | authoritative/runtime binding |
| `PosixFilesystemAdapterProcessBudgetStateRecord` | session-local or global budget snapshot for live mounts, thread counts, FDs, reply bytes, pin debt, and restart pressure | runtime mirror / governance-linked |
| `PosixFilesystemAdapterRestartRecoveryRecord` | restart scan, required drain/reopen work, verdict class, quarantine locator, and close receipt for one crashed or drained mount | authoritative/runtime recovery record |

## 10. Canonical algorithms

| Algorithm | Purpose |
|---|---|
| `declare_posix_filesystem_adapter_runtime_topology_and_execution_classes()` | declare the production kernel-resident family, bounded mirror, helper contract, execution classes, backend classes, and package/unit bindings |
| `normalize_mount_helper_argv_env_to_posix_filesystem_adapter_mount_intent()` | turn `mount(8)` / xfstests / local CLI invocation into one `PosixFilesystemAdapterMountIntentRecord` |
| `admit_posix_filesystem_adapter_mount_intent_under_package_policy_and_global_budget()` | check package/unit/profile admission, idempotency, backend legality, and global session/thread/FD ceilings |
| `spawn_posix_filesystem_adapter_session_runtime_and_transfer_mount_capsule()` | create one `p2` process from one admitted mount intent and bind it to a live mount capsule |
| `materialize_posix_filesystem_adapter_session_thread_sets_from_p5_02_and_p5_03_laws()` | instantiate the session-local request/runtime, page/writeback/runtime, reply-commit, and maintenance thread sets |
| `bind_posix_filesystem_adapter_session_to_policy_authority_publication_pipeline_response_registry_and_observe_surfaces()` | bind the session runtime to the canonical authority/publication/response/observe seams without a sidecar truth path |
| `issue_posix_filesystem_adapter_ready_or_refusal_receipt_and_release_mount_helper()` | turn bootstrap success/failure into the helper-visible outcome and then retire `p1` |
| `drain_posix_filesystem_adapter_session_for_unmount_cutover_failover_or_pressure()` | close ingress, drain session-local queues and page state, emit stop receipts, and retire the mount lawfully |
| `recover_or_quarantine_posix_filesystem_adapter_session_after_crash_or_supervisor_restart()` | run restart scan, choose `v0-v5`, reopen or refuse the mount, or quarantine/retire it |

## 11. Whole-system operational paths added by this law

1. xfstests `mount(8)` or local mount request -> `helper.posix_filesystem_adapter.mount.mount_fuse_tidefs.h0` emits one `PosixFilesystemAdapterMountIntentRecord` -> bounded mirror or admitted runtime class handles the request -> ready receipt returns -> helper exits instead of becoming the hidden daemon
2. live `posix_filesystem_adapter` lookup/read/mutate traffic -> one per-mount `p2` process owns `P5-02` request/runtime lanes plus `P5-03` page/writeback state -> `publication_pipeline` and `response_registry` remain bound through `PosixFilesystemAdapterSessionBridgeBindingRecord` -> reply truth is not split across mount helper, session supervisor, and reply sidecars
3. operator stop, unmount, or cutover fence arrives -> `p0` records the stop trigger and moves the session to `phase.posix_filesystem_adapter.draining.s4` -> `p2` drains queues, dirty windows, page loans, mmap state, and reply commits -> stop receipt closes the mount without best-effort shell cleanup
4. a mirror or runtime class fails after steady-state admission -> `PosixFilesystemAdapterCrashIncidentRecord` plus `PosixFilesystemAdapterRestartRecoveryRecord` choose `v0-v5` -> the mount either recovers lawfully, is quarantined, or retires instead of relying on daemonize folklore

## 12. Acceptance effect on the design pack

With this law settled:

- `P5-01` becomes detailed enough for later implementation planning,
- the full `P5` POSIX/FUSE userspace runtime workstream is now at `L3`,
- the repo now has one explicit answer to where the mount helper ends, where the production kernel runtime begins, where any bounded mirror ends, where mount-lifetime state lives, and how crash containment is enforced,
- `P5-02`, `P5-03`, `memory_arena_0`, `publication_pipeline`, `response_registry`, and `package_profile_catalog` now share one process/topology grammar instead of one-off daemon wrappers and shell-local restart behavior,
- the production design ledger now has **no remaining `L1` items**,
- and the full production design ledger is now closed at `L3`, and later work is no longer missing shared seam/deletion law.
