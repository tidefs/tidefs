# Kernel Teardown Runtime Evidence Decision

Maturity: current decision for `kernel.teardown.no_work_after.v1`.

This record decides the first implementation boundary for mounted runtime
evidence behind the blocked kernel teardown claim. It preserves the existing
source-model proof and claims-gate receipt boundary, and it does not update
workflow code, runtime harnesses, validators, claim registry files, generated
claim docs, or product behavior.

## Claim Boundary

`kernel.teardown.no_work_after.v1` remains `blocked` in
`validation/claims.toml` and `docs/CLAIM_REGISTRY.md`.

The registry already records source/model evidence:

- `kernel-context-token-model` at
  `validation/artifacts/kernel/teardown-race-proof-artifact.json`
- `teardown-race-proof-artifact` at the same source-model artifact
- `claims-gate-review` at
  `validation/artifacts/kernel/teardown-no-work-after-claims-gate-review.toml`

The registry blockers are still correct:

- the recorded teardown proof review is bounded source/model evidence, not
  mounted Linux runtime evidence;
- T5 mounted-kernel teardown stress with Linux workqueue and callback activity
  tracing is missing;
- T6 mounted kernel I/O teardown and recovery rows across the filesystem
  runtime are missing.

No current claim wording may say that TideFS has mounted Linux, full-kernel, or
no-daemon no-work-after-teardown safety. The claim can strengthen only after
matching runtime artifacts and a claims-gate review land in follow-up work.

## Evidence Reviewed

- #291 added the kernel context-token and teardown source-model seed. Its
  acceptance criteria explicitly kept source-model code out of product runtime
  evidence and left `kernel.teardown.no_work_after.v1` planned until validation
  artifacts existed.
- #320 turned the seed into claim-grade source-model proof for work enqueue,
  work start, completion, begin teardown, final teardown, generation/token
  invalidation, and callback context classes. It also required any mounted C
  shim or QEMU work to be separate if runtime behavior was needed.
- #536 added the teardown proof review receipt. The receipt says it does not
  exercise a mounted Linux module, Linux workqueue execution, mounted
  filesystem I/O, QEMU, xfstests, mmap, syncfs, or crash/recovery runtime rows.
- `docs/CLAIMS_GATE_POLICY.md` defines `source-model`, `mounted-kernel-vfs`,
  and `full-kernel-no-daemon` as separate tiers. Lower-tier evidence can
  diagnose higher-tier claims, but cannot validate them.
- `docs/TEST_SIGNAL_AUDIT.md` lists `kernel_env_model_*` tests as source-model
  proof signal only.
- `docs/NEXTGEN_VERIFICATION_PERFORMANCE_OFFLOAD_PLAN.md` says the kernel
  teardown model is bounded source-model evidence only and maps mounted kernel
  VFS to T5 and full-kernel no-daemon to T6.
- `docs/GITHUB_CI.md` describes QEMU Smoke, Kernel mmap validation, xfstests,
  and Release Candidate as self-hosted runtime lanes; runtime-heavy validation
  belongs there, not in local Codex worktrees.

Adjacent issue state at this review:

- #604 is closed. It fixed the k7-vfs `generic/013` D-state hang scope and does
  not own teardown artifact contracts.
- #614 is closed. It recorded uBLK started-export admission evidence and is
  separate from mounted kernel VFS teardown.
- #644 is closed by PR #759. It added kernel fsync/syncfs evidence manifests;
  that manifest shape is fsync-specific and not a teardown contract.
- #671 remains open. It owns the top-level release-candidate evidence index and
  must consume lane-local evidence rather than define the teardown lane itself.
- PR #714 for #643 is open and relevant for generic xfstests run manifests,
  but it does not define the teardown claim artifact fields required here.

## Current Workflow Target State

The current self-hosted workflow surface has useful building blocks, but not a
trustworthy teardown evidence row:

- `QEMU Smoke` can dispatch `kmod-xfstests-smoke`, `kernel-fsync-validation`,
  `kernel-mmap-validation`, `fuse-vm-test`, `qemu-ublk-smoke`, or `all`.
- `xfstests` can dispatch `target=k7-vfs` and focused `tests` lists, but its
  current artifact contract is generic row output, not teardown-specific
  workqueue/callback evidence.
- `kernel-fsync-validation` emits a claim evidence manifest for
  `kernel.fsync.durability.v1`, not for teardown.
- `nix/vm/kernel-mount-cycle-stress-validation.nix` performs mount, write,
  sync, unmount, rmmod, reload, dmesg, and slab checks. It is a good behavioral
  seed, but today it writes an ad hoc `manifest.json`, records
  `validation_tier` as a freeform QEMU guest string, stores output under a
  local `/root/ai/tmp` path, and does not record Linux workqueue/callback trace
  sources or post-final-teardown refusal observations.
- `nix/vm/kernel-no-daemon-validation.nix` exercises a broader T6 no-daemon
  mounted operation matrix and counts `REFUSAL` lines, but it is too broad for
  the first teardown evidence row and does not prove teardown-specific
  workqueue/callback behavior.

## Alternatives

### Alternative A: First Implement A T5 Mounted-Kernel VFS Row

This would wire a focused mounted-kernel teardown stress row around the
existing mount-cycle stress behavior and emit a teardown artifact from GitHub
Actions.

Pros:

- matches the first missing registry blocker, T5 mounted-kernel teardown
  stress;
- can be smaller than T6 because it only needs mounted VFS teardown lifecycle,
  not all no-daemon filesystem runtime;
- can reuse the existing Linux 7.0 QEMU module, mount-cycle, dmesg, and cleanup
  machinery.

Cons:

- the current target cannot yet emit claim-grade teardown evidence;
- without a validator, the workflow would risk producing an artifact that looks
  structured but omits required fail-closed fields;
- any direct workflow change would overlap the artifact-contract decision that
  must be stable before registry wiring.

Decision: implement this after the teardown artifact schema and validator
exist. This is the first runtime row, but not the first implementation slice.

### Alternative B: First Implement A T6 Full-Kernel/No-Daemon Row

This would extend the full no-daemon validation path and try to close the
stronger runtime class first.

Pros:

- aims directly at the strongest claim boundary;
- can eventually prove no-daemon teardown and recovery across a broader mounted
  filesystem runtime.

Cons:

- too broad for the first runtime evidence row;
- combines teardown proof with unrelated no-daemon VFS operation coverage;
- would still need the teardown artifact schema and T5 mounted-kernel evidence
  to explain what is being proved;
- risks implying product no-daemon safety before the narrower mounted-kernel
  teardown trace is trustworthy.

Decision: defer. T6 is a follow-up after the T5 artifact has passed and the
claim review has recorded what remains blocked.

### Alternative C: First Implement A Prerequisite Artifact Schema And Validator

This would add a narrow teardown runtime artifact type and an xtask checker
before any workflow writes claim-facing teardown evidence.

Pros:

- makes the runtime row fail closed before it can affect claim wording;
- captures the required fields that the generic fsync and xfstests manifests do
  not cover;
- lets future workflow and claim-registry slices share one contract;
- does not require local QEMU or heavy validation.

Cons:

- it is not itself mounted runtime evidence;
- it delays runtime collection by one slice.

Decision: selected first implementation slice.

### Alternative D: First Implement A Workflow-Target Slice

This would add a `kernel-teardown-validation` workflow or QEMU Smoke target
before adding the validator.

Pros:

- makes the runtime row dispatchable quickly;
- can reuse the existing self-hosted QEMU runner labels and mount-cycle script.

Cons:

- without the schema/validator, missing trace or cleanup fields could be
  uploaded as ambiguous logs;
- the existing runtime target currently cannot emit trustworthy teardown
  evidence because it lacks workflow-owned source identity, structured teardown
  phases, and trace/refusal fields.

Decision: defer until the schema exists. The workflow-target slice should be
second, and it should fail if the validator rejects the produced artifact.

## Selected Path

The first safe implementation is a prerequisite artifact-schema/validator
slice. The first runtime row after that is a focused T5
`mounted-kernel-vfs` teardown stress row. T6 `full-kernel-no-daemon` evidence
and claim-registry wording remain blocked until later slices record matching
runtime artifacts.

Selected validation tier for the first runtime row:
`mounted-kernel-vfs` (T5).

Runtime target shape:

- self-hosted GitHub Actions dispatch on the feature branch;
- a narrow target id such as `kernel-teardown-mounted-vfs`;
- Linux 7.0 QEMU guest with `tidefs_posix_vfs.ko`;
- bootstrap mounted VFS lifecycle stress based on mount, write, sync, begin
  teardown, final unmount, module unload, remount/reload cleanup, and post-final
  operation refusal probes;
- Linux workqueue/callback tracing enabled through tracefs/ftrace or an
  equivalent kernel-owned trace source, with trace capture copied into the
  uploaded artifact directory.

Artifact producer:

- the workflow step that runs the teardown target must write
  `kernel-teardown-runtime.json` and `evidence-manifest.json` into the uploaded
  artifact directory;
- the Nix/QEMU harness may generate raw logs and trace files, but the workflow
  owns run identity, source ref/SHA, artifact-relative paths, and final upload.

Artifact validator/checker expectation:

- a focused validator, for example
  `cargo run -p tidefs-xtask -- validate-kernel-teardown-runtime-artifact
  <path>`, must load the teardown JSON and reject missing or inconsistent
  fields;
- the workflow-target slice must run that validator before upload or as a
  follow-up focused claim-validation workflow;
- the generic `validate-evidence-manifest` schema may wrap the produced
  artifact, but it is not enough by itself because teardown needs phase,
  trace, refusal, and cleanup semantics.

Fail-closed conditions:

- missing workflow name, run id, run attempt, source ref, or source SHA;
- source SHA mismatch between workflow context and artifact;
- validation tier other than `mounted-kernel-vfs` for the T5 artifact;
- target id not equal to the selected teardown target;
- missing phase result for begin teardown, final teardown, post-final refusal,
  cleanup, or module unload/reload;
- any workqueue or callback trace event that starts TideFS work after final
  teardown;
- missing trace source, trace capture, or trace capture digest;
- post-final operation accepted when it must be refused, or refusal is not
  observable;
- cleanup failure hidden behind a pass status;
- dmesg WARNING, BUG, oops, lockdep, KASAN, KCSAN, hung-task, or call-trace
  evidence not represented in status;
- no uploaded artifact or malformed JSON;
- validator/checker failure.

## Artifact Contract

The teardown runtime artifact must be JSON with unknown fields rejected by the
validator. Required fields:

- `artifact_version`
- `claim_id`, exactly `kernel.teardown.no_work_after.v1`
- `evidence_class`, for example
  `runtime-kernel-teardown-no-work-after-artifact`
- `workflow_name`
- `workflow_run_id`
- `workflow_run_attempt`
- `workflow_job`
- `source_ref`
- `source_sha`
- `validation_tier`, exactly `mounted-kernel-vfs` for the first runtime row
- `target_id`, exactly the selected teardown target id
- `kernel_release`
- `module_name`
- `module_digest` or other stable module build identity
- `teardown_phases`, with named phase, status, start/end timestamp or monotonic
  ordering, and notes for at least:
  `module_load`, `mount`, `pre_teardown_io`, `begin_teardown`,
  `final_teardown`, `post_final_refusal_probe`, `cleanup`, `module_unload`,
  and `reload_probe`
- `workqueue_trace_source`, naming tracefs/ftrace events, module tracepoints,
  dmesg markers, or another kernel-owned trace source
- `workqueue_trace_artifact_path`
- `workqueue_trace_digest`
- `callback_trace_source`
- `callback_trace_artifact_path`
- `callback_trace_digest`
- `post_final_teardown_refusal_observations`, including operation, expected
  refusal, observed result, and whether new work was enqueued or started
- `cleanup_outcome`, including unmount, rmmod, reload/remount probe, dmesg
  state, and remaining TideFS work observations
- `status`, one of `pass`, `fail`, `blocked`, or `no-result`
- `fail_closed_reasons`, empty only for `pass`

The companion generic evidence manifest may record the teardown JSON path and
digest, but the teardown JSON remains the semantic artifact.

## Claim Registry Boundary

The source-model evidence remains valid only for the modeled kernel teardown
token state machine. It covers modeled enqueue/start/complete ordering,
begin-teardown, final-teardown, generation invalidation, and callback classes.

Mounted runtime evidence would require a passing T5 artifact from the selected
mounted-kernel VFS target, validated by the teardown checker, with workqueue
and callback trace sources proving no TideFS work starts after final teardown
and with explicit post-final refusal and cleanup observations.

The claim registry must remain blocked until:

- the T5 mounted-kernel artifact exists and is validated;
- the T6 full-kernel/no-daemon teardown and recovery row exists and is
  validated, or the registry explicitly records that T6 remains a blocker;
- a claims-gate review artifact names the source-model, T5, and any T6
  evidence reviewed and states the remaining non-claims;
- `validation/claims.toml` and generated `docs/CLAIM_REGISTRY.md` are updated
  only from that evidence.

## Follow-Up Implementation Mapping

1. Follow-up issue #906:
   `kernel-teardown-evidence: add mounted runtime artifact schema and validator`

   Expected write set:
   `crates/tidefs-validation/src/kernel_teardown_evidence.rs`,
   `crates/tidefs-validation/tests/kernel_teardown_evidence.rs`,
   `crates/tidefs-validation/src/lib.rs`, and
   `xtask/tidefs-xtask/src/main.rs`.

   Validation tier:
   `cargo-unit` plus `git diff --check` and Focused Rust for
   `tidefs-validation,tidefs-xtask`.

   Non-overlap:
   no workflow, Nix VM runtime, claim registry, generated claim docs, or product
   behavior changes.

2. Follow-up issue #907:
   `kernel-teardown-runtime: emit T5 mounted VFS teardown artifact`

   Expected write set:
   `.github/workflows/qemu-smoke.yml` or a new focused
   `.github/workflows/kernel-teardown-validation.yml`, `flake.nix`,
   `nix/vm/kernel-mount-cycle-stress-validation.nix` or a new
   `nix/vm/kernel-teardown-validation.nix`, and `docs/GITHUB_CI.md` if the new
   target needs user-facing dispatch documentation.

   Validation tier:
   `mounted-kernel-vfs`; dispatch the smallest focused teardown target on
   self-hosted GitHub Actions. Use no local QEMU.

   Non-overlap:
   no claim-registry status change; no T6 no-daemon matrix expansion; consume
   the validator from the first follow-up.

3. Follow-up issue #908:
   `kernel-teardown-no-daemon: add T6 teardown and recovery row`

   Expected write set:
   `nix/vm/kernel-no-daemon-validation.nix` or a focused sibling no-daemon
   teardown row, `flake.nix`, an appropriate self-hosted workflow target, and
   `docs/GITHUB_CI.md` only for dispatch documentation.

   Validation tier:
   `full-kernel-no-daemon`; run only after the T5 artifact is passing or when a
   live issue explicitly records why T6 can proceed independently.

   Non-overlap:
   no claim-registry wording unless this issue also records the accepted T6
   artifact and a separate claims-gate review authorizes that update.

4. Follow-up issue #909:
   `kernel-teardown-claims: review runtime evidence and update claim blockers`

   Expected write set:
   `validation/artifacts/kernel/*` for the claims-gate review artifact,
   `validation/claims.toml`, and generated `docs/CLAIM_REGISTRY.md`.

   Validation tier:
   Focused Claim Validation for
   `kernel.teardown.no_work_after.v1`, `git diff --check`, and no local heavy
   runtime validation.

   Non-overlap:
   no workflow or runtime harness changes. This issue may keep the claim
   blocked with narrower blocker text if T5 is accepted but T6 remains missing.
