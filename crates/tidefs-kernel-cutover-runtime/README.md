# tidefs-kernel-cutover-runtime

Userspace-to-kernel transition state machine with fence management, gate evaluation, and rollback.

## Authority Boundary

This crate is the current source/model authority for kernel cutover mode
sequencing, dry-run gate admission, cutover fence token lifecycle, rollback
receipts, deterministic validation digests, and the T4 source/model teardown
review receipt for `kernel.teardown.no_work_after.v1`.

It is not mounted Linux runtime authority yet. Mounted-kernel cutover/fence
evidence remains tracked by
[#1186](https://github.com/tidefs/tidefs/issues/1186), and full kernel-mode
product claims stay blocked until accepted T5/T6 runtime artifacts and
claim-registry review justify them.

## Daemon Independence

This crate has zero dependencies on any userspace daemon crates
(`tidefs-fuser`, `tidefs-posix-filesystem-adapter-*`,
`tidefs-block-volume-adapter-*`). It has no runtime dependencies at all
beyond the `blake3` hashing crate (dev-only). No daemon-only contracts,
types, or initialization patterns are transitively pulled into the kernel
build.

Verified with:
```sh
cargo tree -p tidefs-kernel-cutover-runtime --edges normal | grep -iE 'tidefs-fuser|posix-filesystem-adapter|block-volume-adapter'
# (produces no output)
```


## BLAKE3 Validation

Domain: `tidefs-kernel-cutover-validation-v1`

39 integration tests in `tests/cutover_validation.rs` exercise the full cutover lifecycle with deterministic state digests.

### Coverage

| Category | Tests | Scenarios |
|---|---|---|
| Snapshot determinism | 5 | Same state, different modes, in-progress, rollback plan, domain separation |
| Full transition lifecycle | 5 | Userspace→MixedPosixRead, MixedPosixRead→MixedFullClient, MixedFullClient→FullKernel, 4-mode forward chain, 4-mode rollback chain |
| Digest chain | 2 | Intermediate state chain determinism, full chain replay |
| Rollback & recovery | 6 | Preflight rollback, staged fence rollback, verify-truth rollback, symmetry forward-back-forward, custom plan, no-active-cutover error |
| Error injection | 6 | Gate refusal, blocked/quarantine results, double begin, illegal skip, illegal non-adjacent, advance without active |
| Fence errors | 2 | Double acquire, kind mismatch on release |
| Concurrent isolation | 2 | Independent executors, full cutover isolation |
| Committed-root chain integrity | 3 | Forward determinism, rollback validation, partial-rollback redo determinism |
| Fence manager digest | 2 | Acquisition changes digest, different kinds different digests |
| Transition digest | 2 | Deterministic, different directions |
| Step chain | 2 | Full sequence, truncated vs full |
| Fence token | 1 | Token affects state digest |
| Rollback receipt | 1 | Validation field preservation |
| Full roundtrip | 1 | Userspace→FullKernel→Userspace complete cycle |

### Digest Schema

Each digest is computed with `blake3::Hasher::new_derive_key(DOMAIN)` where `DOMAIN = "tidefs-kernel-cutover-validation-v1"`.

**state_digest**: `[current_mode, target_mode_present?, target_mode_value?, current_step_present?, current_step_value?, rollback_plan_present?, plan_fields..., held_fence_present?, fence_token_bytes...]`

**transition_digest**: `[b"transition", from_mode, to_mode]`

**fence_manager_digest**: `[b"fence-manager", has_fence, held_kind?]`

**executor_digest**: `[b"executor", state_digest, fence_manager_digest]`

**step_chain_digest**: `[b"step-chain", step_ordinals...]`

## Teardown Proof Review Receipt

`teardown_proof_review_receipt()` exports the claims-gate review fields for
`kernel.teardown.no_work_after.v1`: the covered teardown token states,
forbidden post-teardown work cases, source proof artifact digest, validation
tier, and claim id.

The receipt is T4 source/model evidence only. It deliberately records
`mounted_linux_runtime_evidence = false` and keeps the claim blocked until
additional T5/T6 evidence exists:

- T5 mounted-kernel teardown stress with Linux workqueue and callback activity tracing.
- T6 full-kernel/no-daemon teardown and recovery rows across the filesystem runtime.
