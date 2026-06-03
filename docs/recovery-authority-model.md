# Recovery Authority Model

TideFS recovery follows a single authority model: committed roots plus intent
replay are the production recovery answer. Automatic repair (scrub writeback,
metadata fixup) is a separate, opt-in pipeline gated by explicit policy.
Operators never need to run fsck to recover a filesystem.

## Recovery Pipeline

```
Committed-Root Selection  ->  Intent-Log Replay  ->  Scrub Inspection  ->  Repair Writeback
       (read-only)            (mutable replay)      (read-only)          (mutable repair)
```

Pipeline stages are gated by `RecoveryPolicy` (defined in
`tidefs-recovery-loop` and re-exported from `tidefs-scrub-core`):

| RecoveryPolicy       | Committed-Root | Intent Replay | Scrub Read | Repair Writeback |
|----------------------|:---:|:---:|:---:|:---:|
| ReadOnly             | yes | no  | yes | no  |
| ReplayOnly (default) | yes | yes | yes | no  |
| RepairWriteback      | yes | yes | yes | yes |

### ReadOnly
durable state. Suitable for forensics, online verification, and pre-mount
audit.

### ReplayOnly (Default)
Intent-log entries are replayed to bring the filesystem to the last committed
state. Scrub inspection runs read-only. Repair writeback and metadata fixup
are skipped. This is the safe production default: it recovers acknowledged data
without silent automatic repair.

### RepairWriteback
Full recovery pipeline: intent-log replay, scrub repair writeback, and
metadata fixup. Requires explicit operator opt-in (e.g. `tidefsctl mount
--recovery-policy repair-writeback`).

## What fsck Is

`run_fsck` in `tidefs-local-filesystem` is an advisory diagnostic pass that
scans namespace invariants, link counts, and committed-root validity. It runs
at mount time and reports warnings, but it does not mutate state. Production
recovery never requires an operator to run fsck.

## Design Authority

- Committed-root selection: always runs at mount (read-only).
- Intent-log replay: runs when policy allows replay (`ReplayOnly` or
  `RepairWriteback`).
  invoked on-demand through `LocalFileSystem::scrub_repair_pass`.
- Repair writeback: only runs when policy is `RepairWriteback` and a
  `BlockReconstructor` or healthy replica is available.

## Related

- `crates/tidefs-recovery-loop/src/lib.rs` — `RecoveryPolicy` enum definition
- `crates/tidefs-local-filesystem/src/recovery.rs` — mount-time recovery path
- `crates/tidefs-scrub-core/src/lib.rs` — `RecoveryPolicy` re-export
- A9 in `/root/ai/docs/projects/tidefs/state/full-review-attention-register.md`
