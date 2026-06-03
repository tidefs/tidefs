# Formal no-production-fsck failure model (OW-004) (v0.403; last design review - needs refresh)

> TFR-019 authority note: this imported implementation note is review material,
> the behavior below as needing reconciliation with current source,
> `docs/REVIEW_TODO_REGISTER.md`, and `docs/WHOLE_REPO_REVIEW.md`.

Historical tracker wording: item 004.

This document describes the historical `OW-004` failure model that the Local
Filesystem recovery protocol must satisfy. It is deliberately narrower than a
complete storage-system certification model. The point is to state what normal
production recovery can decide automatically, what it must reject explicitly,
and where development verifiers may help without becoming a required production
fsck step.

## Recovery theorem

For any crash, power loss, process death, or storage read error inside this
model, reopening a Local Filesystem store must converge to exactly one of:

```text
previous committed root
new committed root
explicit integrity/media error
```

Recovery must not mount a partial namespace, must not invent repaired truth, and
must not require production fsck before it can decide which of those three
outcomes applies.

## Commit vocabulary

The source-level publication protocol is:

```text
1. Write new versioned content objects.
2. Write immutable transaction inode objects.
3. Write immutable transaction directory objects.
4. Write the immutable transaction superblock object.
5. Sync transaction objects.
6. Write one root-slot commit candidate.
7. Sync the root-slot commit.
```

Only a valid root-slot commit can publish namespace truth. Transaction objects
and content objects written before root-slot publication are staging data. A
root-slot candidate is selectable only when its referenced superblock, manifest,

## Sync semantics

The model assumes POSIX-like `fsync` / `sync_all` intent, with the usual local
disk caveat: if the host, filesystem, virtual disk, or physical device lies
about durable flush, TideFS cannot prove stronger durability than the platform
provides.

Within that assumption:

- data visible before transaction-object sync is not publication;
- transaction-object sync makes staging objects eligible to be referenced;
- root-slot write creates a candidate but not a guaranteed durable commit;
- root-slot sync is the durable publication boundary;
- a reported sync or read error is an explicit error path, not a repair prompt.

## Failure classes

| Class | In model | Required result |
|---|---:|---|
| Clean durable commit | yes | new committed root |
| Process death before root-slot write | yes | previous committed root |
| Process death after root-slot write before root-slot sync | yes | previous or new committed root |
| Power loss with write reordering | yes | previous root, new root, or explicit error; never partial truth |
| Torn writes at final append tail | yes | automatic replay truncation, then previous/new/error |
| Lost writes not proven by sync | yes | previous or new committed root |
| Media corruption in a newer candidate with an older valid root | yes | previous committed root |
| Object-store I/O, checksum, unsupported-version, or non-final-segment damage | yes | explicit integrity/media error |
| Malicious storage, Byzantine storage, or arbitrary false reads after successful verification | no | outside this model |

The words `write reordering`, `torn writes`, `lost writes`, `media corruption`,
`sync semantics`, and `explicit-error behavior` are intentionally source-gate
markers. `tidefs-xtask check-no-fsck-failure-model` verifies that the document,

## Reordering rule

A crash may expose writes in any order unless a completed sync boundary forces
the ordering. Recovery therefore does not trust object presence alone. It

```text
root-slot commit
transaction manifest
transaction superblock checksum
transaction inode records
transaction directory records
referenced content object versions
mount invariants
```

If a newer candidate fails any check and an older candidate is valid, the older
root is selected automatically. If no valid candidate remains and root-slot
records exist, recovery reports explicit integrity/media error.

## Torn-write rule

The Local Object Store may automatically truncate an interrupted append tail in
the final segment. That is not production fsck because it is deterministic
append-log replay, not namespace repair.

Damage in a non-final segment is not repaired. It is an explicit error because
older data that may be referenced by committed roots can no longer be trusted.

## Lost-write rule

A write that was not proven durable by the relevant sync may be absent on
reopen. The allowed result depends on which publication records survive:

- no valid new root candidate: previous committed root;
- valid new root candidate and complete referenced graph: new committed root;

No lost-write case may make a transaction object, directory object, content
object, or superblock independently authoritative.

## Explicit-error behavior

Explicit errors include:

- all root-slot records invalid;
- checksum mismatch;
- unsupported record or root version;
- malformed root-slot commit;
- missing or mismatched transaction manifest;
- missing transaction object referenced by a root candidate;
- mount-invariant failure in a candidate;
- non-final object-store segment corruption;
- host I/O error while reading or syncing required storage.

These errors may block mounting, but they are not an instruction to run
production fsck. They mean the store did not contain an automatically selectable
committed root under the declared model.


The source model is exposed through:

```text
FORMAL_NO_PRODUCTION_FSCK_FAILURE_MODEL
NoProductionFsckFailureClass
NoProductionFsckFailureModelCase
NO_PRODUCTION_FSCK_FAILURE_MODEL_CASES
no_production_fsck_failure_model_cases()
```


- `no_production_fsck_failure_model_covers_ow004_classes`
- `crash_injection_boundaries_select_only_old_or_new_committed_roots`
- `real_directory_crash_recovery_matrix_reports_only_allowed_outcomes`
- `all_root_slots_invalid_reports_explicit_integrity_error_without_fsck`
- `invalid_newer_same_slot_root_falls_back_to_previous_version_without_operator_repair`
- `missing_manifest_newer_root_is_skipped_without_operator_repair`
- `bad_link_count_committed_root_is_skipped_before_mount_without_fsck`
- `unreachable_inode_committed_root_is_skipped_before_mount_without_fsck`
- `truncated_tail_is_repaired_without_losing_committed_record`
- `checksum_mismatch_rejects_replay`

The filesystem demo prints the model cases as:

```text
no_fsck_failure_model.cases
no_fsck_failure_model.case class=...
```

## Still outside the model

This does not yet prove preview-release storage maturity. Still open:

- property/fuzz crash schedules;
- filesystem- and device-level fault injection beyond the current matrix;
- online scrub/repair that is proactive maintenance, not required mount
  recovery;
