# Validation Fixtures

This directory is for small, source-controlled validation fixtures such as
golden binary records, seed inputs, and static compatibility samples.

Runtime validation output must stay outside the repository, normally under:

```text
/root/ai/tmp/tidefs-validation/
```

Do not create repo-local validation output, output indexes, promotion state, or
policy surface here. A validation command may record commit, branch, dirty
state, command, kernel, backend, and result in its external output directory,
but those files are scratch state unless the operator explicitly requests a
separate handoff outside this repository.

## Evidence Artifact Manifests

Claim-producing tools should write a reusable JSON manifest record for each
artifact that may be cited by `validation/claims.toml` or later claim
receipts. The TideFS-owned schema lives in
`tidefs_validation::evidence_artifact_manifest::EvidenceArtifactManifest`.

Each manifest records:

- `manifest_version = 1`
- `claim_id`
- `evidence_class`
- `validation_tier`
- `source`
- `scope`
- `artifact_path`
- `content_digest` as `blake3:<64 hex>`
- optional `generated_at`
- `blocking_issues`

The `artifact_path` must be relative to the repository or validation artifact
root, and `content_digest` must match the bytes at that path. Use the
manifest helpers in `tidefs-validation` to serialize, parse, and verify the
record instead of parsing per-tool output shapes.

Model-only artifacts must use a model tier such as `source-model` and a scope
that names the model boundary. They are useful evidence, but they are not
runtime crash, performance, uBLK, kernel, distributed, or offload validation.
Only artifacts produced by the corresponding runtime workflow may use runtime
tiers such as `mounted-userspace`, `qemu-guest`, `mounted-kernel-vfs`,
`kernel-block-io`, `full-kernel-no-daemon`, or
`multi-process-distributed`.
