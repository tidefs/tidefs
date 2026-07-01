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

- `manifest_version = 2`
- `claim_id`
- `evidence_class`
- `validation_tier`
- `scope`
- `artifact_path`
- `content_digest` as `blake3:<64 hex>`
- `run_id`
- `source_ref`
- `outcome` as `pass`, `product-fail`, `harness-fail`,
  `environment-refusal`, or `skip`
- `residual_risk`
- `source`
- `generated_at`
- `blocking_issues`

`blocking_issues` lists only current unresolved GitHub blockers for the
artifact or registry evidence requirement. Closed issues and merged pull
requests are historical context, not active blockers, and must be recorded in
claim blocker text or authority docs instead of this field when they still
explain evidence lineage.

The `artifact_path` must be relative to the repository or validation artifact
root, and `content_digest` must match the bytes at that path. Use the
manifest helpers in `tidefs-validation` to serialize, parse, and verify the
record instead of parsing per-tool output shapes.

Version-1 manifests are retired pre-standardization input. They can be read as
historical review material, but `validate-evidence-manifest` rejects them for
future claim closure because the run id, source ref, outcome, residual risk,
and blocking issue state were not explicit common fields.

Model-only artifacts must use a model tier such as `source-model` and a scope
that names the model boundary. They are useful evidence, but they are not
runtime crash, performance, uBLK, kernel, distributed, or offload validation.
Only artifacts produced by the corresponding runtime workflow may use runtime
tiers such as `mounted-userspace`, `qemu-guest`, `mounted-kernel-vfs`,
`kernel-block-io`, `full-kernel-no-daemon`, or
`multi-process-distributed`.

For the current policy mapping from validation tiers to claim evidence
classes, and for the rule that lower-tier evidence may diagnose but cannot
validate higher-tier claims, see
`docs/CLAIMS_GATE_POLICY.md#validation-tier-evidence-map`.
