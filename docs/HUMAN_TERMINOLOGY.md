# Human terminology history

Status: **historical input**, not current workspace or source authority.

`docs/DOCUMENTATION_AUTHORITY_REGISTER.md` classifies this file as imported
historical input. It preserves useful terminology history, but crate paths,
workspace membership, and implementation status below must be checked against
the current workspace and `docs/workspace-package-classification.md` before
they are used as source authority.

The imported naming note preferred human-readable architecture names over
opaque compact family labels in preview-facing source, package names, CLI
output, docs, and new public APIs. Treat that rule as terminology history
unless another current policy or spec promotes the same boundary.

## Imported architecture-name map

| Human name | Rust/package locator | Plain-English role |
|---|---|---|
| Control Plane | `control_plane` | Operator/control API, request envelopes, carrier frames, and control-plane receipts. |
| Publication Pipeline | `publication_pipeline` | Emission tickets and admitted-decision publication. |
| Response Registry | `response_registry` | Visible answers, response indexes, and recall bindings. |
| Truth View | `truth_view` | Operator-visible truth and archive-recall bundles. |
| Archive Control | `archive_control` | Archive disposition, tombstones, and non-live guards. |
| POSIX Filesystem Adapter | `posix_filesystem_adapter` | POSIX/VFS projection path; future FUSE and kernel adapter. |
| Block Volume Adapter | `block_volume_adapter` | Block-volume projection path; future userspace block export and kernel block integration. |
| Explanation Query | `explanation_query` | Operator explanation/query surface. |
| Canonical Schema Codec | `schema_codec` | Fixed-width little-endian encode/decode records and packet codecs. |
| Package Profile Catalog | `package_profile_catalog` | Build profile, capability, bundle, and service-surface manifests. |
| VFS Boundary Mirror | `vfs_boundary_mirror` | Fixed-size VFS boundary mirrors between owned and ABI-safe values. |
| Authority Publication Kernel | `authority_publication` | Future authority publication and head/root movement family. |
| Claim/Reserve/Witness Kernel | `claim_reserve_witness` | Future claim, reserve, witness, repair, escrow, and quorum family. |
| Response Normalizer | `response_normalizer` | Future response-language and charter-rendering family. |

## Historical source examples

The following examples are retained for terminology history, not as a current
crate map. `docs/workspace-package-classification.md` records that
`tidefs-types-control-plane-core`,
`tidefs-types-publication-pipeline-core`, and
`tidefs-types-response-registry-core` were deleted after their live record
definitions already existed in `crates/tidefs-types-vfs-core`.

Human package paths:

```text
crates/tidefs-types-control-plane-core (deleted historical root; see crates/tidefs-types-vfs-core)
crates/tidefs-types-publication-pipeline-core (deleted historical root; see crates/tidefs-types-vfs-core)
crates/tidefs-types-response-registry-core (deleted historical root; see crates/tidefs-types-vfs-core)
crates/tidefs-types-posix-filesystem-adapter-core
crates/tidefs-types-secret-key-policy-core
crates/tidefs-schema-codec-posix-filesystem-adapter
crates/tidefs-schema-codec-vfs
apps/tidefs-posix-filesystem-adapter-daemon/src/runtime
apps/tidefs-posix-filesystem-adapter-daemon
```

Human Rust identifiers:

```text
ControlPlaneRequestEnvelopeHead
PolicyAuthorityRequestCapsuleRecord
PublicationPipelineEmissionTicketRecord
ResponseRegistryVisibleAnswerRecord
PosixFilesystemAdapterProductWakeReceiptRecord
SecretLeaseGrantRecord
LocalFileSystem
LocalObjectStoreFormatRule
```

## Stable locators

Readable locators such as `control_plane`, `policy_authority`, and
`schema_codec` appeared in the imported naming guidance as examples of
understandable English labels for crate imports, stable IDs, and wire strings.

The imported rule was not "never use a compact string." It was: **never
introduce opaque family labels when a human-readable locator can be used
instead.**

## Storage naming rule

The imported note cited the Local Object Store and Local Filesystem naming
pattern:

```text
crates/tidefs-local-object-store
crates/tidefs-local-filesystem
```

Future storage, userspace, kernelspace, and distributed components should use
current workspace and documentation authority before treating this historical
pattern as binding.


The imported note also warned that source names must not make runtime-output
trees, packets, or historical closeout labels part of the current product
surface; current product-surface authority must come from current specs and
source evidence.
