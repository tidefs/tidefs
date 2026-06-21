# Scrub Identity Authority

Maturity: design authority for the local scrub identity boundary under
TFR-005. Produced under GitHub issue #742.

This document names the identity boundary used when local scrub records a
content finding. It is a documentation slice only: it does not change scrub
runtime behavior, repair scheduling, transform routing, or dispatch policy.

## Upstream Authority

`docs/TIMESTAMP_GENERATION_AUTHORITY.md` is the upstream authority for the
meaning of `data_version` as a content object version. In that model,
`data_version` is owned by `tidefs-local-filesystem`, encoded in inode,
content-manifest, and content-chunk records, consumed by content object key
generation, and consumed by `ScrubBlockId.data_version`.

This document narrows only the scrub identity use of that token.

## Identity Boundary

The authoritative content identity carried by `ScrubBlockId` is:

```text
(inode_id, data_version)
```

`inode_id` names the local filesystem inode whose committed content is being
checked. `data_version` names the content version for that inode. The
`ScrubBlockKind` field selects the scrub subject inside that content identity:
inline content, the content manifest, or a chunk index. It is a block selector,
not a separate timestamp, generation, or epoch authority.

The current local scrub implementation constructs that identity from the
persisted content records it is checking:

- inline content findings use `record.data_version`;
- content chunk findings use `chunk_ref.data_version`;
- object keys are derived from the same `(inode_id, data_version)` content
  identity.

## Negative Authority

Scrub identity is not any of these authorities:

- not wall-clock time;
- not POSIX `atime`, `mtime`, `ctime`, or `btime`;
- not storage `metadata_version`;
- not VFS `subtree_rev`, `dir_rev`, or file-handle `generation`;
- not a `CommitGroupId` or storage-generation tick, even when a content write
  originally stamped `data_version` from the current transaction group;
- not an intent-log epoch, replay position, or recovery ordering token;
- not a checksum-layer identity by itself;
- not repair dispatch authority by itself.

The scrub path may use checksum-layer evidence to prove what byte layer failed,
and later repair paths may require placement or receipt evidence before any
writeback. Those are additional evidence authorities. They do not redefine the
local scrub content identity named here.

## Relationship To Mounted Scrub And Repair Work

This document deliberately does not own the future transform-aware mounted
scrub or repair behavior:

- Issue #650 owns the mounted content scrub read authority API.
- Issue #651 owns routing local scrub through that mounted content identity.
- Issue #652 owns repair dispatch gating on mounted scrub evidence.

Those later slices must preserve the `(inode_id, data_version)` content
identity while adding the evidence they own, such as plaintext mounted content
identity, checksum-layer evidence, and placement or receipt evidence status.
They must not treat POSIX timestamps, `metadata_version`, transaction-group
ticks, or intent-log epochs as substitutes for `ScrubBlockId.data_version`.

## Non-Claims

This document does not:

- change code, on-disk format, or runtime behavior;
- route scrub through transform-aware content reads;
- authorize repair scheduling or repair writeback;
- close TFR-005;
- close issues #650, #651, or #652.
