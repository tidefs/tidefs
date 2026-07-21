# Scrub Subject Design Reference

Maturity: model-only reference. LocalFS has no foreground scrub carrier,
`ScrubBlockId`, or repair-dispatch consumer.

This document records the subject tuple used by the separate `tidefs-scrub-core`
comparison model. It does not describe current LocalFS runtime behavior,
mounted scrub, repair scheduling, transform routing, or dispatch policy.

## Upstream Authority

`docs/TIMESTAMP_GENERATION_AUTHORITY.md` is the upstream authority for the
meaning of `data_version` as a content object version. In that model,
`data_version` is owned by `tidefs-local-filesystem`, encoded in inode,
content-manifest, and content-chunk records, consumed by content object key
generation and receipt-authorized reads.

This document narrows only the scrub identity use of that token.

## Identity Boundary

The comparison model's content subject is:

```text
(inode_id, data_version)
```

`inode_id` names the local filesystem inode whose committed content is being
checked. `data_version` names the content version for that inode. The
subject-kind field selects a block inside that content identity:
inline content, the content manifest, or a chunk index. It is a block selector,
not a separate timestamp, generation, or epoch authority.

`tidefs-scrub-core::cross_replica_comparison::ScrubSubject` models this tuple,
but no LocalFS runtime currently produces or consumes it. The live online
verifier instead reads committed records through `MountedContentReadAuthority`.

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

The comparison model attaches checksum-layer and receipt evidence to this
subject. That evidence does not create a LocalFS repair authority or redefine
the content identity.

## Relationship To Mounted Behavior

There is no current mounted scrub or LocalFS repair bridge. Closed historical
issues that introduced the retired test scaffold do not establish runtime
behavior. Any future carrier must begin from current Pool receipt authority and
must not treat POSIX timestamps, `metadata_version`, transaction-group ticks,
or intent-log epochs as substitutes for committed content identity.

## Non-Claims

This document does not:

- change code, on-disk format, or runtime behavior;
- establish a current LocalFS scrub or repair consumer;
- route scrub through transform-aware content reads;
- authorize repair scheduling or repair writeback;
- close TFR-005.
