# Chunked File Layout (OW-101)

> TFR-019 authority note: this imported implementation note is review material,
> the behavior below as needing reconciliation with current source,
> `docs/REVIEW_TODO_REGISTER.md`, and `docs/WHOLE_REPO_REVIEW.md`.

This document records the historical file-content layout slice for review.

## Implemented State

The Local Filesystem no longer writes new regular-file or symlink content as a single whole-file payload. The versioned content object remains the stable root reference for an inode data version, but new writes store a chunk manifest there instead of inline file bytes.

Each chunk manifest names:

- the inode id and data version;
- the logical file size;
- `FILESYSTEM_CONTENT_CHUNK_SIZE`;
- one contiguous entry per logical chunk;
- the data version, length, and checksum of each referenced per-chunk object.

Each per-chunk object stores its own inode id, data version, chunk index, and payload bytes. The transaction manifest includes both the content manifest object and every referenced chunk object through `VersionedContentChunk` entries, so recovery, audit, and root-retention planning protect the complete file-content graph.

## Mutation Rules



Older whole-content objects remain readable as compatibility input. Once an older inline-content file is rewritten, the new data version is emitted as a chunk manifest plus per-chunk objects.


Source and tests:

- `random_write_updates_only_intersecting_chunk_refs`
- `truncate_rewrites_boundary_chunk_and_drops_tail_refs`
- `transaction_manifest_entries_for_existing_content`
- `read_content_chunk_from_store`
- `write_chunked_content_with_overlay`


```sh
cargo run -p tidefs-xtask -- check-chunked-file-layout
tidefs-xtask check-chunked-file-layout
```

This check binds the source markers, documentation, filesystem demo markers,
tracking is in Forgejo.
