# Hot Read Cache

> TFR-019 authority note: this imported implementation note is review material,
> the behavior below as needing reconciliation with current source and
> `docs/REVIEW_TODO_REGISTER.md`.

This historical note covers hot read cache integration into read paths, not only
policy modules.

## Scope

The implemented cache lives inside `LocalFileSystem` and serves repeated
`read_file` and `read_symlink` calls. It is a bounded runtime mirror over
content already published through the local filesystem transaction/root model.

The cache is not authority:

- it never decides publication success;
- it never changes recovery root selection;
- losing every cache entry cannot change visible committed filesystem truth;

## Identity

Every cache entry is keyed by immutable content identity:

- object role: regular file or symlink content;
- inode id;
- inode data version;
- inode size.

Path names are deliberately not cache identity. Hard links and renames can keep
serving the same content when the inode data version and size are unchanged.

## Bounds

The default cache policy is:

- `DEFAULT_HOT_READ_CACHE_MAX_ENTRIES`;
- `DEFAULT_HOT_READ_CACHE_MAX_BYTES`;
- least-recently-used eviction when either bound would be exceeded.

Content larger than the byte bound bypasses admission. A bypass is counted in
the report and the next read remains store-backed.



- `replace_file` rewrites content;
- `write_file` changes content;
- `truncate_file` changes content;
- `fallocate_file` extends content;
- the final link to file or symlink content is unlinked;
- a rename replaces the final link to a file or symlink target;
- snapshot rollback replaces live filesystem state.

publish-uncertain mutation paths where live state may remain changed.


`HotReadCacheReport` exposes:

- `hits`;
- `misses`;
- `insertions`;
- `evictions`;
- `admission_bypasses`;
- `resident_entries`;
- `resident_bytes`;
- policy bounds.

The filesystem demo prints `hot_read_cache.*` rows after a repeated read. The
oversized bypass, and rollback clearing.

The implementation-tracked non-release drift check is:

```sh
cargo run -p tidefs-xtask -- check-hot-read-cache
```

Short form: `tidefs-xtask check-hot-read-cache`.
