# Local Filesystem Zero-Length Write

This note hardens `LocalFileSystem::write_file` in
`crates/tidefs-local-filesystem`.

It must not extend a file to the supplied offset, create new content objects,
allocator accounting.


- nonexistent paths still fail;
- directories and non-file inodes still fail through the normal write path;
- non-empty offset writes still zero-fill gaps and update content;
- zero-length writes return the current inode record unchanged;
- zero-length writes preserve file size, data version, metadata version,
  content bytes, hot-read-cache entries, and allocator reservation.


```text
cargo test -p tidefs-local-filesystem --all-targets
```

This is local filesystem model correctness only. It does not claim POSIX
completeness, FUSE or kernel runtime behavior, distributed storage,
production fsck/repair, mmap coherency, intent-log durability, or block/ublk
progress.
