# FUSE lseek preview surface (PC-004B)

This issue is a child of PC-004. It narrows one FUSE mount-surface gap without
claiming that the parent POSIX-complete FUSE gate is closed.

## Implemented surface

The userspace FUSE preview now has implementation-tracked non-release `lseek` behavior for the current
dense-file preview model:

- `SEEK_SET` returns the requested non-negative absolute offset.
- `SEEK_END` returns a non-negative offset relative to the current file size.
- `SEEK_DATA` treats every byte before EOF as data and returns the requested
  offset when it is inside the file.
- `SEEK_HOLE` treats EOF as the only truthful hole boundary and returns EOF when
  the requested offset is inside the file.
- offsets at or beyond EOF for `SEEK_DATA` and `SEEK_HOLE` return `ENXIO`.
- negative offsets return `EINVAL`.
- `SEEK_CUR` stays `EOPNOTSUPP` because the FUSE callback does not carry enough
  current-offset authority for this preview helper to answer it truthfully.

The helper uses the same open-handle path as reads and writes. Coverage
explicitly includes open-unlinked handles that keep their detached session size
for lseek answers until final release.

## Boundaries

This is not a POSIX-complete sparse extent map. TideFS does not yet retain
authoritative sparse-hole extents below the preview FUSE adapter, so the only
truthful `SEEK_HOLE` answer for dense preview files is EOF.

This is not xfstests-grade completion for PC-004. It is one implementation-tracked non-release
increment on the current userspace FUSE preview surface.



```sh
nix develop --command cargo test -p tidefs-posix-filesystem-adapter-daemon lseek --all-targets
nix develop --command cargo run -p tidefs-xtask -- check-fuse-mount-path
git diff --check
```


```text
```
