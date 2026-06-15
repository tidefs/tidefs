# tidefs-model-core

`tidefs-model-core` is a pure in-memory executable model for the minimal
TideFS local VFS semantics used by trace and oracle work. It does not read or
write host filesystem paths, and it is not a runtime filesystem authority.

The crate consumes `tidefs-types-vfs-core` request envelopes for the VFS
operations already present in the contract seed: `GetAttr`, `Read`, `Write`,
and `Sync`. The current contract does not yet encode create, mkdir, rename,
link, unlink, or truncate, so the crate also exposes `ModelRequest` as a
temporary internal model request vocabulary for issue #283. A later contract
issue should move those operations into the canonical request envelope before
adapter traces depend on them as shared wire records.
