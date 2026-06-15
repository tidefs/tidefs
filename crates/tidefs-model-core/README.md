# tidefs-model-core

`tidefs-model-core` is a pure in-memory executable model for the minimal
TideFS local VFS semantics used by trace and oracle work. It does not read or
write host filesystem paths, and it is not a runtime filesystem authority.

The crate consumes `tidefs-types-vfs-core` request envelopes for the canonical
VFS contract seed: `GetAttr`, `Read`, `Write`, `Sync`, `Create`, `Mkdir`,
`Rename`, `Link`, `Unlink`, and `Truncate`. Namespace records identify
component operands with fixed-width `VfsNameToken` values plus parent inodes;
model replay binds those tokens to validated model component names through
`ContractNameContext`, not through host paths or process-local string indexes.

The crate still exposes `ModelRequest` as a path-oriented helper for tests and
callers that have not yet moved to canonical contract envelopes.
