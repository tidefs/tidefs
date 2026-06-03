# FUSE Extended Attribute Validation

BLAKE3-verified validation harness for POSIX extended attribute operations
through the TideFS xattr storage layer.

## Covered Operations

- `setxattr` (upsert, XATTR_CREATE, XATTR_REPLACE)
- `getxattr` (value size report and full-value retrieval)
- `listxattr` (key enumeration with determinism verification)
- `removexattr` (key deletion and post-removal absence)

## BLAKE3 Domain

- Domain: `tidefs-validation-fuse-xattr-v1`
- Hash: BLAKE3-256 domain-separated (domain prepended to payload)
- Name-set hashing: sorted names with NUL separators, domain-prefixed

## Test Count

25 tests covering the full POSIX xattr lifecycle.

## Edge Cases Covered

- Empty values (zero-length)
- Large values up to 64 KiB
- Namespace prefixes: user.\*, trusted.\*, security.\*, system.\*
- Special-character key names (dots, dashes, underscores, numbers, mixed case)
- Value overwrite with BLAKE3 hash evolution tracking
- Multi-inode isolation (independent stores)
- Concurrent set/get on same inode (4 threads, 50 iterations each)
- Concurrent set/remove on different keys (10 pre-populated keys)
- Store version tracking across mutations
- Value-size boundaries (0, 1, 255, 256, 1023, 1024, 4095, 4096, 65535, 65536)
- ACL flag set/clear
- Deterministic listxattr output (same name set -> same BLAKE3 hash)

## Fix Commits

No implementation fixes were required. The xattr storage layer
passed all BLAKE3-verified integrity tests without modifications.
