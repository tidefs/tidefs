# style guide (v0.398)

## Naming

Use human names first. Stable internal locators remain stable identifiers and should not be introduced as primary terminology.

## Recovery language

Never describe an fsck-style operator pass as required production recovery.

Allowed terms:

```text
development invariant verifier
offline forensic tool
online proactive verifier/scrubber
recovery probe
recovery audit
```

Forbidden production framing:

```text
run fsck to recover normal crashes
repair guessed namespace state before mounting
production mount depends on manual checker
```


Recovery probe and recovery audit may classify, explain, and refuse. They must not mutate object-store bytes, rewrite directories, invent missing links, or choose guessed truth.

## Rust

Prefer human module paths such as:

```rust
use tidefs_local_filesystem::human::local_filesystem::*;
use tidefs_local_object_store::human::local_object_store::*;
```
