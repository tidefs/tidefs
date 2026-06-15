# tidefs-env-ublk-model

Bounded pure model for the uBLK qid/tag request lifecycle behind
`ublk.qid_tag.exactly_once_completion.v1`.

The crate models queue/tag allocation, in-flight ownership, completion, abort,
timeout, recovery, and reissue transitions. Legal uBLK read, write, flush, and
discard events refine into the current TideFS block request/completion contract
types in `tidefs-types-vfs-core`.

This is model evidence only. It does not run a uBLK daemon, issue ioctls,
submit block I/O, or claim full block-volume runtime correctness.
