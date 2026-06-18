# tidefs-claim-ledger

`tidefs-claim-ledger` records claim and receipt integrity for TideFS storage
and validation workflows.

Validation receipt records are an append-only, hash-linked evidence stream.
Each record carries the claim id, evidence class, validation tier, status,
artifact digest, previous receipt digest, and producer metadata. The
`ValidationReceiptLedger` verifies ordering, duplicate sequence numbers,
previous-digest linkage, and historical record mutation.

The receipt ledger is not the source of claim truth. Claim status remains
authoritative in `validation/claims.toml` and through `xtask validate-claim`.
A valid receipt chain proves that stored receipts were not reordered or
mutated. Callers detect wholesale replacement by retaining the head digest and
checking it with `verify_head_digest`; receipt integrity does not by itself
validate a TideFS product claim.

Receipt records store artifact digests and bounded producer labels only. They
must not carry GitHub secrets, tokens, private artifact payloads, or encrypted
secret material.
