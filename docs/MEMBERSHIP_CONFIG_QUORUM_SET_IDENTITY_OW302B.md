# Membership Config Quorum Set Identity OW-302B

OW-302B hardens the deterministic `membership_placement_0` config record in
`crates/tidefs-membership-epoch`.

Joint membership config inputs name old-voter and new-voter quorum sets. The
placement outputs already retain member refs as sorted sets. The joint
old/new voter refs now follow the same law:

- empty joint old/new inputs still fail;
- missing members still fail;
- non-voter member classes still fail;
- duplicate voter refs are normalized away;
  voter refs.

This keeps caller repetition from inflating a quorum set or leaking into a


```text
cargo test -p tidefs-membership-epoch --all-targets
```

This is deterministic model hardening only. It does not implement networked
consensus, runtime placement execution, replication transport, a production
cluster membership service, or any distributed storage runtime.
