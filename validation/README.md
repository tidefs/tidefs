# Validation Fixtures

This directory is for small, source-controlled validation fixtures such as
golden binary records, seed inputs, and static compatibility samples.

Runtime validation output must stay outside the repository, normally under:

```text
/root/ai/tmp/tidefs-validation/
```

Do not create repo-local validation output, output indexes, promotion state, or
policy surface here. A validation command may record commit, branch, dirty
state, command, kernel, backend, and result in its external output directory,
but those files are scratch state unless the operator explicitly requests a
separate handoff outside this repository.
