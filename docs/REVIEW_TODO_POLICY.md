# Review Todo Policy

TideFS debt is tracked in the review register, not scattered as anonymous
comments.

Rules:

- Add durable debt to `docs/REVIEW_TODO_REGISTER.md`.
- Use stable ids with the `TFR-NNN` prefix.
- Inline comments may only point to a register id, for example
  `Review debt TFR-005: ...`.
- Do not add bare `TODO`, `FIXME`, `HACK`, "later", or "continuation"
  comments; when durable debt is found or touched, record it in the register
  and point any inline note to a stable `TFR-NNN` id.
- Active validation scripts and harness surfaces follow the same rule for
  `TBD`, placeholder, fake, dummy, continuation, `TODO`, `FIXME`, and `HACK`
  wording. Negative-test and refusal fixture text may carry those words only
  when the surrounding text classifies the fixture or refusal explicitly.
