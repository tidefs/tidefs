# xfstests coverage: measured vs estimated

We track two different "coverage" numbers for tidefs:

1) **Measured pass rate** (the only real truth)
   - Comes from actually running xfstests.

2) **Estimated coverage / readiness** (model-based)
   - A **weighted feature-completeness** score that can be computed from the repo state **without running xfstests**.
   - This is useful for turn-by-turn development and for planning, but it is **not** a substitute for real runs.

---

## Measured xfstests pass rate

Run the harness:

```bash
```

Then inspect:

- `<run_dir>/scoreboard.md`
- `<run_dir>/scoreboard.json`

And optionally generate a gaps report:

```bash
```

Or point it directly at a scoreboard:

```bash
```

---

## Estimated xfstests readiness score

Compute the model-based estimate:

```bash
```

The model lives at:


Policy:

- The model is **allowed** to be conservative.
- The score should go **up** only when we close real semantics gaps.
- Do **not** treat the score as a marketing number; it is for internal tracking.

---

## Why keep both?

- The **measured** number keeps us honest.
- The **estimated** number lets us stay oriented when we’re iterating quickly and shipping code every turn.
