# Comparing two runs with `ash diff-runs`

`ash compare` runs a fixed baseline-vs-protected pair. `ash diff-runs` compares **any two
existing run directories** of the same kind — for example, the same target before and
after a fix, or two external model runs.

```bash
ash diff-runs --left reports/run-before --right reports/run-after --out reports/diff
```

It writes `run_diff.json` (machine-readable, schema-versioned) and `run_diff.md` (human
view) into `--out`, then you can render or validate them:

```bash
ash report --root reports/diff      # static HTML
ash validate reports/diff           # artifact integrity
```

## Supported comparisons

The two directories must be the **same kind**:

| Left kind | Right kind | Result |
|---|---|---|
| run | run | per-pattern PASS/FINDING diff |
| matrix | matrix | per-pattern stable/variant-sensitive diff |
| external | external | per-pattern status diff (pass/finding/flaky/inconclusive/error) |
| any | different kind | clear error, no output |

Kind is detected from the artifacts present (`traces.json` → run, `matrix.json` → matrix,
`external_summary.json` → external).

## What the diff reports

- `left_label` / `right_label` — the run ids from each `run_index.json` (or the directory
  names);
- a configuration summary for each side (target / model / endpoint / scenario / repeats /
  request_count, as available);
- per-pattern change classification:
  - **fixed** — was a finding on the left, passes on the right;
  - **new** — passed on the left, is a finding on the right;
  - **changed** — finding-like on both sides but the status or severity changed;
  - **unchanged** — same status (and severity);
  - **only_left** / **only_right** — the pattern appears on only one side (e.g. different
    scenarios);
- counts for each change class, validated against the entries;
- the control family for each changed pattern.

## What it is not

A diff is an **artifact comparison**: it tells you what changed between two recorded runs.
It does **not** re-run anything and is **not** a certification. For stochastic external
runs, compare runs with the same scenario, variants, repeats, and temperature, and treat
`flaky` / `inconclusive` differences as noise rather than improvement. See
[benchmark-semantics.md](benchmark-semantics.md).
