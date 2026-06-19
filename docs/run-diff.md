# Comparing two runs with `ash diff-runs`

`ash compare` runs a fixed baseline-vs-protected pair. `ash diff-runs` compares **any two
existing run directories** of the same kind - for example, the same target before and
after a fix, or two external model runs.

```bash
ash diff-runs --left reports/run-before --right reports/run-after --out reports/diff
```

For external model/runtime artifacts, the narrower wrapper is:

```bash
ash compare-models --left reports/external-a --right reports/external-b --out reports/model-diff
```

Both commands compare recorded artifacts only; they do not re-run targets or call models.
Use `--format json` when another tool should consume the comparison summary.

It writes `run_diff.json` (machine-readable, schema-versioned) and `run_diff.md` (human
view) into `--out`, then you can render or validate them:

```bash
ash report --root reports/diff      # static HTML
ash validate reports/diff           # artifact integrity
```

`run_diff.json` v0.2 writes the explicit labels below. For compatibility during the
migration from v0.1, it also keeps deprecated coarse alias counters (`fixed`, `new`,
`changed`, `unchanged`) and `ash validate` still accepts existing v0.1 diff artifacts.
New readers should use the explicit labels. Consumers that parse per-entry `change`
values must branch on `schema_version`: v0.1 artifacts use the coarse labels, while v0.2
artifacts use the explicit labels below.

## Supported comparisons

The two directories must be the **same kind**:

| Left kind | Right kind | Result |
|---|---|---|
| run | run | per-pattern PASS/FINDING diff |
| matrix | matrix | per-pattern stable/variant-sensitive diff |
| external | external | per-pattern status diff (pass/finding/flaky/inconclusive/error) |
| any | different kind | clear error, no output |

Kind is detected from the artifacts present (`traces.json` -> run, `matrix.json` -> matrix,
`external_summary.json` -> external).

## What the diff reports

- `left_label` / `right_label` - the run ids from each `run_index.json` (or the directory
  names);
- a configuration summary for each side (target / model / endpoint / scenario / repeats /
  request_count, as available);
- per-pattern change classification (see the label table below);
- counts for each change class, validated against the entries;
- the control family for each changed pattern.

## Change labels

A pattern status is one of `pass`, `finding` (and `variant_sensitive` for matrix runs), or
- for external runs only - the **non-decisive** statuses `flaky`, `inconclusive`, `error`.
A non-decisive status is *not* a pass and *not* a finding: the model erred, timed out, or
contradicted itself, so the boundary neither held nor broke. The labels keep that
distinction explicit so an external-run reviewer never has to guess whether "fixed" meant
`finding -> pass` or `error -> pass` (see issue #29).

| Label | Meaning |
|---|---|
| `finding_fixed` | finding on the left, pass on the right |
| `new_finding` | pass on the left, finding on the right |
| `changed_status` | finding-like on both sides, but status or severity moved |
| `unchanged_finding` | same finding (status and severity) on both sides |
| `stable_pass` | pass on both sides |
| `inconclusive_error_drift` | a side is `inconclusive`/`error` and it moved; **not** a fix or a new finding |
| `stable_inconclusive` | `inconclusive`/`flaky` on both sides (still no conclusion) |
| `stable_error` | `error` on both sides |
| `only_left` / `only_right` | the pattern appears on only one side (e.g. different scenarios) |

`finding_fixed` and `new_finding` are reserved for `pass <-> finding` moves between two
decisive statuses. Any transition that touches `inconclusive`/`error` is reported as
`inconclusive_error_drift`, so a weak local model that recovers from `error` to `pass` is
never counted as a security improvement.

## What it is not

A diff is an **artifact comparison**: it tells you what changed between two recorded runs.
It does **not** re-run anything and is **not** a certification. For stochastic external
runs, compare runs with the same scenario, variants, repeats, and temperature, and treat
`inconclusive_error_drift` / `stable_inconclusive` / `stable_error` as noise rather than
improvement. See [benchmark-semantics.md](benchmark-semantics.md).
