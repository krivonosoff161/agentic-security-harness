# Comparison report example

This directory is a committed, validated example of the benchmark's main workflow:

```text
same corpus -> baseline target -> protected target -> comparison report
```

It uses only local synthetic targets. There are no LLM calls, provider calls, real
secrets, or third-party systems.

## Result

| Metric | Baseline `demo-agent` | Protected `protected-demo-agent` |
|---|---:|---:|
| Patterns failed | 23 | 0 |
| Patterns passed | 0 | 23 |
| Total findings | 23 | 0 |
| High findings | 21 | 0 |
| Medium findings | 2 | 0 |

Findings reduced: **23 -> 0**.

This means the protected local demo target handles the current synthetic corpus better
than the vulnerable local demo target. It does not guarantee real-world protection.

This example is the primary public showcase candidate. Before promoting it in a release,
README, or external write-up, review the
[public showcase report checklist](../../docs/showcase-report-checklist.md).

## Files

| Path | Meaning |
|---|---|
| `baseline/traces.json` | Machine-readable traces from the vulnerable local target. |
| `baseline/scorecard.json` | Derived scorecard for the baseline traces. |
| `baseline/summary.md` | Human-readable baseline summary. |
| `protected/traces.json` | Machine-readable traces from the protected local target. |
| `protected/scorecard.json` | Derived scorecard for the protected traces. |
| `protected/summary.md` | Human-readable protected summary. |
| `comparison.md` | Side-by-side before/after report. |

## How to reproduce

```bash
pip install -e ".[dev]"
ash compare --baseline demo-agent --protected protected-demo-agent --out reports/comparison
ash validate reports/comparison
```

To validate the committed example itself:

```bash
ash validate examples/comparison-report
```

## How to read it

- A **FAIL** in the baseline means the vulnerable synthetic agent showed the expected
  failure for that pattern.
- A **PASS** in the protected target means the deterministic control prevented that
  specific synthetic failure.
- The useful signal is the delta between both targets on the same corpus.
- If future changes add patterns, this example should be regenerated and validated.
