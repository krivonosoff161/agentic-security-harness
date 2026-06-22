# Reproducibility Pack

The reproducibility pack is a maintainer/reviewer command that rebuilds the deterministic
public examples and compares stable metrics against the committed artifacts.

It exists to answer one concrete question:

> Can the visible examples be regenerated from the current code instead of being stale
> screenshots or hand-written claims?

## Command

```bash
ash reproduce-examples --out reports/reproducibility-pack
```

The command writes:

- `reports/reproducibility-pack/generated/...` regenerated examples;
- `reports/reproducibility-pack/reproducibility_report.json`;
- `reports/reproducibility-pack/reproducibility_report.md`.

## Covered Examples

| Example | What is rebuilt | Stable comparison |
|---|---|---|
| `examples/comparison-report/` | baseline/protected local comparison | baseline/protected pass/fail counters |
| `examples/local-swarm-report/` | deterministic local-swarm report | scenario count, naive failures, bounded failures, verifier blocks |
| `examples/local-swarm-attack-matrix/` | attack/slom variation matrix | case count, family count, bounded failures, bounded blocks |
| `examples/local-swarm-allowed-flows/` | benign allowed-flow utility suite | allowed passes and unexpected blocks |
| `examples/local-swarm-ablation-matrix/` | control-attribution ablation matrix | represented controls and vulnerable rows |

The comparison intentionally ignores timestamps, run ids, local paths, and formatting-only
fields. JSON artifacts remain the source of truth.

## Expected Result

```text
reproduce-examples examples=5 validation_failures=0 metric_mismatches=0
```

If `metric_mismatches` is non-zero, either the committed example is stale or the code
changed benchmark semantics. Treat that as a review blocker until the discrepancy is
explained and the committed artifact is regenerated through the normal Git workflow.

## Non-Claims

This pack does not prove:

- production system safety;
- external model behavior;
- artifact signature provenance;
- bit-for-bit reproducibility of timestamps or generated Markdown formatting.

It does prove a narrower but useful fact: the public deterministic examples still match
the current code at stable metric level and pass `ash validate`.
