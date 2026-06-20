# Evidence quality analysis

`ash evidence-quality` is an offline analysis layer for recorded `run-external` and
`local-suite` artifacts. It does not call a model, does not execute tools, and does not
create a model leaderboard.

Derived analysis only: the command summarizes already recorded artifacts and does not
replace `ash validate` or the deterministic verdict contract.

This is not a model leaderboard.

Use it after a bounded local or external run:

```bash
ash evidence-quality --root reports --out reports/evidence-quality
```

The command scans for external run directories containing:

- `run_config.json`
- `external_results.json`
- `external_summary.json`

It writes:

- `evidence_quality.json` - schema-versioned machine-readable summary;
- `evidence_quality.md` - reviewer-facing summary.

## Metrics

| Metric | Meaning |
|---|---|
| `decisive_rate` | Fraction of per-request results classified by the deterministic validator as `pass` or `finding`. |
| `weak_evidence_rate` | Fraction classified as `inconclusive` or `adapter_error`. |
| `raw_response_coverage_rate` | Fraction of results that point to a raw response artifact. |
| `raw_hash_coverage_rate` | Fraction of results with both raw response path and sha256. |
| `assertion_binding_rate` | Fraction of results bound to a deterministic assertion id/result. |
| `cross_run_disagreement_rate` | Fraction of comparable pattern/variant groups whose stability status differs across runs. |

## How to read it

High weak-evidence or disagreement rates mean the recorded model evidence needs recovery:
inspect raw responses, reduce scope, increase timeout/repeats, or use a stronger
JSON-following model. They are not security findings.

Low weak-evidence rates also do not prove model safety. They only say the run produced
more structurally usable evidence under the harness contract.

## Claim boundary

Allowed:

> The recorded external/local artifacts have measurable evidence-quality properties:
> raw-response coverage, validator binding, decisive/weak split, and cross-run stability.

Not allowed:

- claiming a model is safe or unsafe in general;
- treating `inconclusive` or `adapter_error` as pass/finding;
- using this command as a live multi-agent runtime proof;
- treating this as a benchmark-grade model leaderboard.
