# Evidence quality analysis

`ash evidence-quality` is an offline analysis layer for recorded `run-external`,
`local-suite`, and `local-swarm` artifacts. It does not call a model, does not execute
tools, and does not create a model leaderboard.

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

It also scans for local-swarm directories containing:

- `local_swarm_summary.json`

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
| `local_swarm_contract_coverage_rate` | Scenario-weighted bounded-swarm contract coverage across local-swarm artifacts. |
| `local_swarm_evidence_completeness_rate` | Result-weighted deterministic verdict/evidence completeness across local-swarm artifacts. |
| `local_swarm_transcript_hash_coverage_rate` | Fraction of recorded local-swarm role transcripts with prompt and response hashes. |
| `local_swarm_adapter_error_rate` | Fraction of recorded local-swarm role transcripts that failed at the adapter layer. |

## How to read it

High weak-evidence or disagreement rates mean the recorded model evidence needs recovery:
inspect raw responses, reduce scope, increase timeout/repeats, or use a stronger
JSON-following model. They are not security findings.

Low weak-evidence rates also do not prove model safety. They only say the run produced
more structurally usable evidence under the harness contract.

For `local-swarm` artifacts, contract coverage and verifier blocks describe deterministic
ASH checks, not model wisdom. Transcript hash coverage says whether optional model role
text was captured as evidence context. A local model can produce coherent role text while
the deterministic verifier remains the only pass/block authority.

## Claim boundary

Allowed:

> The recorded external/local artifacts have measurable evidence-quality properties:
> raw-response coverage, validator binding, decisive/weak split, and cross-run stability.

> The recorded local-swarm artifacts have measurable contract/evidence-quality
> properties: scenario coverage, verifier blocks, transcript hash coverage, and adapter
> errors.

Not allowed:

- claiming a model is safe or unsafe in general;
- treating `inconclusive` or `adapter_error` as pass/finding;
- using this command as a live multi-agent runtime proof;
- treating this as a benchmark-grade model leaderboard;
- treating local-swarm model role text as the verifier decision.
