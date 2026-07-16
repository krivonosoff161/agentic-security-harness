# Semantic drift sanitized example

Historical/unreconciled detector-observation summary. The committed observation schema
is `0.1`; the current producer schema is `0.2`. Public validation does not replay private
response bytes or attest model/runtime identity. The deterministic contract rows remain
an executable specification.

Start with [`semantic_drift_report.md`](semantic_drift_report.md). The primary legacy
machine-readable record is [`semantic_drift_summary.json`](semantic_drift_summary.json).

Validate it with:

```bash
ash validate examples/semantic-drift-sanitized
```

What this example shows:

- 4 semantic relabeling cases.
- 28 deterministic bounded-vs-ablation contract rows.
- 80 historical detector-labelled observations declared by a maintainer run.
- 0 bounded deterministic drift acceptances.
- 19 ablation deterministic drift acceptances.
- 13 drift detections, 4 synthetic canary leaks, and 15 verifier blocks in the local
  smoke.
- 0 declared adapter errors and complete response-hash-field presence. Hash presence
  does not prove retained private bytes or execution origin.

What it does not show:

- Real secret leakage.
- A CVE or exploit against a third-party system.
- A production safety guarantee.
- A model leaderboard.
- Exhaustive long-session semantic-drift coverage.

Raw prompts, raw responses, canonical-state hashes, and synthetic canary values remain
private under `.internal/` and are not committed.
