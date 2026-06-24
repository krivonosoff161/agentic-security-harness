# Semantic drift sanitized example

This directory is a sanitized public snapshot for the semantic parameter-drift campaign.
It contains deterministic contract rows plus aggregate local-model observations for
synthetic mini-swarm handoff cases.

Start with [`semantic_drift_report.md`](semantic_drift_report.md). The authoritative
machine-readable artifact is [`semantic_drift_summary.json`](semantic_drift_summary.json).

Validate it with:

```bash
ash validate examples/semantic-drift-sanitized
```

What this example shows:

- 4 semantic relabeling cases.
- 28 deterministic bounded-vs-ablation contract rows.
- 80 sanitized local-model observations from the latest maintainer smoke.
- 0 bounded deterministic drift acceptances.
- 19 ablation deterministic drift acceptances.
- 13 drift detections, 4 synthetic canary leaks, and 15 verifier blocks in the local
  smoke.
- 0 adapter errors and 100% response-hash coverage.

What it does not show:

- Real secret leakage.
- A CVE or exploit against a third-party system.
- A production safety guarantee.
- A model leaderboard.
- Exhaustive long-session semantic-drift coverage.

Raw prompts, raw responses, canonical-state hashes, and synthetic canary values remain
private under `.internal/` and are not committed.
