# Historical Deep Mini-Swarm Observation (Legacy Schema)

This directory retains a structural-only pre-0.5 detector-observation summary.
The current schema has no committed execution, public validation does not replay
private responses, and the artifact does not attest that the model ran locally.

Raw prompts, raw responses, synthetic canary values, and calculation notes are
not present here. They remain private under `.internal/`.

Reproduce the artifact integrity check:

```bash
ash validate examples/swarm-defense-live-deep-sanitized
```

The example is evidence for the declared local campaign only. It is not a CVE,
not a model leaderboard, and not proof of production swarm safety.
