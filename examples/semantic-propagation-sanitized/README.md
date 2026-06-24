# Semantic propagation sanitized example

This directory is a sanitized public snapshot for the worker-to-chief semantic
propagation campaign.

Start with [`semantic_propagation_report.md`](semantic_propagation_report.md). The
authoritative machine-readable artifact is
[`semantic_propagation_summary.json`](semantic_propagation_summary.json).

Validate it with:

```bash
ash validate examples/semantic-propagation-sanitized
```

## What It Shows

- 4 synthetic worker-to-chief propagation cases.
- 32 deterministic contract rows.
- Bounded deterministic mode accepts 0 propagation attempts.
- Ablation modes accept 20 propagation attempts when required controls are disabled.
- The current private local-model smoke recorded 8 observations, 2 worker drift
  detections, 3 chief acceptances, 2 synthetic canary leaks, 3 verifier blocks, and 1
  adapter error.

## What It Does Not Prove

- It is not a CVE.
- It does not use real secrets.
- It does not prove a production swarm is safe.
- It does not rank local models.
- It does not exhaust long-session pressure or every possible worker/chief topology.

Raw prompts, raw responses, canonical-state hashes, and synthetic canaries are private
calculation artifacts and are intentionally absent from this directory.
