# Semantic propagation sanitized example

Historical/unreconciled detector-observation summary. The committed observation schema
is `0.2`; the current producer schema is `0.3`. Public validation does not replay private
response bytes or attest model/runtime identity. The deterministic projection remains
an executable specification.

Start with [`semantic_propagation_report.md`](semantic_propagation_report.md). The
primary legacy machine-readable record is
[`semantic_propagation_summary.json`](semantic_propagation_summary.json).
The public defense model is documented in
[`docs/semantic-propagation-defense-model.md`](../../docs/semantic-propagation-defense-model.md).

Validate it with:

```bash
ash validate examples/semantic-propagation-sanitized
```

Regenerate the deterministic sanitized form with:

```bash
ash semantic-propagation-campaign --write --out reports/semantic-propagation
ash validate reports/semantic-propagation
```

Run an optional private local-model smoke with raw transcripts under `.internal/`:

```bash
ash semantic-propagation-campaign --execute --out .internal/semantic-propagation/latest --summary-out reports/semantic-propagation --worker-model qwen2.5:0.5b --chief-model llama3.2:1b --pressure-mode pseudo_code --pressure-mode memory_rewrite --max-chains 8
ash validate reports/semantic-propagation
```

## What It Shows

- 4 synthetic worker-to-chief propagation cases.
- 32 deterministic contract rows.
- 6 declared defensive controls and 6 control-effect rows.
- Bounded deterministic mode accepts 0 propagation attempts.
- Ablation modes accept 20 propagation attempts when required controls are disabled.
- The legacy public summary declares 8 detector-labelled observations, 2 worker drift
  detections, 3 chief acceptances, 2 synthetic canary leaks, 3 verifier blocks, and 1
  adapter error.
- Hash-field coverage is 87.5%. This does not prove retained private bytes, detector
  truth, execution origin, or current-schema behavior.

## What It Does Not Prove

- It is not a CVE.
- It does not use real secrets.
- It does not prove a production swarm is safe.
- It does not rank local models.
- It does not exhaust long-session pressure or every possible worker/chief topology.

Raw prompts, raw responses, canonical-state hashes, and synthetic canaries are private
calculation artifacts and are intentionally absent from this directory.
