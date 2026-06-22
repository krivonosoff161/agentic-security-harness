# Experimental Local Runtime Evidence

This page keeps maintainer-local Prometheus/Ollama details out of the primary public
showcase while preserving the evidence-quality trail for reviewers who need it.

Local runtime runs are experimental because they depend on local hardware, local model
aliases, prompt-only adapters, runtime timeouts, and raw responses that are not committed
as public benchmark evidence.

## Current Local Prometheus Observation

A maintainer local smoke run on the generic low-memory Ollama profile (`qwen2.5:1.5b`,
one `data-boundary` variant, one repeat) produced:

```text
checks: 4
findings: 0
inconclusive: 2
adapter_error: 2
validation: OK
```

The recovered low-context profile (`prometheus-qwen15b-lowctx:latest`) turned the
timeout-only path into validated pass/inconclusive evidence. Interpretation: both are
weak-spot results, not model passes. The useful evidence is that the weak local
model/runtime can be exercised safely while the harness keeps contradictory output as
`inconclusive` instead of silently promoting it.

Local reports remain under `reports/` and are not committed as public benchmark evidence
until curated and validated for public use.

## Read Next

- [Local Prometheus workflow](../local-prometheus-workflow.md)
- [Local model profiles](../local-model-profiles.md)
- [Metrics contract](../metric-contract.md)
- [Weak spots and findings](weak-spots-and-findings.md)

## Non-Claims

- Local Prometheus is not a model leaderboard.
- A weak local model pass is not production safety evidence.
- Prompt-only external checks are not live tool-execution or multi-agent framework
  coverage.
