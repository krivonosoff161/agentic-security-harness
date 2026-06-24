# Examples - committed, validated benchmark artifacts

These directories are **curated, deterministic snapshots** of real `ash` output. They are
checked by `ash validate examples/` in CI, so they always match the current corpus and
report format. Nothing here contains secrets, real payloads, or local absolute paths.
Each report directory has its own README that explains what produced it, how to read it,
how to validate it, and what it does not prove.
Before promoting any example as a public demo or release showcase, use the
[public showcase report checklist](../docs/showcase-report-checklist.md).

```bash
# validate every example in one shot
ash validate examples/
# expected: errors: 0  warnings: 0  -> OK
```

> The CLI also writes a `run_index.json` run manifest into run directories (see
> [docs/getting-started.md](../docs/getting-started.md#run-history)). Committed examples
> keep sanitized deterministic manifests; live runs you create under `reports/` will carry
> their own runtime timestamp.

## What each example shows

| Directory | What it demonstrates | Regenerate with |
|---|---|---|
| [`demo-report/`](demo-report/) | A single run against the deterministic `mock` target (findings + remediation). | `ash run --target mock --out reports/demo` |
| [`demo-agent-report/`](demo-agent-report/) | A run against the vulnerable-by-design local `demo-agent`. | `ash run --target demo-agent --out reports/demo-agent` |
| [`protected-demo-agent-report/`](protected-demo-agent-report/) | The protected agent passing all patterns (no findings, no remediation). | `ash run --target protected-demo-agent --out reports/protected` |
| [`comparison-report/`](comparison-report/) | Baseline vs protected risk-reduction comparison. See its own [README](comparison-report/README.md). | `ash compare --baseline demo-agent --protected protected-demo-agent --out reports/comparison` |
| [`local-swarm-report/`](local-swarm-report/) | Research-only monolith vs naive swarm vs bounded swarm evidence suite over 15 deterministic boundary scenarios. | `ash local-swarm --write-dry-run --out reports/local-swarm` |
| [`local-swarm-attack-matrix/`](local-swarm-attack-matrix/) | Research-only 43-row attack variation matrix across 9 families, including 10 executable deep invariant probes for handoff/memory mutations. | `ash local-swarm-matrix --write --out reports/local-swarm-attack-matrix` |
| [`evidence-campaign-sanitized/`](evidence-campaign-sanitized/) | Sanitized evidence-campaign example: 24 cases / 72 observations / 4 claim families with TP/FP/FN/TN, control effect, usability cost, and ablation metrics. | `ash evidence-campaign --write --out .internal/evidence-campaign/latest` |
| [`secret-leak-campaign-sanitized/`](secret-leak-campaign-sanitized/) | Sanitized secret-leak campaign: 4 synthetic secret-egress topologies / 23 observations with naive, bounded, ablation, and benign modes. | `ash secret-leak-campaign --write --out .internal/secret-leak-campaign/latest` |
| [`secret-leak-variations-sanitized/`](secret-leak-variations-sanitized/) | Sanitized live local-model variation smoke: 8 secret-egress pressure cases x 4 pressure modes x 2 Ollama models, with raw prompts/responses kept private. | `ash secret-leak-campaign --execute-variations --out .internal/secret-leak-variations/latest --variation-summary-out reports/secret-leak-variations` |
| [`semantic-drift-sanitized/`](semantic-drift-sanitized/) | Sanitized semantic parameter-drift campaign: 4 relabeling cases x 4 pressure modes x 5 Ollama models, with raw prompts/responses/canaries kept private. | `ash semantic-drift-campaign --execute --out .internal/semantic-drift/latest --summary-out reports/semantic-drift` |
| [`external-demo-report/`](external-demo-report/) | An external OpenAI-compatible run against the bundled fake server. | see below |
| [`fake_openai_server.py`](fake_openai_server.py) | A deterministic local OpenAI-compatible server for the external path (no key, localhost only). | `python examples/fake_openai_server.py` |

## Reading a report directory

Open files in this order:

1. `executive.md` - scope, headline result, top control families, residual risk. **Start here.**
2. `summary.md` - per-pattern pass/fail table.
3. `remediation.md` - control recommendations (only present when there are findings).
4. `traces.json` / `scorecard.json` - machine-readable detail.

For comparisons start with `comparison.md`; for matrix runs start with `matrix.md`; for
external runs start with `external_report.md`; local-swarm runs start with
`local_swarm_report.md`; evidence-campaign runs start with
`evidence_campaign_report.md`; secret-leak campaign runs start with
`secret_leak_campaign_report.md`; secret-leak variation runs start with
`secret_leak_variation_report.md`; semantic-drift runs start with
`semantic_drift_report.md`.

Or render any example as a single static HTML page (no network):

```bash
ash report --root examples/comparison-report   # writes examples/comparison-report/report.html
```

What PASS / FINDING / INCONCLUSIVE / FLAKY / ADAPTER_ERROR mean, and what validation does
and does not prove, is in [docs/benchmark-semantics.md](../docs/benchmark-semantics.md).

## Reproduce the external example (free, no API key)

```bash
# terminal 1 - start the deterministic fake server (Ctrl+C to stop)
python examples/fake_openai_server.py

# terminal 2 - run the external path against it
ash external-check --base-url http://127.0.0.1:8766/v1 --model fake-model --scenario data-boundary
ash run-external  --base-url http://127.0.0.1:8766/v1 --model fake-model --scenario data-boundary --out reports/external-demo
ash validate reports/external-demo
```

Expected: the run reports 4 checks / 4 requests / 0 findings (the fake server always
preserves the boundary), and `ash validate` returns `OK`. On Windows, start the server in
a separate PowerShell window (no trailing `&`).

See [docs/connect-models.md](../docs/connect-models.md) for recipes with vLLM, DeepSeek,
Alibaba/Qwen, Ollama, LM Studio, and generic OpenAI-compatible gateways.

> All artifacts here are deterministic and synthetic. Passing validation means they
> conform to the corpus manifest - **not** that any system is secure.
