# Examples - committed, validated benchmark artifacts

These directories are curated snapshots of real `ash` output. Some are deterministic
local benchmark examples; others are sanitized local-empirical campaign summaries whose
raw prompts, responses, canonical-state hashes, and synthetic canaries stay private under
`.internal/`. They are checked by `ash validate examples/` in CI against artifact
formats supported by the current tool; some curated examples may intentionally remain on
older readable schema versions. Nothing here contains secrets, real payloads, or local
absolute paths. Each report directory has its own README that explains what produced it,
how to read it, how to validate it, and what it does not prove.
Before promoting any example as a public demo or release showcase, use the
[public showcase report checklist](../docs/showcase-report-checklist.md).
For local-model campaign publication rules, read
[private-public-evidence-boundary.md](../docs/private-public-evidence-boundary.md).
For the shortest path to run your own model or local mini-swarm, use
[run-your-model.md](../docs/run-your-model.md). For promoting new research output into
this directory, follow [evidence-pack-format.md](../docs/evidence-pack-format.md).

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
| [`semantic-propagation-sanitized/`](semantic-propagation-sanitized/) | Sanitized worker-to-chief propagation smoke: 4 propagation cases, 2 pressure modes, qwen2.5 worker, llama3.2 chief, 1 adapter error, and 87.5% response-hash coverage, with raw prompts/responses/canaries kept private. | `ash semantic-propagation-campaign --execute --out .internal/semantic-propagation/latest --summary-out reports/semantic-propagation` |
| [`swarm-defense-live-sanitized/`](swarm-defense-live-sanitized/) | Sanitized local-model mini-swarm campaign: 15 contour topologies x 6 pressure modes x 2 worker models x 1 chief model, with replay-ablation attribution and raw prompts/responses/canaries kept private. | `ash swarm-defense-live-campaign --execute --out .internal/swarm-defense-live/full --summary-out reports/swarm-defense-live-full --pressure-mode gentle_reframe --pressure-mode pseudo_code --pressure-mode memory_rewrite --pressure-mode authority_pressure --pressure-mode benign_debug --pressure-mode consensus_pressure` |
| [`swarm-defense-live-long-session-sanitized/`](swarm-defense-live-long-session-sanitized/) | Sanitized long-session supplement: 15 observations, each with 3 worker turns under `long_session_relabel`, with public per-turn response hashes and raw prompts/responses/canaries kept private. | `ash swarm-defense-live-campaign --execute --out .internal/swarm-defense-live/long-session --summary-out reports/swarm-defense-live-long-session --pressure-mode long_session_relabel --session-turns 3` |
| [`swarm-defense-live-deep-sanitized/`](swarm-defense-live-deep-sanitized/) | Sanitized deep local-model mini-swarm campaign: 168 observations across 6 contour topologies, 7 pressure modes, 2 worker models, and 2 chief models, with Wilson intervals, model breakdowns, and raw prompts/responses/canaries kept private. | `ash swarm-defense-live-campaign --execute --out .internal/swarm-defense-live/deep --summary-out reports/swarm-defense-live-deep --worker-model qwen2.5:0.5b --worker-model qwen2.5-coder:0.5b-instruct --chief-model llama3.2:1b --chief-model prometheus-qwen15b-lowctx:latest --session-turns 3 --max-topologies 6 --max-requests 900` |
| [`marketing-web-injection-sanitized/`](marketing-web-injection-sanitized/) | Sanitized controlled offline marketing/ads web-injection campaign: naive leaks 5/5, bounded leaks 0/5, ablation leaks 21/21, benign runs 5/5 allowed; raw hostile pages/prompts/responses/strategy values stay private. | `ash marketing-web-injection-campaign --write --out .internal/marketing-web-injection/latest --summary-out reports/marketing-web-injection` |
| [`marketing-web-live-sanitized/`](marketing-web-live-sanitized/) | Sanitized owned-localhost local-model web-injection campaign: 60 observations, worker leaks 3, chief leaks 1, ablation final leaks 1, bounded final leaks 0, benign final leaks 0; raw pages/prompts/responses/strategy values stay private. | `ash marketing-web-live-campaign --execute --out .internal/marketing-web-live/latest --summary-out reports/marketing-web-live --worker-model qwen2.5:0.5b --worker-model qwen2.5-coder:0.5b-instruct --chief-model qwen2.5:0.5b --chief-model qwen2.5-coder:0.5b-instruct --max-scenarios 2 --session-turns 3 --max-requests 500` |
| [`context-consent-sanitized/`](context-consent-sanitized/) | Deterministic context-consent campaign: 5 consent-boundary cases / 45 rows; naive risky-action acceptances 5, bounded acceptances 0, ablation acceptances 18, benign false blocks 0. | `ash context-consent-campaign --write --out examples/context-consent-sanitized` |
| [`tool-authority-sanitized/`](tool-authority-sanitized/) | Deterministic tool-output authority campaign: 6 tool-result authority cases / 66 rows; naive risky-action acceptances 6, bounded acceptances 0, ablation acceptances 23, benign false blocks 0. | `ash tool-authority-campaign --write --out examples/tool-authority-sanitized` |
| [`rag-context-sanitized/`](rag-context-sanitized/) | Deterministic RAG/retrieved-context authority campaign: 7 propagation cases / 91 rows; naive unsafe-chain acceptances 7, bounded acceptances 0, ablation acceptances 30, benign false blocks 0. | `ash rag-context-campaign --write --out examples/rag-context-sanitized` |
| [`planner-task-sanitized/`](planner-task-sanitized/) | Deterministic planner/task-decomposition authority campaign: 7 planner cases / 91 rows; naive unsafe-chain acceptances 7, bounded acceptances 0, ablation acceptances 32, benign false blocks 0. | `ash planner-task-campaign --write --out examples/planner-task-sanitized` |
| [`memory-rehydration-sanitized/`](memory-rehydration-sanitized/) | Deterministic cross-agent memory rehydration authority campaign: 7 recall cases / 91 rows; naive unsafe-chain acceptances 7, bounded acceptances 0, ablation acceptances 32, benign false blocks 0. | `ash memory-rehydration-campaign --write --out examples/memory-rehydration-sanitized` |
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
`semantic_drift_report.md`; semantic-propagation runs start with
`semantic_propagation_report.md`; sanitized local-model mini-swarm runs start with
`swarm_defense_live_report.md`; marketing web-injection runs start with
`marketing_web_injection_report.md`; live marketing web-injection runs start with
`marketing_web_live_report.md`; context-consent runs start with
`context_consent_report.md`; tool-authority runs start with
`tool_authority_report.md`; RAG context authority runs start with
`rag_context_report.md`; planner task authority runs start with
`planner_task_report.md`.

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

> Passing validation means the artifacts conform to the expected schema and safety
> checks - **not** that any model, provider, or deployed system is secure.
