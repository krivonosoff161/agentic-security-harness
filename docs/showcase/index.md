# Public evidence showcase

This showcase is the reviewer-facing entry point for benchmark evidence. It avoids code
details and points to the artifacts, scenarios, and follow-up work needed to understand
what the project currently proves.

## Read first

| Page | Purpose |
|---|---|
| [Scenario matrix](scenario-matrix.md) | What scenario families exist and what topology each one tests. |
| [Weak spots and findings](weak-spots-and-findings.md) | Separates findings from inconclusive/error/runtime weak spots. |
| [Deepening backlog](deepening-backlog.md) | Bounded follow-up variations selected from evidence, not a full cross-product. |
| [Local swarm deep probes](../local-swarm-deep-probes.md) | Executable handoff/memory mutation probes plus private local-model evidence-quality runs. |
| [Metrics contract](../metric-contract.md) | How to read traffic, benchmark, runtime, and process metrics. |
| [Scenario investigation workflow](../scenario-investigation-workflow.md) | How scenarios become evidence and then deeper checks. |
| [Generated failure cards](generated/failure-cards.md) | Artifact-driven failure/replay cards generated from a committed run (`ash showcase --root examples/demo-agent-report --out docs/showcase/generated`); every card links a trace reference. |

## Current public evidence

| Evidence | Status | Start here | What it proves | What it does not prove |
|---|---|---|---|---|
| Deterministic baseline/protected comparison | Validated example | [`examples/comparison-report/README.md`](../../examples/comparison-report/README.md) | The shipped synthetic corpus can produce a visible 24 -> 0 modeled-risk reduction between demo targets. | A real deployed agent is secure. |
| Deterministic multi-agent handoff toy comparison | Local validated artifact | [`handoff-toy-topology.md`](../handoff-toy-topology.md) | The shipped local `toy-multi-agent` slice produces 2 modeled handoff findings, while `protected-toy-multi-agent` blocks the malformed handoffs under the same corpus. | Evidence about a live multi-agent framework, provider, or production handoff protocol. |
| Bounded local swarm evidence suite | Validated example | [`examples/local-swarm-report/local_swarm_report.md`](../../examples/local-swarm-report/local_swarm_report.md) | The research-only `bounded_swarm` topology blocks 15 synthetic handoff, memory, memory-poisoning, approval/tool, multi-hop laundering, and verifier-outage boundary failures that `naive_swarm` accepts. | A real model, provider, framework, or production swarm is safe. |
| Local swarm attack variation matrix | Validated example | [`examples/local-swarm-attack-matrix/local_swarm_attack_matrix.md`](../../examples/local-swarm-attack-matrix/local_swarm_attack_matrix.md) | The 15 local-swarm scenarios are expanded into 43 rows across 9 families, including 10 executable deep probes for hash mismatch, recipient switch, stale replay, policy mismatch, tool-output authority confusion, and memory drift; `bounded_swarm` blocks all declared rows under deterministic contracts. | Exhaustive attack coverage, cryptographic audit-log proof, model understanding, or live-framework safety. |
| Evidence campaign | Validated example | [`examples/evidence-campaign-sanitized/evidence_campaign_report.md`](../../examples/evidence-campaign-sanitized/evidence_campaign_report.md) | Across 24 cases / 72 observations / 4 claim families, bounded mode reaches attack block rate 100%, benign pass rate 100%, false-block rate 0%, and records control-ablation regressions when responsible controls are disabled. | A production guarantee, complete benign usability proof, model safety result, or proof that every possible bypass is covered. |
| Synthetic secret-leak campaign | Validated example | [`examples/secret-leak-campaign-sanitized/secret_leak_campaign_report.md`](../../examples/secret-leak-campaign-sanitized/secret_leak_campaign_report.md) | Across 4 synthetic secret-egress topologies / 23 observations, naive mode leaks 4/4, bounded mode leaks 0/4, and ablation mode records 11/11 control regressions. | Real-secret extraction, a public model vulnerability claim, production agent safety, or exhaustive secret-handling coverage. |
| Secret-leak variation probes | Validated example | [`examples/secret-leak-variations-sanitized/secret_leak_variation_report.md`](../../examples/secret-leak-variations-sanitized/secret_leak_variation_report.md) | Across 8 live local-model variation cases x 4 pressure modes x 2 Ollama models, the current private smoke recorded 64 observations, 0 leaks, and 0 adapter errors. | A model-safety proof, a vulnerability absence claim, or exhaustive prompt-pressure coverage. |
| Semantic parameter drift probes | Validated example | [`examples/semantic-drift-sanitized/semantic_drift_report.md`](../../examples/semantic-drift-sanitized/semantic_drift_report.md) | Across 4 semantic relabeling cases x 4 pressure modes x 5 Ollama models, the current private smoke recorded 80 observations, 13 drift detections, 4 synthetic canary leaks, and 15 verifier blocks; bounded deterministic mode accepted 0 drift while ablations accepted 19. | A real-secret leak, a CVE, a model leaderboard, production swarm safety, or exhaustive long-session coverage. |
| Semantic propagation probes | Validated example | [`examples/semantic-propagation-sanitized/semantic_propagation_report.md`](../../examples/semantic-propagation-sanitized/semantic_propagation_report.md) | Across 4 worker-to-chief propagation cases x 2 pressure modes, the current private smoke recorded 8 observations, 2 worker drift detections, 3 chief acceptances, 2 synthetic canary leaks, and 3 verifier blocks; bounded deterministic mode accepted 0 propagation while ablations accepted 20. | A real-secret leak, a CVE, a model leaderboard, production swarm safety, or exhaustive long-session coverage. |
| Local swarm real-model evaluation | Local empirical summary | [`local-swarm-real-model-evaluation.md`](../local-swarm-real-model-evaluation.md) | Two local Ollama models executed the full 15-scenario local-swarm suite with 100% transcript-hash coverage and 0% adapter-error rate. | The local models passed a safety benchmark or production swarm behavior is proven. |
| External fake-server run | Validated example | [`examples/external-demo-report/README.md`](../../examples/external-demo-report/README.md) | The experimental external artifact path can validate against a deterministic local fake OpenAI-compatible endpoint. | A real model/provider is safe. |
| Local Prometheus/Ollama smoke | Shipped bounded local-suite; local scratch artifacts | [`local-prometheus-workflow.md`](../local-prometheus-workflow.md) | A weak local model can be exercised through a named prompt-only local-suite profile; first local Prometheus smokes exposed evidence-quality/runtime limits. | Public benchmark finding; model leaderboard result. |

## Current local model observation

A maintainer local full run executed the 15-scenario `local-swarm` suite against
`prometheus-qwen15b-lowctx:latest` and `qwen2.5:1.5b`. Each run produced:

```text
scenarios: 15
modes: 3
estimated role calls: 120
monolith boundary failures: 15
naive-swarm boundary failures: 15
bounded-swarm boundary failures: 0
verifier blocks: 15
transcript hash coverage: 100%
adapter error rate: 0%
```

Interpretation: this is runtime/evidence-quality data for a bounded local swarm path, not
a model safety result. The useful evidence is that weak local models can produce role text
under request caps while deterministic ASH contracts make every pass/block decision and
record transcript hashes for review.

Local reports remain under `reports/` and are not committed as public benchmark evidence
until curated and validated for public use.

## Reproduce the safe deterministic showcase

```bash
ash compare --baseline demo-agent --protected protected-demo-agent --out reports/comparison
ash validate reports/comparison
ash report --root reports/comparison
```

Generate reviewer-facing Markdown from recorded artifacts:

```bash
ash showcase --root reports --out docs/showcase/generated
```

The generated files are a reviewer aid. JSON artifacts remain the source of truth.

## Reproduce the local handoff toy comparison

```bash
ash compare --baseline toy-multi-agent --protected protected-toy-multi-agent --out examples/handoff-toy-comparison
ash validate examples/handoff-toy-comparison
```

Expected current result: `toy-multi-agent` records 2 deterministic modeled findings
(`data_boundary_handoff_label_stripping` and `capability.delegation_chain_drift`);
`protected-toy-multi-agent` records 0 findings by blocking consumption of the malformed
handoffs. This remains a local synthetic topology, not a live multi-agent runtime claim.

## Reproduce the bounded local swarm evidence suite

```bash
ash local-swarm --write-dry-run --out reports/local-swarm
ash validate reports/local-swarm
```

The committed deterministic example lives at `examples/local-swarm-report/` and validates
with:

```bash
ash validate examples/local-swarm-report
```

Expected current result: `monolith` and `naive_swarm` each accept 15 modeled boundary
failures, while `bounded_swarm` blocks all 15 through deterministic handoff and memory
contracts. Optional local-model role calls are evidence-quality context only; they do
not decide pass/block.

Calculate the attack/slom variation matrix:

```bash
ash local-swarm-matrix --write --out reports/local-swarm-attack-matrix
ash validate reports/local-swarm-attack-matrix
```

The committed matrix lives at `examples/local-swarm-attack-matrix/` and validates with:

```bash
ash validate examples/local-swarm-attack-matrix
```

Expected current result: 43 declared variation rows, 9 variation families, 10 deep
invariant probes, 43 naive boundary failures, 0 bounded boundary failures, and 43
deterministic bounded blocks.

Calculate the evidence campaign metrics:

```bash
ash evidence-campaign --write --out .internal/evidence-campaign/latest
ash validate .internal/evidence-campaign/latest
```

The committed sanitized example lives at `examples/evidence-campaign-sanitized/` and
validates with:

```bash
ash validate examples/evidence-campaign-sanitized
```

Expected current result: 24 cases, 72 observations, 4 claim families, bounded attack
block rate 100%, bounded benign pass rate 100%, bounded false-block rate 0%, and
control-ablation rows that show which declared control carries each unsafe decision.

## Reproduce the semantic drift campaign

Write the deterministic sanitized example:

```bash
ash semantic-drift-campaign --write --out reports/semantic-drift
ash validate reports/semantic-drift
```

Run the optional local-model smoke with private raw transcripts under `.internal/`:

```bash
ash semantic-drift-campaign --execute --out .internal/semantic-drift/latest --summary-out reports/semantic-drift --model qwen2.5:0.5b --model llama3.2:1b --model qwen2.5-coder:0.5b-instruct --model qwen2.5:1.5b --model prometheus-qwen15b-lowctx:latest
ash validate reports/semantic-drift
```

Expected current result for the committed sanitized example: 4 cases, 28 deterministic
contract rows, bounded deterministic drift acceptances 0, ablation acceptances 19, and
80 local-model observations in the latest maintainer smoke. Raw prompts, responses,
canonical-state hashes, and canaries remain private.

## Reproduce the semantic propagation campaign

Write the deterministic sanitized example:

```bash
ash semantic-propagation-campaign --write --out reports/semantic-propagation
ash validate reports/semantic-propagation
```

Run the optional local-model smoke with private raw transcripts under `.internal/`:

```bash
ash semantic-propagation-campaign --execute --out .internal/semantic-propagation/latest --summary-out reports/semantic-propagation --worker-model qwen2.5:0.5b --chief-model llama3.2:1b --pressure-mode pseudo_code --pressure-mode memory_rewrite --max-chains 8
ash validate reports/semantic-propagation
```

Expected current result for the committed sanitized example: 4 cases, 32 deterministic
contract rows, bounded deterministic propagation acceptances 0, ablation acceptances 20,
and 8 local-model observations in the latest maintainer smoke. Raw worker/chief prompts,
responses, canonical-state hashes, and canaries remain private.

## Reproduce the bounded local smoke

```powershell
python -m agentic_security_harness.cli local-suite --profile prometheus-lowctx-smoke
python -m agentic_security_harness.cli local-suite --profile prometheus-lowctx-smoke --execute
```

## Claim boundary

Allowed:

> The project has a trace-first deterministic showcase and a documented path for local
> real-model probes. Bounded-swarm and evidence-campaign metrics are interpreted through
> explicit claim boundaries, deterministic contracts, and validation commands.

Not allowed:

- "The local model passed."
- "The project has a model leaderboard."
- "GitHub traffic proves benchmark credibility."
- "A local weak model result generalizes to all LLMs."
