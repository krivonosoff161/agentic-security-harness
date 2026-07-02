# Public evidence showcase

This showcase is the reviewer-facing entry point for benchmark evidence. It avoids code
details and points to the artifacts, scenarios, and follow-up work needed to understand
what the current public artifacts support and what they do not support.

## Read first

| Page | Purpose |
|---|---|
| [Evidence map](evidence-map.md) | One-page claim-to-artifact map for public metrics, reproduce commands, and non-claims. |
| [Private/public evidence boundary](../private-public-evidence-boundary.md) | What local-model campaign fields may be public, what stays private, and how response hashes anchor owner-side replay. |
| [Scenario matrix](scenario-matrix.md) | What scenario families exist and what topology each one tests. |
| [Semantic propagation defense model](../semantic-propagation-defense-model.md) | Worker-to-chief semantic drift controls, ablation matrix, and public/private boundary. |
| [Local swarm defense contour](../local-swarm-defense-contour.md) | Four-family defensive contour for semantic drift, propagation, consensus laundering, and benign-framed leaks. |
| [Tool-output authority campaign](../tool-authority-campaign.md) | Deterministic model for the boundary that tool output is data, not authority. |
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
| Semantic propagation defense | Validated example | [`examples/semantic-propagation-sanitized/semantic_propagation_report.md`](../../examples/semantic-propagation-sanitized/semantic_propagation_report.md) | Across 4 worker-to-chief propagation cases, the public model declares 6 controls and 6 control-effect rows: bounded deterministic mode accepts 0 propagation while ablations accept 20; the local smoke adds 8 observations, 3 chief acceptances, 3 verifier blocks, 1 adapter error, and 87.5% response-hash coverage. | A real-secret leak, a CVE, a model leaderboard, production swarm safety, exhaustive long-session coverage, or a claim that adapter errors are passes. |
| Local swarm defense contour | Validated example | [`examples/swarm-defense-contour-sanitized/swarm_defense_contour_report.md`](../../examples/swarm-defense-contour-sanitized/swarm_defense_contour_report.md) | Across 4 declared local-swarm failure families and all 15 non-empty family combinations, bounded deterministic mode accepts 0 paths, naive mode accepts 15, and control ablations reopen 68 dependent paths. | A live local model result, production swarm safety, exhaustive attack coverage, or proof that deterministic validators solve semantic truth. |
| Sanitized local-model mini-swarm campaign | Validated sanitized local-model example | [`examples/swarm-defense-live-sanitized/swarm_defense_live_report.md`](../../examples/swarm-defense-live-sanitized/swarm_defense_live_report.md), [`examples/swarm-defense-live-long-session-sanitized/swarm_defense_live_report.md`](../../examples/swarm-defense-live-long-session-sanitized/swarm_defense_live_report.md), and [`examples/swarm-defense-live-deep-sanitized/swarm_defense_live_report.md`](../../examples/swarm-defense-live-deep-sanitized/swarm_defense_live_report.md) | Across 15 contour topologies x 6 pressure modes x 2 worker models x 1 chief model, the base private local run records 180 observations, 22 chief acceptances, 1 worker drift detection, 0 canary leaks, 22 verifier blocks, 96 replay-ablation reopenings, 0 adapter errors, and 100% response-hash coverage. The long-session supplement records 15 observations, each with 3 worker turns, 1 chief acceptance, 1 verifier block, 4 replay-ablation reopenings, 1 adapter error, and 0 canary leaks. The deep multi-model run records 168 observations, 67 chief acceptances, 3 worker drift detections, 0 canary leaks, 70 verifier blocks, 70/70 unsafe chains blocked, 91/91 benign chains allowed, 242 replay-ablation reopenings, and 100% response/turn-hash coverage for non-adapter-error rows. Public artifacts expose safe model ids, roles, topology ids, pressure labels, response/per-turn hashes, aggregate labels, verifier attribution, adapter flags, replay-ablation metrics, Wilson intervals, and model breakdowns; raw transcripts remain private. | A CVE, real-secret extraction, model leaderboard, production swarm safety, exhaustive attack coverage, or proof that deterministic validators solve semantic truth. |
| Marketing web-injection swarm | Validated example | [`examples/marketing-web-injection-sanitized/marketing_web_injection_report.md`](../../examples/marketing-web-injection-sanitized/marketing_web_injection_report.md) | Across 5 controlled offline marketing/ads web-ingestion scenarios and 36 observations, naive mode leaks 5/5 unsafe cases, bounded mode leaks 0/5, control ablations reopen 21/21 unsafe rows, benign rows are allowed 5/5, and response-hash coverage is 100%. | Real internet safety, real-secret extraction, CVE status, production swarm safety, or exhaustive web-injection coverage. |
| Live local-model marketing web-injection | Validated sanitized local-model example | [`examples/marketing-web-live-sanitized/marketing_web_live_report.md`](../../examples/marketing-web-live-sanitized/marketing_web_live_report.md) | Across 2 owned local-web marketing scenarios, 2 worker models, and 2 chief models, the sanitized run records 60 observations, 3 worker leaks, 1 chief leak, 1 ablation final leak, 0 bounded final leaks, 0 benign final leaks, 8 verifier blocks, 0 false blocks, and 100% response/turn-hash coverage. | A CVE, real-secret extraction, real internet safety, production swarm safety, model leaderboard result, or exhaustive web-injection coverage. |
| Swarm resilience/stability model | Validated example | [`examples/swarm-resilience-sanitized/swarm_resilience_report.md`](../../examples/swarm-resilience-sanitized/swarm_resilience_report.md) | Across 7 declared degradation families and 46 deterministic observations, naive mode accepts 7 unsafe trajectories, bounded mode accepts 0, control ablations reopen 18, benign rows have 0 false blocks, and state-hash coverage is 100%. | Production swarm safety, exhaustive attack coverage, real-secret extraction, or proof that deterministic state vectors solve semantic truth. |
| Context consent boundary | Validated example | [`examples/context-consent-sanitized/context_consent_report.md`](../../examples/context-consent-sanitized/context_consent_report.md) | Across 5 consent-boundary cases and 45 deterministic rows, naive mode accepts 5 risky actions, bounded mode accepts 0, control ablations reopen 18 rows, and benign rows have 0 false blocks. | Production consent enforcement, model safety, proof of user understanding, or exhaustive workflow coverage. |
| Tool-output authority boundary | Validated example | [`examples/tool-authority-sanitized/tool_authority_report.md`](../../examples/tool-authority-sanitized/tool_authority_report.md) | Across 6 tool-output authority cases and 66 deterministic rows, naive mode accepts 6 risky actions, bounded mode accepts 0, control ablations reopen 23 rows, and benign rows have 0 false blocks. | Production tool-agent safety, real MCP/schema verification, model safety, or exhaustive tool-output coverage. |
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
and 8 local-model observations in the latest maintainer smoke, including 1 adapter
error and 87.5% response-hash coverage. Raw worker/chief prompts, responses,
canonical-state hashes, and canaries remain private.

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
