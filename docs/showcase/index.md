# Public evidence showcase

This showcase is the reviewer-facing entry point for benchmark evidence. It avoids code
details and points to the artifacts, scenarios, and follow-up work needed to understand
what the current public artifacts support and what they do not support.

## Read first

| Page | Purpose |
|---|---|
| [Evidence map](evidence-map.md) | One-page claim-to-artifact map for public metrics, reproduce commands, and non-claims. |
| [Machine-readable evidence status](../evidence-status-registry.json) | Component-level lifecycle, evidence class, schema, causal scope, labels, reconciliation, origin, and claim boundaries; validated with `ash validate`. |
| [Research problem map](../research-problem-map.md) | Active invariant-to-artifact map with lifecycle, evidence strength, causal scope, and promotion rules. |
| [Private/public evidence boundary](../private-public-evidence-boundary.md) | What local-model campaign fields may be public, what stays private, and why hash commitments require separate owner-side reconciliation. |
| [Agentic rule-violation back-pass](../agentic-rule-violation-backpass.md) | Shipped contours reviewed through entry vector, propagation path, timing window, controls, and residual risk. |
| [Scenario matrix](scenario-matrix.md) | What scenario families exist and what topology each one tests. |
| [Semantic propagation defense model](../semantic-propagation-defense-model.md) | Worker-to-chief semantic drift controls, ablation matrix, and public/private boundary. |
| [Local swarm defense contour](../local-swarm-defense-contour.md) | Four-family defensive contour for semantic drift, propagation, consensus laundering, and benign-framed leaks. |
| [Tool-output authority campaign](../tool-authority-campaign.md) | Deterministic model for the boundary that tool output is data, not authority. |
| [RAG context authority campaign](../rag-context-campaign.md) | Deterministic model for the boundary that retrieved context is evidence, not authority. |
| [Planner task authority campaign](../planner-task-campaign.md) | Deterministic model for the boundary that planning is transformation, not authorization. |
| [Memory rehydration authority campaign](../memory-rehydration-campaign.md) | Deterministic model for the boundary that recalled memory is evidence, not current authority. |
| [Weak spots and findings](weak-spots-and-findings.md) | Separates findings from inconclusive/error/runtime weak spots. |
| [Deepening backlog](deepening-backlog.md) | Bounded follow-up variations selected from evidence, not a full cross-product. |
| [Local swarm deep probes](../local-swarm-deep-probes.md) | Executable handoff/memory mutation probes plus private local-model evidence-quality runs. |
| [Metrics contract](../metric-contract.md) | How to read traffic, benchmark, runtime, and process metrics. |
| [Scenario investigation workflow](../scenario-investigation-workflow.md) | How scenarios become evidence and then deeper checks. |
| [Generated failure cards](generated/failure-cards.md) | Fail-closed generated view. The former committed source uses legacy manifest 0.1 without persisted-byte hashes, so it now yields an honest empty state; cards require a current content-bound validated run and every emitted card links a trace reference. |

## Current public evidence

Machine-readable row mapping:

- Deterministic baseline/protected comparison: `evidence-id:corpus.comparison`.
- Deterministic multi-agent handoff toy comparison:
  `evidence-id:handoff.integrity-comparison`,
  `evidence-id:handoff.authority-comparison`.
- Bounded local swarm evidence suite: `evidence-id:swarm.local-specification`.
- Local swarm attack variation matrix: `evidence-id:swarm.variation-matrix`.
- Evidence campaign: `evidence-id:campaign.evidence-specification`.
- Synthetic secret-leak campaign: `evidence-id:egress.synthetic-specification`.
- Secret-leak variation probes: `evidence-id:egress.local-variations`.
- Semantic parameter drift probes: `evidence-id:semantic.drift-specification`,
  `evidence-id:semantic.drift-history`.
- Semantic propagation defense: `evidence-id:semantic.propagation-specification`,
  `evidence-id:semantic.propagation-history`,
  `evidence-id:semantic.consensus-specification`.
- Local swarm defense contour: `evidence-id:swarm.defense-contour`.
- Historical loopback-endpoint mini-swarm campaign:
  `evidence-id:swarm.live-history`.
- Marketing web-injection swarm: `evidence-id:marketing.injection-specification`.
- Historical loopback-endpoint marketing web-injection:
  `evidence-id:marketing.live-history`.
- Swarm resilience/stability model: `evidence-id:swarm.resilience-specification`.
- Context consent boundary: `evidence-id:authority.context-consent`.
- Tool-output authority boundary: `evidence-id:authority.tool-output`.
- RAG context authority boundary: `evidence-id:authority.rag-context`.
- Planner task authority boundary: `evidence-id:authority.planner-task`.
- Memory rehydration authority boundary: `evidence-id:authority.memory-rehydration`.
- Local swarm real-model evaluation: `evidence-id:runtime.local-swarm-history`.
- External fake-server run: `evidence-id:external.fake-server`.
- Local Prometheus/Ollama smoke: `evidence-id:runtime.local-suite-specification`,
  `evidence-id:runtime.prometheus-smoke-history`.

Every id above must resolve to exactly one registry component. Multiple ids on one row
mean that the human row combines distinct evidence classes; they do not promote one
component into the class of another.

| Evidence | Status | Start here | What it proves | What it does not prove |
|---|---|---|---|---|
| Deterministic baseline/protected comparison | Validated example | [`examples/comparison-report/README.md`](../../examples/comparison-report/README.md) | The shipped synthetic corpus can produce a visible 24 -> 0 modeled-risk reduction between demo targets. | A real deployed agent is secure. |
| Deterministic multi-agent handoff toy comparison | Local validated artifact | [`handoff-toy-topology.md`](../handoff-toy-topology.md) | The shipped local `toy-multi-agent` slice produces 2 modeled handoff findings, while `protected-toy-multi-agent` blocks the malformed handoffs under the same corpus. | Evidence about a live multi-agent framework, provider, or production handoff protocol. |
| Bounded local swarm evidence suite | Validated example | [`examples/local-swarm-report/local_swarm_report.md`](../../examples/local-swarm-report/local_swarm_report.md) | The research-only `bounded_swarm` topology blocks 15 synthetic handoff, memory, memory-poisoning, approval/tool, multi-hop laundering, and verifier-outage boundary failures that `naive_swarm` accepts. | A real model, provider, framework, or production swarm is safe. |
| Local swarm attack variation matrix | Validated example | [`examples/local-swarm-attack-matrix/local_swarm_attack_matrix.md`](../../examples/local-swarm-attack-matrix/local_swarm_attack_matrix.md) | The 15 local-swarm scenarios are expanded into 43 rows across 9 families, including 10 executable deep probes for hash mismatch, recipient switch, stale replay, policy mismatch, tool-output authority confusion, and memory drift; `bounded_swarm` blocks all declared rows under deterministic contracts. | Exhaustive attack coverage, cryptographic audit-log proof, model understanding, or live-framework safety. |
| Evidence campaign | Validated executable specification | [`examples/evidence-campaign-sanitized/evidence_campaign_report.md`](../../examples/evidence-campaign-sanitized/evidence_campaign_report.md) | Across 24 scenario-author-labelled cases / 72 rule-derived observations / 4 claim families, bounded mode reproduces the declared block/allow fixture and named-control attribution. | Independent detector accuracy, independent causal effect, a production guarantee, complete benign usability proof, model safety, or exhaustive bypass coverage. |
| Synthetic secret-leak campaign | Validated example | [`examples/secret-leak-campaign-sanitized/secret_leak_campaign_report.md`](../../examples/secret-leak-campaign-sanitized/secret_leak_campaign_report.md) | Across 4 synthetic secret-egress topologies / 23 observations, naive mode leaks 4/4, bounded mode leaks 0/4, and ablation mode records 11/11 control regressions. | Real-secret extraction, a public model vulnerability claim, production agent safety, or exhaustive secret-handling coverage. |
| Secret-leak variation probes | Unreconciled detector summary | [`examples/secret-leak-variations-sanitized/secret_leak_variation_report.md`](../../examples/secret-leak-variations-sanitized/secret_leak_variation_report.md) | The public artifact declares 64 observations, 0 detector-labelled leaks, 0 adapter errors, and complete hash-field presence. It does not replay private bytes or attest execution origin. | A current empirical result, authenticated model execution, model-safety proof, vulnerability absence claim, or exhaustive prompt-pressure coverage. |
| Semantic parameter drift probes | Legacy structural summary plus executable specification | [`examples/semantic-drift-sanitized/semantic_drift_report.md`](../../examples/semantic-drift-sanitized/semantic_drift_report.md) | The legacy schema-0.1 observation rows retain declared detector labels and aggregates; current schema is 0.2. The deterministic projection records bounded acceptance 0 and 19 rule-derived ablation acceptances. | Current empirical evidence, authenticated execution, a CVE, a model leaderboard, production swarm safety, or exhaustive long-session coverage. |
| Semantic propagation defense | Legacy structural summary plus executable specification | [`examples/semantic-propagation-sanitized/semantic_propagation_report.md`](../../examples/semantic-propagation-sanitized/semantic_propagation_report.md) | The legacy schema-0.2 observation rows retain declared detector labels and aggregates; current schema is 0.3. The deterministic projection records bounded acceptance 0 and 20 rule-derived ablation acceptances. | Current empirical evidence, authenticated execution, causal effect, a CVE, a model leaderboard, production swarm safety, or a claim that adapter errors are passes. |
| Local swarm defense contour | Validated executable specification | [`examples/swarm-defense-contour-sanitized/swarm_defense_contour_report.md`](../../examples/swarm-defense-contour-sanitized/swarm_defense_contour_report.md) | Across 4 declared local-swarm failure families and all 15 non-empty family combinations, bounded deterministic mode accepts 0 paths, naive mode accepts 15, and the generator records 112 rule-derived ablation acceptances. | A live local model result, independent causal effect, production swarm safety, exhaustive attack coverage, or proof that deterministic validators solve semantic truth. |
| Historical loopback-endpoint mini-swarm campaign | Legacy sanitized examples | [`examples/swarm-defense-live-sanitized/swarm_defense_live_report.md`](../../examples/swarm-defense-live-sanitized/swarm_defense_live_report.md), [`examples/swarm-defense-live-long-session-sanitized/swarm_defense_live_report.md`](../../examples/swarm-defense-live-long-session-sanitized/swarm_defense_live_report.md), and [`examples/swarm-defense-live-deep-sanitized/swarm_defense_live_report.md`](../../examples/swarm-defense-live-deep-sanitized/swarm_defense_live_report.md) | These pre-0.5 artifacts retain historical drift/chief/adapter observations. Canary-zero claims are withdrawn because the old aggregator mismatched detector categories; ablation “reopenings” are rule-attribution counts. | A current-contract execution, absence of leakage, causal control effect, local model attestation, signed evidence, or production safety. |
| Marketing web-injection swarm | Validated executable specification | [`examples/marketing-web-injection-sanitized/marketing_web_injection_report.md`](../../examples/marketing-web-injection-sanitized/marketing_web_injection_report.md) | Across 5 controlled offline cases and 36 rows, the generator selects 5 naive leak branches, 0 bounded leak branches, 21 rule-derived ablation leak branches, and 5 benign allow branches. | Empirical causal effect, real internet safety, real-secret extraction, CVE status, production swarm safety, or exhaustive web-injection coverage. |
| Historical loopback-endpoint marketing web-injection | Legacy structural example | [`examples/marketing-web-live-sanitized/marketing_web_live_report.md`](../../examples/marketing-web-live-sanitized/marketing_web_live_report.md) | Schema `0.2` historical detector observations; current schema `0.3` is unexecuted, and verifier/ablation outcomes are rule-derived. | Current evidence, causal control effects, local model attestation, signed integrity, or production safety. |
| Swarm resilience/stability model | Validated executable specification | [`examples/swarm-resilience-sanitized/swarm_resilience_report.md`](../../examples/swarm-resilience-sanitized/swarm_resilience_report.md) | Across 7 declared degradation families and 46 deterministic rows, the generator selects 7 naive unsafe branches, 0 bounded unsafe branches, 18 rule-derived ablation branches, and 0 benign false-block branches. | Empirical causal effect, production swarm safety, exhaustive attack coverage, real-secret extraction, or proof that deterministic state vectors solve semantic truth. |
| Context consent boundary | Validated example | [`examples/context-consent-sanitized/context_consent_report.md`](../../examples/context-consent-sanitized/context_consent_report.md) | Across 5 consent-boundary cases and 45 deterministic rows, naive mode accepts 5 risky actions, bounded mode accepts 0, control ablations reopen 18 rows, and benign rows have 0 false blocks. | Production consent enforcement, model safety, proof of user understanding, or exhaustive workflow coverage. |
| Tool-output authority boundary | Validated example | [`examples/tool-authority-sanitized/tool_authority_report.md`](../../examples/tool-authority-sanitized/tool_authority_report.md) | Across 6 tool-output authority cases and 66 deterministic rows, naive mode accepts 6 risky actions, bounded mode accepts 0, control ablations reopen 23 rows, and benign rows have 0 false blocks. | Production tool-agent safety, real MCP/schema verification, model safety, or exhaustive tool-output coverage. |
| RAG context authority boundary | Validated example | [`examples/rag-context-sanitized/rag_context_report.md`](../../examples/rag-context-sanitized/rag_context_report.md) | Across 7 retrieved-context propagation cases and 91 deterministic rows, naive mode accepts 7 unsafe chains, bounded mode accepts 0, control ablations reopen 30 rows, and benign rows have 0 false blocks. | Production RAG-agent safety, provider/model vulnerability claims, model safety, or exhaustive retrieval coverage. |
| Planner task authority boundary | Validated example | [`examples/planner-task-sanitized/planner_task_report.md`](../../examples/planner-task-sanitized/planner_task_report.md) | Across 7 planner/task-decomposition cases and 91 deterministic rows, naive mode accepts 7 unsafe chains, bounded mode accepts 0, control ablations reopen 32 rows, and benign rows have 0 false blocks. | Production planning-agent safety, provider/model vulnerability claims, model safety, or exhaustive planner coverage. |
| Memory rehydration authority boundary | Validated example | [`examples/memory-rehydration-sanitized/memory_rehydration_report.md`](../../examples/memory-rehydration-sanitized/memory_rehydration_report.md) | Across 7 cross-agent memory rehydration cases and 91 deterministic rows, naive mode accepts 7 unsafe chains, bounded mode accepts 0, control ablations reopen 32 rows, and benign rows have 0 false blocks. | Production memory-agent safety, provider/model vulnerability claims, model safety, or exhaustive memory-system coverage. |
| Local swarm real-model evaluation | Unreconciled maintainer report | [`local-swarm-real-model-evaluation.md`](../local-swarm-real-model-evaluation.md) | Historical documentation declares two local runs and complete transcript-hash-field coverage. No private execution bundle or reconciliation receipt is present in the public repository. | Authenticated model/runtime execution, a current empirical result, a safety benchmark pass, or production swarm behavior. |
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
Legacy manifests without persisted-byte content hashes are excluded rather than
retroactively assigned a new execution identity.

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

Committed artifact boundary: 4 cases, 28 deterministic contract rows, bounded
deterministic drift acceptances 0, and 19 rule-derived ablation acceptances. The 80
observation rows are a legacy schema-`0.1` detector summary; current schema is `0.2`,
private bytes are not publicly reconciled, and current empirical status is not claimed.

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

Committed artifact boundary: 4 cases, 32 deterministic contract rows, bounded
deterministic propagation acceptances 0, and 20 rule-derived ablation acceptances. The
8 observation rows are a legacy schema-`0.2` detector summary; current schema is `0.3`,
private bytes are not publicly reconciled, and current empirical status is not claimed.

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
