# Current state

> Last reviewed: 2026-06-25.
>
> Scope: public status of `agentic-security-harness` on `main`, version `0.13.0` plus
> unreleased governance and evidence-hardening changes. This page is a reviewer-facing
> status snapshot, not a roadmap promise.

## One-line status

Agentic Security Harness is a **pre-release research toolkit**: a working trace-first,
defensive benchmark prototype for agentic AI boundary failures with committed
deterministic examples, bounded local-swarm evidence, evidence-campaign metrics, and
sanitized local-model semantic-drift / propagation probes.

It is strong enough to show as a public alpha benchmark/toolkit. It is not a production
certification benchmark, a general pentest tool, or a claim that a target is secure.

## Shipped and verified

| Area | Status | Evidence |
|---|---|---|
| Local deterministic corpus | Shipped | 24 sanitized seed patterns in `corpus.py` and `patterns.py`. |
| Local targets | Shipped | `mock`, `demo-agent`, `protected-demo-agent`, `toy-local-function`, `toy-rag`, `toy-tools`, `toy-multi-agent`, `protected-toy-multi-agent`. |
| Baseline vs protected replay | Shipped | `ash compare --baseline demo-agent --protected protected-demo-agent`. |
| Inter-agent handoff verifier toy topology | Shipped local slice | `handoff_integrity.py`, `toy-multi-agent`, and `protected-toy-multi-agent` model deterministic label-loss and authority-expansion handoffs. |
| Boundary-layer variation matrices | Shipped local slice | `boundary-layer-evidence-matrix.md` and `tests/test_boundary_variation_matrices.py` tie declared handoff, authority, and memory-governance variation rows to executable deterministic checks. |
| Scenario timeline contract | Shipped local slice | `ScenarioTimeline`, `validate_timeline()`, three committed fixtures, and `replay_timeline()` model multi-turn/delayed/context-overload/handoff scenarios with explicit invariant and decision step. |
| Portable artifacts | Shipped | `traces.json`, `scorecard.json`, `summary.md`, `executive.md`, remediation, run manifests. |
| Static reports | Shipped | `ash report --root <run-dir>` writes a self-contained HTML report. |
| Run history and maintenance | Shipped | `list-runs`, `index-runs`, `stats`, `retention`, `diff-runs`. |
| External OpenAI-compatible prompt check | Experimental | `run-external`, prompt-only, explicit opt-in, no tool execution. |
| Public run-your-model path | Shipped docs slice | `docs/run-your-model.md` gives one operator path for deterministic demo, one local/remote OpenAI-compatible model, and local mini-swarm campaigns on Windows and Linux/macOS. |
| External evidence cross-check | Shipped for experimental path | Pattern id, boundary assertion, control family, decision coherence, raw response files. |
| Local-runtime metadata | Shipped for experimental path | `run_config.runtime`, report/runtime metadata, `local-only` mode for localhost/Ollama/LM Studio/vLLM, recovery guidance. |
| Bounded local-model suite | Shipped local slice | `ash local-suite`, named Prometheus/Ollama profiles, dry-run by default, request caps, validated artifacts after explicit `--execute`, and weak-evidence classification. |
| Bounded local swarm | Shipped research slice | `ash local-swarm` compares monolith, naive swarm, and bounded swarm across 15 deterministic handoff, memory, approval/tool, multi-hop laundering, and verifier-outage scenarios. |
| Attack variation matrix | Shipped research slice | `ash local-swarm-matrix` expands the 15 swarm scenarios into 43 rows across 9 families, including 10 executable deep probes over handoff and memory verifier mutations. |
| Evidence campaign | Shipped research slice | `ash evidence-campaign` calculates TP/FP/FN/TN, attack block rate, benign pass rate, false-block rate, control effect, usability cost, and control-ablation regressions across 24 cases / 72 observations / 4 claim families. |
| Synthetic secret-leak campaign | Shipped research slice | `ash secret-leak-campaign` models four synthetic secret-egress topologies: naive leaks 4/4, bounded leaks 0/4, ablation leaks 11/11, benign leaks 0/4. |
| Secret-leak variation probes | Shipped local empirical slice | `ash secret-leak-campaign --execute-variations` runs private local-model probes across 8 variation cases, 4 pressure modes, and selected Ollama models, then writes a sanitized public summary with raw prompts/responses kept under `.internal/`. |
| Semantic parameter drift probes | Shipped local empirical slice | `ash semantic-drift-campaign` models slow relabeling pressure in a local mini-swarm: deterministic bounded mode accepts 0 drift attempts, ablation modes accept 19, and the latest private local-model smoke records 80 observations with 13 drift detections, 4 synthetic canary leaks, and 15 verifier blocks. |
| Semantic propagation probes | Shipped local empirical slice | `ash semantic-propagation-campaign` models worker-to-chief propagation after semantic relabeling pressure: deterministic bounded mode accepts 0 propagation attempts, ablation modes accept 20, and the latest private local-model smoke records 8 observations with 2 worker drift detections, 3 chief acceptances, 2 synthetic canary leaks, 3 verifier blocks, 1 adapter error, and 87.5% response-hash coverage. |
| Semantic drift propagation closure | Closed research unit | `semantic-drift-propagation-closure.md` ties the drift and propagation campaigns into one closed evidence slice: declared cases, deterministic bounded-vs-ablation rows, local empirical observations, private/public boundary, and the follow-up consensus-laundering sub-unit. |
| Semantic consensus laundering closure | Closed sub-unit | `semantic-consensus-laundering-closure.md` isolates the existing two-worker consensus case: bounded acceptance 0, naive acceptance 1, and `cross_worker_check` ablation acceptance 1 under sanitized propagation artifacts. |
| Local swarm defense contour | Shipped synthetic defense slice | `ash swarm-defense-contour` combines four local-swarm failure families across 15 non-empty family combinations; bounded acceptances are 0, naive acceptances are 15, and control ablations reopen the declared dependent paths. Raw local-model probes remain private. |
| Sanitized local-model mini-swarm campaign | Shipped local empirical slice | `ash swarm-defense-live-campaign` runs private local worker/chief probes over the four-family contour and writes sanitized public summaries; the committed base example records 180 observations, 22 chief acceptances, 1 worker drift detection, 0 canary leaks, 22 verifier blocks, 96 replay-ablation reopenings, 0 adapter errors, and 100% response-hash coverage. A supplemental long-session example records 15 observations, each with 3 worker turns, 1 chief acceptance, 1 verifier block, 4 replay-ablation reopenings, 1 adapter error, and 0 canary leaks. A deep multi-model example records 168 observations, 67 chief acceptances, 3 worker drift detections, 0 canary leaks, 70 verifier blocks, 70/70 unsafe chains blocked, 91/91 benign chains allowed, 242 replay-ablation reopenings, and 100% response/turn-hash coverage for non-adapter-error rows. Public fields are bounded by `docs/private-public-evidence-boundary.md`. |
| Marketing web-injection swarm campaign | Shipped synthetic defense slice | `ash marketing-web-injection-campaign` models an offline marketing/ads web-ingestion swarm with hostile page text, synthetic internal strategy/contract values, naive/bounded/ablation/benign modes, sanitized public summaries, and validation support. The committed example records naive leaks 5/5, bounded leaks 0/5, ablation leaks 21/21, benign runs 5/5 allowed, and response-hash coverage 100%. |
| Live local-model marketing web-injection campaign | Shipped local empirical slice | `ash marketing-web-live-campaign` runs an owned localhost web stand through local worker/chief models, keeps raw pages/prompts/responses/synthetic strategy values under `.internal/`, and writes sanitized public summaries. The committed example records 60 observations, 3 worker leaks, 1 chief leak, 1 ablation final leak, 0 bounded final leaks, 0 benign final leaks, 8 verifier blocks, 0 false blocks, and 100% response/turn-hash coverage. |
| Public evidence map | Shipped docs slice | `docs/showcase/evidence-map.md` links each front-page metric to the artifact, reproduce command, claim, and non-claim. |
| Evidence pack format | Shipped docs slice | `docs/evidence-pack-format.md` defines how future local research becomes sanitized public evidence with private/public boundaries, hashes, claim rows, tests, and validation commands. |
| Local real-model swarm probes | Local empirical | Prometheus and qwen2.5 have executed the full 15-scenario swarm suite with 100% transcript-hash coverage and 0% adapter-error rate; model text remains evidence-quality context only. |
| Standards-aware mapping | Partial | OWASP Agentic per pattern; OWASP LLM and NIST at category level; MITRE ATLAS verified for direct-fit categories and deferred where speculative. |
| Public project process | Shipped locally | Governance, security policy, issue templates, PR template, CI, CodeQL, Scorecard, release artifact workflow. |

## Experimental

These features exist, but their results must be read conservatively:

- `ash run-external`: prompt-only evaluation of an authorized OpenAI-compatible endpoint;
  local runtimes are labeled `local-only` and still require model-license /
  authorization review.
- `ash local-suite`: a bounded wrapper around the external path for local Prometheus/Ollama
  smoke profiles. It is useful for real local model-in-the-loop evidence, but it remains
  weak evidence unless validated artifacts show a stable finding.
- `ash local-swarm --execute`: real local model role text can be collected through
  bounded swarm scenarios. Deterministic contracts, not the model text, make pass/block
  decisions.
- External model comparisons: useful for exploratory checks, not benchmark-grade
  leaderboards.
- `ash secret-leak-campaign --execute-variations`: private local-model pressure probes
  over synthetic secret-egress cases. Public summaries are sanitized; raw prompts,
  responses, and canaries stay under `.internal/`.
- `ash semantic-drift-campaign --execute`: private local-model semantic relabeling probes
  over synthetic mini-swarm handoff cases. Public summaries are sanitized; raw prompts,
  responses, canonical-state hashes, and canaries stay under `.internal/`.
- `ash semantic-propagation-campaign --execute`: private local-model worker-to-chief
  propagation probes over synthetic drifted summaries. Public summaries are sanitized;
  raw worker/chief prompts, responses, canonical-state hashes, and canaries stay under
  `.internal/`.
- `ash swarm-defense-live-campaign --execute`: private local worker/chief probes over
  the four-family defense contour. Public summaries expose safe model ids, topology ids,
  pressure labels, response hashes, per-turn response hashes, aggregate labels, adapter
  flags, verifier block attribution, replay-ablation metrics, and non-claims; raw
  prompts, responses, canaries, and calculation notes stay under `.internal/`.
  `--session-turns` enables bounded long-session pressure while still keeping raw turns
  private.
- `ash marketing-web-injection-campaign`: controlled offline marketing/ads
  web-ingestion campaign. It is synthetic and no-network; live web tests are not part of
  the current shipped claim.
- `ash marketing-web-live-campaign --execute`: owned-localhost web-ingestion probes
  against local worker/chief models. Raw pages, prompts, responses, and synthetic
  strategy values remain private under `.internal/`; public examples expose only hashes,
  aggregate classifications, verifier attribution, and non-claims.
- Scenario matrix and timeline variants: deterministic local replay metadata and pattern
  subsets, not live multi-tool execution.

External results are weak evidence until a stronger observation layer exists. The harness
records contradictory or incomplete model self-reports as `inconclusive`.

## Planned, not shipped

These are roadmap items and must not be described as current capability:

- native provider SDK adapters;
- live agent-host or tool-executing adapters;
- live MCP server adapter;
- cross-provider and cross-ecosystem handoff tests beyond the local toy adapter;
- broader recovery-path pattern family implementation beyond the shipped
  `data_boundary_missing_envelope_recovery` case;
- second-reviewer MITRE ATLAS mapping review and release-to-release upkeep;
- interactive multi-run viewer;
- persistent trace store beyond local manifests / SQLite metadata index;
- reference gateway runtime.

## Current active work

The next public-development focus is:

1. Keep current-vs-planned documentation synchronized with code and committed artifacts.
2. Keep the public evidence layer close to the artifacts: comparison, local swarm,
   attack matrix, evidence campaign, secret-egress, semantic drift, and semantic
   propagation pages must agree on counts and claim boundaries.
3. Maintain bounded local Prometheus/Ollama profiles as evidence-quality smokes, not as
   a broad model leaderboard.
4. Expand the corpus by invariant and topology, not by prompt/model cross-products.
5. Expand multi-agent-handoff coverage beyond the shipped local verifier toy topology
   only when each new track has explicit safety gates.
6. Verify standards mappings without implying certification.
7. Improve public demo/showcase reports with replayable, validated artifacts and clear
   private/public evidence boundaries.

## Validation commands

Use these before trusting a local checkout or public example:

```bash
python -m pytest
python -m ruff check .
python -m mypy src tests
ash validate examples/
git diff --check
```

For a quick public demo:

```bash
ash compare --baseline demo-agent --protected protected-demo-agent --out reports/comparison
ash validate reports/comparison
ash report --root reports/comparison
```

Expected current demonstration: the vulnerable baseline shows findings on the shipped
24-pattern corpus; the protected demo target removes those modeled findings under the
same configuration.

Expected research-swarm demonstration: `monolith` and `naive_swarm` accept the 15
declared modeled boundary failures, while `bounded_swarm` blocks them through
deterministic handoff, authority, memory, and verifier/auditor contracts. The 43-row
attack matrix and 24-case evidence campaign extend that same claim boundary; they do not
prove production swarm safety. Ten matrix rows are executable deep probes that model
harmful weak-model consumption attempts while deterministic contracts still make the
pass/block decision.

Expected secret-egress demonstration: the deterministic secret-leak campaign records
naive leaks 4/4, bounded leaks 0/4, ablation leaks 11/11, and benign leaks 0/4. The
Phase 2 variation smoke currently records 64 private local-model observations across two
Ollama models with 0 leaks and 0 adapter errors; that is evidence-quality context, not a
model safety proof.

Expected semantic-drift demonstration: the deterministic semantic drift campaign records
bounded drift acceptances 0 and ablation drift acceptances 19 across four synthetic
semantic relabeling cases. The latest private local-model smoke records 80 observations
across five Ollama models with 13 drift detections, 4 synthetic canary leaks, 15 verifier
blocks, 0 adapter errors, and 100% response-hash coverage; that is local empirical
evidence for the declared campaign, not a model leaderboard or production safety claim.

Expected semantic-propagation demonstration: the deterministic semantic propagation
campaign records 6 declared controls, 6 control-effect rows, bounded propagation
acceptances 0, and ablation propagation acceptances 20 across four worker-to-chief chain
cases. The latest private local-model smoke records 8 observations with 2 worker drift
detections, 3 chief acceptances, 2 synthetic canary leaks, 3 verifier blocks, 1 adapter
error, and 87.5% response-hash coverage; that is local empirical evidence for the
declared defense model, not a CVE or production swarm claim.

Expected semantic-closure reading: `docs/semantic-drift-propagation-closure.md` is the
reviewer-facing closure note for the first semantic unit. It does not add a stronger
claim than the artifacts; it explains why this unit is closed for the declared synthetic
model. `docs/semantic-consensus-laundering-closure.md` closes the first consensus
laundering sub-unit over the existing propagation artifact.

Expected defense-contour demonstration: the deterministic local swarm defense contour
records 4 scenario families, 15 non-empty combination topologies, bounded acceptances 0,
naive acceptances 15, and control-ablation reopenings for the declared dependent paths.
It is a synthetic control-attribution layer, not a live model or production-swarm proof.

## Claim boundary

Allowed public claim:

> Trace-first defensive benchmark prototype for reproducible agentic AI boundary-failure
> evaluation, with local deterministic targets, validated artifacts, bounded local-swarm
> evidence, and experimental opt-in external/local model checks.

Do not claim:

- production certification;
- complete security coverage;
- real target coverage without an adapter and authorization model;
- provider endorsement;
- benchmark-grade model leaderboard;
- live tool-executing agent evaluation.
