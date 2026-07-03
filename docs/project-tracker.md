# Project tracker

This page explains how public project work is tracked. It is intentionally small:
GitHub Issues and milestones are the source of truth for work in progress; repository
docs describe the current shipped state.

## Current evidence milestone

Active public-development track:

| Milestone | Purpose |
|---|---|
| [v0.17 public evidence showcase and local model probes](https://github.com/krivonosoff161/agentic-security-harness/milestone/5) | Make benchmark evidence easy to inspect before reading code, then add bounded local real-model probes. |

The milestone is not a release claim. It is a work tracker for the next credibility
slice: local Prometheus/Ollama probes, scenario timelines, failure cards, and the
design-led inter-agent handoff integrity track.

## Open work in this track

| Issue | Track | Current focus |
|---|---|---|
| [#140 docs: add phantom resource trust as next research contour](https://github.com/krivonosoff161/agentic-security-harness/issues/140) | Research map / phantom resources | Add hallucinated/model-generated resource trust as planned contour #8 while keeping the current seven-scenario trading-stand gate unchanged. |
| [#136 research: add trading-bot-v2 paper stand target profile](https://github.com/krivonosoff161/agentic-security-harness/issues/136) | Owned target / adapter research | Treat `trading-bot-v2` as an authorized paper-only target stand while keeping ASH as the security runner and evidence owner. |
| [#96 docs: harden public evidence boundary and showcase claims](https://github.com/krivonosoff161/agentic-security-harness/issues/96) | Showcase / evidence boundary | Make public local-model campaign evidence explicit about public fields, private raw calculations, response-hash anchors, validation checks, and non-claims. |
| [#87 docs: rebuild GitHub showcase and documentation map](https://github.com/krivonosoff161/agentic-security-harness/issues/87) | Showcase / documentation | Make the public README, evidence map, tracker, and status docs agree with the committed examples and current claim boundaries. |

## Open maintenance work

None currently tracked.

## Recently completed in this track

| Issue | Track | Delivered focus |
|---|---|---|
| [#92 research: add local swarm defense contour](https://github.com/krivonosoff161/agentic-security-harness/issues/92) | Local swarm / semantic defenses | `ash swarm-defense-contour` adds a four-family synthetic control-attribution layer across 15 scenario combinations, with bounded, naive, and ablation rows plus sanitized public artifacts. |
| [#94 research: add live mini-swarm defense campaign](https://github.com/krivonosoff161/agentic-security-harness/issues/94), [#100 deepen local mini-swarm defense evidence](https://github.com/krivonosoff161/agentic-security-harness/issues/100) | Local swarm / live model evidence | `ash swarm-defense-live-campaign` adds private local worker/chief probes over the four-family contour, with committed sanitized base, long-session, and deep multi-model metrics, replay-ablation attribution, Wilson intervals, model breakdowns, and raw transcripts kept under `.internal/`. |
| [#61 research: add bounded local swarm runner](https://github.com/krivonosoff161/agentic-security-harness/issues/61) | Local swarm / runtime | `ash local-swarm` compares monolith, naive swarm, and bounded swarm over deterministic local-swarm scenarios, with bounded contracts making the pass/block decision. |
| [#63 research: expand bounded local swarm evidence suite](https://github.com/krivonosoff161/agentic-security-harness/issues/63) | Local swarm / evidence | Committed `examples/local-swarm-report/` records the 15-scenario deterministic suite and validates with `ash validate examples/local-swarm-report`. |
| [#64 research: add local-swarm evidence-quality calculations](https://github.com/krivonosoff161/agentic-security-harness/issues/64) | Local swarm / evidence quality | `ash evidence-quality` summarizes recorded external/local artifacts for contract coverage, transcript hash coverage, adapter-error rates, runtime-mode coverage, and evidence maturity. |
| [#65 research: deepen local-swarm memory, tool, and multi-hop attacks](https://github.com/krivonosoff161/agentic-security-harness/issues/65) | Local swarm / deep variants | Deterministic memory-poisoning, tool-output authority-confusion, multi-hop laundering, verifier-outage, and executable deep invariant probes are represented in the local-swarm suite and variation matrix. |
| [#66 research: run local Prometheus swarm evaluation](https://github.com/krivonosoff161/agentic-security-harness/issues/66) | Local swarm / local empirical | Full 15-scenario local Ollama runs completed for `prometheus-qwen15b-lowctx:latest` and `qwen2.5:1.5b`; public docs classify the result as local empirical evidence-quality context, not model safety. |
| [#67 research: add local-swarm attack variation matrix](https://github.com/krivonosoff161/agentic-security-harness/issues/67) | Local swarm / attack matrix | `ash local-swarm-matrix` writes a deterministic 43-row attack variation matrix across 9 families, including 10 executable deep invariant probes. |
| [#80 research: live local-model secret-leak variation campaign](https://github.com/krivonosoff161/agentic-security-harness/issues/80) | Secret-egress / local empirical | `ash secret-leak-campaign --execute-variations` records private local-model pressure probes and writes sanitized public aggregates with raw prompts/responses kept under `.internal/`. |
| [#82 research: semantic parameter drift in local mini-swarm](https://github.com/krivonosoff161/agentic-security-harness/issues/82) | Semantic drift / local empirical | `ash semantic-drift-campaign` records deterministic and local-model semantic relabeling probes with public sanitized metrics and private raw transcripts/canaries. |
| [#19 feature: local Prometheus suite](https://github.com/krivonosoff161/agentic-security-harness/issues/19) | Local runtime | `ash local-suite` runs bounded named local-model profiles through the prompt-only OpenAI-compatible path; the low-context Prometheus profile is first-class, dry-run is the default, real runs validate artifacts, and weak evidence remains explicitly pass/finding/inconclusive/adapter_error. |
| [#20 feature: scenario timeline](https://github.com/krivonosoff161/agentic-security-harness/issues/20) | Corpus / multi-turn | `ScenarioTimeline` fixtures cover delayed activation, context overload, and handoff provenance; each has an invariant, deterministic validator expectation, and `replay_timeline()` shows the vulnerable finding/protected PASS decision step. |
| [#21 feature: trace replay and failure cards](https://github.com/krivonosoff161/agentic-security-harness/issues/21) | Reports | `ash showcase` generates artifact-driven failure cards with trace replay steps, trace/remediation artifact references, reproduce commands, and explicit non-claims; committed generated example is reproducible from `examples/demo-agent-report`. |
| [#29 fix: clarify external run diff status labels](https://github.com/krivonosoff161/agentic-security-harness/issues/29) | Reports / maintenance | Run-diff labels split decisive `finding_fixed`/`new_finding` from non-decisive `inconclusive_error_drift`/`stable_inconclusive`/`stable_error`; `error`/`adapter_error` transitions are never reported as security fixes. |
| [#25 docs: public evidence showcase](https://github.com/krivonosoff161/agentic-security-harness/issues/25) | Showcase | Public showcase entry point and evidence pages exist for reviewer navigation. |
| [#22 docs: metric contract](https://github.com/krivonosoff161/agentic-security-harness/issues/22) | Metrics | Stable vocabulary for GitHub traffic, benchmark evidence, runtime evidence, and project-process metrics. |
| [#23 feature: showcase generator](https://github.com/krivonosoff161/agentic-security-harness/issues/23) | Reports / automation | `ash showcase` generates reviewer-facing Markdown from JSON artifacts. |
| [#24 research: local model profiles](https://github.com/krivonosoff161/agentic-security-harness/issues/24) | Local runtime | Hardware-safe local model profiles and stop conditions are documented. |
| [#31 docs: correct inter-agent handoff research source map](https://github.com/krivonosoff161/agentic-security-harness/issues/31) | Standards / research | Broken citations fixed; adjacent work acknowledged; shipped-vs-planned claims kept conservative. |
| [#32 research: formalize handoff verifier decisions and risk scoring](https://github.com/krivonosoff161/agentic-security-harness/issues/32) | Multi-agent / reports | Deterministic blocker verdicts are separated from normalized severity scoring. |
| [#33 research: define minimal typed handoff envelope](https://github.com/krivonosoff161/agentic-security-harness/issues/33) | Multi-agent / recovery | Envelope fields and payload-type requirements are explicit before fixtures/tests are added. |
| [#30 research: design inter-agent handoff integrity contract](https://github.com/krivonosoff161/agentic-security-harness/issues/30) | Multi-agent / research | Design contract, claim boundary, failure classes, verifier outcomes, and staged work order are documented. |
| [#34 feature: add deterministic toy topology for handoff integrity](https://github.com/krivonosoff161/agentic-security-harness/issues/34) | Multi-agent / corpus | Local synthetic verifier topology ships vulnerable/protected handoff traces for label loss and authority expansion. |
| [#48 research: measure local small-model swarm evidence quality](https://github.com/krivonosoff161/agentic-security-harness/issues/48) | Local empirical / evidence quality | `ash evidence-quality` summarizes recorded external/local artifacts for schema adherence, raw-response/hash coverage, deterministic-validator agreement, inconclusive/error/flaky split, and cross-run disagreement without creating a model leaderboard. |
| [#50 research: rerun local Prometheus probes and publish evidence-quality summary](https://github.com/krivonosoff161/agentic-security-harness/issues/50) | Local runtime / evidence quality | Fresh bounded Prometheus/Ollama rerun recorded 11 local-model checks across `data-boundary`, `authority-control`, and `approval-audit`; docs summarize 3 pass, 8 inconclusive, 0 findings, and fresh-only evidence-quality metrics with raw responses kept local/private. |
| [#53 research: deepen authority delegation public evidence](https://github.com/krivonosoff161/agentic-security-harness/issues/53) | Multi-agent / authority | Authority delegation evidence now covers issuer, scope, purpose, TTL, and delegation-depth non-expansion in verifier tests and public theory docs; revocation remains explicitly out of scope. |
| [#54 research: publish inter-agent handoff toy evidence](https://github.com/krivonosoff161/agentic-security-harness/issues/54) | Multi-agent / handoff | `examples/handoff-toy-comparison/` is a committed public artifact for toy coordinator/worker handoff evidence, validated by `ash validate examples/handoff-toy-comparison`. |
| [#55 research: define memory-governance invariant layer](https://github.com/krivonosoff161/agentic-security-harness/issues/55) | Memory governance / theory | `memory_governance.py` adds executable synthetic checks for TTL-from-write, envelope drift, provenance metadata, trust floor, trust precedence, and scope isolation, with public theory docs and tests. |
| [#57 research: harden boundary layer evidence matrices](https://github.com/krivonosoff161/agentic-security-harness/issues/57) | Boundary-layer research | `boundary-layer-evidence-matrix.md` ties 22 declared handoff, authority, and memory-governance variation rows to executable tests while keeping private scratch calculations out of public evidence. |
| [#78 research: add synthetic secret-leak campaign](https://github.com/krivonosoff161/agentic-security-harness/issues/78) | Secret-egress / evidence | `ash secret-leak-campaign` adds 4 deterministic synthetic secret-egress topologies with naive, bounded, ablation, and benign modes; committed sanitized artifacts validate without raw canaries. |
| [#84 research: semantic drift propagation in worker-to-chief chains](https://github.com/krivonosoff161/agentic-security-harness/issues/84) | Semantic drift / local empirical | `ash semantic-propagation-campaign` adds deterministic and local-model worker-to-chief propagation probes, with public sanitized artifacts and private raw transcripts kept under `.internal/`. |

## Recently completed local research closures

These items close local research tasks that were not tracked as GitHub issues. They are
kept separate from the issue table so the public tracker does not imply that a GitHub
issue was closed when no issue number exists.

| Local task | Track | Delivered focus | Public evidence | Private/local note |
|---|---|---|---|---|
| DB-1 | Data boundary / theory | Formalized the envelope restriction relation `E_out <= E_in`, field-level non-expansion rules, and explicit non-claims. | `docs/theory/data-boundary.md`, `docs/research-claims.md`, documentation contract tests. | Owner-retained local derivation note; not committed and not public evidence. |
| DB-2 | Data boundary / corpus | Added `data_boundary_missing_envelope_recovery`, regenerated the then-current examples/golden snapshots, and updated external-run arithmetic. | `examples/comparison-report/`, `docs/showcase/generated/`, `tests/golden/`, `ash validate examples/`. | Owner-retained local verification checklist; not committed and not public evidence. |
| DB-3 | Data boundary / memory read boundary | Added `data_boundary_memory_envelope_drift`, implemented field-level envelope restriction checks, regenerated the 24-pattern examples/golden snapshots, and updated data-boundary theory/claims. | `src/agentic_security_harness/envelope_policy.py`, `tests/test_envelope_policy.py`, `examples/comparison-report/`, `docs/theory/data-boundary.md`, `ash validate examples/`. | Owner-retained local verification checklist; not committed and not public evidence. |
| SEM-1 | Semantic drift propagation | Closed the first semantic mini-swarm research unit: slow `A -> C` relabeling, worker-to-chief propagation, deterministic controls, ablation reopenings, local-model observations, and explicit non-claims. | `docs/semantic-drift-propagation-closure.md`, `examples/semantic-drift-sanitized/`, `examples/semantic-propagation-sanitized/`, `tests/test_semantic_drift_campaign.py`, `tests/test_semantic_propagation_campaign.py`. | Raw prompts, raw responses, synthetic canaries, canonical-state hashes, and calculation notes remain private under `.internal/`. |
| SEM-2 | Semantic consensus laundering | Closed the first consensus-laundering sub-unit: one poisoned worker plus one conservative worker cannot be averaged into acceptance when worker attestation, canonical state, cross-worker checks, and chief verification hold. | `docs/semantic-consensus-laundering-closure.md`, `examples/semantic-propagation-sanitized/`, `tests/test_semantic_propagation_campaign.py`. | This is a declared two-worker synthetic topology, not production swarm coverage or a model vulnerability claim. |
| SEM-3 | Local swarm defense contour | Added a four-family synthetic control-attribution layer for semantic drift, worker-to-chief propagation, consensus laundering, and benign-framed boundary leaks across all non-empty family combinations. | `docs/local-swarm-defense-contour.md`, `examples/swarm-defense-contour-sanitized/`, `tests/test_swarm_defense_contour.py`. | Raw local-model probes remain private; this is not production swarm coverage or a model vulnerability claim. |
| SEM-4 | Sanitized local-model mini-swarm campaign | Ran bounded private local worker/chief probes across the four-family contour and published sanitized model ids, topology ids, pressure labels, response-hash metrics, verifier block attribution, replay-ablation reopenings, adapter flags, long-session per-turn response hashes, Wilson intervals, and deep multi-model breakdowns. | `docs/live-mini-swarm-defense-campaign.md`, `docs/private-public-evidence-boundary.md`, `examples/swarm-defense-live-sanitized/`, `examples/swarm-defense-live-long-session-sanitized/`, `examples/swarm-defense-live-deep-sanitized/`, `tests/test_swarm_defense_live_campaign.py`. | Raw local-model prompts, responses, canaries, and calculation notes remain private; this is not a CVE, model leaderboard, or production swarm safety claim. |

Supporting docs:

- [metric-contract.md](metric-contract.md) defines how traffic, benchmark, runtime, and
  process metrics should be read.
- [inter-agent-handoff-integrity.md](inter-agent-handoff-integrity.md) defines the
  design-first track for provenance-preserving worker-to-senior agent handoffs.
- [handoff-toy-topology.md](handoff-toy-topology.md) documents the first shipped local
  synthetic verifier topology for malformed summary and capability handoffs.
- [research-claims.md](research-claims.md) tracks research claims from hypothesis
  through validated evidence artifacts.
- [semantic-drift-propagation-closure.md](semantic-drift-propagation-closure.md)
  closes the first semantic mini-swarm research unit.
- [semantic-consensus-laundering-closure.md](semantic-consensus-laundering-closure.md)
  closes the first consensus-laundering sub-unit over the existing propagation
  campaign artifact.
- [boundary-layer-evidence-matrix.md](boundary-layer-evidence-matrix.md) maps the current
  handoff, authority, and memory-governance variation rows to executable tests.
- [local-prometheus-workflow.md](local-prometheus-workflow.md) defines the low-memory
  Ollama smoke workflow for real local model probes.
- [local-swarm-real-model-evaluation.md](local-swarm-real-model-evaluation.md) records
  the full local Ollama `local-swarm` evaluation for Prometheus and qwen2.5.
- [local-model-profiles.md](local-model-profiles.md) records hardware-safe local model
  profiles and stop conditions.
- `ash evidence-quality --root reports --out reports/evidence-quality` summarizes
  evidence quality from recorded external/local/local-swarm artifacts without making
  model calls.
- [showcase/index.md](showcase/index.md) is the public evidence entry point.
- [scenario-investigation-workflow.md](scenario-investigation-workflow.md) keeps
  scenario design, weak spots, findings, and deepening variations separate.
- [scenario-timeline.md](scenario-timeline.md) defines the multi-turn timeline contract.
- [trading-bot-paper-stand-target-profile.md](trading-bot-paper-stand-target-profile.md)
  defines the authorized paper-only owned-system target profile for using
  `trading-bot-v2` as a realistic stand while ASH remains the security runner.
- [trading-bot-paper-stand-runner-design.md](trading-bot-paper-stand-runner-design.md)
  defines the harness-side runner modes, preflight gates, and evidence split
  required before any real paper-stand adapter work.
- [trading-bot-private-evidence-contract.md](trading-bot-private-evidence-contract.md)
  defines the ignored private evidence root, public derivative fields, manifest
  shape, and gate rules for future paper-only target runs.
- [trading-bot-private-invariant-fixture-contract.md](trading-bot-private-invariant-fixture-contract.md)
  defines the payload-free private fixture shape for the next paper-only
  adversarial/invariant layer over the seven mapped scenarios.
- [trading-bot-private-experiment-row-contract.md](trading-bot-private-experiment-row-contract.md)
  defines the stricter private filled-row contract for future real paper-only
  experiment observations: filled private slots, public evidence object,
  opaque condition id, and no control/baseline/template marker.
- [trading-bot-invariant-baseline-sanitized-summary-2026-07-03.md](trading-bot-invariant-baseline-sanitized-summary-2026-07-03.md)
  records the baseline artifact-schema fixture round-trip: 7 pass, 0 finding,
  0 inconclusive, 0 error, validation ok with 0 issues, and no payloads or
  private values included.
- [trading-bot-invariant-negative-control-sanitized-summary-2026-07-03.md](trading-bot-invariant-negative-control-sanitized-summary-2026-07-03.md)
  records the synthetic finding-path control: 0 pass, 7 finding, 0
  inconclusive, 0 error, validation ok with 0 issues, and no payloads or
  private values included. It is not a target finding.
- [trading-bot-invariant-weak-control-sanitized-summary-2026-07-03.md](trading-bot-invariant-weak-control-sanitized-summary-2026-07-03.md)
  records the synthetic inconclusive-path control: 0 pass, 0 finding, 7
  inconclusive, 0 error, validation ok with 0 issues, and no payloads or
  private values included. It is not a target pass or finding.
- [trading-bot-stand-inventory-2026-07-03.md](trading-bot-stand-inventory-2026-07-03.md)
  maps the current owned `trading-bot-v2` paper/research surface to ASH
  observation surfaces without reading secrets or private artifacts.
- [trading-bot-stand-scenario-catalog.md](trading-bot-stand-scenario-catalog.md)
  lists the seven public-safe scenario ids, observation surfaces, invariants,
  and evidence fields without payloads or private calculations.
- [trading-bot-static-probe-snapshot-2026-07-03.md](trading-bot-static-probe-snapshot-2026-07-03.md)
  records the first read-only target source-shape snapshot: 7 scenarios, target
  preflight ok, 3 fully anchored and 4 partial-marker scenarios, with no raw
  source text included.
- [trading-bot-boundary-lock-snapshot-2026-07-03.md](trading-bot-boundary-lock-snapshot-2026-07-03.md)
  records the pre-experiment boundary lock over allowlisted observation files:
  4 locked scenarios, 3 review-required scenarios, 4 secret-environment access
  markers, and 0 provider-call, Telegram-send, or live-order markers.
- [trading-bot-boundary-lock-review-2026-07-03.md](trading-bot-boundary-lock-review-2026-07-03.md)
  records the follow-up marker review: 2 documentation-only files, 1 bounded
  research-root configuration read, 0 secret env reads, 0 unknown env reads, 0
  provider-call sites, 0 Telegram-send sites, 0 live-order sites, and
  `blocking=false`; the remaining requirement is an explicit adapter contract.
- [trading-bot-partial-marker-sanitized-summary-2026-07-03.md](trading-bot-partial-marker-sanitized-summary-2026-07-03.md)
  records the first private-fixture-to-public-summary pass for the 4
  partial-marker scenarios: 0 pass, 0 finding, 4 inconclusive, 0 error.
- [trading-bot-artifact-probe-snapshot-2026-07-03.md](trading-bot-artifact-probe-snapshot-2026-07-03.md)
  records the first read-only artifact check against a separate private
  paper/research artifact root: target preflight ok, 6 existing artifacts
  and 6 schema-anchored artifacts, with no raw rows included.
- [trading-bot-artifact-partial-marker-sanitized-summary-2026-07-03.md](trading-bot-artifact-partial-marker-sanitized-summary-2026-07-03.md)
  records the superseded marker diagnostic: the 3 artifact partial-marker rows
  were caused by generic marker names and are now resolved by schema-key
  markers.
- [trading-bot-artifact-invariant-probe-snapshot-2026-07-03.md](trading-bot-artifact-invariant-probe-snapshot-2026-07-03.md)
  records the first schema-level invariant check over existing paper artifacts:
  7 scenarios mapped, 7 artifact-schema passes, 0 findings, 0 inconclusive, and
  0 errors, with no raw rows or private values included.
- [trading-bot-real-artifact-observation-2026-07-03.md](trading-bot-real-artifact-observation-2026-07-03.md)
  records the first public-safe observation over real existing paper artifacts:
  the chain is present and bounded, ASH `artifact-e2e-observation` reports
  13 artifact checks ok with `execution_boundary_ok=true`, `result_class=pass`,
  and no evidence-quality findings. Raw card text remains private.
- [trading-bot-controlled-experiment-plan-2026-07-03.md](trading-bot-controlled-experiment-plan-2026-07-03.md)
  records the next public-safe layer: three controlled 3-4 scenario paper
  batches over the seven mapped contours, with private evidence slots and no
  target execution. It also defines validation and sanitization for future
  filled private experiment rows.
- [trading-bot-experiment-control-sanitized-summary-2026-07-03.md](trading-bot-experiment-control-sanitized-summary-2026-07-03.md)
  records the first private experiment control round-trip: 7 scenarios, 0 pass,
  0 finding, 7 inconclusive, 0 error, validation ok with 0 issues, no target
  observation, and no raw private values.
- [trading-bot-experiment-baseline-sanitized-summary-2026-07-03.md](trading-bot-experiment-baseline-sanitized-summary-2026-07-03.md)
  records the first observed private experiment baseline round-trip: 7
  scenarios, 7 pass, 0 finding, 0 inconclusive, 0 error, validation ok with 0
  issues, target observation from existing paper artifacts, and no raw private
  values.
- [trading-bot-experiment-negative-control-sanitized-summary-2026-07-03.md](trading-bot-experiment-negative-control-sanitized-summary-2026-07-03.md)
  records the first private experiment finding-path control round-trip: 7
  scenarios, 0 pass, 7 finding, 0 inconclusive, 0 error, validation ok with 0
  issues, no target observation, and no raw private values.
- [trading-bot-experiment-batch-manifest-summary-2026-07-03.md](trading-bot-experiment-batch-manifest-summary-2026-07-03.md)
  records the private batch-manifest guard: 7 scenarios, 3 controlled batches,
  max parallel 4, validation ok with 0 issues, and no env/live/provider/Telegram
  boundary crossing.
- [trading-bot-experiment-intake-gate-summary-2026-07-03.md](trading-bot-experiment-intake-gate-summary-2026-07-03.md)
  records the filled-row intake gate: the observed baseline fixture is
  structurally valid but blocked from promotion because it has 0 real filled
  target-observation rows.
- [trading-bot-experiment-readiness-snapshot-2026-07-03.md](trading-bot-experiment-readiness-snapshot-2026-07-03.md)
  records the current pre-experiment gate: target preflight, artifact-chain,
  execution-boundary, evidence-quality, control-fixture, provider-boundary, and
  live-boundary all pass; readiness is `ready` for private filled experiment
  rows.
- `ash trading-stand --mode offline-fixture` maps sanitized stand-shaped controls
  into `pass`, `finding`, `inconclusive`, and `error` without touching the target.
- `ash trading-stand --mode scenario-catalog` prints the public-safe scenario
  metadata that future private fixtures must map to.
- `ash trading-stand --mode fixture-template --fixture-path <private-json>` writes
  the 7-row private fixture skeleton only under the ignored evidence root.
- `ash trading-stand --mode invariant-fixture-template --fixture-path
  <private-json>` writes the payload-free 7-row private invariant fixture
  skeleton only under the ignored evidence root.
- `ash trading-stand --mode invariant-baseline-fixture --target-path
  <trading-bot-v2> [--artifact-root <private-paper-root>] --fixture-path
  <private-json>` writes a private baseline fixture from the artifact-invariant
  probe result.
- `ash trading-stand --mode invariant-negative-control-fixture --fixture-path
  <private-json>` writes a payload-free synthetic finding control fixture under
  the ignored evidence root.
- `ash trading-stand --mode invariant-weak-control-fixture --fixture-path
  <private-json>` writes a payload-free synthetic inconclusive control fixture
  under the ignored evidence root.
- `ash trading-stand --mode validate-invariant-fixture --fixture-path
  <private-json>` checks private invariant fixtures for full seven-scenario
  coverage and result/boundary consistency before sanitization.
- `ash trading-stand --mode sanitize-fixture --fixture-path <private-json>` reads
  owner-retained private fixture rows and emits only approved public fields plus
  hash anchors.
- `ash trading-stand --mode static-probe --target-path <trading-bot-v2>` reads
  only scenario-catalog observation files and emits file hashes plus marker
  booleans, not raw source text.
- `ash trading-stand --mode boundary-lock --target-path <trading-bot-v2>` reads
  only scenario-catalog observation files and emits boundary marker counts plus
  hashes, not raw source text.
- `ash trading-stand --mode boundary-lock-review --target-path <trading-bot-v2>`
  reviews only boundary-lock-marked files and emits marker classifications,
  counts, and hashes without source lines or private values.
- `ash trading-stand --mode artifact-probe --target-path <trading-bot-v2>
  [--artifact-root <private-paper-root>]` reads only allowlisted paper artifact
  paths and emits existence/count/hash/marker summaries, not raw rows.
- `ash trading-stand --mode artifact-invariant-probe --target-path
  <trading-bot-v2> [--artifact-root <private-paper-root>]` maps those artifacts
  to the seven scenario invariants using schema keys, booleans, and hashes only.
- `ash trading-stand --mode artifact-e2e-observation --target-path
  <trading-bot-v2> --artifact-root <private-paper-root>` summarizes the
  allowlisted real paper-chain artifacts, execution-boundary booleans, and
  evidence-quality findings without raw rows, raw card text, or private values.
- `ash trading-stand --mode experiment-plan --target-path <trading-bot-v2>
  [--artifact-root <private-paper-root>]` prepares the controlled parallel
  paper experiment plan without target execution or payloads.
- `ash trading-stand --mode experiment-template --fixture-path <private-json>`
  writes the payload-free private experiment skeleton under the ignored evidence
  root.
- `ash trading-stand --mode experiment-baseline-fixture --target-path
  <trading-bot-v2> [--artifact-root <private-paper-root>] --fixture-path
  <private-json>` writes observed private baseline rows from existing artifact
  invariants.
- `ash trading-stand --mode experiment-negative-control-fixture --fixture-path
  <private-json>` writes payload-free synthetic finding-path rows for the
  experiment sanitizer/validator path.
- `ash trading-stand --mode experiment-control-fixture --fixture-path
  <private-json>` writes the not-executed, all-inconclusive control fixture for
  validation/sanitization round-trips.
- `ash trading-stand --mode experiment-batch-manifest --fixture-path
  <private-json>` writes the private 3-batch scheduling guard under the ignored
  evidence root.
- `ash trading-stand --mode validate-experiment-batch-manifest --fixture-path
  <private-json>` checks the private batch guard for scenario coverage, batch
  placement, max parallel limits, and stop gates.
- `ash trading-stand --mode experiment-intake --fixture-path <private-json>
  --manifest-path <private-json>` gates private filled rows before public
  sanitization and blocks baseline/control/template row sets.
- `ash trading-stand --mode experiment-readiness --target-path <trading-bot-v2>
  [--artifact-root <private-paper-root>] [--fixture-path <private-json>]`
  evaluates whether artifact, control, safety, and evidence-quality gates allow
  filled private experiment rows.
- `ash trading-stand --mode validate-experiment --fixture-path <private-json>`
  checks filled private experiment rows for seven-scenario coverage, expected
  batch ids, valid result classes, hash anchors, private slots,
  real-observation private-slot completeness, public evidence object,
  condition id, and ignored-root placement.
- `ash trading-stand --mode sanitize-experiment --fixture-path <private-json>`
  emits public-safe experiment summaries without raw vectors, agent scripts,
  target rows, traces, or private calculations.
- `ash trading-stand --mode authorized-paper --target-path <trading-bot-v2>
  --artifact-root <private-paper-root> --fixture-path <private-json>
  --manifest-path <private-json>` evaluates the non-executing authorization
  gate for controlled paper experiments. It reports `accepted` only when
  target preflight, artifact readiness, private fixture validation,
  batch-manifest validation, explicit owner/run approval, and
  no-live/no-provider/no-Telegram boundaries all pass. Without the private
  bundle it remains fail-closed.
- `ash showcase --root reports --out docs/showcase/generated` generates a Markdown
  reviewer view from run artifacts.

## How to read labels

| Label family | Meaning |
|---|---|
| `type:*` | Work type: docs, feature, research, test, infra, security. |
| `area:*` | Project area: reports, corpus, local runtime, adapters, multi-agent, recovery path, standards mapping. |
| `priority:*` | Scheduling priority, not severity of a vulnerability. |
| `status:*` | Current implementation state: ready, needs design, experimental, blocked. |
| `showcase` | Work that directly improves public first-impression evidence. |

For LLM/code agents: do not infer capability from an open issue. Shipped capability is
documented in [current-state.md](current-state.md) and [capability-matrix.md](capability-matrix.md).

## Traffic metrics vs benchmark evidence

GitHub traffic graphs are useful, but they do not prove benchmark quality.

| Metric family | Examples | What it means | What it does not mean |
|---|---|---|---|
| GitHub traffic | clones, unique cloners, views, visitors | People or tools are looking at the repository. | The benchmark is correct, reproducible, or trusted. |
| Benchmark evidence | scenario count, run count, findings, inconclusive checks, validator coverage | What the harness actually measured and validated. | A target is secure in production. |
| Runtime evidence | model, runtime, local-only flag, raw responses, repeats, recovery path | How a real or fake runtime was exercised. | A leaderboard-grade model comparison. |
| Project process | open issues by milestone, labels, status, PRs, CI | Whether work is visible and reviewable. | That every planned feature is shipped. |

## Correct order of work

1. Keep the GitHub tracker honest: every large idea becomes an issue with labels,
   milestone, scope, non-goals, and exit gate.
2. For new methodology tracks such as inter-agent handoff integrity, write the design
   track and exit gates before adding code or corpus cases.
3. Build the evidence showcase from existing deterministic artifacts first.
4. Keep local Prometheus/model-in-loop probes bounded: named profiles, request caps,
   dry-run first, validated artifacts, and explicit weak-evidence interpretation.
5. Generate failure cards and metrics from artifacts. Do not hand-write conclusions that
   are stronger than the trace/scorecard data.
6. Only then expand scenario timelines and local model profiles.

## Local verification before claiming progress

For docs-only tracker updates:

```bash
python -m pytest tests/test_documentation_contract.py
python -m ruff check .
git diff --check
```

For evidence/showcase code:

```bash
python -m pytest
ash validate examples/
ash compare --baseline demo-agent --protected protected-demo-agent --out reports/comparison
ash validate reports/comparison
```

## Claim boundary

Allowed:

> The project publicly tracks the next evidence/showcase and local-runtime work through
> GitHub Issues and milestones, with exit gates tied to validated artifacts.

Not allowed:

- claiming local real-model probes are benchmark-grade or general model-safety evidence;
- treating GitHub clone/view spikes as benchmark validation;
- presenting weak local model runs as a universal model-safety conclusion;
- presenting manually written showcase text as evidence without trace/scorecard links.
