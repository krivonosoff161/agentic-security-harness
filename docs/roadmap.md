# Roadmap

Harness-first and trace-first. Versioning is feature-gated, not date-gated; each version
is shippable. Built-in/local targets are local, deterministic, and synthetic: no network,
no provider calls, no real secrets. The experimental `run-external` path makes
OpenAI-compatible calls only on explicit opt-in (prompt-only); native provider and
agent-host adapters are future.

---

## Done

- **v0.1 - harness core:** models, runner, scorecard, mock target.
- **v0.2 - demo CLI + local demo-agent:** `ash run`, deterministic reports, committed examples.
- **v0.3 - protected replay:** protected-demo-agent, `ash compare`, measured risk reduction 7 -> 0.
- **v0.4 - expanded local corpus:** 7 deterministic seed patterns, corpus manifest
  (`corpus.py`), coverage matrix ([docs/corpus.md](corpus.md)).
- **v0.5 - validation layer:** `ash validate`, benchmark-artifact validation, corpus
  consistency checks.
- **v0.6 - corpus expansion (first slice):** sleeping-prompt delayed activation,
  audit / spam-label abuse, budget / loop abuse - 10 deterministic patterns total.
- **v0.7 - authority and integrity slice:** capability delegation-chain drift,
  mock MCP / tool-schema deception, and hash-chain audit tamper detection - 13
  deterministic patterns total.
- **v0.8 - perception boundary and ambient authority slice:** perception-boundary
  sensor-command confusion, ambient authority escalation, approval laundering,
  and memory governance - 17 deterministic patterns total.
- **v0.8.x - adapter/report foundation:** target metadata contract models and
  lightweight `executive.md` report artifact for deterministic runs.
- **v0.9 - corpus deepening slice:** environment-injected memory poisoning,
  unintentional cross-user contamination, recursive execution amplification,
  tool-selection manipulation, multi-turn indirect instruction escalation -
  24 deterministic patterns total.
- **v0.10 - remediation layer and report depth:** structured control
  recommendations (`ControlRecommendation` model), `remediation.json` and
  `remediation.md` artifacts, executive report integration, remediation
  validation in `ash validate`.
- **v0.11 - product maturity:** external OpenAI-compatible model path with preflight,
  cost cap, control recommendations, and connector recipes
  ([docs/connect-models.md](connect-models.md)); run history manifests
  (`run_index.json`) with `ash list-runs` and manifest validation; getting-started
  guide; cross-platform CI (Ubuntu + Windows, Python 3.11-3.13).
- **v0.12 - report/product depth:** static HTML reports with coverage heatmap
  (`ash report`); onboarding diagnostics (`ash doctor`); toy adapters (`toy-rag`,
  `toy-tools`) with a three-tier validation model (baseline/protected/neutral);
  adapter metadata + explicit stochastic repeat status for external runs; category-level
  OWASP LLM / NIST standards mapping with a validation self-check; release checklist.
- **v0.13 - schema, diff, presets, and packaging readiness:** schema-version registry,
  `ash diff-runs`, HTML report v2, external connection presets, doctor v2, local SQLite
  run metadata index, Dockerfile/devcontainer, and PyPI release notes.
- **Post-v0.13 governance and evidence hardening on `main`:** GitHub issue/PR templates,
  CODEOWNERS, Dependabot, CodeQL, Scorecard, release-artifact workflow, governance files,
  external raw-response evidence files, pattern-level external cross-checks,
  `compare-models`, `stats`, `retention`, JSON output options, and golden external
  artifact snapshots. These are in `CHANGELOG.md` under `Unreleased` until the next tag.
- **Post-v0.13 local multi-agent handoff slice:** `toy-multi-agent` adds a deterministic
  coordinator/worker target for data-label handoff and capability-delegation drift traces
  without provider calls, live tools, or network access.
- **Post-v0.13 evidence and semantic-pressure campaigns:** local-swarm, attack-matrix,
  evidence-campaign, secret-egress, semantic-drift, and semantic-propagation artifacts
  are shipped as research slices with sanitized public summaries and private raw
  local-model calculations under `.internal/`.

---

## Current active focus

The next work is ordered by credibility, not by feature volume:

1. **Keep public status synchronized:** maintain
   [current-state.md](current-state.md), this roadmap, the capability matrix, and the
   README so reviewers can see what is shipped, experimental, planned, and out of scope.
   Active public work is tracked in [project-tracker.md](project-tracker.md) and GitHub
   milestones; open issues are not shipped capability.
2. **Document official/authorized testing paths:** keep
   [authorized-testing-paths.md](authorized-testing-paths.md) aligned with the security
   policy, adapter contract, provider-safe wording, and local-runtime guidance.
3. **MITRE ATLAS upkeep + pattern versioning:** keep asserted technique ids checked
   against the official ATLAS release; add a severity-rationale and pattern-version policy.
4. **Cross-app contamination and audit context split:** implement only after each pattern
   proposal states the invariant, topology, trace evidence, protected control, and
   residual risk.
5. **Public evidence showcase upkeep:** keep README, `docs/showcase/evidence-map.md`,
   examples, and claim registries synchronized so front-page metrics match committed
   artifacts.
6. **Multi-agent handoff expansion:** keep the shipped `toy-multi-agent` slice current,
   then add only reviewed handoff patterns with explicit invariants, trace evidence, and
   safety gates.
7. **Local-runtime evidence upkeep:** keep the Ollama / LM Studio / vLLM prompt-only path
   explicit in artifacts, including model-license notes, `local-only` mode, and recovery
   guidance.
8. **Recovery-path corpus design:** `recovery.trust_gate_no_path` is designed in the
   corpus expansion plan; implementation must stay deterministic and avoid provider-
   specific appeal workflows.
9. **v1.0 stable benchmark release:** stable trace schema, stable corpus manifest, stable
   CLI, validated examples, coherent docs, public tag (see
   [release-checklist.md](release-checklist.md)).

---

## Project tracks

The current release-facing track is **Agentic Security Harness**: a public research
benchmark with synthetic targets, traces, scorecards, validators, and sanitized evidence.

The related **LLM Safety Gateway / Runtime Verifier** direction is a future track, not a
shipped runtime. It would apply harness evidence at organization boundaries such as LLM
traffic, tool calls, file writes, git operations, source provenance, consent receipts, and
privacy-preserving evidence. Keep it documented separately until it has its own design
review, trust-domain model, and implementation boundary. See
[project-tracks.md](project-tracks.md).

---

## Future tracks / not part of the current benchmark release

These are not implemented in the current benchmark release. Some may proceed as a
separate repository or separate track before benchmark v1.0, but they stay out of the
shipped benchmark scope until they have their own design review and release boundary:

- **Reference gateway / LLM Safety Gateway** - a planned optional defense/runtime track
  for risk-reduction replay and organizational LLM-use controls.
- **Native provider adapters** - first-class SDK adapters (Anthropic, OpenAI Responses,
  Google, etc.) beyond the current OpenAI-compatible path.
- **Agent-host / tool-use adapters** - drive an authorized live agent that actually calls
  tools, instead of prompt-only model evaluation.
- **Real LLM adapters** - drive authorized live agents instead of local synthetic targets.
- **Multimodal / audio-ASR** - sanitized, pre-recorded ASR / OCR fixtures for the
  sensor-to-agent path.
- **Web report viewer / dashboard** - an interactive viewer over run manifests. The
  shipped `ash report` is a single static HTML file per run; a multi-run dashboard is
  future.
- **Richer report visualisations** - beyond the shipped static HTML + coverage heatmap:
  trend views across runs, interactive filtering, and severity drill-downs. Markdown/JSON
  remain the source of truth.
- **Persistent result database** - durable run/trace store (e.g. Postgres) after the
  file-based `run_index.json` + hash-chain story is proven.
- **Published Docker image** - the repository has a Dockerfile and devcontainer; publishing
  official images is future.
- **PyPI publication** - package build docs exist; publishing wheels remains future once
  the CLI and trace schema are stable.
- **Deeper scenario corpus expansion** - more boundary families and variants.
- **Agentic topology expansion** - model chains, router/filter/validator paths,
  cross-provider handoff, and recovery-path patterns selected by invariant, not full
  combinatorial sweep.
- **Benchmark leaderboard** - only after the evaluation methodology stabilizes (no
  cross-model scoreboard until results are reproducible and fair).

---

## Honest gap lists

Captured but intentionally not built yet:

- [independent-benchmark-gap-list.md](independent-benchmark-gap-list.md) - onboarding/UX,
  reporting, and reproducibility gaps for a fully self-serve module.
- [benchmark-positioning-gap-list.md](benchmark-positioning-gap-list.md) - where we win
  and lag versus common open eval/red-team toolkits.

## A note on self-learning

The harness does not self-learn. It never mutates its own patterns, thresholds, or
detectors at runtime. Findings and reviewed results produce labels that are stored only;
any adaptive rules built from them are a future, explicitly human-reviewed step. A security
tool that silently rewrites itself is hard to audit - predictability is a feature.
