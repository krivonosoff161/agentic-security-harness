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
  22 deterministic patterns total.
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

---

## Next

- **Methodology and topology governance:** keep the boundary model,
  [evaluation topologies](evaluation-topologies.md), and
  [corpus expansion plan](corpus-expansion-plan.md) current before adding more patterns.
- **Cross-app contamination and audit context split:** cross-surface data-instruction
  contamination and action-audit divergence tests, after pattern proposals pass the
  invariant/topology review.
- **Toy multi-agent handoff adapter:** a coordinator/worker delegation surface, adding to
  the shipped toy adapters (`toy-local-function`, `toy-rag`, `toy-tools`).
- **MITRE ATLAS verification + pattern versioning:** verify ATLAS technique ids against
  the official matrix (currently deferred), add a severity-rationale and pattern-version
  policy. A mitigation checklist artifact can follow the standards mapping.
- **v1.0 - stable benchmark release:** stable trace schema, stable corpus manifest, stable
  CLI, validated examples, coherent docs, public tag (see
  [release-checklist.md](release-checklist.md)).

---

## Future tracks / not part of the current benchmark release

These come after v1.0 and are not implemented today. They stay out of the benchmark
release scope until the core above is stable:

- **Reference gateway** - a planned optional defense target for risk-reduction replay.
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
- **Docker / devcontainer** - reproducible container image for the toolkit.
- **PyPI / package release flow** - tagged releases and published wheels once the CLI and
  trace schema are stable.
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
