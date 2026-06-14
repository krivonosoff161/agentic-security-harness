# Roadmap

Harness-first and trace-first. Versioning is feature-gated, not date-gated; each version
is shippable. Everything is local, deterministic, and synthetic: no network, no LLM or
provider calls, no real targets, no real secrets.

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

---

## Next

- **v0.10.x - cross-app contamination and audit context split:** cross-surface data
  instruction contamination and action-audit divergence tests.
- **v0.10 - local adapter examples:** toy RAG app, toy MCP server, toy multi-agent handoff.
  Still local / synthetic only.
- **v0.11 - report quality:** better Markdown / HTML audit report, coverage heatmap,
  standards matrix, mitigation checklist, before/after score.
- **v0.11.x - adapter contract hardening:** adapter metadata emission, stochastic-run
  reporting rules, and local toy adapter examples before real providers.
- **v0.12 - mapping and standardization:** OWASP LLM mapping, MITRE ATLAS mapping, severity
  rationale, pattern versioning policy.
- **v1.0 - stable benchmark release:** stable trace schema, stable corpus manifest, stable
  CLI, validated examples, coherent docs, public tag.

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
- **Web report viewer / dashboard** - optional static viewer over run manifests; the
  current product surface is CLI + Markdown/JSON only.
- **Richer HTML reports + coverage heatmaps** - stdlib-only static HTML rendering, kept
  out of the core until it earns its complexity; Markdown remains the source of truth.
- **Persistent result database** - durable run/trace store (e.g. Postgres) after the
  file-based `run_index.json` + hash-chain story is proven.
- **Docker / devcontainer** - reproducible container image for the toolkit.
- **PyPI / package release flow** - tagged releases and published wheels once the CLI and
  trace schema are stable.
- **Deeper scenario corpus expansion** - more boundary families and variants.
- **Benchmark leaderboard** - only after the evaluation methodology stabilizes (no
  cross-model scoreboard until results are reproducible and fair).

---

## A note on self-learning

The harness does not self-learn. It never mutates its own patterns, thresholds, or
detectors at runtime. Findings and reviewed results produce labels that are stored only;
any adaptive rules built from them are a future, explicitly human-reviewed step. A security
tool that silently rewrites itself is hard to audit - predictability is a feature.
