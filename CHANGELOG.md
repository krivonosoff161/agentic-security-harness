# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- GitHub Actions CI for `pytest`, `ruff`, `mypy`, and `ash validate examples/` on Python
  3.11 and 3.12.
- **Validation layer + `ash validate`** (v0.5): `src/agentic_security_harness/validation.py`
  validates report dirs (traces / scorecard / summary), comparison dirs (baseline / protected
  + comparison.md), and corpus consistency against the manifest, with a conservative
  forbidden-marker scan and a structured `{ok, errors, warnings}` result. `ash validate
  examples/` runs as a benchmark check. Deterministic, stdlib + Pydantic only, no new deps.
- **Corpus manifest + coverage matrix:** `src/agentic_security_harness/corpus.py` (curated
  machine-readable metadata for the 7 implemented patterns) and `docs/corpus.md`; plus a
  `NOTICE` file.
- Expanded the local defensive corpus to **7 deterministic seed patterns** (v0.4): added
  data-boundary classification mutation, handoff label stripping, tool-permission abuse, and
  provider-boundary leakage (sanitized) on top of the original three. The vulnerable
  `demo-agent` and `mock` fail all 7; `protected-demo-agent` passes all 7; `ash compare` now
  shows findings reduced 7 -> 0. Committed examples regenerated. Local, no network, sanitized.
- Protected **demo-agent** target + risk-reduction comparison (v0.3): a
  `protected-demo-agent` (the same local agent with simple deterministic controls that
  mitigate the three seed patterns -> PASS) and an `ash compare --baseline ... --protected
  ... --out ...` command that writes `baseline/`, `protected/`, and a `comparison.md`
  showing the reduction in findings. Committed examples under
  `examples/protected-demo-agent-report/` and `examples/comparison-report/`. Local,
  deterministic, no network, sanitized data only.
- Local **demo-agent** target (v0.2): a deterministic, synthetic local agent (in-memory
  memory, mock tool calls, data-envelope propagation, recipient-control checks) exposed via
  a target adapter; `ash run --target demo-agent --out <dir>`; committed example under
  `examples/demo-agent-report/`. No network, no LLM, sanitized data only.
- Demo CLI (`ash`) and deterministic report artifacts: `ash run --target mock --out <dir>`
  writes `traces.json`, `scorecard.json`, and `summary.md`; a curated example is committed
  under `examples/demo-report/`. Mock-only, no network.
- v0.1 harness core scaffold (code): Pydantic v2 models (`DataEnvelope`, `Finding`,
  `TraceStep`, `TargetDescriptor`, `ExploitTrace`, `DefensivePattern`), three sanitized seed
  patterns, a deterministic mock target, the runner (`pattern -> trace`), and the scorecard —
  with unit tests. No LLM, network, gateway, or CLI.
- Education + safe-research docs: `docs/mission.md`, `docs/research-rules.md`, and learning
  modules (`docs/learning/01-agentic-security-basics.md`,
  `docs/learning/02-data-boundary-failures.md`); README "Mission", "Safe research rules",
  and "What exists today" sections.
- Project blueprint and documentation set: README, harness (flagship), problem–solution
  catalog, architecture, roadmap, threat model, API reference, deployment, development, and
  competitive-landscape docs.
- Apache-2.0 license, contribution guidelines, and security disclosure policy.
- Competitive landscape (all listed tools) and OWASP claims verified against primary
  sources with inline links — incl. Trylon Gateway (closest prior art), LiteLLM
  guardrails, Guardrails AI, NeMo Guardrails, LLM Guard, Presidio, Lakera; Rebuff
  archived; Protect AI acquired by Palo Alto Networks; Prompt Security intent-to-acquire
  by SentinelOne; OWASP LLM Top 10 2025 numbering.

### Changed
- Strengthened public positioning and attribution: named **Agentic Security Harness**
  (dropped "Product name TBD" headers), replaced "no uniqueness claims" headlines with
  confident honest wording (not first/only; competes on trace portability, corpus clarity,
  data-boundary measurement, and deterministic replay), README now leads as a trace-first
  defensive benchmark, and added a Brand-and-attribution section.
- Repositioned the project as an **Agentic Security Harness** — an open-source harness for
  reproducible, portable agentic exploit **traces**, an **attack graph**, and a
  **scorecard**. The OpenAI-compatible gateway is now the **reference defense** component,
  not the main product. Added an **agentic data-boundary / recipient-control** class (data
  envelope) and a sanitized **multimodal / sensor-to-agent (audio → ASR)** class, a new
  **problem–solution catalog**, and a **responsible-use** policy. Renamed the repository to
  `agentic-security-harness`.
- Softened public positioning to a **defensive education + measurement lab** — the repo
  description and README lead now read "agentic AI failure modes" rather than "exploit
  chains" (no functional change).

### Docs
- Clarified current-vs-planned boundaries in README and gateway-related docs: the current
  release is CLI-only with local synthetic targets; the reference gateway/API remain
  planned design, not shipped runtime.
- Realigned the documentation set with the v0.5 benchmark roadmap and current project
  structure (roadmap, development, architecture, harness, deployment, threat-model,
  api-reference, CONTRIBUTING). Removed stale gateway-era references (`tests/attacks`,
  `tests/unit`, `tests/integration`, `mypy app`) and reframed the reference gateway and real
  adapters as planned/future. Synced the quality gates to `pytest` / `ruff` / `mypy` /
  `ash validate`.

### Fixed
- **Comparison reduction line uses a signed delta** (surfaced by the v0.5 validator):
  `build_comparison_md` now formats the findings delta as a single signed quantity
  (`(-7)` / `(+3)` / `(+0)`) instead of a literal `-` prefix that produced a malformed
  `(--3)` when the protected target had *more* findings than baseline. The validator parses
  the signed value, so producer and validator stay in lockstep. Committed examples are
  byte-identical (the normal baseline-vs-protected case still reads `(-7)`).

### Notes
- The `v0.1` harness core (code) is implemented — see *Added*. Next milestones are corpus
  expansion, local adapter examples, report quality, mapping/standardization, and a stable
  benchmark release; real adapters/reference gateway remain future tracks. See
  [docs/roadmap.md](docs/roadmap.md).
