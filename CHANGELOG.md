# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
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

### Notes
- The `v0.1` harness core (code) is implemented — see *Added*. Next milestones (real target
  adapters, MCP, multi-agent, multimodal, reference gateway) are in
  [docs/roadmap.md](docs/roadmap.md).
