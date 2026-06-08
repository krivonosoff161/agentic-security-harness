# Development

> Product name TBD. This describes how the project is built and extended.

## Setup

```bash
git clone <repo>
cd ai-security-gateway
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"        # add ,pii for optional Presidio-based PII
```

## Quality gates

```bash
ruff check . && ruff format --check .
mypy app                       # strict on app/core and app/scanners first
pytest                         # provider always mocked in CI — no real API calls
```

CI runs ruff + mypy + pytest on Python 3.11 and 3.12. The **attack corpus**
(`tests/attacks/`) must pass. Detector precision/recall — **including the false-negative
rate** — is recorded per release; do not hide misses.

## Test layout

- `tests/unit/` — scanners, detectors, policy precedence, redaction.
- `tests/integration/` — proxy passthrough, error shapes, quarantine flow (provider mocked).
- `tests/attacks/` — versioned red-team corpus: direct / base64 / zero-width / homoglyph
  injections, PII, secrets, plus a benign control set. New attacks are added here first.

## Extension points

The project is built around a few small protocols so contributors can extend it without
touching the core runner.

### Add an attack chain (defensive test pattern)

Add a **sanitized** pattern to the attack library (seeded from `tests/attacks/`): expected
vulnerable behavior, mitigation, and OWASP / MITRE-style mapping. New detection work starts
with a failing pattern here. Payloads stay sanitized — synthetic markers, never real secrets.

### Add a target adapter

Implement the target-adapter contract (drive a system under test, return observations the
runner records into a trace): LLM agent, MCP / tool chain, multi-agent workflow,
voice / multimodal (sanitized ASR/OCR fixtures), or an AI gateway.

### Add a trace detector / oracle

A detector decides whether an observation is a finding. Keep it deterministic; it returns
findings, it does not mutate state.

### Add a scanner

Implement the `Scanner` protocol (`scan(...) -> list[Finding]`) and register it. Keep
scanners **deterministic and fast**; anything LLM-backed goes behind the classifier path
with a circuit breaker and cache. A scanner returns findings; it does **not** decide —
the policy engine owns the decision.

### Add a provider adapter

Implement the `ProviderAdapter` protocol: translate a canonical request to the provider
call and the provider response back to canonical. Isolate provider quirks here so the
rest of the pipeline stays provider-agnostic.

## Conventions

- Style: PEP 8; snake_case functions, PascalCase classes.
- Imports: stdlib → third-party → local, separated by blank lines.
- Small, single-purpose functions.
- Commits: conventional style (`feat:`, `fix:`, `docs:`, `test:`…), one logical change each.
- No application secrets in code or config; provider keys come from env only.

## Design rules

- The simple path needs **zero extra services** (SQLite, no Redis, no classifier).
- The system prompt is **not** a security boundary — never store secrets there
  ([why](threat-model.md#why-the-system-prompt-is-not-a-security-boundary)).
- No self-learning: rules do not mutate at runtime; feedback labels are collected for
  future human-reviewed adaptive rules only.
- **Study, don't copy.** We may study and cite other open-source projects, but do not copy
  code blindly — respect licenses, cite sources, and implement our own minimal, compatible
  adapters / tests.
- **Responsible use:** patterns are sanitized and run only against mock / authorized
  targets ([policy](../SECURITY.md#responsible-use)).
