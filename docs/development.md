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

The project is built around two protocols so contributors can extend it without touching
the core pipeline.

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
