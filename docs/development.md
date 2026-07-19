# Development

> **Agentic Security Harness.** This describes how the project is built and extended.

## Setup

```bash
git clone <repo>
cd agentic-security-harness
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Quality gates

```bash
python -m pytest
python -m ruff check .
python -m mypy src tests tools
ash validate examples/
git diff --check
```

Run these gates locally on Python 3.11+ before every commit. The 24-pattern corpus and
the full test suite must pass. The false-negative count (patterns a target fails to
defend) is recorded honestly per release; do not hide misses.

## Test layout

Shared fixtures live in `tests/conftest.py`. Each module under test has a matching
test file:

- `tests/test_models.py` - Pydantic v2 models.
- `tests/test_runner.py` - pattern -> target -> trace runner.
- `tests/test_scorecard.py` - scorecard scoring.
- `tests/test_cli.py` - the `ash` CLI commands.
- `tests/test_demo_agent.py` - the vulnerable-by-design demo agent.
- `tests/test_protected.py` - the protected demo agent (passes all 24).
- `tests/test_corpus.py` - corpus manifest consistency.
- `tests/test_reporting.py` - report generation.
- `tests/test_validation.py` - the `ash validate` checks.

## Extension points

The project is local, deterministic, and synthetic - no network, no LLM calls, no real
targets, no real secrets. These extension points keep that design.

### How to add a pattern

A pattern is a sanitized defensive test case. Adding one touches a fixed set of files:

1. Add the pattern in `patterns.py` (expected vulnerable behavior and mitigation).
   Use synthetic markers, never real secrets.
2. Add the vulnerable primitive in `demo_agent.py` (the behavior the pattern exercises).
3. Wire the scenario in `demo_adapter.py` so the runner can drive it.
4. Add the protected override in `protected_demo_agent.py` so the protected target defends.
5. Add the mock outcome in `mock_target.py`.
6. Add a corpus entry in `corpus.py` (keep the manifest consistent with `docs/corpus.md`).
   Add standards mappings only after checking the current primary source; leave a field
   empty rather than guessing.
7. Add tests for the new behavior.
8. Regenerate the committed examples under `examples/`.
9. Run `ash validate examples/` to confirm artifacts and corpus stay consistent.

Before adding a pattern, write or update the proposal in the format from
[project-map.md](project-map.md#how-to-add-a-new-research-idea-safely). New patterns must
be selected by boundary invariant and representative topology, not by a full cross-product
of model/provider/framework variants. See [corpus-expansion-plan.md](corpus-expansion-plan.md).

### Add a target adapter

Implement the target-adapter contract: drive a local / synthetic system under test and
return observations the runner records into a trace. Today the targets are `mock`,
`demo-agent` (vulnerable by design), `protected-demo-agent`, `toy-local-function`,
`toy-rag`, `toy-tools`, and `toy-multi-agent`. New adapters stay local and
deterministic - no real provider, gateway, or network calls.

## Conventions

- Style: PEP 8; snake_case functions, PascalCase classes.
- Imports: stdlib -> third-party -> local, separated by blank lines.
- Small, single-purpose functions.
- Commits: conventional style (`feat:`, `fix:`, `docs:`, `test:`...), one logical change each.
- No application secrets in code or config; provider keys come from env only.

## Design rules

- The simple path needs **zero extra services**: local files only, no server, no Redis,
  no classifier, and no database.
- The system prompt is **not** a security boundary - never store secrets there
  ([why](threat-model.md#why-the-system-prompt-is-not-a-security-boundary)).
- No self-learning: rules do not mutate at runtime; feedback labels are collected for
  future human-reviewed adaptive rules only.
- **Study, don't copy.** We may study and cite other open-source projects, but do not copy
  code blindly - respect licenses, cite sources, and implement our own minimal, compatible
  adapters / tests.
- **Responsible use:** patterns are sanitized and run only against mock / authorized
  targets ([policy](../SECURITY.md#responsible-use)).

## Coding & agent rules (safe research)

These apply to every contribution and to any agent working in this repo (see also the
[safe research rules](research-rules.md)):

- **Deterministic tests** - same inputs -> same trace / scorecard; no flakiness.
- **No network or LLM calls in unit tests** - providers and targets are mocked.
- **No real secrets** - synthetic markers only, never real credentials or keys.
- **No real target adapters** without explicit docs **and** an authorization model - until
  then, only mock / demo targets.
- **Keep the trace schema portable and sanitized** - no host-specific data, no real payloads.
- **Self-review checklist before commit:** no secrets; no overclaiming (no first/only/complete-protection claims); no unsafe or abuse wording; scope matches the approved roadmap version;
  `pytest` + `ruff` + `mypy` + `ash validate examples/` green; internal files not tracked; `git diff` only the expected files.
