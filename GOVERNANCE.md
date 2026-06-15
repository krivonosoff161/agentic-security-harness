# Governance

Agentic Security Harness is a pre-1.0 open-source defensive benchmark. Governance is
intentionally lightweight, but changes must preserve the benchmark's public credibility:
synthetic inputs, trace-first evidence, honest limitations, and no provider-specific lock-in.

## Decision model

- The maintainer is the final decision maker for scope, releases, security-sensitive
  changes, and public positioning.
- Significant methodology changes should be discussed in an issue before code lands.
- Corpus expansion requires a written defensive pattern proposal before implementation.
- Native provider, agent-host, tool-executing, or non-synthetic adapters require an
  authorization model and explicit safety gates before merge.

## Required review gates

Before a change is merged or pushed to `main`, verify:

- `python -m pytest`
- `python -m ruff check .`
- `python -m mypy src tests`
- `ash validate examples/`
- `git diff --check`

If a change affects generated artifacts, regenerate examples rather than editing
scorecards or traces by hand.

## Methodology gates

New benchmark patterns must define:

- the boundary invariant under test;
- the evaluation topology;
- the expected vulnerable behavior;
- the deterministic trace evidence;
- the control that makes the protected target pass;
- residual risk and non-goals.

The project does not accept full combinatorial sweeps of agents, models, providers,
memory modes, and time windows as a substitute for methodology. Expansion is invariant
based and bounded; see [docs/corpus-expansion-plan.md](docs/corpus-expansion-plan.md).

## Release authority

Release tags are cut only after the release checklist passes. Until v1.0, releases remain
pre-release alpha/beta artifacts and must not be described as certification or complete
security coverage.
