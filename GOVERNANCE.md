# Governance

Agentic Security Harness is a public research release of a pre-1.0 open-source
defensive benchmark. Governance is
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

## Solo maintainer and external model assistance

This project may be maintained by one human owner with bounded assistance from local or
external language models. That does not turn a model into a maintainer, approver, custodian,
or source of operational authority.

- Give external models only public, synthetic, or sanitized inputs. Never send secrets,
  private evidence, raw employee/model conversations, holdout labels, private paths, or
  provider credentials.
- Review provider terms, source licenses, and attribution before importing code, datasets, or
  substantial text. Availability on the internet is not permission to copy.
- Record a secret-safe provider/model class, task purpose, input classification, and
  deterministic verification summary. Do not commit raw prompts or responses.
- Counts, metrics, mappings, promotion gates, and security verdicts are owned by deterministic
  code and reviewable evidence. Model agreement is not independent validation.
- Model-generated changes receive the same hostile diff, secret, license, test, and exact-head
  review as human-written changes.

The solo-owner merge path remains evidence based: a linked GitHub issue, `codex/*` branch,
pull request, exact-head required checks, resolved review threads, and an explicit owner merge
action. A bounded local task record supplements that issue; it does not replace it. Zero
required outside approvals is a solo-operability choice, not a claim of independent peer
review.

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
public research releases rather than stable benchmark contracts, and must not be
described as certification, complete security coverage, production protection, or a
shipped gateway/runtime verifier.
