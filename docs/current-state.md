# Current state

> Last reviewed: 2026-06-18.
>
> Scope: public status of `agentic-security-harness` on `main`, version `0.13.0` plus
> unreleased governance and evidence-hardening changes. This page is a reviewer-facing
> status snapshot, not a roadmap promise.

## One-line status

Agentic Security Harness is a **pre-release credible alpha**: a working trace-first,
defensive benchmark prototype for agentic AI boundary failures.

It is strong enough to show as a public alpha benchmark/toolkit. It is not a production
certification benchmark, a general pentest tool, or a claim that a target is secure.

## Shipped and verified

| Area | Status | Evidence |
|---|---|---|
| Local deterministic corpus | Shipped | 23 sanitized seed patterns in `corpus.py` and `patterns.py`. |
| Local targets | Shipped | `mock`, `demo-agent`, `protected-demo-agent`, `toy-local-function`, `toy-rag`, `toy-tools`, `toy-multi-agent`, `protected-toy-multi-agent`. |
| Baseline vs protected replay | Shipped | `ash compare --baseline demo-agent --protected protected-demo-agent`. |
| Inter-agent handoff verifier toy topology | Shipped local slice | `handoff_integrity.py`, `toy-multi-agent`, and `protected-toy-multi-agent` model deterministic label-loss and authority-expansion handoffs. |
| Portable artifacts | Shipped | `traces.json`, `scorecard.json`, `summary.md`, `executive.md`, remediation, run manifests. |
| Static reports | Shipped | `ash report --root <run-dir>` writes a self-contained HTML report. |
| Run history and maintenance | Shipped | `list-runs`, `index-runs`, `stats`, `retention`, `diff-runs`. |
| External OpenAI-compatible prompt check | Experimental | `run-external`, prompt-only, explicit opt-in, no tool execution. |
| External evidence cross-check | Shipped for experimental path | Pattern id, boundary assertion, control family, decision coherence, raw response files. |
| Local-runtime metadata | Shipped for experimental path | `run_config.runtime`, report/runtime metadata, `local-only` mode for localhost/Ollama/LM Studio/vLLM, recovery guidance. |
| Standards-aware mapping | Partial | OWASP Agentic per pattern; OWASP LLM and NIST at category level; MITRE ATLAS verified for direct-fit categories and deferred where speculative. |
| Public project process | Shipped locally | Governance, security policy, issue templates, PR template, CI, CodeQL, Scorecard, release artifact workflow. |

## Experimental

These features exist, but their results must be read conservatively:

- `ash run-external`: prompt-only evaluation of an authorized OpenAI-compatible endpoint;
  local runtimes are labeled `local-only` and still require model-license /
  authorization review.
- External model comparisons: useful for exploratory checks, not benchmark-grade
  leaderboards.
- Scenario matrix variants: deterministic local replay metadata and pattern subsets, not
  live multi-tool execution.

External results are weak evidence until a stronger observation layer exists. The harness
records contradictory or incomplete model self-reports as `inconclusive`.

## Planned, not shipped

These are roadmap items and must not be described as current capability:

- native provider SDK adapters;
- live agent-host or tool-executing adapters;
- live MCP server adapter;
- cross-provider and cross-ecosystem handoff tests beyond the local toy adapter;
- broader recovery-path pattern family implementation beyond the shipped
  `data_boundary_missing_envelope_recovery` case;
- second-reviewer MITRE ATLAS mapping review and release-to-release upkeep;
- interactive multi-run viewer;
- persistent trace store beyond local manifests / SQLite metadata index;
- reference gateway runtime.

## Current active work

The next public-development focus is:

1. Keep current-vs-planned documentation synchronized with code.
2. Add an explicit authorized-testing model for local, owned, customer-authorized, and
   provider-program assessments.
3. Verify standards mappings without implying certification.
4. Expand the corpus by invariant and topology, not by prompt/model cross-products.
5. Expand multi-agent-handoff coverage beyond the shipped local verifier toy topology
   only when each new track has explicit safety gates; keep local-runtime metadata and
   recovery guidance current.
6. Improve public demo/showcase reports with replayable, validated artifacts.

## Validation commands

Use these before trusting a local checkout or public example:

```bash
python -m pytest
python -m ruff check .
python -m mypy src tests
ash validate examples/
git diff --check
```

For a quick public demo:

```bash
ash compare --baseline demo-agent --protected protected-demo-agent --out reports/comparison
ash validate reports/comparison
ash report --root reports/comparison
```

Expected current demonstration: the vulnerable baseline shows findings on the shipped
23-pattern corpus; the protected demo target removes those modeled findings under the
same configuration.

## Claim boundary

Allowed public claim:

> Trace-first defensive benchmark prototype for reproducible agentic AI boundary-failure
> evaluation, with local deterministic targets, validated artifacts, and experimental
> opt-in external model checks.

Do not claim:

- production certification;
- complete security coverage;
- real target coverage without an adapter and authorization model;
- provider endorsement;
- benchmark-grade model leaderboard;
- live tool-executing agent evaluation.
