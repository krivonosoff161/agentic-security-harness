# v1.0 readiness matrix

This page tracks the path toward a stable v1.0 benchmark. It is a readiness map, not a
release announcement, and not a claim that v1.0 is ready. The current project status is a
public research release until the blockers in [release-checklist.md](release-checklist.md)
are cleared.

## Release principle

v1.0 means the deterministic benchmark contract is dependable enough for external users
to install, run, validate, and compare without guessing which parts are stable. It does
not mean production certification, real-target coverage, or a model leaderboard.

## Stable vs experimental surface

| Surface | v1.0 target status | Current status | Evidence / gate |
|---|---|---|---|
| Local deterministic corpus | Stable at v1.0 | 24 shipped patterns, still pre-1.0 mutable | Freeze pattern ids and corpus fields; document deprecation policy. |
| Trace artifact schema | Stable at v1.0 | `schema_version=0.1`, policy documented | Freeze `trace` schema major version; run `ash validate examples/`. |
| Scorecard / remediation schemas | Stable at v1.0 | Versioned and validated | Confirm compatibility policy in [artifact-schemas.md](artifact-schemas.md). |
| Run manifest / run diff schemas | Stable enough for CLI history | Versioned and validated | Keep `run_index.json` and `run_diff.json` schema checks green. |
| Static HTML / Markdown reports | View layer, not canonical schema | Shipped | JSON remains authoritative; HTML/Markdown must not make stronger claims. |
| Local targets | Stable demo surfaces | `mock`, `demo-agent`, `protected-demo-agent`, toy targets shipped | `ash targets`, full pytest, and examples validation. |
| Research campaign artifacts | Experimental/research surface | Local-swarm, evidence-campaign, secret-egress, semantic-drift, and semantic-propagation examples validate, but remain research slices | Keep private raw transcripts/canaries out of git; public summaries must state adapter errors, hash coverage, and non-claims. |
| External OpenAI-compatible path | Experimental beyond v1.0 unless observation improves | Prompt-only, opt-in | Keep labeled experimental; no leaderboard claims. |
| Native provider / agent-host adapters | Future | Not shipped | Requires authorization model and adapter safety gates. |
| Reference gateway | Future optional defense target | Not shipped | Must not be described as current runtime. |

## Clean install path

The clean install path for a release candidate must pass from a fresh checkout:

```bash
python -m pip install -e ".[dev]"
ash --help
ash doctor
ash targets
ash compare --baseline demo-agent --protected protected-demo-agent --out reports/comparison
ash validate reports/comparison
ash validate examples/
```

Expected showcase result for the current corpus:

```text
baseline demo-agent: 24 findings
protected-demo-agent: 0 findings
delta: 24 -> 0
```

The public comparison example must satisfy
[showcase-report-checklist.md](showcase-report-checklist.md).

## Fake-server path

The local fake-server path is the no-cost external-mode smoke test:

```bash
python examples/fake_openai_server.py
ash external-check --base-url http://127.0.0.1:8766/v1 --model fake-model --scenario data-boundary
ash run-external --base-url http://127.0.0.1:8766/v1 --model fake-model --scenario data-boundary --execute --out .internal/external-e2e
ash validate reports/e2e
```

It proves only that the experimental OpenAI-compatible path can create and validate
artifacts against a deterministic local endpoint. It does not prove real provider,
tool-executing agent, or model safety.

## Claim boundaries for v1.0

Allowed:

- stable local deterministic benchmark;
- portable traces and validated artifacts;
- baseline-vs-protected risk-reduction measurement on the shipped synthetic corpus;
- experimental prompt-only external checks with clear limitations.

Not allowed:

- production certification;
- complete protection;
- real target coverage without an authorized adapter;
- native provider / agent-host support before implementation;
- cross-model leaderboard or vendor ranking.

## Open v1.0 blockers

| Blocker | Why it matters | Exit gate |
|---|---|---|
| Trace schema freeze | External users need stable trace parsing. | Final trace schema review; compatibility policy confirmed; examples validate. |
| Corpus manifest freeze | Pattern ids are public contract. | Pattern id / field freeze and deprecation policy documented. |
| Standards second review | Mapping claims need independent verification. | OWASP LLM / NIST category mappings reviewed; MITRE ATLAS subset rechecked. |
| Real adapter contract finalization | Future adapters must not weaken authorization/safety boundaries. | Adapter contract and authorization docs aligned; safety gates tested. |
| Docs/reference pass | Public readers must see current-vs-planned clearly. | README/current-state/capability matrix/release checklist agree. |
| CI release commit | Cross-platform install and artifact validation must pass. | Ubuntu 3.11-3.13, Windows 3.11, build package, CodeQL green. |

## Release decision

Do not tag v1.0 until every blocker above has an owner, evidence, and a green release
commit. If a blocker is intentionally deferred, rename the milestone rather than shipping
v1.0 with a hidden gap.
