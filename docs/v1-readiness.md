# v1.0 readiness matrix

This page records the stable v1.0 benchmark contract. It is a readiness map, not a release
announcement: the technical contract is ready for a separately authorized exact-tag run,
while independent standards review and independent maintainer governance remain disclosed
post-v1 credibility work.

## Release principle

v1.0 means the deterministic benchmark contract is dependable enough for external users
to install, run, validate, and compare without guessing which parts are stable. It does
not mean production certification, real-target coverage, or a model leaderboard.

## Stable vs experimental surface

| Surface | v1.0 target status | Current status | Evidence / gate |
|---|---|---|---|
| Local deterministic corpus | Stable at v1.0 | Frozen corpus 1.0.0: 24 ordered ids, closed manifest fields, explicit deprecation/replacement policy | Keep committed manifest/schema, generator, traces, and validator digest bindings green. |
| Trace artifact schema | Stable at v1.0 | Frozen `schema_version=1.0`; legacy `0.1` remains readable with a deprecation warning | Keep contract fixtures, migration tests, and `ash validate examples/` green. |
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

## v1.0 technical gates and disclosed follow-up

| Gate | Why it matters | Status / exit gate |
|---|---|---|
| Trace schema freeze | External users need stable trace parsing. | Integrated in `main` as schema 1.0 with closed typed fields, v0.1 compatibility/migration fixtures, and validator regression coverage. |
| Corpus manifest freeze | Pattern ids are public contract. | Integrated in `main` as corpus 1.0.0 with a closed committed manifest/schema, canonical semantic digest, immutable identifiers, and explicit deprecation/replacement policy. |
| Independent standards review | Improves confidence in mapping claims but does not change deterministic benchmark execution. | Non-blocking post-v1 issue #199; independent review is not claimed until completed. |
| Real adapter contract finalization | Future adapters must not weaken authorization/safety boundaries. | Contract, authorization modes, offline defaults, explicit execution gates, redaction rules, and tests are aligned; native/provider adapters remain future. |
| Docs/reference pass | Public readers must see current-vs-planned clearly. | Integrated-state reconciliation is current and documentation contract tests are green. |
| Integrated-main CI | Cross-platform install and artifact validation must pass. | Exact `main` commit `7c5ad061` passed Ubuntu 3.11-3.13, Windows 3.11, installed-wheel smokes, build, CodeQL, and secret scan. |
| Release execution gate | Published subjects must bind the release source and dependency inventory. | The workflow is implemented; the authorized tag run must produce and verify wheel/sdist/SBOM/checksum attestations. |
| Independent maintainer governance | A second durable reviewer would strengthen branch governance. | Non-blocking post-v1 issue #205; independent governance is not claimed until completed. |

## Release decision

Tag v1.0 only from an explicitly authorized, exact, green release commit and require the
tag workflow to verify every published subject. Issues #199 and #205 do not block that
technical release: they stay public in the post-v1 milestone, and release notes must not
claim independent standards validation, certification, or independent maintainer review.
