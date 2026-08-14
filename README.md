# Agentic Security Harness

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13320/badge)](https://www.bestpractices.dev/projects/13320)
[![CI](https://github.com/krivonosoff161/agentic-security-harness/actions/workflows/ci.yml/badge.svg)](https://github.com/krivonosoff161/agentic-security-harness/actions/workflows/ci.yml)
[![CodeQL](https://github.com/krivonosoff161/agentic-security-harness/actions/workflows/codeql.yml/badge.svg)](https://github.com/krivonosoff161/agentic-security-harness/actions/workflows/codeql.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-Apache--2.0-green)
![Status](https://img.shields.io/badge/status-v1.0--ready-blue)

**Your AI coding agent reads untrusted repository text. Can it keep data separate from
instructions and authority?**

Agentic Security Harness is a local, trace-first benchmark for defensive testing of
agentic AI boundary failures. It runs reproducible synthetic scenarios, records portable
traces and scorecards, and compares a deliberately vulnerable local agent with a protected
one.

In plain English: it turns “the agent behaved unsafely” into evidence you can replay,
validate, compare, and review.

## Quickstart

Install the current source checkout:

```bash
git clone https://github.com/krivonosoff161/agentic-security-harness.git
cd agentic-security-harness
python -m pip install .
ash quickstart --out reports/quickstart
```

After the separately gated PyPI publication, the primary install command becomes:

```bash
python -m pip install agentic-security-harness
```

`ash quickstart` is local and no-network. It runs the same stable 24-pattern corpus against
both demo targets, validates the generated artifacts, and renders a self-contained HTML
report.

| Target | Modeled findings | Patterns passed |
|---|---:|---:|
| `demo-agent` | 24 | 0 |
| `protected-demo-agent` | 0 | 24 |

The deterministic result is **24 modeled findings** for the vulnerable fixture and
**0 modeled findings** for the protected fixture. This is synthetic conformance evidence,
not a production safety claim.

![Terminal comparison showing 24 findings reduced to 0](docs/images/terminal-compare.png)

![Rendered comparison report table](docs/images/comparison-table.png)

Inspect the committed before/after example in
[`examples/comparison-report/`](examples/comparison-report/) or validate every public
example locally:

```bash
ash validate examples/
ash validate docs/evidence-status-registry.json
```

## What this is / is not

| This project is | This project is not |
|---|---|
| A reproducible benchmark for agent operating-environment boundaries. | A production safety certification. |
| A synthetic and authorized defensive testing lab. | A live exploitation or persistence toolkit. |
| A way to compare vulnerable and protected targets using portable artifacts. | Proof that a provider, model, or deployed agent is secure. |
| A stable trace/corpus contract with machine-readable validation. | A model leaderboard or CVE database. |

The benchmark focuses on agent operating-environment boundaries, not just standalone model answers.
Built-in targets are deterministic and offline. The experimental external adapter
is explicit opt-in, prompt-only, and does not execute tools. See
[`docs/benchmark-semantics.md`](docs/benchmark-semantics.md) and
[`docs/authorized-testing-paths.md`](docs/authorized-testing-paths.md).

## Visual evidence snapshot

![Evidence flow from scenario to validated report](docs/assets/evidence-flow.svg)

The public evidence map separates deterministic executable specifications, sanitized local
observations, historical material, and independently reviewed evidence:

- [Evidence map](docs/showcase/evidence-map.md)
- [Evidence classes](docs/evidence-classes.md)
- [Machine-readable evidence registry](docs/evidence-status-registry.json)
- [Evidence pack format](docs/evidence-pack-format.md)
- [Private/public evidence boundary](docs/private-public-evidence-boundary.md)

Public artifacts may include scenario identifiers, aggregate counts, response hashes, and
validator results. They do not include raw private prompts, raw responses, synthetic
canaries, or local paths. Keep external raw material under
`.internal/external-demo/latest`. **Do not** commit `raw_responses/` or other private
runtime evidence.

## Current stable surface

- Trace schema `1.0`, with a bounded legacy `0.1` read/migration window.
- Corpus `1.0.0`, freezing 24 ordered synthetic pattern identifiers.
- Local targets for vulnerable/protected agent, RAG, tool, function, and multi-agent
  handoff comparisons, including `toy-multi-agent` and `protected-toy-multi-agent`.
- JSON traces, scorecards, run manifests, remediation, Markdown reports, and
  self-contained HTML reports.
- Deterministic validators for artifact integrity and declared benchmark semantics.
- Linux/Python 3.11-3.13 as the primary installed-package contour, with Windows 3.11
  compatibility coverage.
- Reproducible wheel/sdist builds, checksums, GitHub attestations, and an exact-subject
  CycloneDX SBOM in the next authorized tag workflow.

The exact shipped, experimental, planned, and historical surfaces live in
[`docs/current-state.md`](docs/current-state.md) and
[`docs/capability-matrix.md`](docs/capability-matrix.md). Technical v1 gates and honest
non-claims are in [`docs/v1-readiness.md`](docs/v1-readiness.md).

## If you only have one minute

- Run the no-network demo above.
- Read the [committed comparison](examples/comparison-report/README.md).
- Browse the [showcase](docs/showcase/index.md) and
  [scenario matrix](docs/showcase/scenario-matrix.md).
- See [weak spots and findings](docs/showcase/weak-spots-and-findings.md).
- Check [current state](docs/current-state.md) and the
  [project tracker](docs/project-tracker.md).
- Bring your own local or OpenAI-compatible model through
  [Run your model](docs/run-your-model.md).

## Use your own model or runtime

The shortest cross-platform operator path is
[`docs/run-your-model.md`](docs/run-your-model.md). It covers:

1. a no-model deterministic demo;
2. one explicitly authorized OpenAI-compatible model;
3. a deterministic local swarm comparison;
4. a bounded local-model mini-swarm campaign.

Connection details and scenario selection are documented in
[`docs/connect-models.md`](docs/connect-models.md) and
[`docs/test-your-model.md`](docs/test-your-model.md). External runs are prompt-only
self-report checks unless a separately reviewed host/tool adapter exists. A coherent answer
is not evidence of safe tool execution.

## Benchmark and evidence documentation

The README is the front door; deeper contracts live in `docs/`:

| Question | Source of truth |
|---|---|
| What is shipped now? | [Current state](docs/current-state.md) |
| What work is open? | [Project tracker](docs/project-tracker.md) and [roadmap](docs/roadmap.md) |
| Which testing paths are authorized? | [Authorized testing paths](docs/authorized-testing-paths.md) |
| Which system shapes are evaluated? | [Evaluation topologies](docs/evaluation-topologies.md) |
| What boundary model is used? | [Agentic boundary model](docs/agentic-boundary-model.md) |
| How is the corpus expanded? | [Corpus expansion plan](docs/corpus-expansion-plan.md) |
| What do metrics mean? | [Metric contract](docs/metric-contract.md) |
| How are scenarios sequenced? | [Scenario timeline](docs/scenario-timeline.md) |
| How should reports be showcased? | [Showcase checklist](docs/showcase-report-checklist.md) |
| How is evidence promoted? | [Evidence pack format](docs/evidence-pack-format.md) |
| How are changes reviewed? | [Git evidence workflow](docs/git-evidence-workflow.md) |

Specialized reviewer paths:

- [Local Prometheus workflow](docs/local-prometheus-workflow.md)
- [Local model profiles](docs/local-model-profiles.md)
- [Multi-agent handoff toy topology](docs/handoff-toy-topology.md)
- [Security audit causal map](docs/security-audit-causal-map-2026-07-15.md)
- [R5 sanitized research status](docs/r5-research-status.md)
- [Project governance](GOVERNANCE.md)

## Standards and portfolio boundaries

The project publishes conservative mappings to OWASP LLM, NIST, and a direct-fit MITRE
ATLAS subset in [`docs/standards-mapping.md`](docs/standards-mapping.md). These are
maintainer-reviewed mappings, not certification or independent standards validation.
Independent review remains public follow-up work.

The related public contract includes:

- [Threat ontology](docs/threat-ontology.md): 26 provider-neutral failure families.
- [Scenario adjudication ledger](docs/scenario-adjudication-ledger.md): 127 bounded source
  units from 13 enumerated builders.
- [Unified event envelope](docs/unified-event-envelope.md): separation of observations,
  data, authority, advisories, decisions, and effects.

The 127 units are **not 127 canonical attacks** and **not a repository-wide total**. The
contract grants no executor, provider, deployment, enforcement, or production authority.

## Public security stack

Agentic Security Harness is the benchmark/evidence layer in a small public defensive
stack:

```text
llm-safety-playbooks -> ai-agent-handoff -> agentic-transfer-verifier -> agentic-security-harness
```

- [`llm-safety-playbooks`](https://github.com/krivonosoff161/llm-safety-playbooks)
  documents practical boundary rules.
- [`ai-agent-handoff`](https://github.com/krivonosoff161/ai-agent-handoff)
  represents task briefs and handoff state as reviewable files.
- [`agentic-transfer-verifier`](https://github.com/krivonosoff161/agentic-transfer-verifier)
  checks provenance, authority, approval, and audit evidence around transfers.
- This repository measures modeled failures and produces validated benchmark artifacts.

The repositories are related but not interchangeable. A playbook is not a runtime control,
a handoff file is not a sandbox, and a passing benchmark is not a production certificate.

## Release and package status

The source tree is prepared for the stable v1 contract. Tagging, GitHub Release creation,
TestPyPI upload, and PyPI publication remain separate, auditable owner gates. Until the
package-index promotion succeeds, source and GitHub Release installation are the supported
paths.

- [Release checklist](docs/release-checklist.md)
- [PyPI release process](docs/release-to-pypi.md)
- [Changelog](CHANGELOG.md)
- [Security policy](SECURITY.md)

Independent standards review and a durable second GitHub reviewer are transparent
post-v1 credibility tasks. Their absence does not change deterministic test results, but
independent review is not claimed.

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
python -m mypy src tests tools
ash validate examples/
```

Development follows
`idea -> issue -> branch -> implementation -> tests/artifacts -> PR -> GitHub checks -> review gate`.
See [`docs/git-evidence-workflow.md`](docs/git-evidence-workflow.md),
[`CONTRIBUTING.md`](CONTRIBUTING.md), and [`docs/agent-operating-guide.md`](docs/agent-operating-guide.md).

## Responsible use

Use only synthetic, local, owned, or explicitly authorized targets. Do not use this project
for credential theft, persistence, evasion, destructive payloads, or unauthorized systems.
See [`SECURITY.md`](SECURITY.md) and
[`docs/authorized-testing-paths.md`](docs/authorized-testing-paths.md).

## Citation, contributing, and license

- Citation metadata: [`CITATION.cff`](CITATION.cff)
- Governance: [`GOVERNANCE.md`](GOVERNANCE.md)
- Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Support: [`SUPPORT.md`](SUPPORT.md)
- License: Apache-2.0, see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE)
