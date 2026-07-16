# Reporting design

> **Agentic Security Harness.** Reports must make the benchmark useful to two audiences:
> executives who need the risk-reduction picture, and technical reviewers who need to
> inspect the exact trace and control failure.

## Report principle

The report should never claim broad protection. It should answer a narrower question:

```text
For this corpus, target, and run configuration, what boundary failures were observed,
where did they break, and what changed after replaying the same corpus against a protected target?
```

## Current artifacts

Each `ash run` writes:

- `traces.json` - portable machine-readable traces;
- `scorecard.json` - deterministic aggregate;
- `summary.md` - human-readable table;
- `executive.md` - concise executive view with control families;
- `remediation.json` - structured control recommendations (when findings exist);
- `remediation.md` - human-readable remediation report (when findings exist).

`ash compare` writes:

- `baseline/` artifacts (including remediation if findings exist);
- `protected/` artifacts;
- `comparison.md` with control priorities section.

`ash validate` checks that committed artifacts match the corpus manifest and contain no
forbidden markers, including `remediation.json` and `remediation.md`.

Every run also writes a `run_index.json` manifest (`list-runs`, `stats`, and `retention`
read it). `run-matrix` adds `matrix.json` / `matrix.md`; `run-external` writes
`run_config.json`, `external_results.json`, `external_summary.json`, and
`external_report.md`. `ash diff-runs` / `ash compare-models` write `run_diff.json` and
`run_diff.md`. `ash report` renders any run/diff directory into a static `report.html`
(see below).

## Executive report shape

A reviewer should see these first:

1. **Scope:** target, adapter, corpus version, run mode, network/model status.
2. **Headline delta:** baseline findings vs protected findings.
3. **Boundary coverage:** data, authority, perception, memory, approval, audit, budget,
   schema/tool boundaries.
4. **Top failures:** highest severity findings grouped by break point.
5. **Residual risk:** what the run does not prove.
6. **Next tests:** which adapters or pattern variants should be added next.

Example:

```text
Corpus: 24 local synthetic patterns
Baseline: demo-agent, 24 findings
Protected: protected-demo-agent, 0 findings
Measured delta: 24 -> 0
Residual risk: local deterministic traces only; no real model/provider/runtime tested
```

## Technical report shape

A technical report should show:

- pattern id and category;
- target descriptor;
- graph path;
- break point (`broke_at`);
- trace step where the finding occurred;
- data envelope / capability / schema / memory metadata used by the test;
- expected vulnerable behavior;
- observed behavior;
- mitigation expected from a protected target;
- validation status.

## Static HTML report (shipped)

`ash report --root <run-dir> [--out <file>]` renders a single self-contained
`report.html` (inline CSS, no JavaScript, no CDN, no network, no telemetry). It works for
run, compare, matrix, and external directories and includes:

- executive summary and pass/finding counts;
- severity distribution;
- pattern results table;
- a coverage heatmap (pattern x variant) for matrix runs;
- a baseline-vs-protected before/after view for comparisons;
- a stochastic repeat-status view for external runs;
- run / adapter metadata;
- a "what this does not prove" section.

JSON and Markdown remain authoritative; the HTML is a view layer. A richer per-pattern
trace viewer and cross-run trend views remain future work.

The renderer validates the supplied artifact directory before it creates the output file.
Schema, cross-artifact projection, secret-marker, and manifest/content-hash failures stop
rendering. A benchmark expectation mismatch is different from artifact corruption: the
report is still produced so the regression remains visible, but it carries an explicit
"not a clean result" warning. Legacy manifests remain readable under their declared
structural contract; only current manifest schema v0.3 provides persisted-byte hash binding,
and neither form authenticates authorship.
The output must use a `.html` filename. The writer refuses symlink output files and will not
overwrite any non-HTML source artifact under the run directory; this keeps a custom `--out`
from replacing `traces.json`, `run_index.json`, or another authoritative input after it has
passed validation.

## Report safety rules

Reports must not contain:

- real secrets;
- raw provider credentials;
- private customer data;
- live exploit payloads;
- private URLs or account ids;
- instructions for abusing third-party systems.

If a real authorized adapter is added later, report writers must sanitize or label private
fields before anything is committed to the public repository.

## Current gaps

- No per-pattern HTML trace viewer (the static report is summary-level).
- No interactive cross-run dashboard; `stats`, `list-runs`, `index-runs`, and `diff-runs`
  provide CLI-level history and comparison.
- No stochastic-run report for **native** model adapters (the external path covers
  OpenAI-compatible prompt-only runs, with repeats and stochastic status).
- No mitigation-checklist artifact yet.

Shipped already: the static HTML report with coverage heatmap, an adapter metadata block
in `run_index.json`, and the category-level standards mapping. The remaining report-quality
tasks should improve how the 24-pattern corpus is reviewed without changing the benchmark
semantics.

## Remediation layer (v0.10)

The remediation layer produces structured control recommendations from findings.
Each recommendation maps a finding to:

- **control family** (e.g. `provenance`, `memory_governance`, `tool_selection`)
- **priority** (p0/p1/p2/p3 based on finding severity)
- **quick fix** - immediate action
- **engineering fix** - implementation-level change
- **architecture fix** - stronger architectural design
- **verification** - how to confirm the fix works
- **residual risk** - what remains after the fix

The remediation artifacts (`remediation.json`, `remediation.md`) are deterministic,
synthetic, and local. They do not imply complete protection.
