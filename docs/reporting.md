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
- `summary.md` - human-readable table.

`ash compare` writes:

- `baseline/` artifacts;
- `protected/` artifacts;
- `comparison.md`.

`ash validate` checks that committed artifacts match the corpus manifest and contain no
forbidden markers.

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
Corpus: 17 local synthetic patterns
Baseline: demo-agent, 17 findings
Protected: protected-demo-agent, 0 findings
Measured delta: 17 -> 0
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

## Suggested future HTML report

A future `ash report` command could render a static HTML directory:

```text
report/
  index.html
  patterns/
    <pattern_id>.html
  traces/
    <trace_id>.json
  assets/
```

Views:

- executive summary;
- coverage matrix;
- break-point histogram;
- severity histogram;
- baseline-vs-protected comparison;
- per-pattern trace viewer;
- residual-risk section;
- adapter metadata section.

The HTML report must be static and local: no external CDN, no telemetry, no JavaScript that
loads remote assets.

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

- No HTML report yet.
- No executive-summary artifact separate from `comparison.md`.
- No stochastic-run report for real LLM targets.
- No adapter metadata block beyond the current `TargetDescriptor`.
- No visual coverage chart.

These are report-quality tasks, not corpus tasks. They should improve how the 17-pattern
corpus is reviewed without changing the benchmark semantics.
