# Benchmark positioning - where we win / where we still lag

A read-only, high-level comparison against common open evaluation/red-team toolkits, to
position this project honestly. This is **not** a feature-by-feature claim and copies no
content from those projects; it reflects their well-known public shape only. Nothing here
is a commitment to build - gaps that should wait are marked.

## Reference points (public, general shape)

- **garak** - LLM vulnerability scanner with many probes/detectors and many model
  backends; breadth-first scanning.
- **promptfoo** - prompt/eval and red-team runner with provider breadth, YAML configs,
  assertions, a web viewer, and CI integration.
- **PyRIT** - risk-identification toolkit with automated, multi-turn adversarial
  orchestration and scoring.
- **Inspect** (eval-framework style) - solvers/scorers, sandboxed tool use, a log viewer.
- **lm-evaluation-harness** - standardized task-based LM evaluation focused on
  reproducibility and breadth of tasks.

## What we already do well

- **Deterministic, offline core.** The 23-pattern corpus runs without network or a model,
  so the baseline is reproducible byte-for-byte. Most red-team tools are network/model
  bound and therefore flaky by nature.
- **Trace-first portable artifacts + validation.** Every run is a machine-readable trace,
  and `ash validate` is an explicit artifact-integrity check - uncommon in scanner-style
  tools that emit prose reports.
- **Baseline-vs-protected risk-reduction story.** A vulnerable and a controlled target on
  the same corpus give a measured before/after, not just a pass/fail dump.
- **Remediation + control-family mapping.** Findings map to control families with
  quick/engineering/architecture fixes - more actionable than a raw vulnerability list.
- **Honest framing.** No-network-by-default, explicit external opt-in, "validate != safety",
  and category-level standards mapping with explicit deferral. No certification claims.
- **Tiny footprint.** One runtime dependency (`pydantic`); self-contained static HTML with
  no CDN/JS.

## Where we still lag

- **Provider breadth.** We support only generic OpenAI-compatible endpoints; the others
  ship native adapters for many providers. (We document recipes instead.)
- **No automated / multi-turn attack generation.** PyRIT and garak generate attacks; our
  corpus is a fixed, synthetic, defensive set by design. This is a deliberate scope
  choice, but it is a capability gap for users who want fuzzing.
- **No web dashboard / multi-run trend viewer.** promptfoo and Inspect-style tools have
  rich viewers; we ship a single static per-run HTML page.
- **Smaller probe count.** garak has many probes; our corpus is 23 curated boundary
  patterns - narrower but deeper on the agentic operating-environment boundary.
- **No tool-execution / agent-host evaluation.** The external path is prompt-only.
- **No plugin/entry-point ecosystem** for third-party probes/adapters yet.
- **Not packaged on PyPI;** install is from source.

## What should be next (small, methodology-safe)

- Document more OpenAI-compatible runtimes (already most local stacks work).
- A plugin/entry-point adapter system - only after the trace schema and corpus manifest
  are frozen.
- A per-pattern HTML trace viewer and a `diff two runs` helper for responsible comparison.

## What must NOT be built before methodology stabilizes

- A cross-model leaderboard or scoreboard (would imply a vendor comparison the corpus
  cannot yet support fairly).
- Automated attack/fuzz generation that could be misused offensively.
- A broad native-provider matrix presented as a benchmark-grade comparison.
- Any feature implying certification or production-safety guarantees.

See [independent-benchmark-gap-list.md](independent-benchmark-gap-list.md) for the
onboarding/UX gap list and [roadmap.md](roadmap.md) for sequencing.
