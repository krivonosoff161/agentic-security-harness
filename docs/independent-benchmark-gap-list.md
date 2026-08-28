# Independent-benchmark gap list

> Historical gap snapshot. Use [Current state](current-state.md) and the generated
> [ecosystem roadmap](ecosystem-roadmap.md) for current status. Completed distribution
> items remain below as history rather than being silently deleted.

Honest list of what is still missing for this to feel like a fully self-serve, independent
benchmark module. **Nothing here is implemented by listing it** - these are future-work
notes captured during the v0.12.1 UX-hardening pass so they are not lost. Items must not
be confused with the stable technical contract (see
[release-checklist.md](release-checklist.md) for release gates and non-blocking follow-up).

## Onboarding / UX

- A `quickstart` aggregate command (or a single scripted demo) that runs doctor -> run ->
  report -> validate in one step for first-time users.
- A short asciinema/GIF or a committed `report.html` screenshot in the README so users see
  the output before installing.
- A copy-paste "verify your install" one-liner whose expected output is documented.

## External / model path

- A native-provider adapter path (Anthropic / OpenAI Responses / Google) - currently only
  generic OpenAI-compatible. **Future**; needs an authorization model first.
- Agent-host / tool-use adapters that actually execute tools - currently prompt-only.
  **Future**; large scope, must stay opt-in and authorized.
- Streaming responses and multi-turn agent conversations. **Future.**
- A cost/usage estimate in tokens (not just request count) for paid endpoints.

## Reporting

- A per-pattern HTML trace viewer (the static report is summary-level only).
- Cross-run trend / history views (today each report is a single run).
- A machine-readable "diff two runs" command for responsible comparison.

## Reproducibility / methodology

- A frozen, versioned trace schema and corpus manifest with a documented compatibility
  policy (a v1.0 blocker).
- Second-reviewer verification of the OWASP LLM / NIST category mappings and the current
  MITRE ATLAS verified subset.
- A documented statistical guidance note for interpreting flaky/inconclusive rates across
  repeats.

## Distribution

- PyPI publishing and a pinned, reproducible install. **Completed:** v1.3.0 is published
  with exact wheel/sdist checksums, SBOM, attestations, and post-index installation checks.
- A source-build Docker/Compose synthetic Runtime Gateway contour is shipped. Publishing
  an official public image remains future work.

## Explicitly out of scope until methodology stabilizes

- A cross-model leaderboard or public scoreboard.
- A persistent results database or multi-run web dashboard.
- Any feature that would imply certification or production-safety guarantees.
