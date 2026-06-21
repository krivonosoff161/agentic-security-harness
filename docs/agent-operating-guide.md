# Agent Operating Guide

Date: 2026-06-17

This guide defines how AI agents should work on Agentic Security Harness. It exists to keep the repository from becoming an unreviewable pile of code, prompts, scripts, and reports.

The goal is not to produce more files. The goal is to leave a clear evidence trail: what changed, why it changed, how it was verified, and what remains open.

## Project Identity

Agentic Security Harness is a trace-first defensive benchmark for agentic AI failure modes.

The project should stay focused on:

- synthetic and authorized targets
- reproducible scenarios
- portable traces
- deterministic validators
- scorecards and reports
- baseline-vs-protected comparison
- remediation guidance
- clear separation of `pass`, `finding`, `inconclusive`, and `error`

Do not turn the project into a generic cybersecurity prompt library or a broad collection of unrelated scripts.

## Core Rule

Every meaningful change must answer six questions:

1. What problem does this solve?
2. What changed?
3. How was it verified?
4. What artifact proves it?
5. What remains open?
6. What commit or diff records it?

If those questions cannot be answered, the task is not complete.

## Startup Checklist

At the start of work:

1. Confirm the active repository path.
2. Read `C:\Users\krivo\.codex\PROJECT_CONTEXT.md`.
3. Read this guide.
4. Run `git status --short --branch`.
5. Check whether the branch is clean, dirty, ahead, behind, or diverged.
6. Identify unrelated dirty files before editing.
7. Do not overwrite user or other-agent work.

Repo confusion is a real failure mode. Do not mix this project with trading, profile, infrastructure, or unrelated research work.

## Work Types

Classify the task before acting.

### Code Change

Code changes should be narrow and verified.

Required:

- inspect existing patterns first
- avoid unrelated refactors
- add or update tests for changed behavior
- run targeted checks
- explain residual risk
- keep examples and golden artifacts in sync when output changes

### Research

Research should become a durable project asset.

Required:

- source map
- claims separated from assumptions
- conservative wording
- open questions
- next tasks
- benchmarkability assessment

### Documentation

Docs should support development and credibility.

Required:

- date or version context when relevant
- current state
- decisions
- open questions
- exact next steps
- links to artifacts or commands

Avoid history-only documents. Convert history into decisions and tasks.

### Review / Audit

Review output starts with findings.

Required:

- severity
- file and line references
- reproduction or reasoning
- missing tests
- residual risk

Do not accept another agent report as ground truth. Verify by code, tests, git status, and artifacts.

### Showcase / Demo

Showcase work must make the project understandable quickly.

Required:

- one reproducible demo path
- generated trace/report examples
- metrics that matter
- screenshots or video script when useful
- explanation of why the result is trustworthy

## Git Discipline

Git history is part of the product evidence.
The canonical issue -> branch -> artifact -> PR -> GitHub checks workflow is
[git-evidence-workflow.md](git-evidence-workflow.md). Use this guide for agent behavior
and the workflow doc for the public process contract.

Before editing:

```bash
git status --short --branch
git log --oneline --decorate --max-count=5
```

Before committing:

```bash
git status --short --branch
git diff --stat
git diff --check
```

For code changes, run the relevant tests and linters. For broad changes, prefer:

```bash
python -m pytest
python -m ruff check .
python -m mypy src tests
git diff --check
```

Commit rules:

- **All changes go through a branch and pull request.** Do not push directly to `main`.
  `main` is the stable, release-facing branch.
- one coherent logical change per commit
- no unrelated cleanup bundled into feature work
- no commit without owner approval
- no push without owner approval
- never use destructive git commands unless explicitly requested

Good commit message examples:

- `feat: add scenario validation status`
- `fix: preserve boundary labels in reports`
- `docs: document benchmark evidence workflow`
- `test: cover inconclusive model verdicts`

## Dirty Tree Rules

If the tree is dirty:

1. List dirty files.
2. Identify which files belong to the current task.
3. Ignore unrelated files.
4. Inspect any dirty file before editing it.
5. Do not revert or overwrite another agent's work.

If another agent is actively working, do not race it. Either wait or work in a separate document.

## Verification Standards

Do not claim completion without checks.

Minimum for code:

- relevant tests
- targeted CLI dry-run or artifact validation when applicable
- lint/type checks when relevant
- `git diff --check`
- final git status

Minimum for docs:

- source links checked
- claims conservative
- no stale overclaiming
- open questions listed

Minimum for benchmark artifacts:

- trace is valid
- scorecard is valid
- report is generated
- `ash validate` or equivalent validation passes
- result class is explicit: `pass`, `finding`, `inconclusive`, or `error`

## Evidence Trail

A change is stronger when it leaves inspectable evidence.

Prefer artifacts such as:

- traces
- scorecards
- remediation reports
- validated JSON
- scenario matrices
- comparison tables
- test output summaries
- run histories
- source maps
- decision records
- screenshots or short demo videos

The public story should be simple:

1. Here is the failure mode.
2. Here is the trace.
3. Here is the validator.
4. Here is the scorecard.
5. Here is the remediation.
6. Here is the comparison after protection.

## Development Visibility

The repository should show living progress, not unexplained code churn.

For substantial work, update one of:

- `docs/current-state.md`
- `docs/project-tracker.md`
- `docs/research-roadmap.md`
- `docs/showcase/index.md`
- `docs/showcase/deepening-backlog.md`
- `CHANGELOG.md` for release-facing changes

Use docs to expose:

- what changed
- why it matters
- what was verified
- what is still missing
- which task should happen next

This matters because outsiders usually see the README, docs, examples, commits, and reports before they read source code.

## Scope Control

Allowed project roles for new files:

- benchmark scenario
- target adapter
- runtime adapter
- trace collector
- validator
- scorecard/report
- remediation output
- comparison workflow
- documented research hypothesis
- showcase artifact
- operator/developer workflow

If a new file does not fit one of those roles, justify it before adding it.

Avoid:

- broad cybersecurity skill dumps
- unrelated helper scripts
- unvalidated model claims
- offensive real-target workflows
- live third-party testing
- overbroad "AI security" positioning

## Safety And Claims

This is a defensive benchmark/toolkit.

Keep all work within:

- synthetic targets
- mock/demo targets
- owned or explicitly authorized targets
- no secrets
- no real exfiltration
- no provider abuse
- no live attack instructions

Positioning rules:

- say "measures risk reduction"
- say "detects/reproduces specific failure modes"
- say "validated artifacts"
- do not say "complete protection"
- do not say "first/only" unless independently verified
- do not imply deterministic validators prove semantic truth

Separate deterministic evidence from model judgment.

## External Model Runs

External or local model runs are evidence only when recorded and validated.

Required:

- model name
- endpoint/runtime class
- scenario set
- raw response stored safely
- validation result
- pass/finding/inconclusive/error split
- limitations

If a model returns contradictory self-report, do not force it into pass or finding. Use `inconclusive` when the evidence contract is broken.

## External Repositories

External repos are references, not authority.

Before importing ideas:

1. Check license.
2. Check scope.
3. Check scripts and install hooks.
4. Check whether content is defensive, offensive, or mixed.
5. Extract useful patterns, not random code.
6. Record risks if the repo is used as a source.

Do not install broad external agent skill packs into this project without explicit approval.

## Metrics To Surface

Useful public metrics:

- number of scenarios
- number of boundary patterns
- number of validated run artifacts
- pass/finding/inconclusive/error counts
- tests passing
- model/runtime comparison results
- baseline-vs-protected finding reduction
- known limitations

Avoid vanity metrics that do not support trust.

## Definition Of Done

A task is done when:

- behavior exists or the research artifact is written
- relevant checks ran
- evidence artifacts are inspectable
- docs or tracker updated if workflow changed
- git status is understood
- remaining gaps are named

"Code was written" is not done.

"An agent said it passed" is not done.

"The README looks bigger" is not done.

## Final Report Format

End substantial work with:

```text
Changed:
Verified:
Artifacts:
Not done:
Git:
Next:
```

Keep it short, factual, and tied to evidence.
