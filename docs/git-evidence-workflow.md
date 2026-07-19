# Git Evidence Workflow

This project treats Git history as part of the benchmark evidence. A change is not
complete because code was written; it is complete when the repository shows what changed,
why it changed, how it was verified, and which public artifact or test proves it.

## Default Flow

Use this flow for meaningful code, research, documentation, and showcase work:

```text
idea -> issue -> branch -> implementation -> tests/artifacts -> PR -> GitHub checks
-> review gate -> merge -> issue closed
```

Small typo fixes can be simpler, but any change that affects behavior, claims, examples,
or public credibility should follow the full flow.

## Required Work Record

Every substantial task should leave these records:

| Record | Purpose |
|---|---|
| GitHub issue | Names the problem, expected output, scope boundaries, and acceptance checks. |
| Branch | Keeps work off `main`; `main` is stable and release-facing. |
| Commit(s) | One coherent logical change per commit. |
| Pull request | Reviewer-facing summary of what changed, what was verified, and what remains open. |
| Artifacts | Traces, scorecards, matrices, reports, docs, or examples that prove the result. |
| Checks | Local checks plus GitHub CI/CodeQL/required checks. |

The PR may contain multiple related commits, but it should still tell one coherent story.

## Before Editing

```bash
git status --short --branch
git log --oneline --decorate --max-count=5
```

Then decide:

- Which issue or task does this work close?
- Is the current branch correct?
- Are there dirty files from another person or agent?
- Which artifacts or docs must change if the behavior changes?
- Which claim boundary must be protected from overclaiming?

Do not edit unrelated dirty files. Do not push directly to `main`.

## Evidence Rules

Use the strongest evidence that matches the change:

| Change type | Required evidence |
|---|---|
| Corpus/pattern behavior | Tests, regenerated examples, `ash validate examples/`. |
| New CLI/artifact | Unit tests, schema/version docs, validation support when applicable. |
| Research/theory | Claim boundary, source map or code mapping, assumptions, non-claims, next step. |
| Local/external model probe | Runtime/model name, scenario set, validation result, evidence-quality limits. |
| Showcase/readme work | Reproduce command, artifact link, explicit non-claims. |
| Git/process work | Linked workflow docs and documentation-contract test coverage. |

Private calculations may guide a public document, but public claims must point to public
or clearly described evidence. Do not commit raw local model text or private scratch data
unless a separate public-artifact policy explicitly allows it.

## Required Local Checks

For broad changes, run:

```bash
python -m pytest -q
python -m ruff check .
python -m mypy src tests tools
python -m agentic_security_harness.cli validate examples
git diff --check
```

For narrow documentation changes, at minimum run the documentation contract tests and
`git diff --check`; run the full suite before pushing when the PR is active or the change
touches public navigation, examples, schemas, or claims.

## Pull Request Body

The PR body should include:

```text
Summary:
- what changed

Issues:
- Closes #...

Claim boundary:
- what is allowed to say
- what is not claimed

Local verification:
- exact commands and results

Artifacts:
- committed examples/docs/reports
- private/local artifacts, if any, clearly marked as not public evidence

Not done:
- honest deferred work
```

Do not report a task as complete if the PR body still says the main acceptance is blocked.

## GitHub Checks And Review Gate

After push, verify GitHub, not only local output:

```bash
gh pr checks <PR_NUMBER> --watch
gh pr view <PR_NUMBER> --json mergeStateStatus,reviewDecision,statusCheckRollup
```

Meaning:

- Green checks mean CI/CodeQL/required automation accepted the branch.
- `REVIEW_REQUIRED` means the repository review gate is working; it is not a test failure.
- A GitHub issue should normally remain open until the PR is merged, even when code is
  already implemented and checks are green.

If GitHub reports code scanning or security issues, inspect the exact finding and fix or
document why it is not applicable. Do not ignore security warnings before research or
release-facing work.

## Definition Of Done

A task is done when:

- the behavior, document, or research artifact exists;
- tests and validators relevant to the change pass;
- examples/artifacts are synchronized when output changed;
- README/project-map/showcase/tracker links are updated when public navigation changed;
- PR body records verification and claim boundaries;
- GitHub checks are green or any remaining gate is explicitly non-code review;
- the issue is linked for closure on PR merge.

Not done:

- "the model/agent said it passed";
- "the code exists but examples are stale";
- "local tests pass but GitHub is red";
- "the issue is closed manually while the PR has not merged";
- "docs make a stronger claim than tests/artifacts prove".
