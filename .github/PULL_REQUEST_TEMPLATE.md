## Summary

Describe the change and why it belongs in Agentic Security Harness.

## Change type

- [ ] Documentation / positioning
- [ ] Benchmark methodology
- [ ] Corpus pattern
- [ ] Target adapter
- [ ] CLI / reporting / validation
- [ ] Tests / CI / packaging

## Safety and scope

- [ ] Uses only synthetic/mock/authorized targets.
- [ ] Adds no real secrets, credentials, private endpoints, or live target details.
- [ ] Adds no raw prompts, raw model/tool output, private evidence, or machine-local paths.
- [ ] Does not describe future work as shipped behavior.
- [ ] Does not claim certification, complete protection, or benchmark-grade leaderboard results.
- [ ] If this changes corpus behavior, it preserves the vulnerable-vs-protected measurement model.

## Model or agent assistance

- [ ] No external model/agent assistance was used, or it is declared below.
- [ ] Any assisted task used only public, synthetic, or sanitized inputs.
- [ ] Provider/model class, bounded task purpose, and source/license review are recorded
      without committing prompts, responses, credentials, or private evidence.
- [ ] Deterministic code/tests own counts, metrics, and verdicts; model output is not an
      approval, authority grant, or independent human review.

Assistance/provenance summary:

<!-- `none`, or a secret-safe summary. Never paste prompts, responses, keys, or private paths. -->

## Evidence

- [ ] `python -m pytest`
- [ ] `python -m ruff check .`
- [ ] `python -m mypy src tests tools`
- [ ] `ash validate examples/`
- [ ] Gitleaks secret scan
- [ ] `git diff --check`

## Artifacts and docs

- [ ] `CHANGELOG.md` updated under `[Unreleased]`.
- [ ] Examples regenerated and validated if output changed.
- [ ] README / docs updated if current-vs-planned behavior changed.
- [ ] New research patterns follow the project-map structure:
      `problem -> scenario -> expected behavior -> detection signal -> mitigation -> harness test -> residual risk`.
