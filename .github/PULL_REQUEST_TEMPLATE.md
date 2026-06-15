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
- [ ] Does not describe future work as shipped behavior.
- [ ] Does not claim certification, complete protection, or benchmark-grade leaderboard results.
- [ ] If this changes corpus behavior, it preserves the vulnerable-vs-protected measurement model.

## Evidence

- [ ] `python -m pytest`
- [ ] `python -m ruff check .`
- [ ] `python -m mypy src tests`
- [ ] `ash validate examples/`
- [ ] `git diff --check`

## Artifacts and docs

- [ ] `CHANGELOG.md` updated under `[Unreleased]`.
- [ ] Examples regenerated and validated if output changed.
- [ ] README / docs updated if current-vs-planned behavior changed.
- [ ] New research patterns follow the project-map structure:
      `problem -> scenario -> expected behavior -> detection signal -> mitigation -> harness test -> residual risk`.
