# Release checklist

Practical preflight for cutting a release. The project is **pre-1.0**; this list is the
path toward a stable v1.0, not a claim that v1.0 is ready.

## Every release

Run all of these green before tagging:

```bash
python -m pytest -q
python -m ruff check .
python -m mypy src tests
ash validate examples/
python -m build --wheel        # optional locally; CI builds + twine-checks
```

Then verify by hand:

- [ ] `pyproject.toml` `version`, `__version__`, and the top `CHANGELOG.md` entry agree.
- [ ] `CHANGELOG.md` has a dated section for this version (move items out of `Unreleased`).
- [ ] GitHub release notes are drafted from `CHANGELOG.md`; no future feature is listed as
      shipped.
- [ ] Open security advisories / dependency alerts are reviewed before tagging.
- [ ] `ash --help` lists every command; no command errors on `--help`.
- [ ] README "What exists today" / "Current vs planned" match the code (no future feature
      described as current).
- [ ] Counts are current: 22 patterns, 14 categories, target list in `ash targets`.
- [ ] No local-only files staged (e.g. `reports/`, untracked notes).
- [ ] Fake-server E2E passes locally (see below).

## Fake-server E2E (no external network)

```bash
python examples/fake_openai_server.py            # terminal 1 (Ctrl+C to stop)
ash external-check --base-url http://127.0.0.1:8766/v1 --model fake-model --scenario data-boundary
ash run-external  --base-url http://127.0.0.1:8766/v1 --model fake-model --scenario data-boundary --out reports/e2e
ash report --root reports/e2e
ash validate reports/e2e
# stop the server; confirm the port is free
```

## v1.0 blockers (not done yet)

v1.0 means a stable, dependable benchmark. Open blockers:

- [ ] **Stable trace schema** - freeze `schema_version` and document the compatibility
      policy.
- [ ] **Stable corpus manifest** - freeze pattern ids and the corpus fields; document a
      deprecation policy for renames.
- [ ] **Standards mapping review** - verify OWASP LLM / NIST category mappings with a
      second reviewer; decide MITRE ATLAS (currently deferred).
- [ ] **Real adapter contract** - finalise the contract for non-synthetic adapters
      (still future; see [adapter-contract.md](adapter-contract.md)).
- [ ] **Docs pass** - every doc cross-reference resolves; no stale counts; limitations
      page current.
- [ ] **CI matrix confirmed** - Ubuntu (3.11-3.13) + Windows green on the release commit.
- [ ] **GitHub project surface current** - issue templates, PR template, CODEOWNERS,
      governance, support, and maintainer docs still match the release scope.

## Not in scope for v1.0

These remain future tracks (see [roadmap.md](roadmap.md)) and must not be presented as
shipped: native provider adapters, agent-host / tool-use adapters, streaming, a web
report viewer / dashboard, a persistent result database, Docker images, PyPI publishing,
and any cross-model leaderboard.
