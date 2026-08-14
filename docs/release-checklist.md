# Release checklist

Practical preflight for cutting a public research release. The project is **pre-1.0**;
this list is the path toward a stable v1.0 benchmark contract, not a claim that v1.0 is
ready. The broader readiness map is [v1-readiness.md](v1-readiness.md).

## Every release

Run all of these green before tagging:

```bash
python -m pytest -q
python -m ruff check .
python -m mypy src tests tools
ash validate examples/
python -m build --wheel        # optional locally; CI builds and smoke-installs wheel + sdist
```

Then verify by hand:

- [ ] `pyproject.toml` `version`, `__version__`, and the top `CHANGELOG.md` entry agree.
- [ ] `CHANGELOG.md` has a dated section for this version (move items out of `Unreleased`).
- [ ] GitHub release notes are drafted from `CHANGELOG.md`; no future feature is listed as
      shipped.
- [ ] Open security advisories / dependency alerts are reviewed before tagging.
- [ ] `ash --help` lists every command; no command errors on `--help`.
- [ ] A clean installed wheel runs `ash quickstart --out <new-temp-dir>` outside the
      source checkout and produces a valid `run_index.json` plus self-contained
      `report.html` on Ubuntu/Python 3.11-3.13; the Windows compatibility job is green.
- [ ] README "What exists today" / "Current vs planned" match the code (no future feature
      described as current).
- [ ] README status says `public research release` or the exact tagged release status,
      not `pre-release`, unless the release is intentionally being withdrawn from public
      showcase.
- [ ] `docs/project-tracks.md` still keeps the shipped benchmark separate from the future
      LLM Safety Gateway / Runtime Verifier direction.
- [ ] `docs/run-your-model.md` still works as the shortest external operator path for
      deterministic demo, one OpenAI-compatible model, and local mini-swarm runs.
- [ ] Any new research result follows [evidence-pack-format.md](evidence-pack-format.md)
      and the [private/public evidence boundary](private-public-evidence-boundary.md).
- [ ] `docs/current-state.md`, `docs/roadmap.md`, and `docs/capability-matrix.md` agree
      on shipped / experimental / planned status.
- [ ] `docs/authorized-testing-paths.md`, `SECURITY.md`, and adapter docs agree on
      authorized-use boundaries.
- [ ] Counts are current: 24 patterns, 14 categories, target list in `ash targets`.
- [ ] Any README/release/demo showcase satisfies
      [showcase-report-checklist.md](showcase-report-checklist.md).
- [ ] No local-only files staged (e.g. `reports/`, untracked notes).
- [ ] Fake-server E2E passes locally (see below).

The tag-triggered release workflow independently rejects non-canonical tags, mismatched
`pyproject.toml`/`__version__`/CHANGELOG versions, and any failure in pytest, Ruff, mypy, or
committed-artifact validation before building. It builds twice from the same source commit,
normalizes sdist archive metadata to the commit epoch, and requires exact wheel and sdist byte
equality. It then smoke-installs both distributions and publishes SHA-256 checksums with the
Actions artifact. After those gates it requests GitHub/Sigstore
attestations for the exact wheel, sdist, and checksum file, and a separate job verifies the subject
digest plus the expected repository, workflow, tag ref, source commit, issuer, builder, event,
hosted-runner, SLSA-predicate, and verified-time policy.

This workflow definition is not retroactive: existing releases remain unsigned, and the change is
not operationally verified until a future authorized tag run passes the verification job. A green
attestation proves the configured build provenance for the named bytes; it does not prove package
safety, semantic truth, local-model execution, private observation, or reviewer identity. Evidence
registry rows must remain below `signed_attested` until their exact subject and validated
attestation are explicitly bound by a supported registry contract.

The tag workflow now generates a deterministic CycloneDX 1.6 SBOM from exact wheel/sdist
metadata plus the hash-pinned runtime lock. The document records both subject hashes and
source tag/SHA, is covered by `SHA256SUMS`, and is itself attested and independently
verified. This takes effect only on the next authorized tag; older release sets remain
truthfully SBOM-free.

## Fake-server E2E (no external network)

```bash
python examples/fake_openai_server.py            # terminal 1 (Ctrl+C to stop)
ash external-check --base-url http://127.0.0.1:8766/v1 --model fake-model --scenario data-boundary
ash run-external --base-url http://127.0.0.1:8766/v1 --model fake-model --scenario data-boundary --execute --out .internal/external-e2e
ash report --root .internal/external-e2e
ash validate .internal/external-e2e
# stop the server; confirm the port is free
```

## v1.0 blockers (not done yet)

v1.0 means a stable, dependable benchmark. Open blockers:

- [x] **Stable trace schema** - schema 1.0, its closed-field contract, the v0.1 read
      window, migration behavior, and regression fixtures are documented and tested.
- [x] **Stable corpus manifest** - corpus 1.0.0 freezes the 24 ordered pattern ids and
      fields, publishes a closed manifest/schema plus canonical digest, and documents
      explicit deprecation/replacement rules.
- [ ] **Standards mapping review** - verify OWASP LLM / NIST category mappings with a
      second reviewer; re-check the current MITRE ATLAS verified subset against the latest
      official ATLAS release.
- [x] **Real adapter contract** - authorization modes, offline/default behavior, explicit
      execution gates, metadata redaction, and validation requirements are documented and
      tested. Native/provider and tool-executing adapters remain future.
- [x] **Docs pass** - current state, tracker, roadmap, limitations, and v1 readiness agree
      on the integrated contracts and remaining external gates; documentation tests pass.
- [x] **Integrated-main CI matrix confirmed** - exact commit `55aebe9c` passed Ubuntu
      3.11-3.13, Windows 3.11, installed-wheel smokes, build, CodeQL, and secret scan.
- [ ] **Release-tag artifact gate** - the future authorized tag must produce and verify
      exact-subject wheel/sdist/SBOM/checksum attestations. Workflow readiness is not a
      substitute for a completed tag run.
- [x] **GitHub project surface current** - issue templates, PR template, CODEOWNERS,
      governance, support, and maintainer docs match the release scope; the missing second
      reviewer remains explicitly tracked by issue #205.

## Not in scope for v1.0

These remain future tracks (see [roadmap.md](roadmap.md)) and must not be presented as
shipped: native provider adapters, agent-host / tool-use adapters, streaming, a web
report viewer / dashboard, a persistent result database, published Docker images, PyPI
publishing, and any cross-model leaderboard.
