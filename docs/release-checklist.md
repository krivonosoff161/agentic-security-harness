# Release checklist

Practical preflight for cutting a public research release. The stable v1.0 benchmark
contract was released as `v1.0.0` on 2026-08-14; this checklist remains the required
procedure for subsequent releases. The broader readiness map is
[v1-readiness.md](v1-readiness.md).

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
- [ ] `CITATION.cff` version agrees; add `date-released` only in the exact release commit.
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
- [ ] GitHub environments `testpypi` and `pypi` exist with reviewed deployment protection,
      and both package indexes have exact-repository Trusted Publishers configured.
- [ ] The manual package promotion workflow is dispatched only at the exact successful tag,
      first to TestPyPI and then, after evidence review and separate approval, to PyPI.
- [ ] If an upload succeeded but a post-upload observation failed, use the main-only,
      read-only `verify-published-release.yml` workflow; never retry or overwrite the
      immutable package version merely to change historical CI status.

The tag-triggered release workflow independently rejects non-canonical tags, mismatched
`pyproject.toml`/`__version__`/CHANGELOG versions, and any failure in pytest, Ruff, mypy, or
committed-artifact validation before building. It builds twice from the same source commit,
normalizes sdist archive metadata to the commit epoch, and requires exact wheel and sdist byte
equality. It then smoke-installs both distributions and publishes SHA-256 checksums with the
Actions artifact. After those gates it requests GitHub/Sigstore
attestations for the exact wheel, sdist, and checksum file, and a separate job verifies the subject
digest plus the expected repository, workflow, tag ref, source commit, issuer, builder, event,
hosted-runner, SLSA-predicate, and verified-time policy.

This workflow definition is not retroactive: older releases remain unsigned. The `v1.0.0`
tag run passed the build and independent provenance verification jobs. A green
attestation proves the configured build provenance for the named bytes; it does not prove package
safety, semantic truth, local-model execution, private observation, or reviewer identity. Evidence
registry rows must remain below `signed_attested` until their exact subject and validated
attestation are explicitly bound by a supported registry contract.

The tag workflow now generates a deterministic CycloneDX 1.6 SBOM from exact wheel/sdist
metadata plus the hash-pinned runtime lock. The document records both subject hashes and
source tag/SHA, is covered by `SHA256SUMS`, and is itself attested and independently
verified. `v1.0.0` is the first release set carrying this SBOM; older release sets remain
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

## v1.0 technical readiness

v1.0 means a stable, dependable synthetic benchmark contract. Technical gates:

- [x] **Stable trace schema** - schema 1.0, its closed-field contract, the v0.1 read
      window, migration behavior, and regression fixtures are documented and tested.
- [x] **Stable corpus manifest** - corpus 1.0.0 freezes the 24 ordered pattern ids and
      fields, publishes a closed manifest/schema plus canonical digest, and documents
      explicit deprecation/replacement rules.
- [x] **Real adapter contract** - authorization modes, offline/default behavior, explicit
      execution gates, metadata redaction, and validation requirements are documented and
      tested. Native/provider and tool-executing adapters remain future.
- [x] **Docs pass** - current state, tracker, roadmap, limitations, and v1 readiness agree
      on the integrated contracts and remaining external gates; documentation tests pass.
- [x] **Integrated-main CI matrix confirmed** - exact commit `7c5ad061` passed Ubuntu
      3.11-3.13, Windows 3.11, installed-wheel smokes, build, CodeQL, and secret scan.
- [x] **Release execution gate** - tag `v1.0.0` produced and independently verified
      exact-subject wheel/sdist/SBOM/checksum attestations in release run
      [`31827272644`](https://github.com/krivonosoff161/agentic-security-harness/actions/runs/31827272644).
- [x] **GitHub project surface current** - issue templates, PR template, CODEOWNERS,
      governance, support, and maintainer docs match the release scope.

## Non-blocking post-v1 credibility work

- [ ] Independently review the OWASP LLM / NIST mappings and re-check the direct-fit MITRE
      ATLAS subset ([issue #199](https://github.com/krivonosoff161/agentic-security-harness/issues/199)).
- [ ] Add a durable second GitHub reviewer and then strengthen approval rules
      ([issue #205](https://github.com/krivonosoff161/agentic-security-harness/issues/205)).

These tasks improve external confidence but do not invalidate the tested deterministic
benchmark contract. Until they are completed, release material must say that independent
standards review and independent maintainer governance are not claimed.

## Not in scope for v1.0

These remain future tracks (see [roadmap.md](roadmap.md)) and must not be presented as
shipped: native provider adapters, agent-host / tool-use adapters, streaming, a web
report viewer / dashboard, a persistent result database, published Docker images, and any
cross-model leaderboard. PyPI promotion is a release operation, not a shipped runtime
capability; it remains false until the exact package-index gates complete.
