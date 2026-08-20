# Releasing (PyPI, Docker, devcontainer)

The package is published as `1.0.0` on
[PyPI](https://pypi.org/project/agentic-security-harness/1.0.0/). This page documents the
manual, environment-gated OIDC promotion path used for that release and required for
future releases. See the gates in [release-checklist.md](release-checklist.md).

## Packaging facts (current)

- `pyproject.toml`: name `agentic-security-harness`, Apache-2.0, `requires-python >=3.11`,
  one runtime dependency (`pydantic`), `Operating System :: OS Independent`, typed
  (`py.typed` shipped in the wheel).
- Console script: `ash = agentic_security_harness.cli:main`.
- License files `LICENSE` and `NOTICE` are included in the wheel.

## Build and verify release subjects

```bash
python -m pip install --require-hashes -r requirements/build.txt
python -m build --no-isolation  # builds sdist + wheel in dist/
# smoke-install the wheel in a clean env:
python -m pip install --force-reinstall dist/*.whl
ash --help
ash validate examples/
```

CI reproducibly builds and smoke-installs the wheel. The tag-only release workflow also
builds and compares wheel/sdist twice, emits a deterministic CycloneDX 1.6 SBOM bound to
their exact SHA-256 values and the hash-pinned runtime lock, includes the SBOM in
`SHA256SUMS`, and attests all four release subjects. Release `v1.0.0` exercised this
contract successfully; it is not retroactive evidence for older releases.

## Publishing to TestPyPI and PyPI

`.github/workflows/publish-pypi.yml` is a manual `workflow_dispatch` workflow. It accepts
an exact canonical release tag, the successful tag-triggered `release.yml` run id, and one
closed target (`testpypi` or `pypi`). It can run only when the workflow itself is selected
at the exact tag ref. Promotion remains a separate owner action and uses PyPI Trusted
Publishing (short-lived GitHub OIDC), never a repository token or local
`TWINE_PASSWORD`.

Before first use, configure two protected GitHub environments named exactly `testpypi`
and `pypi`, then configure matching Trusted Publishers at the package indexes. Environment
reviewers and deployment protection rules are repository settings, not code, and must be
confirmed in GitHub before dispatch. A workflow file cannot reserve the package name or
prove that those external settings exist.

The workflow downloads only the artifact produced by the named successful tag-triggered
release run, verifies its checksums and GitHub attestations against the selected tag/SHA,
and copies only the wheel and sdist into the upload directory. It never rebuilds package
bytes during promotion.

### TestPyPI gate

- exact tag, package version, package `__version__`, and dated changelog entry agree;
- trace/corpus contracts and all v1 blockers required by the release decision are closed;
- release CI, reproducible builds, installed sdist/wheel smoke, committed-artifact
  validation, SBOM generation, checksums, attestations, and independent provenance policy
  verification are green on that tag;
- the protected `testpypi` GitHub environment has an owner-approved Trusted Publisher and
  required reviewers; no long-lived package credential is stored;
- upload only the already-attested wheel and sdist from the tag workflow, then install the
  exact version from TestPyPI in a clean Linux environment and run `ash quickstart`,
  `ash --help`, and artifact validation;
- record the TestPyPI project URL, exact file hashes, install command/result, and rollback
  decision. A failed or ambiguous smoke blocks PyPI; it never triggers an automatic retry.

### PyPI promotion gate

- require a new explicit owner approval after TestPyPI evidence is reviewed;
- use a separate protected `pypi` environment/Trusted Publisher with no broad workflow
  trigger; the release job must be tag-only and exact-SHA bound;
- require PyPI filename/hash equality with the attested TestPyPI-approved wheel/sdist;
- clean-install the published exact version on Linux Python 3.11-3.13 and Windows 3.11,
  run the quickstart and validator, then publish release notes linking checksums, SBOM and
  provenance evidence;
- package indexes are immutable: a bad upload is corrected only by a new version. Never
  overwrite, delete-and-reuse, or silently rebuild the same version.

The production branch of the workflow reads TestPyPI's official JSON metadata and requires
exact filename/SHA-256 equality with the attested wheel and sdist before requesting a PyPI
OIDC token. After upload it smoke-installs the exact version on Linux Python 3.11-3.13 and
Windows Python 3.11.

For `v1.0.0`, both package indexes expose wheel/sdist SHA-256 values identical to the
attested GitHub Release subjects. The first promotion runs uploaded successfully but their
post-upload verifier falsely included action-generated `*.publish.attestation` sidecars in
the expected package-file set. Independent index-hash checks and clean installed-package
quickstarts passed; the verifier now restricts comparison to wheel and sdist subjects.

### Read-only verification of an existing release

Historical GitHub Actions runs are immutable, and package indexes do not permit replacing
an existing version. Do not rerun an upload to make an old status green. Instead,
`.github/workflows/verify-published-release.yml` provides a manual, main-only verification
path for an already published tag. It has no environment, OIDC token, package-index
credential, or write permission.

Given the exact release tag and successful tag-triggered `release.yml` run id, it:

- checks out the tag and binds it to the successful source workflow and non-draft GitHub
  Release;
- downloads the immutable GitHub Release asset set, verifies `SHA256SUMS`, and revalidates
  all four GitHub/Sigstore attestations against the tag commit and pinned release workflow;
- requires exact wheel/sdist filename and SHA-256 equality on both TestPyPI and PyPI;
- clean-installs the exact published version from TestPyPI on Linux and from PyPI on Linux
  Python 3.11-3.13 plus Windows Python 3.11, then runs `ash --help`, `ash quickstart`, and
  `ash validate`.

A successful verification run adds current read-only evidence. It does not rewrite the
historical promotion runs, republish the package, or grant deployment/enforcement
authority.

## Docker (local/offline CLI + fake-server demo)

A `Dockerfile` builds a local, offline image. No secrets, no network at runtime by
default; the external path stays opt-in.

```bash
docker build -t ash .
docker run --rm ash                                   # runs `ash doctor`
docker run --rm -v "$PWD/reports:/work/reports" ash \
  ash run --target toy-rag --out reports/demo         # writes to a mounted volume
docker run --rm -p 8766:8766 ash \
  python /app/examples/fake_openai_server.py          # the fake model server
```

The image installs only the package (and `pydantic`); `tests/` and `docs/` are excluded
via `.dockerignore`.

## Devcontainer

`.devcontainer/devcontainer.json` provides a minimal Python 3.12 dev environment that
installs the dev extras and runs `ash doctor` on create. No secrets are baked in.
