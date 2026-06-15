# Releasing (PyPI, Docker, devcontainer)

The package is import- and wheel-clean today; this page is the practical path to a public
release. PyPI publishing itself is **future** (a v1.0 step) - do not assume the package is
on PyPI yet. See the gates in [release-checklist.md](release-checklist.md).

## Packaging facts (current)

- `pyproject.toml`: name `agentic-security-harness`, Apache-2.0, `requires-python >=3.11`,
  one runtime dependency (`pydantic`), `Operating System :: OS Independent`, typed
  (`py.typed` shipped in the wheel).
- Console script: `ash = agentic_security_harness.cli:main`.
- License files `LICENSE` and `NOTICE` are included in the wheel.

## Build and verify a wheel

```bash
python -m pip install --upgrade build twine
python -m build                  # builds sdist + wheel in dist/
python -m twine check dist/*     # metadata sanity
# smoke-install the wheel in a clean env:
python -m pip install --force-reinstall dist/*.whl
ash --help
ash validate examples/
```

CI already runs the equivalent build + `twine check` + wheel smoke on every push.

## Publishing to PyPI (future - when v1.0 gates pass)

```bash
# TestPyPI first
python -m twine upload --repository testpypi dist/*
# then PyPI (requires an API token in TWINE_PASSWORD; never commit it)
python -m twine upload dist/*
```

Do this only after: version bumped, CHANGELOG dated, schema/corpus frozen (see
[artifact-schemas.md](artifact-schemas.md)), and the v1.0 blockers in
[release-checklist.md](release-checklist.md) are cleared.

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
