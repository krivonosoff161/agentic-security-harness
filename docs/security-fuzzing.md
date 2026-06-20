# Security Fuzzing

This repository uses ClusterFuzzLite for bounded fuzzing of parser and artifact-validation
surfaces.

## Current Targets

| Target | Surface | Why it matters |
| --- | --- | --- |
| `external_decision_fuzzer.py` | External-model JSON decision parsing and outcome classification. | External model output is untrusted evidence and must not crash or bypass deterministic classification. |
| `artifact_validation_fuzzer.py` | `ash validate` report, external-run, and run-diff artifact loading. | Committed or user-supplied artifacts are untrusted input to the validation/reporting path. |

## Execution

Pull requests that touch fuzzing, runtime requirements, source, or tests trigger
`.github/workflows/clusterfuzzlite.yml`.

The workflow is intentionally bounded:

- Python fuzzing through ClusterFuzzLite/Atheris.
- Short PR fuzzing budget (`120` seconds) to keep CI cost low.
- No secrets, no live model calls, no network calls from fuzz targets.
- Runtime dependencies are installed from `requirements/runtime.txt` with
  `--require-hashes`.
- GitHub Actions and the ClusterFuzzLite base image are pinned.

## Local Smoke

The fuzz targets expose `fuzz_one_input(data: bytes)` functions so they can be smoke-tested
without Atheris:

```powershell
python -m pytest tests/test_fuzzing_integration.py
```

Full ClusterFuzzLite execution is expected to run in GitHub Actions.

