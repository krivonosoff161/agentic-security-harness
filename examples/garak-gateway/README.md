# garak plan → Harness Gateway example

An independent, experimental Harness connector example. **Not an official NVIDIA/garak
integration.** Source candidate only: published Harness 1.6.0 does not contain the new
adapter. [Contract and Python API](../../docs/garak-plan-connector.md).

The same fixed public-synthetic plan reaches the actual garak detector and the separate
strict Harness adapter/Connector/Gateway. No model, provider, real tool, listener or
network target is used in the run. Network is used explicitly during dependency/source
setup only. The allowed case executes one built-in constant lookup; all other cases
execute zero tools. The Gateway's policy is unchanged.

## Run (Python 3.11, Linux x86_64 / Windows AMD64)

Create/activate a fresh venv in a checkout of this source candidate, then:

```text
python -m pip --isolated install --only-binary=:all: --require-hashes -r requirements/build.txt -r requirements/runtime.txt -r examples/garak-gateway/requirements-smoke.txt
python -m build --no-isolation --wheel --outdir dist
python -m pip --isolated install --no-index --no-deps --no-compile dist/agentic_security_harness-1.6.0-py3-none-any.whl
python -I -B examples/garak-gateway/prepare_source.py --out upstream-source
python -I -B examples/garak-gateway/check.py --out garak-observation.json --garak-source upstream-source/garak-ac4c5567f0c17834aace52b14788c1ca3548738b
python -I -B examples/garak-gateway/verify.py garak-observation.json --require-detector
```

The locally built wheel is a **candidate with the repository's current version**, not
a replacement for the published 1.6.0 artifact. Do not upload it. Output and sibling
scratch paths must be new; failed evidence is not overwritten. Keep source archives,
scratch logs and generated files outside commits. Omitting `--garak-source` runs only
the Harness path and records `detector_status=not_run`; it is not garak compatibility.
Verification with `--require-detector` rejects such a report.

| Fixed case | Detector observation | Harness path | Synthetic executions |
|---|---|---|---|
| allowed | 0.0 / no hit | admit → allow | 1 |
| forbidden | 1.0 / hit | admit → deny unknown tool | 0 |
| unparseable | 0.0 / no hit | normalization rejects; Gateway not evaluated | 0 |
| argument-boundary | 0.0 / no hit | admit → deny arguments | 0 |

These are the checker's expected finite controls, not model success rates. The selected
garak PR is unmerged; `manifest.json` pins its archive, package tree and named detector
import dependencies. Only this source detector is exercised, not the full distribution
or a garak campaign. All upstream copyright/license files remain in the downloaded tree.
Archive link entries are never followed: the sole pinned calibration link is retained
as inert text, as Python's ZIP extractor materializes it. That calibration path is not
used by the named detector. The package-tree digest sorts relative paths case-sensitively
on both platforms; it describes this archive materialization, not a Git symlink checkout.
Pre-existing bytecode/cache entries are rejected before import, not excluded from the pin.

The committed [Windows observation](observation.windows.json) records the actual four-case
named-detector run on 2026-09-27, including ten scratch housekeeping write events and zero
network/process attempts. Verify it without installing garak:

```text
python -I -B examples/garak-gateway/verify.py examples/garak-gateway/observation.windows.json --require-detector
```

Fresh Linux/Windows observations are also uploaded by the
[optional compatibility workflow](../../.github/workflows/garak-connector.yml).

The stdlib verifier checks the separate statuses, counts and commitments. It does not
import the adapter or detector. Python audit counts cover denied attempts, not universal
OS isolation. garak's own import housekeeping is redirected to fresh scratch and counted;
only the content-free observation is a public artifact. No response repair or model retry
occurs. A future real-model campaign needs a separate manifest and call budget.

Initial local setup observation: clearing every Windows environment entry produced an
`OSError` before case completion. The failed artifact was retained. The corrected runner
retains only `SystemRoot` and redirects user/config/cache/temp paths; all four actual
detector cases then completed with one pure lookup and no network/process attempts.
Linux/Windows exact-head CI is the cross-platform gate, not this local observation alone.
Additional development checks caught an overly strict import-origin check, platform-dependent
tree ordering and rejection of that inert archive link. These were harness/setup corrections,
not detector failures or successful model observations; no failed local artifact was overwritten.
