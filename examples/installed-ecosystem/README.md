# Installed ecosystem compatibility example

This directory is an explicit, offline operator example, not package auto-discovery.
Use the repository checkout matching the selected release and a fresh environment.
The scripts use installed distributions, not `src/`, and require no API key or model.

For the **1.6.0 candidate** before publication, start at the repository root with
Python 3.11. Create a fresh environment using `python -m venv .venv`. Activate it
with `.venv\Scripts\Activate.ps1` in PowerShell or `source .venv/bin/activate` in Bash.
Then build and install the candidate:

```bash
python -m pip install --require-hashes -r requirements/build.txt
python -m build --no-isolation --wheel --outdir dist
python -m pip install --require-hashes -r requirements/runtime.txt
python -m pip install --no-compile --only-binary=:all: --require-hashes -r requirements/companions.txt
python -m pip install --no-index --no-deps --no-compile dist/agentic_security_harness-1.6.0-py3-none-any.whl
python -m pip check
python -I -B examples/installed-ecosystem/check.py --out result.json
ash quickstart --out installed-quickstart
ash validate installed-quickstart
```

The currently published baseline remains 1.5.1 until the separate publication gates
pass. Companion runtime dependencies
are included in the hash lock, but no transport is activated. `python -m pip check`
must succeed. For general installation use the documented `all` extra after publication.

`--no-compile` is intentional for the two extensions: their strict distribution
inspection requires hashed `RECORD` entries. Pip-generated `.pyc` entries have no
hash/size and are refused, even though installation itself succeeded. Use a **new**
environment; this command is not a repair of an already byte-compiled installation.
Do not delete evidence or weaken the verifier to force acceptance.

Expected: `ok: true`, both positive extension projections accepted, incomplete Transfer
telemetry inconclusive, missing Handoff artifact binding reported as a finding, native
Ollama-shaped public fixtures independently admitted/denied/rejected without transport.
The output contains only versions, typed outcomes, digests and counters. An existing
output file is never overwritten. The same command works in Windows PowerShell and Bash.

Early Python audit hooks refuse socket and process activity. They are not an OS sandbox.
No provider, model, credential, live tool or target is accessed. A passing example does
not authenticate a producer, measure classifier quality, certify a model, or prove
production safety. Router/Filter are passive imports here; Playbooks is a pinned data
pack, not an action authorizer. Installing all components is not a universal pipeline.

See [the external pilot protocol](../../docs/external-pilot.md) for sharing results.
