# Installed ecosystem compatibility example

This directory is an explicit, offline operator example, not package auto-discovery.
Use this fixed 1.6.0 example and its locks in a fresh environment.
The scripts use installed distributions, not `src/`, and require no API key or model.

For **published 1.6.0**, start at the repository root with
Python 3.11. Create a fresh environment using `python -m venv .venv`. Activate it
with `.venv\Scripts\Activate.ps1` in PowerShell or `source .venv/bin/activate` in Bash.
Then install the exact public wheels; no local Core build is required:

```bash
python -m pip --isolated install --index-url https://pypi.org/simple --no-compile --only-binary=:all: --require-hashes -r requirements/runtime.txt -r requirements/companions.txt -r examples/installed-ecosystem/core-release.txt
python -m pip check
python -I -B examples/installed-ecosystem/check.py --out result.json
ash quickstart --out installed-quickstart
ash validate installed-quickstart
```

The Core wheel SHA-256 is
`bf393cb3644520a20e9c56d760c0e1ab330ddf8a099e704035a2bdad728a4a45`,
bound to [v1.6.0 publication evidence](../../docs/releases/v1.6.0.md#publication-evidence).
The lock uses the official PyPI file URL from its JSON metadata plus the independently
verified hash, avoiding a fresh-release simple-index lookup delay. It does not add a
second dependency index or relax hash verification.
Companion/runtime dependencies are included in the hash locks, but no transport is
activated. `python -m pip check` must succeed. For general installation the `all`
extra is also available; use this explicit lock route for reproducible binding.

The immutable v1.6.0 tag retains its pre-publication local-build instructions. Its
example code and companion locks are identical; `core-release.txt` is the later
source-owned binding to the published wheel, not a change to that wheel. A future
version requires a separately reviewed version/example/lock update.

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
