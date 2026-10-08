# Installed ecosystem compatibility example

This directory is an explicit, offline operator example, not package auto-discovery.
Use the current 1.13.0 route below in a fresh environment; historical 1.12.0, 1.11.0, 1.10.1, 1.9.1,
1.9.0, 1.8.0, 1.7.1, 1.7.0 and 1.6.0 routes and their immutable locks are retained separately.
The scripts use installed distributions, not `src/`, and require no API key or model.

For **published 1.13.0**, pass `--core-version 1.13.0` explicitly
to check.py, chain.py, verify_chain.py and check_supplied_input.py. The default and
core-release.txt remain the immutable published 1.6.0 contour; a reported version
never selects its own verification policy. The caller-input regression also checks
that bounded.digest is unavailable by default and can be explicitly mapped only
to the Gateway's existing pure SHA-256 operation. Model bytes cannot enable it.

The [2026-09-27 generalization report](../../docs/proposal-generalization-20260927.md)
distinguishes four exact useful model proposals from one permitted but semantically
wrong operation, three rejected useful-task proposals and eight negative controls.

## Current published 1.13.0

Create a fresh Python 3.11 environment with `python -m venv .venv-v1130`.
Activate `.venv-v1130\Scripts\Activate.ps1` in PowerShell or
`source .venv-v1130/bin/activate` in Bash. From the repository root, install
the exact PyPI wheel with hash-locked dependencies, then run the fixed offline
installed checks:

```bash
python -m pip --isolated install --index-url https://pypi.org/simple --no-compile --only-binary=:all: --require-hashes -r requirements/runtime.txt -r requirements/companions.txt -r examples/installed-ecosystem/core-release-v1.13.0.txt
python -m pip check
python -I -B examples/installed-ecosystem/check.py --out result.json --core-version 1.13.0
python -I -B examples/installed-ecosystem/chain.py --out functional-chain.json --core-version 1.13.0
python -I -B examples/installed-ecosystem/verify_chain.py functional-chain.json --core-version 1.13.0
python -I -B examples/installed-ecosystem/check_supplied_input.py --out supplied-input.json --core-version 1.13.0
ash quickstart --out installed-quickstart
ash validate installed-quickstart
```

[Publication evidence](../../docs/releases/v1.13.0.md) binds the reviewed
source, attested subjects and exact-wheel installation checks. These offline
compatibility examples do not replay the separate local-model observations.
For document jobs, host review and bounded workflow plans, follow the
[document workflow guide](../../docs/document-workflow.md) and
[clean-install replay protocol](../../docs/document-workflow-replay.md).

## Historical published 1.12.0

Create a fresh Python 3.11 environment with `python -m venv .venv-v1120`.
Activate `.venv-v1120\Scripts\Activate.ps1` in PowerShell or
`source .venv-v1120/bin/activate` in Bash. From the repository root, install
the exact PyPI wheel with hash-locked dependencies, then run the fixed offline
installed checks:

```bash
python -m pip --isolated install --index-url https://pypi.org/simple --no-compile --only-binary=:all: --require-hashes -r requirements/runtime.txt -r requirements/companions.txt -r examples/installed-ecosystem/core-release-v1.12.0.txt
python -m pip check
python -I -B examples/installed-ecosystem/check.py --out result.json --core-version 1.12.0
python -I -B examples/installed-ecosystem/chain.py --out functional-chain.json --core-version 1.12.0
python -I -B examples/installed-ecosystem/verify_chain.py functional-chain.json --core-version 1.12.0
python -I -B examples/installed-ecosystem/check_supplied_input.py --out supplied-input.json --core-version 1.12.0
ash quickstart --out installed-quickstart
ash validate installed-quickstart
```

[Publication evidence](../../docs/releases/v1.12.0.md) binds the reviewed
source, attested subjects and seven-job read-only cross-index installation
matrix. These deterministic examples make no new model-reliability claim.
For the new document workflow, follow the [first-job guide](../../docs/document-workflow.md#first-job).

## Historical published 1.11.0

Create a fresh Python 3.11 environment with `python -m venv .venv-v1110`.
Activate `.venv-v1110\Scripts\Activate.ps1` in PowerShell or
`source .venv-v1110/bin/activate` in Bash. From the repository root, install
the exact PyPI wheel with hash-locked dependencies, then run the fixed offline
installed checks:

```bash
python -m pip --isolated install --index-url https://pypi.org/simple --no-compile --only-binary=:all: --require-hashes -r requirements/runtime.txt -r requirements/companions.txt -r examples/installed-ecosystem/core-release-v1.11.0.txt
python -m pip check
python -I -B examples/installed-ecosystem/check.py --out result.json --core-version 1.11.0
python -I -B examples/installed-ecosystem/chain.py --out functional-chain.json --core-version 1.11.0
python -I -B examples/installed-ecosystem/verify_chain.py functional-chain.json --core-version 1.11.0
python -I -B examples/installed-ecosystem/check_supplied_input.py --out supplied-input.json --core-version 1.11.0
ash quickstart --out installed-quickstart
ash validate installed-quickstart
```

[Historical publication evidence](../../docs/releases/v1.11.0.md) binds the tag,
wheel, index descriptions and the separate seven-job read-only installation
matrix. The initial production Linux 3.11 index lookup failed before package
execution; no build or upload was repeated. These deterministic examples make
no new model-reliability claim. The default and `core-release.txt` remain
pinned to the immutable 1.6.0 contour.

### Optional configured document output

Use `ash workspace-check`, `ash workspace-write` and `ash workspace-verify`
for the [host-configured text writer](../../docs/guarded-workspace-writer.md).
The host chooses output aliases and filenames; the proposal supplies text only.
This creates a new real file, unlike the no-effect compatibility baseline.

## Historical published 1.10.1

Create a fresh Python 3.11 environment with `python -m venv .venv-v1101`.
Activate `.venv-v1101\Scripts\Activate.ps1` in PowerShell or
`source .venv-v1101/bin/activate` in Bash. From the repository root, install
the exact published wheel with hash-locked dependencies, then run the fixed
public-synthetic installed checks without a model or real external effects:

```bash
python -m pip --isolated install --index-url https://pypi.org/simple --no-compile --only-binary=:all: --require-hashes -r requirements/runtime.txt -r requirements/companions.txt -r examples/installed-ecosystem/core-release-v1.10.1.txt
python -m pip check
python -I -B examples/installed-ecosystem/check.py --out result.json --core-version 1.10.1
python -I -B examples/installed-ecosystem/chain.py --out functional-chain.json --core-version 1.10.1
python -I -B examples/installed-ecosystem/verify_chain.py functional-chain.json --core-version 1.10.1
python -I -B examples/installed-ecosystem/check_supplied_input.py --out supplied-input.json --core-version 1.10.1
ash quickstart --out installed-quickstart
ash validate installed-quickstart
```

[Publication evidence](../../docs/releases/v1.10.1.md) binds the exact source,
wheel, index descriptions and Linux/Windows read-only installation matrix.
These deterministic checks do not repeat the six local Qwen2.5 1.5B replies or
turn them into published-wheel model evidence. The default and `core-release.txt`
remain pinned to the immutable 1.6.0 contour.

### Optional actual file-effect benchmark

The compatibility checks above have no real file effects beyond their named output
artifacts. The controlled-file workflow deliberately writes an allowed report in a
fresh public-synthetic fixture. Run it only with a new output directory whose parent
already exists, then verify disk and ancestry evidence:

```bash
ash controlled-file-workflow --out fresh-file-run
ash controlled-file-verify --out fresh-file-run
```

This is separate from the no-effect compatibility baseline. The verifier reports
integrity and report correctness separately; see the
[workflow contract](../../docs/controlled-file-workflow.md).

## Historical published 1.9.1

Create a fresh Python 3.11 environment with `python -m venv .venv-v191`.
Activate `.venv-v191\Scripts\Activate.ps1` in PowerShell or
`source .venv-v191/bin/activate` in Bash. From the repository root, install
the exact published wheel with hash-locked dependencies, then run the fixed
public-synthetic installed checks without a model or real effects:

```bash
python -m pip --isolated install --index-url https://pypi.org/simple --no-compile --only-binary=:all: --require-hashes -r requirements/runtime.txt -r requirements/companions.txt -r examples/installed-ecosystem/core-release-v1.9.1.txt
python -m pip check
python -I -B examples/installed-ecosystem/check.py --out result.json --core-version 1.9.1
python -I -B examples/installed-ecosystem/chain.py --out functional-chain.json --core-version 1.9.1
python -I -B examples/installed-ecosystem/verify_chain.py functional-chain.json --core-version 1.9.1
python -I -B examples/installed-ecosystem/check_supplied_input.py --out supplied-input.json --core-version 1.9.1
ash quickstart --out installed-quickstart
ash validate installed-quickstart
```

[Publication evidence](../../docs/releases/v1.9.1.md) binds the exact wheel,
source, both index descriptions and read-only install matrix. This patch does
not repeat the historical 1.6.0 model study or the separate 1.9.0
installed-candidate observation. The default and `core-release.txt` remain
pinned to the immutable 1.6.0 contour.

### Optional actual file-effect benchmark

The compatibility checks above have no real file effects beyond their named output
artifacts. Separately, the controlled-file workflow from 1.9.0 deliberately writes
an allowed report in a newly created public-synthetic fixture. Run it only with a
fresh output directory whose parent already exists, then verify disk/history data:

```bash
ash controlled-file-workflow --out fresh-file-run
ash controlled-file-verify --out fresh-file-run
```

This is not part of the no-effect compatibility baseline; the verifier measures
report correctness and protected-file integrity separately. See the
[workflow contract](../../docs/controlled-file-workflow.md).

## Historical published 1.9.0

Create a fresh Python 3.11 environment with `python -m venv .venv-v190`.
Activate `.venv-v190\Scripts\Activate.ps1` in PowerShell or
`source .venv-v190/bin/activate` in Bash. From the repository root, install
the exact published wheel with hash-locked dependencies, then run the fixed
public-synthetic installed checks without a model or real effects:

```bash
python -m pip --isolated install --index-url https://pypi.org/simple --no-compile --only-binary=:all: --require-hashes -r requirements/runtime.txt -r requirements/companions.txt -r examples/installed-ecosystem/core-release-v1.9.0.txt
python -m pip check
python -I -B examples/installed-ecosystem/check.py --out result.json --core-version 1.9.0
python -I -B examples/installed-ecosystem/chain.py --out functional-chain.json --core-version 1.9.0
python -I -B examples/installed-ecosystem/verify_chain.py functional-chain.json --core-version 1.9.0
python -I -B examples/installed-ecosystem/check_supplied_input.py --out supplied-input.json --core-version 1.9.0
ash quickstart --out installed-quickstart
ash validate installed-quickstart
```

[Publication evidence](../../docs/releases/v1.9.0.md) binds the exact wheel,
source and index subjects. This compatibility route does not replay the historical
1.6.0 model study or the separate 1.9.0 installed-candidate observation. The
default and `core-release.txt` remain pinned to the immutable 1.6.0 contour.

### Optional actual file-effect benchmark

The compatibility checks above have no real file effects beyond their named output
artifacts. Separately, the 1.9.0 controlled-file workflow deliberately writes an
allowed report in a newly created public-synthetic fixture. Run it only with a
fresh output directory whose parent already exists, then verify disk/history data:

```bash
ash controlled-file-workflow --out fresh-file-run
ash controlled-file-verify --out fresh-file-run
```

This is not part of the no-effect compatibility baseline; the verifier measures
report correctness and protected-file integrity separately. See the
[workflow contract](../../docs/controlled-file-workflow.md).

## Historical published 1.8.0

Create a fresh Python 3.11 environment with `python -m venv .venv-v180`.
Activate `.venv-v180\Scripts\Activate.ps1` in PowerShell or
`source .venv-v180/bin/activate` in Bash. From the repository root, install
the exact published wheel and hash-locked dependencies, then run the installed
APIs with fixed public synthetic inputs and no model or real effects:

```bash
python -m pip --isolated install --index-url https://pypi.org/simple --no-compile --only-binary=:all: --require-hashes -r requirements/runtime.txt -r requirements/companions.txt -r examples/installed-ecosystem/core-release-v1.8.0.txt
python -m pip check
python -I -B examples/installed-ecosystem/check.py --out result.json --core-version 1.8.0
python -I -B examples/installed-ecosystem/chain.py --out functional-chain.json --core-version 1.8.0
python -I -B examples/installed-ecosystem/verify_chain.py functional-chain.json --core-version 1.8.0
python -I -B examples/installed-ecosystem/check_supplied_input.py --out supplied-input.json --core-version 1.8.0
ash quickstart --out installed-quickstart
ash validate installed-quickstart
```

Wheel SHA-256: `3cee43202117a062710a0a12cb660dc7f211f610a8c691c826e8adeead18aa14`.
[Publication evidence](../../docs/releases/v1.8.0.md) binds the file to the
attested tag build and both indexes. The first production Linux 3.11
simple-index lookup failed before application checks; a separate read-only
cross-index run passed all seven jobs without re-upload. This route is package
compatibility evidence, not a replay of the historical 1.6.0 model study.

## Historical published 1.7.1

Create a fresh Python 3.11 environment with `python -m venv .venv-v171`.
Activate `.venv-v171\Scripts\Activate.ps1` in PowerShell or
`source .venv-v171/bin/activate` in Bash. Install the exact published wheel and
hash-locked dependencies, then check the installed
APIs with fixed public synthetic inputs and no model or real effects:

```bash
python -m pip --isolated install --index-url https://pypi.org/simple --no-compile --only-binary=:all: --require-hashes -r requirements/runtime.txt -r requirements/companions.txt -r examples/installed-ecosystem/core-release-v1.7.1.txt
python -m pip check
python -I -B examples/installed-ecosystem/check.py --out result.json --core-version 1.7.1
python -I -B examples/installed-ecosystem/chain.py --out functional-chain.json --core-version 1.7.1
python -I -B examples/installed-ecosystem/verify_chain.py functional-chain.json --core-version 1.7.1
python -I -B examples/installed-ecosystem/check_supplied_input.py --out supplied-input.json --core-version 1.7.1
ash quickstart --out installed-quickstart
ash validate installed-quickstart
```

Wheel SHA-256: `3cf26abd2adc79e860d77969112e47aaeb1a50c03a3aed459b2830116d6bc110`.
[Publication evidence](../../docs/releases/v1.7.1.md#publication-evidence) binds
the file to the attested build and both indexes. The final read-only run passed
Linux/Windows installation checks; initial index lookup failures remain recorded.
This is package compatibility evidence, not a new model experiment.

## Historical published 1.7.0

From this repository checkout, create a fresh Python 3.11 environment with
`python -m venv .venv`. Activate it with `.venv\Scripts\Activate.ps1` in PowerShell
or `source .venv/bin/activate` in Bash. Install only the hash-locked published wheels:

```bash
python -m pip --isolated install --index-url https://pypi.org/simple --no-compile --only-binary=:all: --require-hashes -r requirements/runtime.txt -r requirements/companions.txt -r examples/installed-ecosystem/core-release-v1.7.0.txt
python -m pip check
python -I -B examples/installed-ecosystem/check.py --out result.json --core-version 1.7.0
python -I -B examples/installed-ecosystem/chain.py --out functional-chain.json --core-version 1.7.0
python -I -B examples/installed-ecosystem/verify_chain.py functional-chain.json --core-version 1.7.0
python -I -B examples/installed-ecosystem/check_supplied_input.py --out supplied-input.json --core-version 1.7.0
ash quickstart --out installed-quickstart
ash validate installed-quickstart
```

The 1.7.0 wheel hash is
`87210392f1596477008bd78fdc71229047b863f42b3a459c6f9222508043a6eb`;
[release evidence](../../docs/releases/v1.7.0.md#publication-evidence) binds both
indexes to the exact attested subject. This is a new explicit installation route,
not a rerun or rebinding of the historical model observations on 1.6.0.

## Historical published 1.6.0

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

## Functional six-component chain

The original `check.py` remains the eight-case installation baseline above. The
separate `chain.py` exercises actual installed APIs in a single causally linked
public-synthetic flow, not just passive imports:

```bash
python -I -B examples/installed-ecosystem/chain.py --out functional-chain.json --core-version 1.13.0
python -I -B examples/installed-ecosystem/verify_chain.py functional-chain.json --core-version 1.13.0
```

Run these after the current 1.13.0 exact-wheel installation above; use fresh output
paths if you already ran that section. For the historical 1.6.0 environment, omit
`--core-version` (its default stays 1.6.0). The example itself is
repository-owned and version-bound; it is not a new wheel or a change to the
immutable 1.6.0 release. No credentials or account configuration are used.

| Component | Executed boundary |
|---|---|
| Core Quarantine | Closed canonical profile admission; malformed and authority fields rejected. |
| Filter | `PreFilter.score` and `EscalationPolicy.decide`; drop, cheap and chief routes. |
| Router | Real `client.call` code with an explicitly injected in-memory transport/configuration; role selection, response parsing, token accounting and canonical receipt encoding/decoding. No actual provider is contacted. |
| Transfer | `verify_envelope` consumes the Router/request commitments; non-empty untrusted authority and self-parent controls stop the flow. |
| Handoff | Build/project initial and child metadata against the actual artifact bytes; tamper, replay and parent rebinding are rejected. |
| Playbooks | Installed `policy_pack_bytes`, exact pack decoding, observation-bound signal evaluation; tampering rejected and the selected unknown Handoff signal returns `challenge`, stopping this example before Gateway. Signals are fixture-owned, not inferred classifications. |
| Core Gateway | `GatewayEngine.call_tool` applies real policy before its built-in constant lookup; an unknown key is denied even after the preceding components accept their inputs. |

`chain-cases.json` freezes 16 cases and independent expected outcomes. Two valid
routes reach all seven boundaries and each executes one built-in constant lookup.
The other 14 routes stop at their declared boundary. Synthetic execution is counted
separately from real effects; real model/provider calls and real effects stay zero.
Process/network access and undeclared file writes are denied by an early Python audit
hook. The only output write is the explicitly named, previously absent report.

The Gateway audit sink is an explicit in-memory test double, not a durable or
authenticated ledger. Router transport is a test double, not a model or endpoint.
The caller's example withholds dispatch on rejected/incomplete prior evidence; this
does not add standalone enforcement to Transfer, Handoff or Playbooks. The finite
self-parent/replay cases do not prove arbitrary graph-cycle or distributed replay
protection. Python audit hooks are not an OS sandbox.

The stdlib-only verifier imports none of the product packages or runner. It checks
closed report fields, pins, exact runner/fixture digests, all stage prefixes,
outcomes, causal digest links, transport accounting and zero real effects.
Digest integrity is not producer authenticity or independent human review.
Linux and Windows CI run both candidate-wheel and exact published-wheel contours.

### Caller-supplied input regression

The separate [2026-09-26 model campaign](../../docs/ollama-quarantine-adapter.md#two-step-ecosystem-proposal-campaign-2026-09-26)
publishes its fixed corpus in `local-model-cases.json` and a content-free historical
snapshot in `local-model-observation.json`. These are evidence, not inputs replayed
by the deterministic CLI or a claim that a live-model path completed successfully.

`run_case(..., canonical_input=bytes)` is an in-memory example seam, not a provider
adapter or new package API. Supplied bytes still pass through the same Quarantine
admission and are committed into the case digest; they cannot replace the registry,
policy or component bindings. The default 16-case CLI remains unchanged.

```bash
python -I -B examples/installed-ecosystem/check_supplied_input.py --out supplied-input.json --core-version 1.13.0
```

This separate eight-case offline installed check covers a valid key, an unknown key,
authority-shaped arguments, malformed JSON and four caller-gated digest controls.
It expects two synthetic executions (one lookup and one explicitly enabled digest)
and zero real effects/model calls. Both installed-wheel CI contours run it.
Any real-model use of this seam requires a separate finite campaign manifest;
passing this check does not establish model behavior.

### Explicit proposal protocol and real-model follow-up

The separate [paired experiment](../../docs/ollama-quarantine-adapter.md#proposal-contract-follow-up-2026-09-26)
records twelve new local calls in `proposal-contract-cases.json` and the content-free
`proposal-contract-observation.json`. Three actual proposals reached all seven
boundaries and performed the built-in constant lookup; all six negative controls
stopped as declared. This does not replace the earlier eight-call evidence.

The pure repository-owned helper prints the exact protocol wording used for a
fixed public lookup. It performs no model call, package discovery or execution:

```bash
python -I -B examples/installed-ecosystem/proposal_contract.py --key project-status
python -I -B examples/installed-ecosystem/proposal_contract.py --key gateway-mode
```

Use its `build_lookup_prompt` return value as `prompt` in the documented native
adapter example. The default `contract` framing matched both fixed proposals in
this run; `--framing literal` retains the comparison variant, which matched one
of two. Prompt wording is guidance, never authorization. The adapter still owns
normalization, Quarantine still rejects unknown identifiers/arguments, and Gateway
still decides the action. Do not repair a response or broaden policy to force a pass.
The helper is an example, not a newly published wheel API or a general agent planner.
