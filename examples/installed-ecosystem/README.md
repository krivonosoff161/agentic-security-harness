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

## Functional six-component chain

The original `check.py` remains the eight-case installation baseline above. The
separate `chain.py` exercises actual installed APIs in a single causally linked
public-synthetic flow, not just passive imports:

```bash
python -I -B examples/installed-ecosystem/chain.py --out functional-chain.json
python -I -B examples/installed-ecosystem/verify_chain.py functional-chain.json
```

Run these after the same exact-wheel installation above. The example itself is
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
python -I -B examples/installed-ecosystem/check_supplied_input.py --out supplied-input.json
```

This separate offline installed check covers a valid key, an unknown key,
authority-shaped arguments and malformed JSON. It expects one synthetic execution
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
