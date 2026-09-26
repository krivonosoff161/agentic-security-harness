# One small external pilot

This is a reproducibility request for a defensive toolkit, **not independent validation**
already achieved. Start with one public synthetic workflow and one external reviewer.
Do not promise a production firewall, universal connector or a model leaderboard.

## Scope and preparation

For a functional ecosystem review, use the
[16-case chain and independent verifier](../examples/installed-ecosystem/README.md#functional-six-component-chain).
The earlier eight-case `check.py` is an installation/compatibility baseline only.
The [expert-readiness contract](expert-readiness.md) defines the current technical
scope and the remaining independent-human gates.

No credentials, customer data, private repositories, model access, real tools or
production targets are required. Use a fresh Python 3.11 environment and the exact
release's fixed example and locks. The published 1.6.0 baseline is documented in
[Getting started](getting-started.md); its installed example is at
[examples/installed-ecosystem](../examples/installed-ecosystem/README.md).
That page provides a hash-locked PyPI route with no local package build required.
For the explicit extension path, follow the example's `--no-compile` installation in
a new environment. Ordinary pip bytecode entries are not accepted by the strict
extension `RECORD` contract; a successful install alone is not a successful binding.

The installed gate installs exact companion wheels and Core's selected wheel, checks
dependency consistency, and runs the same fixed example on Linux and Windows. The
public command and result expectations live with the example rather than in private Lab.

## What to reproduce

1. Run `ash quickstart --out <new-directory>` and `ash validate <new-directory>`.
   Expect 24 vulnerable/protected synthetic pairs and a self-contained report. The
   modelled contrast is not detector accuracy on independent data.
2. After the exact-wheel setup above, run the functional chain and its separate verifier:

   ```bash
   python -I -B examples/installed-ecosystem/chain.py --out functional-chain.json
   python -I -B examples/installed-ecosystem/verify_chain.py functional-chain.json
   ```

   Expect 16 cases: two full paths with two built-in constant lookups in total,
   and 14 paths stopping at their declared boundary. Synthetic execution is counted
   separately: real effects, real model/provider calls and network/process attempts
   must all remain zero.
3. Check each **negative control** stops for its stated reason: malformed input,
   authority escalation, receipt/accounting mismatch, Handoff tamper/replay/rebinding,
   Playbooks tampering/unknown evidence, and Gateway denial. A missing dependency
   or failed import is not a successful negative control.
4. Optionally run
   `python -I -B examples/installed-ecosystem/check.py --out installation-baseline.json`.
   This separate eight-case installation baseline explicitly
   inspects, approves and binds Transfer/Handoff extensions; installation alone does
   none of this. Missing Handoff artifact binding is a finding and incomplete
   Transfer telemetry is inconclusive. Its offline native-response fixtures use
   pure Gateway decisions with no dispatch.

The functional chain executes Filter/Router APIs and Playbook interpretation, but
Router uses an in-memory transport and Gateway uses an in-memory audit sink. Filter
scores/signals are fixture-owned; this is not a classifier-quality measurement.
Only the optional installation baseline treats Router/Filter as passive imports.
Neither route proves general cycle/replay resistance, authenticated custody, a
universal runtime connector or production safety. Public example/code licenses and
individual package licenses apply; no third-party private corpus is requested.

## Stop and report

Stop if a command unexpectedly asks for credentials, starts a model/service, accesses
a target or attempts a real action. Preserve only the error class, package versions,
OS/Python version and safe reproduction steps. Do not paste environment variables,
headers, raw model output, private paths or account identifiers into an issue.

The JSON functional result contains fixed case ids, typed outcomes, versions,
causal digests and separate synthetic-execution/real-effect counters. Review it
before sharing; also state the exact source
commit and whether the wheel came from a release or local candidate build.

## Feedback we need

- Could a new user install and run the declared route without undocumented setup?
- Did the negative control fail for the stated reason, or merely due to missing setup?
- Which required observations are unavailable from your existing evaluation runner?
- Does an existing tool already provide this result with fewer moving parts?
- Is the explanation of what is **not** established clear?

One reproduced defect, a counterexample, an upstream integration suggestion or evidence
that the layer is unnecessary is useful. Do not interpret a reply, star or successful
installation as an endorsement. Optional next contribution: one fixture/validator
review with a named invariant and explicit limits. Real-agent/provider work needs a
separate data, authority, observation and retention agreement.
