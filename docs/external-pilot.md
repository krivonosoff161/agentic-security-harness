# One small external pilot

This is a reproducibility request for a defensive toolkit, **not independent validation**
already achieved. Start with one public synthetic workflow and one external reviewer.
Do not promise a production firewall, universal connector or a model leaderboard.

## Scope and preparation

No credentials, customer data, private repositories, model access, real tools or
production targets are required. Use a fresh Python 3.11 environment and the exact
release checkout. The currently published baseline is documented in
[Getting started](getting-started.md); the 1.6.0 candidate's installed example is at
[examples/installed-ecosystem](../examples/installed-ecosystem/README.md).
Do not advertise that candidate as downloadable from PyPI before publication.
For the explicit extension path, follow the example's `--no-compile` installation in
a new environment. Ordinary pip bytecode entries are not accepted by the strict
extension `RECORD` contract; a successful install alone is not a successful binding.

The candidate gate installs exact companion wheels and Core's selected wheel, checks
dependency consistency, and runs the same fixed example on Linux and Windows. The
public command and result expectations live with the example rather than in private Lab.

## What to reproduce

1. Run `ash quickstart --out <new-directory>` and `ash validate <new-directory>`.
   Expect 24 vulnerable/protected synthetic pairs and a self-contained report. The
   modelled contrast is not detector accuracy on independent data.
2. Run the selected release's installed-ecosystem example. It explicitly inspects,
   approves and binds Transfer/Handoff distributions; installation alone does none of this.
3. Check the **negative control**: missing Handoff artifact binding must produce a
   finding; incomplete Transfer telemetry must remain inconclusive.
4. Check the offline native-response fixtures: valid lookup proposal, unknown key,
   authority-shaped malformed argument and no-request. The Gateway remains a pure
   decision point; there must be zero transport attempts and no dispatch.

Router/Filter are passive import surfaces in this example; Playbooks is a digest-bound
data pack. Neither their real classification quality nor a universal all-component
runtime chain is claimed. Public example/code licenses and the individual package
licenses apply; no third-party private corpus is requested.

## Stop and report

Stop if a command unexpectedly asks for credentials, starts a model/service, accesses
a target or attempts a real action. Preserve only the error class, package versions,
OS/Python version and safe reproduction steps. Do not paste environment variables,
headers, raw model output, private paths or account identifiers into an issue.

The JSON example result contains fixed case ids, typed outcomes, versions, a pack
digest and no-action counters. Review it before sharing; also state the exact source
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
