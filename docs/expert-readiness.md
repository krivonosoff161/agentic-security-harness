# Expert engagement readiness

This is a bounded acceptance contract, not a claim that the whole research roadmap
or independent security audit is complete. The technical focus is an executable
six-component public-synthetic ecosystem with inspectable failure paths.

## Reproduce the actual supported route

Follow the exact installation and the two functional-chain commands in
[the installed ecosystem example](../examples/installed-ecosystem/README.md#functional-six-component-chain).
The case manifest names every supported route and its expected terminal boundary.
No package discovery, hidden model connection or real tool activation is needed.

Quarantine admission feeds Filter routing, Router's in-memory transport and receipt,
Transfer verification, Handoff sequence projection, Playbooks advisory evaluation,
and the Gateway's built-in synthetic operation. Rejection stops later stages.
Gateway policy remains the action decision point; an advisory result is never an
authorization. This is meaningful functional interoperability, not a proof that
every arbitrary provider, modality or deployed agent can be connected automatically.

Technical acceptance requires exact published-wheel installation and a separately
validated 16-case result on both Linux and Windows, in addition to the normal test,
type, lint, documentation and security workflow gates. A successful package release
alone does not satisfy this contract. CI checks and PR evidence belong to issue
[#299](https://github.com/krivonosoff161/agentic-security-harness/issues/299).

## Execution evidence

At exact example commit `1287bf3cb0d5d2e971789201b46a90666ca55170`:

- Published-wheel functional jobs passed on [Linux](https://github.com/krivonosoff161/agentic-security-harness/actions/runs/35614272014/job/106380849389)
  and [Windows](https://github.com/krivonosoff161/agentic-security-harness/actions/runs/35614272014/job/106380849757).
- Candidate-wheel jobs passed on [Linux](https://github.com/krivonosoff161/agentic-security-harness/actions/runs/35614272014/job/106380849897)
  and [Windows](https://github.com/krivonosoff161/agentic-security-harness/actions/runs/35614272014/job/106380849685).
- Both published reports were downloaded and independently revalidated: 16 cases,
  two full paths, two synthetic operations, zero real effects, identical result
  digest `85e994df089ffd4ea5a34ebf13155c92a05a7217c5c906eae9f8fd9a9ca9b80a`.

Those four passing jobs do not mean the entire first workflow passed: the separate
source matrix caught an unrefreshed roadmap digest in the central component lock.
The correction rebinds that digest and adds a checkout-independent regression test;
it does not change runtime code, package pins or the functional result. Final
exact-head checks and integration are recorded in [PR #300](https://github.com/krivonosoff161/agentic-security-harness/pull/300).
The earlier local full suite passed 2137 tests with 29 conditional skips; the new
lock regression adds one test. Content-free CI artifacts have a 30-day retention;
the committed runner/fixtures allow a fresh reproduction after expiry.

## Current work and research are different

The master [ecosystem roadmap](ecosystem-roadmap.md) distinguishes functional
integration from installation and from human independent review. Future work may
add new scenarios, integrations, modalities or stronger proof obligations; it does
not silently expand the claims of this fixed example.

Router and Filter retain their own repositories and APIs; Playbooks remains data-only
advice. The caller composes them explicitly. No companion source is copied into
Harness and no private Runtime Guard implementation is bundled here.

## Mathematics and publication boundary

[Public theory](theory/README.md) contains curated definitions, invariants,
deterministic-check specifications and their limits. It is not the private working
archive. Scratch calculations, exploratory proofs, private source maps, raw model
outputs and machine-local evidence remain outside public Git. The local `.internal/`
directory is ignored; ignore rules are not a substitute for pre-commit inspection.

The publication path for a research claim is: explicit statement and assumptions,
counterexample search, reproducible checker/experiment, evidence-bound limitations,
then a separately reviewed public projection. A finite checker is not a universal
proof. A mathematical assumption that a trusted root exists is not evidence that a
particular transport or deployed host supplies that root. No private mathematical
package is automatically promoted by this integration work.

## The only external acceptance work

- Independent standards-mapping review: [#199](https://github.com/krivonosoff161/agentic-security-harness/issues/199).
- A durable second maintainer/reviewer and corresponding branch controls:
  [#205](https://github.com/krivonosoff161/agentic-security-harness/issues/205).
- An external reproduction and technical critique using [the pilot protocol](external-pilot.md).

These remain open until real people participate. An AI check, a successful CI run,
or a self-review must not close them. Scorecard's single-maintainer warning must not
be hidden by weakening checks or inventing approvals. They do not imply a known
runtime exploit, but they are genuine limits on independence and governance.

The first contact should ask for one reproduction, counterexample, or interface
review, with release/example/pilot links. Do not send private research, raw evidence,
credentials or customer data. No endorsement, provider access, grant, or partnership
is implied by preparing that request.
