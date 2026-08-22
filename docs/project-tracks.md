# Project tracks

> Last reviewed: 2026-08-12.
>
> Scope: how Agentic Security Harness relates to the future internal LLM Safety Gateway /
> Runtime Verifier direction. This page records project direction; it does not announce a
> shipped gateway product.

## Track A: Agentic Security Harness

**Status:** shipped as a public research release.

Agentic Security Harness is the current repository product: a trace-first defensive
benchmark for agentic AI boundary failures.

It focuses on:

- synthetic and authorized targets;
- deterministic local demos;
- baseline-vs-protected comparison;
- portable traces, scorecards, remediation, reports, and validators;
- sanitized public evidence artifacts;
- clear non-claims around production safety, certification, and model leaderboards.

Its job is to answer:

> Can a declared agentic boundary failure be reproduced, measured, and inspected from a
> committed artifact?

This track is what users should run today.

## Track B: LLM Safety Gateway / Runtime Verifier

**Status:** the private Runtime Guard repository is the canonical Security product
composition root with a merged authority-free roadmap and bounded shadow research;
no production runtime is shipped and no production protection is claimed.

The gateway/verifier direction would apply the harness lessons inside an organization
that uses external or local LLMs. It would not need access to the internal state of a
cloud model. Instead, it would observe the boundaries around model use:

- prompts and context sent to external or local models;
- model responses before they become instructions or code changes;
- tool calls, file writes, git operations, network destinations, and handoffs;
- source/provenance labels;
- current user consent for protected actions;
- secret-like data, private client data, and policy-sensitive artifacts.

The core decisions would be conservative and auditable:

- `allow`
- `redact`
- `block`
- `ask_user`
- `sandbox_only`
- `log_only`

This track must be designed as a separate trust domain, not merely another dashboard over
ordinary company logs. It should use standard cryptography and key-management practices,
but separate keys, roles, retention, audit logs, and break-glass access from normal
corporate systems.

It must not:

- rely on seeing the hidden "brain" of cloud models;
- store raw employee/model conversations by default;
- expose internal conversations broadly to developers, managers, or the primary LLM;
- share the same keys and administrative path as the systems it monitors;
- claim production protection before a working implementation and deployment model exist.

The first public bounded foundation is documented in
[runtime-guard-product-foundation.md](runtime-guard-product-foundation.md). It adds
metadata-only Pydantic contracts, a pure deterministic evaluator, adversarial tests,
formal invariants, and provider/license gates. It has no CLI entry point, network
listener, executor, credential broker, durable store, IAM integration, or deployment
authority and must not be described as a gateway product.

A separate private Runtime Guard research implementation now owns receipt lifecycle,
bounded synthetic execution, observe-only swarm scoring, and later detector-research
foundations. Its existence does not turn this public repository into a gateway and does not
establish production protection. The public cross-project boundary is limited to the
merged provider-neutral ontology and authority-free interchange contract. That contract
remains a development and conformance boundary, not production integration.

The public Harness also owns the Agent Host V1 **recording contract**: an offline,
authority-free bridge from external host event records into canonical inspection evidence.
It does not own live host execution, provider credentials, policy enforcement, or effect
execution; those remain separate Runtime Guard/product trust domains.

Its R5 result is projected through the sanitized, validator-backed
[R5 sealed synthetic status](r5-research-status.md). One frozen common-control run reached
terminal scientific `FAIL`; aggregate calculations and receipt bindings are public, while
raw cases, labels, seeds, keys, ledger, and custody remain private. The result does not
establish independence, population performance, promotion, production protection, or
operational authority.

The advisory model routes are constrained by
[runtime-guard-model-fleet-contract.md](runtime-guard-model-fleet-contract.md), and the
Python contract plus falsifiable acceptance matrix are documented in
[runtime-guard-api-acceptance-pack.md](runtime-guard-api-acceptance-pack.md).

## Relationship between the tracks

Track A produces evidence. Track B would use that evidence as runtime policy input.

| Harness evidence contour | Possible future gateway control |
|---|---|
| Data vs instruction boundaries | Treat repo/docs/issues/tool output as untrusted data unless a trusted authority elevates it. |
| Approval and context laundering | Require explicit current consent before protected actions. |
| Context consent boundary | Reject claims that "approval exists" when no current consent receipt is present. |
| Semantic drift and propagation | Track untrusted claims as they move across summaries, handoffs, and agent roles. |
| Swarm defense contours | Observe multi-agent handoffs and block unsafe chain acceptance. |
| Secret-egress campaigns | Redact or block secret-like data before it leaves the organization boundary. |
| Audit integrity patterns | Keep tamper-evident records of policy decisions and raw-evidence access. |

The split is intentional:

- The harness stays credible by remaining a bounded, reproducible benchmark.
- The gateway direction stays honest by being described as future runtime architecture,
  not as shipped behavior.

## Near-term plan

1. Keep Agentic Security Harness release-facing: validated examples, stable docs,
   honest limitations, and public research release notes.
2. Review the bounded executable specification, trust/privacy model, provider/legal
   boundary, and minimal receipt API without adding an operational execution path.
3. Keep executable product research in the separate private Runtime Guard repository.
   Promote only provider-neutral schemas, synthetic fixtures, and validated evidence into
   the public Harness.

## Definition of separation

Agentic Security Harness may document gateway ideas and provide benchmark evidence that
future gateway controls can replay. It should not quietly become an enterprise proxy,
employee-monitoring store, or production policy engine without a separate issue, design
review, implementation boundary, and release plan.
