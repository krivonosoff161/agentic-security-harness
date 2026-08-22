# Project tracks

> Last reviewed: 2026-08-22.
>
> Scope: how Agentic Security Harness relates to the internal LLM Safety Gateway / Runtime
> Verifier direction and the public local synthetic gateway contour. This page does not
> claim production protection.

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

**Status:** private Runtime Guard research remains the canonical private product-research
root. This public repository now carries a bounded local synthetic reference gateway;
no production runtime is shipped and no production protection is claimed.

The production gateway/verifier direction would apply the harness lessons inside an organization
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
authority. The newer [Runtime Gateway development contour](runtime-gateway.md) is a
separate runnable reference layer: loopback/container-local HTTP, two fixed synthetic
tools, closed pre-dispatch decisions, keyed privacy commitments, and a local hash-chain
audit. It still has no live provider, credential broker, arbitrary executor, authenticated
approval service, IAM integration, or production deployment authority.

A separate private Runtime Guard research implementation owns private receipt lifecycle,
bounded research execution, observe-only swarm scoring, and later detector foundations.
The public reference gateway does not import private source or evidence and does not
establish production protection. The portfolio cross-project boundary remains the merged
provider-neutral ontology and authority-free interchange contract; the local gateway is a
development/integration contour, not portfolio promotion or production integration.

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

Track A produces evidence. Track B now has a local synthetic reference implementation;
using Harness evidence as real organizational policy input remains future work.

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
- The gateway direction stays honest by separating the shipped local synthetic behavior
  from future provider, credential, approval, IAM, and production behavior.

## Near-term plan

1. Keep Agentic Security Harness release-facing: validated examples, stable docs,
   honest limitations, and public research release notes.
2. Maintain the local synthetic gateway, privacy-minimized audit, Docker operator path,
   and adversarial integration tests as a bounded public reference product.
3. Add any provider transport, authenticated approval, arbitrary effect execution, IAM,
   or deployment only through separate trust/privacy/release gates. Keep private research
   evidence outside the public Harness.

## Definition of separation

Agentic Security Harness may implement a credential-free local synthetic gateway and
provide benchmark evidence that future controls can replay. It must not quietly become an
enterprise proxy, employee-monitoring store, credential broker, or production policy
engine without a separate issue, design review, implementation boundary, and release plan.
