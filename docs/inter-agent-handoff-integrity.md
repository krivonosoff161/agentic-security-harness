# Inter-agent handoff integrity

> Status: design track. This is not shipped benchmark coverage yet.
>
> Scope: defensive-only modeling of how agentic systems should preserve provenance,
> integrity, authority, and recovery metadata when data moves between agents.

## Problem statement

Agentic workflows often split one user goal across multiple workers:

```text
senior agent
  -> news worker
  -> calendar worker
  -> task/list worker
  -> synthesis / decision step
```

The dangerous assumption is:

> A worker returned a summary, therefore the senior agent can treat the summary as fact.

This project track treats that assumption as a boundary problem. A senior agent should not
trust an inter-agent result unless the handoff preserves enough evidence to answer:

- who produced the data;
- what task and authority scope produced it;
- which sources were used;
- whether the payload changed after production;
- which policy/schema version governed the handoff;
- what the system should do if verification fails.

## Working term

Use this term in project planning:

**inter-agent handoff integrity**

Related standards language:

- data provenance;
- data lineage;
- chain of custody;
- attestation;
- integrity verification;
- trust-boundary verification.

The project should not claim this term is a formal standard. It is the local name for the
benchmark track.

## Defensive scenario shape

Use synthetic, local-only fixtures. A representative scenario is:

```text
Task: prepare a conference briefing.

Worker A collects synthetic public news snippets.
Worker B checks a synthetic calendar record.
Worker C checks a synthetic task list.

The senior agent receives all three worker results and builds a final answer.
```

The benchmark question is not whether the senior model is smart. The benchmark question is:

> Does the system preserve and verify the handoff evidence before the senior agent treats
> worker output as trusted data?

## Failure classes to model

These are safe failure classes, not operational instructions:

| Class | Example invariant |
|---|---|
| Payload integrity drift | The payload presented to the senior agent must match the payload produced by the worker. |
| Source-label loss | Source labels must survive summarization and handoff. |
| Agent identity confusion | The receiver must know which worker produced which result. |
| Task/scope drift | A worker result for one task or authority scope must not be reused as if it belonged to another. |
| Recipient / forwarding drift | A result marked not-forwardable must not be forwarded as a trusted fact. |
| Policy-version drift | A result created under one policy/schema version must not be silently accepted under another. |
| Replay/staleness | Old worker results must not be accepted as current without explicit freshness metadata. |
| Verifier outage | If the handoff cannot be verified, the system must fail closed or require review. |

## Required controls

This track should evaluate controls, not rely on model judgment alone:

| Control | Purpose |
|---|---|
| Typed handoff envelope | Prevent "plain text summary equals fact" behavior. |
| Payload hash | Detect payload change after worker output. |
| Source labels | Preserve where each claim came from. |
| Agent/task/session identity | Bind a result to its producer and assignment. |
| Policy/schema version | Make rule drift visible. |
| Handoff verifier | Check envelope integrity before senior-agent use. |
| Append-only audit / hash chain | Make review and replay possible. |
| Canary handoff tests | Prove the verifier still catches safe synthetic failures. |
| Recovery path | Return `blocked` / `needs_review` with a reproduce path instead of silently passing data. |

## Out of scope

Keep this track defensive and reviewable:

- no real corporate systems;
- no real credentials or private user data;
- no malware, persistence, evasion, or intrusion instructions;
- no live third-party targets;
- no public step-by-step abuse procedure;
- no claim that hiding a verifier is sufficient security;
- no model-judged finding without deterministic verification.

## What belongs in the repository

| Public repository | Local scratch only |
|---|---|
| Problem statement and defensive invariant. | Uncurated local experiment logs. |
| Synthetic fixtures and toy targets. | Machine-specific runtime captures. |
| Handoff envelope contract. | Any environment-specific sensitive details. |
| Deterministic verifier behavior. | Private notes about real organizations or systems. |
| Safe reports showing pass/block/review behavior. | Raw scratch reports unless curated and validated. |
| Operator/recovery checklist. | Anything that would read like operational abuse guidance. |

## Planned work order

Do not implement all of this at once. Each stage has a visible exit gate.

| Stage | Work | Exit gate |
|---|---|---|
| 0. Design lock | This document, tracker entry, non-goals, terminology. | Reviewers can tell what is planned and what is not shipped. |
| 1. Contract design | Define a minimal handoff envelope and expected verifier outcomes. | Contract has tests for schema validity and claim boundaries. |
| 2. Deterministic toy topology | Add a synthetic senior/worker topology with vulnerable and protected behavior. | Vulnerable path accepts unverified handoff; protected path blocks or reviews. |
| 3. Evidence artifacts | Write trace/report artifacts for handoff pass/block/review outcomes. | `ash validate` accepts the generated artifacts. |
| 4. Canary operations | Add daily/canary-style local checks as an operator pattern. | Report shows verifier alive, expected pass, expected block, and recovery guidance. |
| 5. Local model probe | Optional weak local model participant under strict request caps. | Local model output is classified as pass/finding/inconclusive/error without overclaiming. |

## Definition of done for a benchmark pattern

A handoff-integrity pattern is not done until it has:

1. a specific invariant;
2. a synthetic fixture;
3. vulnerable and protected target behavior;
4. deterministic validation signal;
5. trace evidence;
6. remediation/control family;
7. recovery path;
8. documentation that says whether it is shipped, experimental, or planned.

## Claim boundary

Allowed:

> This track models why inter-agent summaries should not be accepted as trusted facts
> without provenance-preserving handoff verification.

Not allowed:

- "This prevents all insider or server compromise."
- "A hidden verifier is enough security."
- "The benchmark proves real corporate systems are vulnerable."
- "The model itself can cryptographically know whether data was modified."
