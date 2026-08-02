# Unified event and envelope contract

> Status: Harness-owned `portfolio-observation-v1.0` wire contract implemented locally with
> content-bound schema, synthetic conformance fixtures and exhaustive adapter-audit
> primitives. Runtime Guard, Transfer Verifier and AI Agent Handoff now pin the exact V1
> owner schema/manifest through downgrade-only adapters. This proves cross-repository
> conformance for the pinned versions, not authenticated producers or complete telemetry.
> No reverse authoritative conversion, allow receipt, or executor connection is claimed.

## Purpose

The portfolio needs one lossless interchange boundary among Harness, Runtime Guard, Transfer
Verifier, adapters, the future semantic sentinel, and the evidence plane. The contract must
carry evidence without allowing evidence to become authority.

## Separation of objects

One universal blob would recreate the current confusion. The integration contract therefore
uses six related objects:

1. `ObservationEvent` — what a producer claims was observed;
2. `DataEnvelope` — restrictions attached to the observed data;
3. `AuthorityEnvelope` — independently authenticated permission constraints;
4. `AdvisoryAssessment` — non-authoritative detector/model output;
5. `GuardDecision` — deterministic policy result for one exact action;
6. `EffectReceipt` — separately recorded result of consuming one allow receipt.

No conversion among these objects is implicit.

## Canonical observation event

Required conceptual fields:

| Field | Meaning |
|---|---|
| `schema_version` | Exact contract version |
| `event_id` | Producer-claimed digest-shaped event identifier; this draft validates shape only |
| `project_id` | Canonical registered project |
| `repository_id` | Repository identity, not a filesystem path |
| `repository_sha` | Exact object id |
| `occurred_at` | Timezone-aware event time |
| `producer` | Pseudonymous producer identity; the draft event can state only `unattested` |
| `source_surface` | Tool, memory, provider, app, sensor, user or agent boundary |
| `activity` | Typed transformation or attempted action |
| `entity_refs` | Digest-shaped safe evidence pointers; existence/authenticity is external |
| `parent_event_ids` | Explicit lineage; no inferred authority |
| `data_envelope_ref` | Restrictions on content |
| `authority_envelope_ref` | Optional authenticated authority, never model-generated |
| `telemetry_state` | Complete, incomplete, malformed, unattested or conflicting |

Raw prompts, raw tool output, credentials, private paths and unrestricted payloads are absent
from the default event.

The stable V1 Python model implements one bounded canonical representation: UTF-8 JSON,
sorted keys, compact separators, UTC timestamps with six fractional digits, and one trailing
line feed. Unknown, missing, duplicate, oversized, non-canonical, and unsupported-version
payloads fail closed. The JSON Schema, manifest, and synthetic positive/negative fixtures are
content-bound under `schemas/portfolio-observation.v1.*` and
`tests/fixtures/portfolio-observation-v1/`.

`event_id` deliberately remains a producer-claimed digest-shaped identifier. It is not a
content hash and does not prove provenance. `ObservationCommitmentV1` separately records the
exact canonical-byte SHA-256 and a domain/schema-separated commitment. Neither object can
state verified producer attestation or operational authority. Cryptographic producer
attestation remains unimplemented.

## R4 companion contracts

The stable observation remains unchanged. Five separate Harness-owned contracts add bounded
accounting without turning observations into authority:

- `portfolio-outcome-v1.0` separates advisory, policy, verification, execution and
  no-effect sink records; every record is content-bound, evidence-only and non-executable,
  while scientific candidate projection exposes only advisory records and physically
  excludes policy, verification, execution and sink proxy labels;
- `mcp-redaction-receipt-v1.0` retains structural counts and dropped-field classes, never
  raw MCP arguments, output, errors, locators or credentials;
- `portfolio-trajectory-accounting-v1.0` binds every observation commitment, complete edge,
  logical operation, retry/idempotency identity, route transition and route permission. It
  is evaluator-only, uses closed non-scientific vocabularies, rejects inconsistent attempt
  identities, binds canonical UTC event timestamps, derives its complete event span, and
  derives a content-bound trajectory identity independent of input ordering or timezone
  representation. Unknown retry/route evidence forces incomplete state, and causal edge
  timestamps cannot run backwards;
- `portfolio-coverage-expectation-v1.0` declares content-bound expected channels and event
  count for a repository identity and reviewed source digest. External ordering evidence is
  still required before calling that declaration a temporal precommitment;
- `portfolio-telemetry-manifest-v1.0` demonstrates self-consistency against that pinned
  profile, embeds the validated adapter audit and trajectory evidence, and forces
  incomplete/rejected state when channels, records, trajectory evidence or the observation
  window are incomplete. It does not independently authenticate producers or prove
  end-to-end capture.

Their generated JSON Schemas are shape checks. Exact schemas, Python semantic validator and
positive/negative fixtures are content-bound by
`schemas/r4-companion-contracts.v1.manifest.json`. Scientific attack and containment labels
remain evaluator-only and absent from runtime contracts; execution and no-effect outcomes
are evaluator-visible evidence that candidate projection cannot receive.
The general `project_companion_for_candidate_v1` boundary revalidates every companion and
returns only advisory outcomes; evaluator-only trajectory, telemetry, policy, verification,
execution and sink records are physically withheld.

## Stable V1 wire and version boundary

- Contract id: `portfolio-observation-v1.0`.
- Maximum canonical record size: 4096 bytes including the trailing line feed.
- Maximum event collection cardinalities: 64 evidence pointers and 64 parent event ids.
- Adapter audits are bounded to 128 declared fields, 128 mappings and 64 reason codes.
- Commitment domain: `agentic-security-portfolio/observation/v1.0`.
- Legacy `portfolio-observation-v0.1` objects are not silently decoded as V1.
- A future migration must be an explicit pure function with downgrade-only tests; schema
  negotiation or best-effort field inference is forbidden.
- The generated JSON Schema describes value shape. The Python decoder additionally enforces
  duplicate-key rejection and exact canonical bytes.

## Non-expansion relations

For a transformation from parent `p` to child `c`:

```text
data_scope(c)      <= data_scope(p)
recipients(c)      <= recipients(p)
purposes(c)        <= purposes(p)
storage(c)         <= storage(p)
forwarding(c)      <= forwarding(p)
trust(c)           <= authenticated_trust(p)
authority(c)       <= authenticated_authority(p)
capability(c)      <= authenticated_capability(p)
expires_at(c)      <= expires_at(p)
delegation_depth(c) < delegation_depth(p), when delegated
```

Summarization, classification, retrieval, model agreement, repetition, tool output, memory
recall, fallback routing, or semantic confidence cannot relax these relations.

## Advisory boundary

An `AdvisoryAssessment` may contain:

- supported ontology family ids;
- `observe`, `challenge`, `escalate`, `abstain`, or `inconclusive`;
- reason codes;
- confidence/calibration metadata;
- safe evidence pointers;
- detector and policy versions.

It must contain `operational_authority=none`. It cannot contain or mint:

- capability;
- consent;
- authenticated identity;
- provenance attestation;
- allow receipt;
- effect claim.

## Decision and effect boundary

The authoritative path is:

```text
validated action
  + authenticated capability
  + action-bound consent when required
  + deterministic policy
  + current provider/resource/budget policy when applicable
  -> GuardDecision
  -> short-lived one-time AllowReceipt
  -> bounded executor consumes receipt
  -> EffectReceipt
```

An advisory may cause `challenge`, `escalate`, or `abstain`. It cannot independently cause
`allow`.

## Adapter requirements

Every adapter must publish a field matrix:

| Requirement | Rule |
|---|---|
| Loss accounting | Every dropped or synthesized source field is explicit |
| Unknown fields | Reject or preserve as non-authoritative extension data |
| Time | Reject naive or impossible timestamps |
| Identity | Distinguish claimed, authenticated and pseudonymous identity |
| Hashes | State exactly which bytes and serialization are bound |
| Telemetry | Missing lineage or producer attestation cannot be silently filled |
| Authority | Text fields and model output never populate authenticated authority |
| Errors | Structural failure yields abstention/fail-closed, not a negative finding |

`AdapterAuditV1` makes the loss row executable. An adapter declares exact source and target
field universes, identity/derived mappings, dropped source fields, context-supplied targets,
and constant targets. The classifications must be disjoint and exhaustive on both sides.
The target universe is fixed to every field of `CanonicalObservationEventV1`; an adapter
cannot claim completeness by declaring a convenient subset.
Dropping, deriving, supplying context, or inserting constants requires
`authority_downgrade=true`; `authority_envelope_ref` and `operational_authority` must remain
constant targets in this shadow contract. A source provenance label such as
`classification_source` is an identity, not a trust rank, and cannot self-promote by changing
its text value.

## First compatibility targets

1. Harness `ActionEnvelope`/`GuardContext` to canonical objects;
2. Runtime Guard `ObservationEvent` and `ActionRequest` to canonical objects;
3. Transfer Verifier `TransferEnvelope`/`TransferEdge` to canonical objects.
4. AI Agent Handoff's strict `handoff.metadata_sidecar` to canonical observations; raw
   Markdown remains untrusted content and is never the adapter source model.

The adapters should first be implemented as pure functions with round-trip and intentional
loss tests. No executor, provider or live agent integration is needed for this phase.

## Open decisions

- stable repository identity across forks and mirrors;
- authenticated producer model and key lifecycle;
- keyed pseudonymization and retention policy;
- extension namespace and schema negotiation;
- exact canonical JSON/CBOR representation;
- revocation and distributed receipt consumption;
- policy language or compiler boundary;
- semantic-sentinel input projection and output calibration.
