# Unified event and envelope contract

> Status: integration design draft. No current runtime consumes this contract.

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

The current Python model does not implement canonical serialization or cryptographic
attestation. Hash-shaped values are untrusted claims until a separate verifier binds exact
bytes and an attestation receipt. A producer cannot self-declare `verified` inside this
observation.

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

## First compatibility targets

1. Harness `ActionEnvelope`/`GuardContext` to canonical objects;
2. Runtime Guard `ObservationEvent` and `ActionRequest` to canonical objects;
3. Transfer Verifier `TransferEnvelope`/`TransferEdge` to canonical objects.

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
