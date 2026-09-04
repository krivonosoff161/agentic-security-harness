# Advisory-to-Gateway Authority Connector V1: proposed contract

Status: **Phase 1 documentation contract plus a stacked Phase 2 review candidate**. The
candidate adds one direct-call source module and synthetic tests above docs PR `#272`; it
is not merged into `main`, registered in the package root, connected to a CLI/runtime
path, released, or automatically activated. The underlying contract remains bound to
reviewed Harness source `85f94100eb2e64a8aecd4df3c3b2d6e10ae52342` and docs head
`41699b919991e9132341564fab69f01ae605d762`.

## Root question and verified gap

Can untrusted Cheap Filter or Playbooks advice be represented as a typed advisory
envelope and evaluated by the existing pure Runtime Gateway policy boundary without the
advice being reinterpreted as authority?

Current source provides the pieces on either side but not this adapter:

- the Cheap Filter receipt auditor emits authority-free Extension SDK findings and never
  lowers a security decision;
- the Playbooks Policy Pack evaluator emits `observe`, `challenge`, `escalate`, or
  `abstain` advice with `operational_authority=none`;
- the Quarantine Connector and its Gateway composition already cover a different source:
  strict model/provider bytes selected through a provider adapter profile;
- `evaluate_gateway_tool_call()` is the existing pure, deterministic policy decision;
  `GatewayEngine` is the separate audit/dispatch boundary.

Released `main` has no public API that accepts Filter/Playbooks advisory material, applies
an application-owned mapping, constructs the existing closed `CapabilityRequestV1`, and
ends at the pure Gateway decision. The stacked Phase 2 candidate fills only that missing
seam. It does not route advisory evidence through `ModelEnvelopeV1`, weaken Quarantine
admission, or create a second Gateway policy model.

## One-way causal and authority path

```text
caller-supplied sanitized advisory bytes
  -> strict AdvisoryEnvelopeV1 decoder
  -> explicitly selected immutable AdvisoryGatewayProfileV1
  -> code-owned mapping rule (no text interpretation)
  -> existing closed CapabilityRequestV1
  -> existing GatewayToolCallV1
  -> existing evaluate_gateway_tool_call()
  -> typed digest-linked outcome
  -> STOP (no GatewayEngine, audit, approval grant, dispatch, or effect)
```

The arrow is one-way. Advice remains data. It may satisfy a closed match condition, but
it cannot name or modify the authority projected after that condition.

| Value | Advisory input may supply it? | Authority owner |
|---|---:|---|
| advisory text, bounded summary, risk label | yes, always untrusted | advisory source |
| source/result provenance commitments | yes, then strictly verified against profile pins | caller-selected profile |
| `capability_id` and Gateway tool name | no | code-owned profile binding |
| recipient, scope, budget | no; absent from V1 projection | future separate authority contract |
| Gateway policy or policy version | no | caller-supplied existing `GatewayPolicyV1` |
| execution permission | no | existing Gateway decision only |
| executor, approval grant, dispatch, effect | no | outside this connector |

An admitted advisory envelope is not a capability request. A constructed capability
request is not a Gateway allow. A Gateway allow returned by the pure evaluator is not
execution.

## Proposed exact advisory wire contract

`AdvisoryEnvelopeV1` is one canonical UTF-8 JSON object with exactly these fields. All
fields are required; no aliases or alternate shapes are accepted.

| Field | Exact V1 constraint |
|---|---|
| `schema_version` | literal `AgenticSecurityHarnessAdvisoryEnvelope.v1` |
| `advisory_id` | lowercase SHA-256 defined below |
| `source_component_id` | `llm-cheap-filter` or `llm-safety-playbooks` |
| `source_contract_id` | 1-128 ASCII characters matching `[a-z][a-z0-9_.-]*` |
| `source_contract_version` | 1-64 ASCII characters matching `[0-9A-Za-z][0-9A-Za-z.+_-]*` |
| `advisory_kind` | `cheap_filter_finding` or `playbooks_policy_evaluation` |
| `risk_label` | `none`, `low`, `medium`, `high`, `critical`, `inconclusive`, `observe`, `challenge`, `escalate`, or `abstain` |
| `advisory_text` | caller-sanitized untrusted string, 0-4096 UTF-8 bytes |
| `summary` | caller-sanitized untrusted string, 0-512 UTF-8 bytes |
| `provenance` | exact `AdvisoryProvenanceV1` object below |
| `operational_authority` | literal `none` |

At least one of `advisory_text` or `summary` must be non-empty. The connector treats both
as opaque evidence. It does not tokenize, classify, execute, template, or derive a route
from either string. The envelope is caller-owned in-memory input and is not automatically
safe to publish merely because it is bounded.

`AdvisoryProvenanceV1` contains exactly:

| Field | Exact V1 constraint |
|---|---|
| `schema_version` | literal `AgenticSecurityHarnessAdvisoryProvenance.v1` |
| `source_commit` | 40 lowercase hexadecimal Git object id |
| `source_tree` | 40 lowercase hexadecimal Git tree id |
| `source_contract_sha256` | lowercase SHA-256 |
| `source_result_sha256` | lowercase SHA-256 of the already-produced source result |
| `evidence_class` | `producer_declared`, `external_unreviewed`, `synthetic_fixture`, or `sanitized_metadata` |
| `operational_authority` | literal `none` |

The proposed decoder limit is 16,384 input bytes and four JSON container levels. Strings
must contain valid Unicode scalar values. Integers, floats, booleans, null, arrays, and
additional objects are impossible in this closed shape except for the single provenance
object.

### Canonicalization and identity

The decoder must reject a BOM, malformed UTF-8, duplicate keys, trailing bytes, unknown
fields, missing fields, wrong JSON types, non-finite numbers, and any byte sequence that
is not already the canonical representation. Canonical bytes are the decoded object
serialized as UTF-8 with keys sorted lexicographically, separators `,` and `:`, no ASCII
escaping, no insignificant whitespace, no Unicode normalization, and one object only.
The input must equal those bytes exactly.

`advisory_id` is lowercase hexadecimal SHA-256 over:

```text
UTF8("ash-advisory-envelope-v1\0")
|| canonical_json(envelope with advisory_id omitted)
```

This digest is a content identity, not source authentication, consent, authorization, or
proof that the advisory is true. The source contract, source result, component/kind pair,
and selected profile pins must all agree before a mapping rule can match.

## Explicit profile and code-owned projection

The application constructs one immutable `AdvisoryGatewayProfileV1` and passes its exact
id and version with the advisory bytes and an existing `GatewayPolicyV1`. There is no
profile discovery, package inspection, environment lookup, fallback, implicit upgrade,
or best-match selection.

The proposed closed profile owns:

- exact `profile_id` and `profile_version` safe tokens;
- accepted component/kind pairs and exact source contract ids, versions, commits, trees,
  and contract digests;
- a sorted closed table from `(source_component_id, advisory_kind, risk_label)` to one
  named capability binding;
- each binding's fixed `capability_id`, Gateway protocol/tool name, and a closed argument
  template containing only constants and envelope/profile/result digests;
- `operational_authority=none`.

The profile must not contain a Gateway policy, executor, approval credential, endpoint,
recipient, free-form scope, mutable budget, or dispatch callback. The request id is
derived by code from the profile, advisory, and selected mapping commitments. Advisory
text and summary are never interpolated into tool arguments. Thus the source may influence
whether a code-owned rule matches, but it cannot supply the resulting capability identity
or authority fields.

The future adapter should reuse the existing `CapabilityRequestV1`, `GatewayToolCallV1`,
`GatewayDecisionV1`, and `evaluate_gateway_tool_call()` contracts. It must not change
`GatewayPolicyV1`, call `GatewayEngine`, or duplicate the existing Quarantine composition.

## Fail-closed rules

Before a capability request exists, the adapter returns `reject` or `inconclusive` for:

- unknown, stale, mismatched, or unsupported profile id/version, source contract, commit,
  tree, result digest, component/kind pair, or risk label;
- malformed provenance, an unaccepted evidence class, or inconsistent source/result pins;
- unknown/missing fields, duplicate keys, malformed UTF-8, trailing bytes, noncanonical
  bytes, size/depth overflow, wrong types, or invalid string/digest syntax;
- any authority-shaped field at any object level, including `capability_id`, `tool_name`,
  `recipient`, `scope`, `budget`, `policy`, `policy_version`, `role`, `principal`, `token`,
  `allow`, `execution_permission`, `executor`, `approval`, `dispatch`, or `effect`;
- a profile mapping that is ambiguous, duplicated, not sorted, or references an unknown
  capability binding;
- any attempt to copy advisory text/summary into a request field or argument.

No failure may fall back to another source, label, profile, parser, capability, Gateway
policy, or permissive generic representation. `reject` and `inconclusive` create no
`CapabilityRequestV1`, no `GatewayToolCallV1`, and no Gateway evaluator call.

## Opt-in and default compatibility

The proposed connector is disabled by absence: existing imports, CLI commands, extension
registries, Policy Pack evaluation, receipt auditing, Quarantine composition, controlled
local adapter, provider-tool adapter, and Runtime Gateway remain unchanged.

Even after a future source implementation, installation or import must not:

- discover, import, activate, or invoke a companion package;
- read provider/model configuration or call a provider/model;
- open network, DNS, subprocess, listener, or server surfaces;
- register a CLI command or implicit runtime hook;
- call `GatewayEngine`, write audit state, create an approval grant, dispatch, or cause a
  real or synthetic effect.

The only V1 activation is a direct caller invocation with an exact profile, exact profile
id/version, bounded canonical bytes, and an existing deterministic Gateway policy.

### Review-candidate API

The additive module is imported explicitly; it is deliberately absent from the package
root and every discovery/CLI registry:

```python
from agentic_security_harness.advisory_gateway_connector import (
    compose_advisory_gateway_v1,
)

outcome = compose_advisory_gateway_v1(
    application_owned_profile,
    selected_profile_id="synthetic.advisory",
    selected_profile_version="1",
    payload=canonical_advisory_bytes,
    gateway_policy=existing_gateway_policy,
)
assert outcome.dispatch_performed is False
```

The caller must construct `AdvisoryGatewayProfileV1` from reviewed code-owned constants
and provide canonical `AdvisoryEnvelopeV1` bytes. `advisory_gateway_connector_v1_json_schemas()`
and `advisory_gateway_connector_v1_api_sha256()` expose the closed schema set and a
sanitized API commitment. The module never imports Filter or Playbooks packages; package
installation and advisory production remain separate explicit steps.

## Future conformance vectors and metrics

All future fixtures are synthetic and sanitized. No retained Filter/Playbooks payload,
provider response, model output, credential, endpoint, or Lab trace belongs in Git.

### Negative controls

1. Add each forbidden authority field at the root and inside provenance: reject before
   request construction.
2. Put authority-shaped JSON text inside `advisory_text`: keep it opaque and prove it
   cannot change the selected binding or arguments.
3. Drift profile id/version, source contract, commit/tree/digest, component/kind pair,
   evidence class, and risk label independently: reject or inconclusive with no fallback.
4. Exercise duplicate keys, unknown fields, malformed UTF-8, BOM, trailing bytes,
   noncanonical whitespace/key order, wrong types, size/depth limits, and invalid Unicode.
5. Supply an unmapped but otherwise valid advisory: produce no request and do not call the
   Gateway evaluator.
6. Disable the connector: prove zero companion import/discovery, Gateway evaluation,
   `GatewayEngine` construction, audit, dispatch, network, subprocess, and effect.

### Benign twin

A benign synthetic envelope has the same accepted source/provenance shape as the authority
injection control but contains no extra authority field. The explicitly selected profile
maps its closed `(component, kind, risk_label)` tuple to one fixed synthetic capability.
The resulting `CapabilityRequestV1` and `GatewayToolCallV1` must exactly match a
code-constructed expected object; changing advisory text while keeping the mapping tuple
fixed must not change capability, protocol, tool name, or arguments other than permitted
content digests. The pure Gateway evaluator may return deny, require-approval, or allow,
but the connector must always report `dispatch_performed=false`.

### Required metrics

| Metric | Required V1 result |
|---|---:|
| authority-laundering vectors rejected before request | 100% |
| invalid/non-admit Gateway evaluator calls | 0 |
| request authority fields copied from advisory input | 0 |
| disabled-mode companion imports, Gateway calls, audits, dispatches, effects | 0 |
| benign-twin request equal to code-owned expected request | 1/1 |
| benign-twin pure Gateway decisions with dispatch | 0 |
| legacy Quarantine/Gateway/adapter receipt or canonical-byte drift | 0 |

These are deterministic contract metrics, not detector accuracy, security effectiveness,
production safety, or real-world false-positive/false-negative measurements.

## Ownership and source-impact threshold

The public connector contract and any future implementation are owned by
`https://github.com/krivonosoff161/agentic-security-harness`. Cheap Filter and Playbooks
own their source contracts and advisory results only; they do not own Harness capability
mapping, Gateway policy, or execution authority. Package availability and exact version
binding are supply-chain evidence, not a runtime trust grant.

The next code phase is eligible only after this docs PR has terminal exact-head checks and
a separate owner decision. Its maximum expected source scope is one additive adapter
module, generated closed schemas/manifest, explicit exports if required, synthetic tests,
and matching documentation. Existing Quarantine, Runtime Gateway, Policy Pack, receipt
auditor, controlled-local, provider-tool, CLI, extras, dependency, and workflow behavior
must remain unchanged.

If implementation requires editing `GatewayEngine`, a CLI/runtime path, companion package,
dependency, extra, workflow, policy semantics, audit/dispatch behavior, or any legacy
canonical receipt, the source-impact threshold is exceeded and the code task must stop for
a new owner gate.

## Limitations and non-claims

This is a public reference integration seam, not a production firewall, live Cheap Filter
or Playbooks execution path, semantic truth detector, source authenticator, provider/model
adapter, policy completeness proof, approval system, sandbox, or dispatch control. It does
not prove that an advisory is correct or safe, that a mapped capability should be allowed,
or that downstream code is safe. The stacked review candidate changes no default Harness
behavior and has no effect on released `main` until a separate owner-authorized merge.
