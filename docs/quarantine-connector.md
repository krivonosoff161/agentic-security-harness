# Quarantine Connector: future opt-in admission contract

Status: design proposal for owner review. No connector, profile registry, decoder,
schema, receipt, corpus, or runtime integration described here is implemented by the
current Harness release.

The proposed Quarantine Connector is an additive, explicitly selected boundary between
untrusted LLM output and the existing Runtime Gateway. It does not replace or weaken the
Gateway policy and does not change the accepted bytes, dispatch behavior, or receipts of
the current controlled-local and provider-tool paths.

## Proposed boundary

The future opt-in path is:

```text
LLM response
  -> ModelEnvelopeV1
  -> explicit profile registry
  -> strict decoder
  -> QuarantineVerdictV1 (admit | reject | inconclusive)
  -> CapabilityRequestV1
  -> existing Runtime Gateway policy
  -> controlled/synthetic dispatch
```

The `ModelEnvelopeV1` stage above is an untrusted candidate, not a validated object. The
explicitly selected profile and strict decoder must validate it before a verdict exists.
All LLM-originated material remains untrusted throughout this path. `admit` means only
that the candidate matched the closed profile and, when present, produced a closed
capability request. It does **not** mean `allow`.
Only the existing deterministic Runtime Gateway policy can permit a controlled or
synthetic dispatch.

The connector would be the first formal admission boundary between an untrusted LLM
response and the action-facing Gateway surface. It would not prove that the model's
intent is safe, that policy coverage is complete, that downstream code is safe, or that
an integration is production-ready.

## Proposed closed objects

These names describe a future compatibility surface, not current Python or schema APIs.

### `ModelEnvelopeV1`

The proposed candidate envelope contains only bounded, versioned fields owned by one
explicitly selected profile. Creating or transporting a candidate grants nothing; it
becomes an admitted envelope only after the selected profile's strict decoder succeeds.
Durable representations use strict canonical UTF-8 JSON and
domain-separated commitments. Raw prompts, response text, credentials, headers,
provider endpoints, routes, policy, roles, tokens, executor choices, and free-form
authority fields do not belong in the envelope.

An LLM response cannot assign itself a tool, route, policy, role, token, capability, or
permission merely by including a matching field or phrase. A capability identifier is
eligible for a request only when an explicitly selected profile defines that exact field
and the complete input passes the profile's closed decoder. The connector never infers or
repairs authority-bearing fields.

### Explicit profile registry and strict decoder

Profile discovery is not automatic. The caller explicitly selects an immutable profile
id and version from an application-owned registry. Unknown, stale, mismatched, or
unsupported profiles yield `reject` or `inconclusive`; they never fall back to another
decoder, a permissive generic parser, provider autodetection, or a companion package.

Each future profile must declare its complete outer shape, closed field vocabulary,
serialization rules, extraction locations, byte/depth/string/list limits, and treatment
of transport-only metadata. The strict decoder validates the entire profile-native
object before any `CapabilityRequestV1` can exist. It cannot invent a missing value,
coerce a type, select a route, rewrite semantic content, repair malformed JSON, or drop
semantic context.

Unknown profiles, extra fields, duplicate keys, malformed UTF-8, trailing bytes, type
mismatches, noncanonical values, unsupported versions, ambiguous shapes, and
semantic-bearing context without an explicit profile contract produce `reject` or
`inconclusive`, never fallback or best-effort admission.

Stateful context is valid only through a future explicit, opaque, bounded contract bound
to the selected profile, session, and endpoint. The context must not carry implicit tool,
route, policy, token, or capability authority. Missing, unbound, cross-profile,
cross-session, cross-endpoint, or otherwise ambiguous state is rejected rather than
silently discarded.

Profile registration does not discover, install, import, activate, or bind a companion
distribution. Harness extras remain passive until an operator or application explicitly
invokes their existing contracts.

### `QuarantineVerdictV1`

The proposed closed verdict has exactly three dispositions:

- `admit`: the selected profile accepted the complete input and constructed the closed
  envelope; this grants no operational authority;
- `reject`: a deterministic profile, byte, shape, authority, context, or provenance rule
  failed;
- `inconclusive`: the connector cannot establish a safe typed interpretation or cannot
  complete its own observation without guessing.

A future verdict links the exact profile and envelope commitments and uses bounded stable
reason codes. Its operational authority is always `none`. Neither `reject` nor
`inconclusive` constructs or dispatches a Gateway call.

### `CapabilityRequestV1`

The proposed capability request is still untrusted. It may contain only a closed protocol
and capability identifier, bounded canonical arguments, and correlation commitments
defined by the selected profile. It has no `allow`, policy, role, token, approval,
endpoint, executor, route override, or result field.

Only a pure, separately reviewed conversion from an admitted request to the existing
untrusted Gateway call shape may cross the next boundary. The existing Gateway engine
then makes its own deterministic decision under its current policy.

## Compatibility invariants

This proposal is additive and opt-in. Any future implementation must preserve all of the
following:

- existing controlled-local and provider-tool behavior remains unchanged by default;
- existing Runtime Gateway policy remains the only action-permitting decision point;
- legacy receipt schemas, canonical bytes, hashes, fixtures, and public contracts remain
  byte-identical;
- a new admission commitment uses an additive sidecar or a separately versioned future
  receipt instead of rewriting a legacy receipt;
- profile discovery and companion activation remain explicit and nonautomatic;
- no provider call, listener, executor, package discovery, or retention policy is implied
  by the connector contract;
- the terms here do not redefine the planned ingress queue in `api-reference.md`, handoff
  quarantine, memory quarantine, or historical Runtime Guard verdict vocabularies.

## Future conformance requirements

No public conformance corpus is claimed to exist yet. A later implementation proposal
must add reviewable, deterministic vectors before any API or runtime integration is
considered complete.

### Byte and shape

Cover valid minimal no-request and request cases, duplicate keys, unknown fields, wrong
scalar and container types, unsupported versions, malformed UTF-8, trailing bytes,
nonfinite or otherwise noncanonical values, and every declared size/depth/string/list
limit. Every non-admit case must demonstrate that no Gateway call is constructed.

### Profile mismatch and no fallback

Cover unknown, stale, newer, and cross-family profiles; documented transport-only outer
metadata; semantic-bearing outer context; endpoint/profile mismatch; and explicit
stateful profile/session/endpoint binding. No case may pass through autodetection, generic
fallback, silent context removal, or a different profile.

### Authority injection

Cover model-originated tool substitutions, extra capability fields, route changes,
`allow`, policy, role, token, approval, endpoint, executor, and missing required
capability fields. None may mint authority or bypass the existing Gateway policy.

### Receipt custody, replay, and pin drift

Cover exact envelope/profile/verdict/request commitments, replay and reordering,
cross-session or cross-endpoint reuse, stale profile pins, changed profile bytes, and
Gateway decision linkage. Legacy controlled-local, provider-tool, Gateway, extension,
and auditor receipt bytes must remain byte-identical.

### Passive extras

Verify base-only behavior and each optional extra independently. Installation alone must
not discover, select, import, bind, configure, invoke, or activate a decoder profile or
companion module.

### Legacy regressions

Re-run the existing controlled-local adapter and provider-tool envelope contracts against
their exact accepted and rejected bytes. A future connector must not make either path
more permissive, change reason-code meaning, dispatch additional tools, or alter the
closed synthetic Gateway behavior.

## Explicit non-claims

This document does not claim a defect in the current Harness. It does not claim that the
future connector is implemented, installable, enabled, production-safe, compatible with
every provider or model, able to determine intent, sufficient to make an unsafe policy
safe, or able to secure downstream modules. It grants no model, provider, package,
profile, extension, or operator any new authority.
