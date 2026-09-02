# Quarantine Connector V1: opt-in source contract

Status: additive source-level APIs proposed for the next Harness release. They are not in
the published `v1.4.0` package. The source implementation provides closed Pydantic
objects, an explicit registry, a strict canonical-JSON decoder, a pure verdict function,
a non-executing Gateway-call bridge, and a separate opt-in composition ending at the
existing pure Gateway policy decision. Generated JSON Schemas and synthetic conformance
tests cover both APIs. They provide no transport, listener, provider/model adapter,
durable receipt, CLI, auto-activation, dispatch, or production integration.

The Quarantine Connector source API is an additive, explicitly selected boundary between
untrusted model/provider output and the existing Runtime Gateway. It does not replace or weaken the
Gateway policy and does not change the accepted bytes, dispatch behavior, or receipts of
the current controlled-local and provider-tool paths.

## Implemented source boundary

The opt-in source path is:

```text
LLM response
  -> ModelEnvelopeV1
  -> explicit profile registry
  -> strict decoder
  -> QuarantineVerdictV1 (admit | reject | inconclusive)
  -> CapabilityRequestV1
  -> existing pure Runtime Gateway policy decision
  -> composition stops (no dispatch)
```

On the wire, the candidate is canonical JSON bytes matching the
`AgenticSecurityHarnessModelEnvelope.v1` representation. The Python `ModelEnvelopeV1`
object exists only after the explicitly selected profile and strict decoder accept those
bytes. All model/provider-originated material remains untrusted throughout this path.
`admit` means only that the complete representation matched the closed profile and, when
present, produced a closed capability request. It does **not** mean `allow`. Only the
existing deterministic Runtime Gateway policy can permit a controlled or synthetic
dispatch.

The connector is the first source-level admission object between untrusted model/provider
bytes and the action-facing Gateway call surface. It does not prove that the model's
intent is safe, that policy coverage is complete, that downstream code is safe, or that
an integration is production-ready.

## Closed source objects

The public source entry point is
`agentic_security_harness.quarantine_connector`. The application constructs a closed
`ProviderAdapterProfileRegistryV1`, explicitly supplies the selected profile id/version
and candidate bytes to `evaluate_quarantine_input_v1()`, and may call
`bridge_quarantine_admission_v1()` only with the resulting admit verdict. The module is
not imported by a CLI, transport, adapter, or automatic package hook.

### `ModelEnvelopeV1`

The admitted envelope contains only bounded, versioned fields owned by one explicitly
selected profile, the selected profile/input digests, an optional digest-only context
binding, and an optional typed capability request. Candidate bytes grant nothing; an
envelope exists only after the selected profile's strict decoder succeeds. The wire
representation uses strict canonical UTF-8 JSON and the typed objects use
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

Each `ProviderAdapterProfileV1` declares an exact id/version, canonical-JSON
representation, context mode, byte/depth/string/collection/object limits, and a sorted
closed mapping of application-owned capability ids to existing Gateway protocol/tool
names and argument-key sets. The strict decoder validates the complete representation
before any `CapabilityRequestV1` can exist. It cannot invent a missing value, coerce a
type, select a route from model bytes, rewrite semantic content, repair malformed JSON,
or drop semantic context.

Unknown profiles, extra fields, duplicate keys, malformed UTF-8, trailing bytes, type
mismatches, noncanonical values, unsupported versions, ambiguous shapes, and
semantic-bearing context without an explicit profile contract produce `reject` or
`inconclusive`, never fallback or best-effort admission.

Stateful context is valid only for a profile whose `context_mode` is explicitly
`required`, through `QuarantineContextBindingV1`: profile id/version plus opaque
session and endpoint SHA-256 commitments. The binding carries no raw endpoint and no
implicit tool, route, policy, token, or capability authority. Missing, unbound,
cross-profile, or otherwise malformed state is rejected rather than silently discarded.
The current connector validates binding shape and profile identity; custody, replay, and
external session/endpoint pin verification remain caller and future receipt concerns.

Profile registration does not discover, install, import, activate, or bind a companion
distribution. Harness extras remain passive until an operator or application explicitly
invokes their existing contracts.

### `QuarantineVerdictV1`

The closed verdict has exactly three dispositions:

- `admit`: the selected profile accepted the complete input and constructed the closed
  envelope; this grants no operational authority;
- `reject`: a deterministic profile, byte, shape, authority, context, or provenance rule
  failed;
- `inconclusive`: the connector cannot establish a safe typed interpretation or cannot
  complete its own observation without guessing.

The verdict links exact profile, input, envelope, and request commitments and uses bounded
stable reason codes. Its operational authority is always `none`. Neither `reject` nor
`inconclusive` retains admitted typed objects or can cross the bridge. No verdict
dispatches a Gateway call.

### `CapabilityRequestV1`

The capability request is still untrusted. It contains only selected profile identity,
a request id, one application-owned capability id, and bounded canonical arguments whose
keys are closed by that profile. It has no `allow`, policy, role, token, approval,
endpoint, executor, route override, or result field.

`bridge_quarantine_admission_v1()` is that pure conversion: it verifies the profile
commitment again and constructs only the existing untrusted `GatewayToolCallV1`. It does
not instantiate or call `GatewayEngine`.

### Opt-in Gateway decision composition

The separate `agentic_security_harness.quarantine_gateway_composition` module adds one
caller-invoked seam: `compose_quarantine_gateway_v1()`. The caller must supply the exact
immutable profile registry, selected profile id/version, bounded candidate bytes, and an
existing `GatewayPolicyV1`. The function performs admission first and calls only
`evaluate_gateway_tool_call()` when an admitted envelope contains a capability request.
It never accepts or constructs a `GatewayEngine`.

`QuarantineGatewayCompositionV1` is a privacy-minimized typed outcome. It retains the
closed Connector disposition/reason, selected profile identity, registry/verdict/input/
profile/envelope/request/bridge commitments when applicable, and the existing safe
Gateway decision plus its commitment. It never retains raw candidate bytes, arguments,
tool names, endpoint data, credentials, free-form policy, executor identity, audit state,
or tool output. `dispatch_performed` is always `false` and operational authority is always
`none`.

| Connector result | Gateway policy evaluated | Dispatch or execution |
|---|---:|---:|
| `reject` / `inconclusive` | no | no |
| `admit` + `no_request` | no | no |
| `admit` + capability request, Gateway `deny` or `require_approval` | yes | no |
| `admit` + capability request, Gateway `allow` | yes | no |

This makes the product boundary explicit:
`Connector admission != Gateway decision != tool execution`. A Gateway `allow` is a pure
policy result in this API, not an engine call, audit receipt, dispatch instruction, or
proof that execution occurred.

## Compatibility invariants

The source implementation is additive and opt-in and preserves all of the following:

- existing controlled-local and provider-tool behavior remains unchanged by default;
- existing Runtime Gateway policy remains the only action-permitting decision point;
- the composition uses only the existing pure policy evaluator and cannot call the
  dispatching Gateway engine;
- legacy receipt schemas, canonical bytes, hashes, fixtures, and public contracts remain
  byte-identical;
- new admission commitments exist only in the new objects and bridge sidecar; no legacy
  receipt is rewritten;
- profile discovery and companion activation remain explicit and nonautomatic;
- no provider call, listener, executor, package discovery, or retention policy is implied
  by the connector contract;
- the terms here do not redefine the planned ingress queue in `api-reference.md`, handoff
  quarantine, memory quarantine, or historical Runtime Guard verdict vocabularies.

## Conformance status and future requirements

`tests/test_quarantine_connector.py` and
`tests/test_quarantine_gateway_composition.py` provide synthetic deterministic source
vectors. They are not a provider/model corpus, runtime integration result, or proof over
retained raw responses. Runtime integration still requires a separate review.

### Byte and shape

Current vectors cover valid minimal no-request and request cases, duplicate keys, unknown
fields, wrong scalar/container types, unsupported versions, malformed UTF-8, trailing
bytes, noncanonical JSON, and representative byte/depth/string limits. Non-admit vectors
demonstrate that the bridge cannot construct a Gateway call. Exhaustive boundary-value
generation for every declared limit remains future corpus work.

### Profile mismatch and no fallback

Current vectors cover unknown/version-mismatched profiles, semantic-bearing outer
context, required binding, and profile mismatch. No case passes through autodetection,
generic fallback, silent context removal, or a different profile. Cross-session,
cross-endpoint, replay, and pin-drift custody require a future receipt/integration layer.

### Authority injection

Current vectors cover model-originated authority keys including route, `allow`, policy,
role/principal, token, endpoint, tool definition, and effect, plus unknown capability and
argument-key drift. An admitted application-mapped request is also shown independently
denied by the Gateway, proving that admission does not mint authority or bypass policy.

### Receipt custody, replay, and pin drift

The source objects provide exact envelope/profile/verdict/request/bridge commitments and
the composition adds an in-memory commitment to the existing safe Gateway decision.
This is not a durable, authenticated, ordered, replay-resistant receipt. Replay/reordering,
cross-session or cross-endpoint reuse, stale pins, custody, and persistence remain
unimplemented. Focused legacy controlled-local, provider-tool, and Gateway regressions
remain required, and their bytes/manifests must remain byte-identical.

### Passive extras

The source module has no package-discovery or activation hook and package extras are
unchanged. Installation-matrix verification remains a release gate: installation alone
must not discover, select, import, bind, configure, invoke, or activate a decoder profile
or companion module.

### Legacy regressions

The existing controlled-local adapter, provider-tool adapter, and Runtime Gateway suites
are rerun with this source increment. The connector is not imported or invoked by those
paths and must not make either path more permissive, change reason-code meaning, dispatch
additional tools, or alter the closed synthetic Gateway behavior.

## Explicit non-claims

This document does not claim a defect in the current Harness. It does not claim that the
source connector or composition is included in the published package, enabled, wired to
a CLI/transport/engine, runtime-integrated, production-safe, compatible with every
provider or model, able to determine intent, sufficient to make an unsafe policy safe,
or able to secure downstream modules. A returned Gateway `allow` does not prove or cause
tool execution. These APIs grant no model, provider, package, profile, extension, or
operator any new authority.
