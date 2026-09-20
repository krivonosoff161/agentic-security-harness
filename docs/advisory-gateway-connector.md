# Advisory-to-Gateway Authority Connector V1

Status: **implemented, opt-in source APIs; not part of published v1.4.0**.
The additive modules `advisory_gateway_connector`, `advisory_ingress`, and
`external_playbooks_ingress` are direct-call only. They are not registered in the package
root or a CLI/runtime path and never activate automatically. The contract originated at
Harness source `85f94100eb2e64a8aecd4df3c3b2d6e10ae52342`; implementation tests, not that
historical snapshot, describe the current source behavior. A source merge is not a package
release or deployment.

## Root question and verified gap

Can untrusted Cheap Filter or Playbooks advice be represented as a typed advisory
envelope and evaluated by the existing pure Runtime Gateway policy boundary without the
advice being reinterpreted as authority?

The pre-connector source provided the pieces on either side:

- the Cheap Filter receipt auditor emits authority-free Extension SDK findings and never
  lowers a security decision;
- the Playbooks Policy Pack evaluator emits `observe`, `challenge`, `escalate`, or
  `abstain` advice with `operational_authority=none`;
- the Quarantine Connector and its Gateway composition already cover a different source:
  strict model/provider bytes selected through a provider adapter profile;
- `evaluate_gateway_tool_call()` is the existing pure, deterministic policy decision;
  `GatewayEngine` is the separate audit/dispatch boundary.

Published v1.4.0 has no public API that accepts Filter/Playbooks advisory material, applies
an application-owned mapping, constructs the existing closed `CapabilityRequestV1`, and
ends at the pure Gateway decision. The additive source modules fill only that missing
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

## Exact advisory wire contract

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

The decoder limit is 16,384 input bytes and four JSON container levels. Strings
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

The closed profile owns:

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

The adapter reuses the existing `CapabilityRequestV1`, `GatewayToolCallV1`,
`GatewayDecisionV1`, and `evaluate_gateway_tool_call()` contracts. It does not change
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

The connector is disabled by absence: existing imports, CLI commands, extension
registries, Policy Pack evaluation, receipt auditing, Quarantine composition, controlled
local adapter, provider-tool adapter, and Runtime Gateway remain unchanged.

Installation or import must not:

- discover, import, activate, or invoke a companion package;
- read provider/model configuration or call a provider/model;
- open network, DNS, subprocess, listener, or server surfaces;
- register a CLI command or implicit runtime hook;
- call `GatewayEngine`, write audit state, create an approval grant, dispatch, or cause a
  real or synthetic effect.

The only V1 activation is a direct caller invocation with an exact profile, exact profile
id/version, bounded canonical bytes, and an existing deterministic Gateway policy.

### Explicit source API

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

## Strict source-result ingress seam

The connector intentionally starts after an `AdvisoryEnvelopeV1` already
exists. A second, additive direct-call seam lets a caller
can present an exact Cheap Filter receipt or Playbooks policy evaluation without also
constructing its own provenance assertions.

`AdvisoryIngressProfileV1` is an immutable maintainer-owned object. It binds one
explicit ingress id/version to all of the following:

- exactly one supported source representation: the reviewed Cheap Filter triage receipt
  or the reviewed `PolicyPackEvaluationV1` representation;
- the exact source component, contract id/version, source commit/tree, and contract digest;
- one fixed advisory kind, fixed risk label, fixed advisory text/summary, and accepted
  evidence class;
- the existing code-owned capability bindings and label mapping used to derive a single
  `AdvisoryGatewayProfileV1` for the admitted result.

The source result cannot provide or override any of these fields. In particular, it cannot
select a component, kind, label, capability, tool, route, policy, role, principal, token,
endpoint, executor, approval, dispatch, or effect. Profile selection is exact and explicit;
there is no discovery, companion inspection, best match, fallback, or implicit upgrade.

### Accepted source representations

The ingress decoder operates on caller-supplied bounded bytes and imports no companion
distribution:

1. A Cheap Filter input must be exact canonical bytes for the already reviewed triage
   batch receipt contract and must pass the existing Harness receipt audit against its
   exact reviewed source pin. Because that contract is accounting-only and expressly not
   a security verdict, its only V1 ingress label is the profile-owned `inconclusive`; the
   receipt cannot lower a security decision or choose a mapping.
2. A Playbooks input must be exact canonical bytes for the in-repository
   `PolicyPackEvaluationV1` contract, must validate its content identity and exact reviewed
   source pin, and must equal the profile-owned expected advisory disposition. A different
   valid disposition requires a different explicitly selected profile; it never changes
   the selected profile's label dynamically.

Unknown representations, malformed or noncanonical bytes, duplicate/unknown fields,
invalid self-identities, static source drift, semantic-label drift, and authority-shaped
fields are rejected before an advisory envelope or connector call exists. Validation may
reuse the existing Harness-owned receipt and Policy Pack contracts, but it must not import,
discover, instantiate, or invoke `llm_cheap_filter` or `llm_safety_playbooks`.

For an admitted result, code computes `source_result_sha256 = SHA256(exact_input_bytes)`.
It combines that dynamic digest with only the selected profile's static source identity to
derive the exact one-result `AdvisorySourcePinV1`, then constructs the envelope and calls
the existing `compose_advisory_gateway_v1()` path. The source cannot assert its own digest,
and changing even one input byte changes the derived result pin. A digest is content
binding only: it is not producer authentication, freshness, correctness, consent, or
authority.

### Session and replay contract

The call takes an exact immutable `AdvisoryIngressReplayStateV1` plus an explicit
integer sequence. The state contains only an opaque session commitment, the next expected
sequence, the previous ingress-receipt digest when one exists, and a bounded unique set of
already consumed source-result digests. It contains no raw input, endpoint, credential,
policy, tool output, or mutable authority.

Before source evaluation, the adapter rejects a session identity mismatch, an unexpected
sequence, a repeated source-result digest, malformed state, or history-cap overflow. An
admitted result returns a new immutable state and an ingress receipt digest binding the
old state, sequence, dynamic result digest, derived envelope/profile identities, connector
outcome identity, and new state. The adapter does not persist or coordinate that state:
the caller must atomically adopt the returned state before another call. Lost, forked, or
concurrently reused caller state is outside V1's replay guarantee and must not be described
as durable replay prevention.

### Causal stop points and output custody

The result is safe-to-publish metadata only: disposition/reason, ingress profile
identity and digest, session/sequence commitments, source-result digest, derived advisory
identity, connector outcome identity, ingress receipt digest, and `dispatch_performed=false`.
It retains no raw source bytes, advisory text, endpoint, secret, free-form policy, executor
choice, or tool output.

| Ingress state | Envelope | Connector/Gateway evaluator | Dispatch/effect |
|---|---:|---:|---:|
| malformed, source/profile drift, session/replay failure | 0 | 0 | 0 |
| valid source, connector reject/inconclusive | 1 | connector only; Gateway evaluator 0 | 0 |
| valid source, mapped connector admit | 1 | one existing pure Gateway evaluation | 0 |

`Ingress admission != connector admission != Gateway decision != tool execution`. Even a
pure Gateway `allow` remains only a decision object. The ingress seam must not construct
`GatewayEngine`, write an audit record, create an approval grant, invoke a provider/model,
dispatch a tool, or cause a network/process/filesystem effect.

### Source API, evidence, and non-claims

The additive module remains absent from the package root and every discovery/CLI registry:

```python
from agentic_security_harness.advisory_ingress import (
    ingest_advisory_source_result_v1,
)

outcome = ingest_advisory_source_result_v1(
    application_owned_ingress_profile,
    selected_profile_id="playbooks.policy.review",
    selected_profile_version="1",
    selected_session_sha256=application_session_commitment,
    sequence=application_replay_state.next_sequence,
    replay_state=application_replay_state,
    payload=canonical_source_result_bytes,
    gateway_policy=existing_gateway_policy,
)
assert outcome.dispatch_performed is False
```

`advisory_ingress_v1_json_schemas()` returns the three closed ingress models. The sanitized
`advisory_ingress_v1_api_sha256()` commitment is
`a9899c60f6af11018099ab9d6eee60e08e8833aa0e9f050e5eedbdd448fa43c7`.
Synthetic regression tests check strict Filter/Playbooks representation validation;
dynamic byte-bound result commitment; static profile authority; semantic-label mismatch
rejection; malformed, authority-bearing, session-drift, and replay rejection before
connector invocation; benign admission; exact next-state/receipt linkage; pure Gateway
deny and allow outcomes with zero dispatch; and zero companion import/discovery.

The seam is not a component runner, package bridge, provider/model integration, semantic
truth detector, source authenticator, durable replay database, transaction manager,
production safety boundary, policy completeness proof, approval system, sandbox, or
execution path. It does not establish the real-world correctness of a Filter or Playbooks
result and does not make either companion an authority source.

## External Playbooks receipt-pair ingress

This section defines the separate consumer for one unchanged external Playbooks
input/output pair. It does not widen the `PolicyPackEvaluationV1` path above and does not
reinterpret an external receipt as that internal Harness model. The external output schema
`llm-safety-policy-evaluation-receipt-v1.0` and the internal schema
`harness-policy-pack-evaluation-v1.0` have different fields, identity domains, and byte
rules; stripping the external final line feed would not make them interchangeable.

The boundary is additive and explicit-call only:

```text
exact external input receipt bytes + exact external output receipt bytes
  -> explicitly selected immutable ExternalPlaybooksIngressProfileV1
  -> strict pair validator and correspondence checks
  -> content-free external ingress receipt and immutable replay next-state
  -> existing advisory envelope/connector using only code-owned mapping
  -> existing pure Gateway policy evaluator
  -> STOP
```

There is no schema detection, representation fallback, companion import, evaluator
invocation, file or URL resolution, `GatewayEngine`, audit write, dispatch, or effect in
this boundary. `External pair admission != advisory admission != Gateway decision != tool
execution`. The input and output remain evidence with `operational_authority=none`; they
cannot choose or modify a capability, tool, protocol, arguments, policy, scope, recipient,
budget, role, principal, token, endpoint, executor, approval, route, dispatch, or effect.

### Reviewed profile pins

The first profile is closed over the following reviewed source snapshot and artifacts.
These values identify the supported contract; they are not a statement that a later
remote head, release, or installed distribution is byte-equal. The profile rejects pin
overrides. The operator must independently verify producer artifacts before using it;
the consumer does not fetch or authenticate source code at runtime.

| Profile subject | Exact required value |
|---|---|
| external input schema | `llm-safety-policy-input-receipt-v1.0` |
| external output schema | `llm-safety-policy-evaluation-receipt-v1.0` |
| Playbooks source commit | `190769a15a44f5a5af790b33fc37724e6417c27f` |
| Playbooks source tree | `e3a5601a779c8b2e2f92516da30cf2750d320b5b` |
| `tools/policy_pack.py` Git blob | `5efefc3aa8baecb5496ee87717b625c4efe71331` |
| `tools/policy_pack.py` byte SHA-256 | `3e117b26a75e4aa297ef82658059a627d251000f27bb819f5b332edfbc06c5c8` |
| pack semantic id | `44fa5aced73c6a2fc1eb3cb827955d245c887fa8d7c596e353bb2e9678119169` |
| `contracts/policy-pack.v1.json` byte SHA-256 | `1c8ca14e6ab83d92742f6fba0b0d1b1bc422ebe30163c6619e9c80f5413b8915` |
| pack schema byte SHA-256 | `fd99422169c4cbfbe0f80a16a39cf7557d7ef6d28669b03ae940b24b9e2172a1` |
| input schema byte SHA-256 | `d6a39ad8cb1cfc9e61094fa3c92b11d66b2df3370a326f89ecb4a52c49dd3e8b` |
| output schema byte SHA-256 | `b5e4d5554fb930529fd493dad903a25698c99c62c57d99934f66edda8b4f6f1c` |
| pack manifest byte SHA-256 | `f16f7b905150a5b19adbf8c412c1f6eede23718ef0dd35187e4fd8381d92463c` |
| committed mixed-signals vector byte SHA-256 | `21373b3b151b451baf8b71ab0a9dd9f8303e9ab6239301b59046dfec2b087040` |

All digest fields are exactly 64 lowercase hexadecimal characters. The profile owns the
source, schema, pack, rule-table, evidence-class, component/kind, expected-disposition,
fixed-text, and advisory mapping commitments. Untrusted receipt bytes may repeat required
identities for correspondence checks but cannot replace a profile pin. A playbook path is
matched as data against the pinned rule table and is never opened as an instruction.

### Exact pair bytes and identities

The API accepts two `bytes` values and one exact selected profile. For a decoded
object `x`, define `C(x)` as Python UTF-8 JSON with sorted keys, compact separators,
`ensure_ascii=False`, `allow_nan=False`, and no final line feed. Each accepted wire value
is exactly `C(x) || 0x0a`: one final LF byte, with no BOM, CRLF, trailing space, second LF,
or other trailing byte. This is the pinned producer representation, not a claim of general
RFC 8785 canonicalization. The validator checks the supplied bytes; it must not repair or
reserialize a noncanonical value and then admit the replacement.

Both roots must be objects with strict UTF-8, unique keys, closed fields, exact types,
valid Unicode scalar values, and finite numbers. The input limit is 16,384 bytes, the
output limit is 65,536 bytes, and the consumer-specific maximum structural depth is eight
containers. These tighter consumer limits do not change the producer contract.

For canonical input bytes `I`, decoded input `i`, canonical output bytes `O`, and decoded
output `o`, the validator requires all of these independent bindings:

```text
i.input_receipt_id =
  SHA256("llm-safety-playbooks/policy-input/v1" || NUL
         || C(i without input_receipt_id))

o.input_receipt_id = i.input_receipt_id
o.input_sha256 =
  SHA256("llm-safety-playbooks/policy-input-bytes/v1" || NUL || I)
o.receipt_id =
  SHA256("llm-safety-playbooks/policy-output/v1" || NUL
         || C(o without receipt_id))

input_bytes_sha256 = SHA256(I)
source_result_sha256 = SHA256(O)
i.pack_sha256 = o.pack_sha256 = selected profile pack semantic id
```

`NUL` is one zero byte. The producer-domain `o.input_sha256` and the plain
`input_bytes_sha256` are deliberately different commitments. The semantic pack id is
domain-separated over the pack object without its own id and is not the digest of the
complete LF-terminated pack artifact.

The caller also supplies a trusted expected subject commitment. The validator binds the
input subject to that commitment, then checks all seven input states against the output's
ordered rule results, playbook digests, dispositions, reason codes, summary, overall
disposition, and pinned rule table. A schema-valid, self-consistent output is insufficient
when it is not bound to the exact input and expected subject.

The derived external ingress receipt contains only stable identities and digests: profile,
source/tree/contracts/pack, input and output byte hashes, external receipt ids, expected
subject commitment, session/sequence, previous and next replay-state commitments, and the
downstream advisory/connector/Gateway decision identities when reached. It retains neither
wire bytes nor free-form receipt text, raw subject content, endpoint, credential, policy,
executor choice, or tool output. Hashes establish content correspondence, not producer
authenticity, execution, correctness, freshness, consent, or authorization.

### Closed semantic mapping and causal stop points

The selected profile fixes one expected external disposition and one immutable mapping to
the existing advisory connector. A different disposition requires a different explicitly
selected profile; no receipt label can switch the active profile or mapping. The validator
requires `may_authorize_effects=false` and `operational_authority=none` at the external
root and each rule result, plus `raw_content_included=false` and
`digest_is_authentication=false` in the input. Unknown or authority-shaped fields are
rejected at every depth.

This first profile accepts only `source_class=synthetic_fixture`, matching the derived
advisory evidence class. Other producer source classes are rejected, not silently relabeled
as synthetic. Supporting them needs a separately reviewed profile/evidence contract.

An admitted pair is projected into the existing advisory path with code-owned fields and
`SHA256(O)`. It is never converted into a fabricated `PolicyPackEvaluationV1`. The
existing pure Gateway evaluator may be reached only after the external pair and advisory
connector both admit. A Gateway `deny` is a completed policy decision, not a parser error;
even a Gateway `allow` remains non-executing metadata.

| External result | Advisory connector | Pure Gateway evaluator | State advance | Dispatch/effect |
|---|---:|---:|---:|---:|
| pair rejection | 0 | 0 | 0 | 0 |
| pair admitted, mapping absent/inconclusive | 1 | 0 | 1 immutable next-state | 0 |
| pair admitted and mapped | 1 | exactly 1 | 1 immutable next-state | 0 |

The caller must atomically adopt the returned immutable replay next-state. This V1 design
does not provide a durable store, cross-process transaction, concurrent coordination, or
cross-session replay guarantee.

### Deterministic pre-Gateway rejection order

The external validator uses the following closed gate order. Each failed call exposes one
typed reason and a typed stage; it does not fall through to another profile, representation,
parser, mapping, or policy.

| Ordered gate | Typed reasons | Advisory connector / Gateway calls |
|---|---|---:|
| trusted configuration and selection | trusted model/pin misuse raises `ExternalPlaybooksIngressError` or construction-time validation error; selection returns `profile_identity_mismatch`, `session_identity_mismatch`, `sequence_mismatch`, `replay_history_full` | 0 / 0 |
| previously consumed exact output | `source_result_replay` | 0 / 0 |
| bounded input/output byte and parser boundary | `input_type_invalid`, `input_empty`, `input_oversized`, `output_type_invalid`, `output_empty`, `output_oversized`, `malformed_utf8`, `bom_forbidden`, `duplicate_json_key`, `malformed_json`, `root_type_invalid`, `input_bounds_invalid`, `noncanonical_json` | 0 / 0 |
| closed schemas and authority | `external_schema_invalid`, `authority_claim_forbidden` | 0 / 0 |
| receipt/input/subject/pack/rule correspondence | `receipt_identity_mismatch`, `input_output_binding_mismatch`, `subject_binding_mismatch`, `pack_binding_mismatch`, `rule_binding_mismatch`, `semantic_accounting_mismatch` | 0 / 0 |
| profile-owned semantic mapping | `source_semantic_label_mismatch` | 0 / 0 |
| valid pair without advisory mapping | existing connector `mapping_not_registered` / inconclusive | 1 / 0 |

Rejection does not advance replay state or expose a capability request. An exact-output
replay vector must start from the returned next-state; combining an empty old state with an
incorrect sequence would test only `sequence_mismatch`.

### Public-synthetic vectors and evidence metrics

`DP002-PB-EXT-01` is the positive `challenge` vector. Its input matches the exact hash in
the profile table; the seven source-declared states contain three non-`absent` results.
The committed content-free [regression manifest](../tests/fixtures/external-playbooks-ingress-v1/manifest.json)
pins the two public-synthetic input/output byte pairs. The source suite independently
constructs these deterministic records and checks their exact hashes. It never imports
or runs an external producer, and therefore does not establish producer execution or
package/runtime equivalence. That separate claim requires a fresh exact-source Lab run;
an internal `PolicyPackEvaluationV1` must never be substituted for these wire records.

A benign twin uses the same declared wire contract with all seven states `absent`, a fixed
public-synthetic subject commitment, and a separately selected `observe` profile. These
two vectors test deterministic correspondence and mapping, not classifier quality.

Minimum isolated negative vectors alter: LF/canonical bytes; duplicate/unknown fields;
schema; receipt or input digest; expected subject; pack or rule binding; a rule state or
summary with recomputed self-id; authority fields; profile/session selection; and exact
output replay against returned state. Each vector preserves all earlier preconditions so
its designated typed rejection cannot be masked by canonicality or sequence failure.

The source-owned suite checks exact commitments, reached stage, actual and expected typed
reason, next-state linkage, and replay consumed-set delta. Positive cases
must each admit the exact pair, bind the actual bytes, select the fixed mapping, and call
the pure Gateway evaluator exactly once. Negative cases must reach their designated reason,
make zero connector/Gateway calls where required, and leave state unchanged. Missing
telemetry, unexpected exceptions, or skipped controls are not passing evidence.

Negative tests install downstream sentinels rather than trusting self-reported booleans.
A fresh-interpreter passive-import test denies process/network/write attempts before
effects. Tests also cover wrong root-field types, invalid Unicode, oversized keys, depth,
history capacity, and non-synthetic evidence-class rejection. These checks are finite
regressions, not a sandbox or universal proof. A separate producer campaign must account
every invocation and effect independently; its raw content does not belong in this repo.

### Explicit external ingress API

```python
from agentic_security_harness.external_playbooks_ingress import (
    ingest_external_playbooks_pair_v1,
)

outcome = ingest_external_playbooks_pair_v1(
    application_owned_external_profile,
    selected_profile_id=application_owned_external_profile.profile_id,
    selected_profile_version=application_owned_external_profile.profile_version,
    selected_subject_sha256=expected_synthetic_subject_commitment,
    selected_session_sha256=application_session_commitment,
    sequence=application_replay_state.next_sequence,
    replay_state=application_replay_state,
    input_payload=exact_external_input_bytes,
    output_payload=exact_external_output_bytes,
    gateway_policy=existing_gateway_policy,
)
assert outcome.dispatch_performed is False
```

`external_playbooks_ingress_v1_json_schemas()` exposes the two closed models;
`external_playbooks_ingress_v1_api_sha256()` commits to those schemas and fixed source/rule
pins. This is an API-shape commitment, not a digest of all implementation behavior.
No `PolicyPackEvaluationV1`, Playbooks source, `GatewayEngine`, CLI/runtime path,
dependency, extra, workflow, audit/dispatch semantic, or legacy canonical byte changes.

## Conformance vectors and metrics

All fixtures are synthetic and sanitized. No retained private Filter/Playbooks payload,
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

The public connector contract and implementation are owned by
`https://github.com/krivonosoff161/agentic-security-harness`. Cheap Filter and Playbooks
own their source contracts and advisory results only; they do not own Harness capability
mapping, Gateway policy, or execution authority. Package availability and exact version
binding are supply-chain evidence, not a runtime trust grant.

This source increment is limited to additive adapter modules, a content-free fixture
manifest, synthetic tests, and matching documentation. Existing Quarantine, Runtime Gateway, Policy Pack, receipt
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
or that downstream code is safe. These source APIs change no default Harness behavior;
their presence in a checkout does not change published v1.4.0 artifacts.
