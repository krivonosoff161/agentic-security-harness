# Native Ollama to Quarantine and pure Gateway

Status: additive source capability, **unreleased**; the published `1.5.1` wheel
does not contain this module. Build/install the reviewed source revision in an
isolated environment. This is not an arbitrary-provider connector or a production
deployment guide.

## Boundary

The opt-in module `agentic_security_harness.ollama_quarantine_adapter` implements:

```text
application-selected profile + fixed local model
  -> native Ollama /api/generate (one explicit call)
  -> bounded native-response parser and proposal normalization
  -> Quarantine Connector admission
  -> pure Gateway policy decision (only for admitted requests)
  -> content-free outcome; no dispatch
```

The application, not the model, owns profile identity, request identity, capability
mapping and policy. The model supplies only `capability_id` and `arguments`, or an
explicit `no_request: true` object. The adapter constructs the existing canonical
envelope without changing those values. A malformed response is not silently
converted into `no_request`. Unknown capabilities cannot acquire a mapping.

The requested JSON Schema controls the **data shape**, not authorization. A caller
chooses proposal mode or the separate `no_request=True` mode. Proposal mode does
not fix capability/argument values. A resulting `allow` demonstrates compatibility
with the configured pure policy, not autonomous tool choice or model intent.
No-request mode rejects an unexpected proposal before Gateway evaluation.

## Explicit local example

Precondition: the operator already installed and started Ollama with the named
local model. This API does not start services, download/pull models, discover
profiles, install companions or read environment variables/credentials. Use only
public or otherwise explicitly approved input. The following example makes **one
model request** if run; it does not execute the proposed synthetic lookup.

```python
from agentic_security_harness.ollama_quarantine_adapter import (
    OllamaQuarantineConfigV1,
    invoke_ollama_quarantine_v1,
)
from agentic_security_harness.quarantine_connector import (
    ProviderAdapterProfileRegistryV1,
    ProviderAdapterProfileV1,
    QuarantineCapabilityBindingV1,
)
from agentic_security_harness.runtime_gateway import default_gateway_policy_v1

registry = ProviderAdapterProfileRegistryV1(profiles=(
    ProviderAdapterProfileV1(
        profile_id="example.ollama", profile_version="v1",
        capabilities=(QuarantineCapabilityBindingV1(
            capability_id="bounded.lookup", gateway_protocol="mcp",
            gateway_tool_name="synthetic.lookup",
            allowed_argument_keys=("key",), required_argument_keys=("key",),
        ),),
    ),
))
outcome = invoke_ollama_quarantine_v1(
    OllamaQuarantineConfigV1(),
    model_id="prometheus-qwen15b-lowctx:latest",  # operator-selected installed model
    prompt=(
        'Encode this public toy record as JSON only: '
        '{"capability_id":"bounded.lookup","arguments":{"key":"project-status"}}. '
        'Preserve its values. This is data encoding, not execution.'
    ),
    request_id="example:001",
    registry=registry,
    selected_profile_id="example.ollama", selected_profile_version="v1",
    gateway_policy=default_gateway_policy_v1(),
)
print(outcome.model_dump_json())  # hashes/typed decisions; no raw response
assert outcome.dispatch_performed is False
```

`reason_code == "evaluated"` means parsing/composition completed, not that the
request was admitted or allowed. Inspect `composition.connector_disposition`,
`composition.gateway_evaluated` and `composition.gateway_decision` separately.
An admitted `no_request` has no Gateway decision. Connector rejection, policy
denial, malformed model output and transport failure remain distinct outcomes.

For offline testing, `evaluate_ollama_generate_response_v1` accepts native response
bytes and performs the same pure normalization/decision, with zero transport
attempts. `ollama_proposal_schema_v1` exposes the closed requested shape.

## Supported transport and limits

- Literal IPv4 `127.0.0.1` only, one operator-selected port; fixed `/api/generate`.
  No URL, custom path/header, authentication, proxy, redirect, DNS or retry surface.
- Non-streaming JSON; response body at most 65,536 bytes, proposal at most 16,384
  bytes, depth at most 12, bounded objects/arrays and finite bounded numbers.
- An absolute configurable deadline (0.1 to 120 seconds), including slow/trickled
  responses; bounded wire/header reads. JSON Content-Type and unambiguous HTTP
  framing required. Compressed/redirected responses are rejected.
- Exact model identity, `done: true`, `done_reason: "stop"`; malformed, truncated,
  duplicate-key, unknown-field and nonempty thinking-channel replies are rejected.
  Returned native continuation token IDs are bounded, discarded, never replayed.
- Whitespace/key order may be normalized; markdown, missing fields, duplicate keys,
  unknown capabilities, argument case and authority-bearing fields are not repaired.
- Fixed generation options: temperature 0, seed 42, 256 output tokens, 2048 context
  tokens, one-minute keep-alive. These settings do not guarantee determinism.
- Results retain hashes, typed outcomes and available token counts, not prompts,
  response text, continuation context, model name or argument values. Safe public
  profile/version metadata follows the existing composition receipt contract.

Loopback does **not** authenticate the service, its model weights or the producer.
The adapter is not an OS sandbox or a general model-output safety proof. The pure
Gateway decision does not execute, approve future execution, authenticate custody
or replace an independently authorized execution boundary. Hashes are local
correlation evidence, not signatures. Raw replies exist only transiently in memory;
the caller remains responsible for its input data and process isolation.

## Verification and compatibility

`tests/test_ollama_quarantine_adapter.py` uses fixed public fixtures and owned local
HTTP servers; it never contacts an installed model. It checks admitted/denied/
no-request paths, authority-shaped mutations, framing, byte/depth budgets, absolute
timeouts and absence of dispatch. The full CI matrix runs these checks on Linux
Python 3.11/3.12/3.13 and Windows Python 3.11. Real model observations are separate
bounded evidence, not classifier quality or universal safety claims.

Native protocol references: [Ollama generate API](https://docs.ollama.com/api/generate)
and [structured outputs](https://docs.ollama.com/capabilities/structured-outputs).
Other providers require an explicitly declared adapter and its own conformance
tests; neither this module nor the offline [provider adapters](provider-tool-adapters.md)
claim compatibility with every model/connection type. The older
[controlled local adapter](controlled-local-adapter.md) remains unchanged and has
a different OpenAI-compatible tool-host contract.
