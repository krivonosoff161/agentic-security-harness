# Controlled local provider/tool-host adapter V1

Status: stacked source candidate above the unreleased receipt-auditor branch. It is not
present in the published `v1.2.0` package and is not a production provider integration.

This adapter gives an operator-controlled local OpenAI-compatible `/v1/responses`
endpoint one deliberately narrow path into the Runtime Gateway. The model may propose
tool calls, but it cannot select a transport, add credentials, discover plugins, call an
upstream MCP server, or bypass gateway policy.

Qwen, DeepSeek, Llama, Mistral, and other local model names are accepted only as opaque
operator-selected identifiers. A name does not prove the vendor, weights, runtime,
license, provenance, safety, or authenticity of the process listening on the port.

## Trust boundary

The V1 transport is closed:

- scheme is plain `http` inside the host loopback boundary;
- host is the literal IP `127.0.0.1` or `::1`, never a DNS name;
- the operator fixes one port and the only request path is `/v1/responses`;
- the client opens an IPv4/IPv6 socket directly, without `getaddrinfo` or proxy
  environment variables;
- redirects, authentication headers, caller headers, content encoding, transfer
  encoding, streaming, and missing/ambiguous `Content-Length` are rejected;
- request, response, timeout, retry, nesting, array, object, and tool-call counts are
  bounded;
- response bytes must be unique-key UTF-8 canonical JSON with exact
  `Content-Type: application/json`.

The endpoint is still an untrusted local process. Loopback limits network destination; it
does not authenticate the process or isolate it from the workstation. Start and secure
the local runtime separately, verify the model's license, and do not place secrets in
prompts merely because traffic stays local.

## Policy-before-dispatch

Responses are normalized through the existing `openai_responses` provider-tool adapter.
The stateful bridge reserves correlation digests before dispatch and rejects duplicate or
replayed tool-call identities. The only implemented executors remain:

- `synthetic.lookup` over two fixed values;
- `synthetic.sha256` over bounded text.

`system.shell` is denied. `external.send` creates only the Runtime Gateway's
`pending_non_executable` approval identity; V1 exposes no approval-grant endpoint. Any
unknown tool is denied. A completed adapter invocation means transport and policy
evaluation completed—it is not a security `PASS`, and individual tool dispositions may
still be `deny` or `require_approval`.

The replay set is in-memory, stores only correlation digests, and fails closed at 4096
identities. Restarting the adapter resets that set, so V1 is not a durable distributed
idempotency service. Bounded retry happens only before a complete response is accepted;
no gateway tool runs until one whole response has passed framing and JSON validation.
Calls on one adapter instance are serialized so its audit before/after interval cannot be
mixed by another invocation on that instance. The supplied `GatewayEngine` and ledger must
remain dedicated to that adapter while it runs; unrelated direct engine use is outside the
receipt's attribution contract. Cancellation after a response reserves any parsed call
identities before returning, so resuming cannot accidentally execute the cancelled calls.

## Python operator path

The operator starts a compatible local server separately and chooses its loopback port.
Harness does not launch, download, authenticate to, or configure that server.

```python
from pathlib import Path

from agentic_security_harness import (
    ControlledLocalAdapterConfigV1,
    ControlledLocalAdapterV1,
    GatewayAuditLedger,
    GatewayEngine,
)

config = ControlledLocalAdapterConfigV1(
    host="127.0.0.1",
    port=11434,
    timeout_milliseconds=2_000,
    max_retries=1,
)

with GatewayAuditLedger(Path(".internal/local-adapter-audit").resolve()) as audit:
    adapter = ControlledLocalAdapterV1(config, GatewayEngine(audit))
    outcome = adapter.invoke(
        model_id="Qwen/Qwen3-8B",
        input_text="Use a synthetic tool only if it helps answer this fixture.",
        request_id="operator-fixture-1",
    )
    print(outcome.receipt.status, outcome.receipt.reason_code)
```

Do not pass a token, custom header, URL, filesystem path, provider SDK client, callback,
or MCP connection: V1 has no field for them. `tool_executions` is transient in-process
interoperability data; persist only the canonical invocation receipt unless a separate
data-handling policy explicitly permits more.

## Receipt and privacy semantics

[`schemas/controlled-local-adapter.v1.manifest.json`](../schemas/controlled-local-adapter.v1.manifest.json)
binds the implementation, Runtime Gateway, provider normalizer, fixed policy digest,
schemas, tests, workflow, and this document.

The canonical invocation/tool receipt contains:

- endpoint, config, policy, model, request, response, call, arguments, result, and receipt
  digests;
- bounded attempt/tool/audit counters and before/after audit heads;
- fixed transport, cancellation, framing, replay, policy, and outcome reason codes;
- `provider_authenticated=false` and `operational_authority=none`.

It contains no prompt, response text, tool name, arguments, result, credential, header,
endpoint, machine path, exception text, key, or approval grant. The Runtime Gateway audit
ledger keeps keyed commitments and a hash chain; its local privacy key is not copied into
the receipt. Digests minimize retained content but do not make low-entropy values secret.

## Verification and non-claims

```bash
python tools/controlled_local_adapter_contracts.py check
python -m pytest -q tests/test_controlled_local_adapter.py
```

Linux and Windows run the same synthetic loopback fixtures for SSRF, DNS/proxy isolation,
redirect, framing, chunking, size, timeout, retry, canonical JSON, replay, cancellation,
policy, approval, receipt, and privacy boundaries.

Passing these tests demonstrates only this fixed local/synthetic contract. It does not
authenticate a local provider, protect a compromised host, secure arbitrary tools,
support paid or external provider calls, establish model safety, grant operational
authority, or constitute deployment/enforcement evidence.
