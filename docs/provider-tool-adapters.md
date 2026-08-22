# Provider-neutral tool-call adapters

The Runtime Gateway includes an offline normalization layer for four provider/tool
envelope families:

- OpenAI Responses completed `function_call` output items;
- Anthropic Messages completed `tool_use` content blocks;
- Google Interactions completed `function_call` steps;
- stateless MCP 2026-07-28 `tools/call` requests.

This layer deliberately stops before provider transport. It accepts an already-retained
JSON object or bounded JSON bytes, produces the same closed `GatewayToolCallV1` contract,
and passes that call through the existing policy and synthetic-tool dispatcher. It does
not import a provider SDK, open a socket, read credentials or environment variables, or
load an arbitrary executor.

## Why this layer exists

Provider response formats differ, but the security decision should not. The adapter keeps
transport-specific correlation identifiers transient, replaces them with domain-separated
hashes in audit data, ignores unrelated model text, and never copies raw arguments into the
privacy-minimized audit ledger.

```text
retained provider envelope
  -> strict format/size/depth checks
  -> ProviderToolCallV1
  -> GatewayToolCallV1
  -> one closed policy
  -> allow / deny / require_approval
  -> provider-shaped synthetic result
```

Denied and approval-required calls never reach a tool implementation. Allowed execution is
limited to the Runtime Gateway's fixed `synthetic.lookup` and `synthetic.sha256` tools.
Approval-required provider responses include only the stable request digest and
`pending_non_executable` state; they do not create a grant.

## Offline example

```python
from pathlib import Path

from agentic_security_harness import (
    GatewayAuditLedger,
    GatewayEngine,
    execute_provider_tool_payload_v1,
)

payload = Path(
    "examples/provider-tool-adapters/openai-responses.json"
).read_bytes()

with GatewayAuditLedger(Path("gateway-audit")) as audit:
    result = execute_provider_tool_payload_v1(
        GatewayEngine(audit),
        "openai_responses",
        payload,
        request_id="synthetic-example",
    )

assert result[0].decision.disposition == "allow"
```

Committed examples for every supported family are under
[`examples/provider-tool-adapters/`](../examples/provider-tool-adapters/).

## Closed limits

The adapter rejects malformed or duplicate-key JSON, incomplete calls, unknown fields in
security-relevant call blocks, non-finite values, excessive nesting, more than eight tool
calls, oversized payloads/arguments/responses, and unsupported provider families. A payload
with no supported call is an error rather than a successful no-op.

## Specification references

The narrow fixtures track the public shapes documented by:

- [OpenAI Responses API](https://developers.openai.com/api/reference/typescript/resources/beta/subresources/responses/methods/create)
- [Anthropic tool use](https://docs.anthropic.com/ko/docs/agents-and-tools/tool-use/implement-tool-use)
- [Google Gemini function calling](https://ai.google.dev/gemini-api/docs/function-calling)
- [MCP 2026-07-28 release](https://blog.modelcontextprotocol.io/posts/2026-07-28/)

These references do not imply provider endorsement or full SDK/protocol conformance.

## Non-claims

This is not a live OpenAI, Anthropic, Google, or MCP client. It provides no credential
broker, streaming transport, retry semantics, producer authentication, authenticated human
approval service, arbitrary tool execution, production deployment, certification, or
security guarantee. Live provider transports remain a separately gated future integration.
