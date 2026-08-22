# Provider tool-adapter fixtures

These four payloads are deterministic, credential-free examples for the Runtime Gateway's
provider-neutral tool-call normalization layer. They are retained response/request shapes,
not live provider traffic. Running them does not import a provider SDK, open a network
connection, read environment credentials, or execute an arbitrary tool.

The examples cover the deliberately narrow supported subset:

- OpenAI Responses completed `function_call` output;
- Anthropic Messages completed `tool_use` content;
- Google Interactions completed `function_call` step;
- stateless MCP `tools/call` with the project's frozen 2026-07-28 metadata contract.

All four normalize into `GatewayToolCallV1` and pass through the same closed policy. Only the
two built-in `synthetic.*` tools can execute; denied and approval-required decisions do not
reach a tool implementation.
