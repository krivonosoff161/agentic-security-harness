# Runtime Gateway development contour

The Runtime Gateway is the first executable product layer above the benchmark. It accepts
OpenAI-compatible chat requests and MCP JSON-RPC tool calls, applies a closed policy before
dispatch, and records a privacy-minimized append-only decision trail.

This initial contour is deliberately local and synthetic. It is useful for integration,
policy, audit, and operator testing, but it is **not** a production firewall and does not
connect to OpenAI, Anthropic, Google, a remote MCP server, or arbitrary executors.

## Run locally

From a source checkout:

```bash
python -m pip install -e .
ash gateway-init --out gateway.toml
ash gateway-check --config gateway.toml
ash gateway-fixture --config gateway.toml \
  --provider openai_responses \
  --input examples/provider-tool-adapters/openai-responses.json
ash gateway-serve --config gateway.toml
```

`gateway-init` works from an installed wheel as well as a source checkout. It creates one
portable config and refuses to overwrite an existing file. The committed
`examples/runtime-gateway/gateway.toml` is the equivalent source-tree example.
`gateway-fixture` evaluates one bounded regular JSON fixture through the exact policy and
private audit ledger. It prints only aggregate decisions and digests, never the payload,
tool arguments, provider output, credential, or audit path.

Then open <http://127.0.0.1:8787/dashboard> or test health:

```bash
curl http://127.0.0.1:8787/healthz
curl http://127.0.0.1:8787/readyz
```

The local example stores its audit ledger under `.internal/runtime-gateway/`. That folder
is private runtime state and must not be committed.

## Run with Docker Compose

```bash
docker compose -f compose.gateway.yml up --build
```

The container binds `0.0.0.0` only inside its isolated synthetic-container contour;
Compose publishes it on host loopback at `127.0.0.1:8787`. The service runs as a non-root
user, drops Linux capabilities, uses a read-only root filesystem, and writes only to the
named audit volume. Other containers attached to the same Docker network can still reach
the synthetic service, so do not place credentials or private prompts in this development
contour.

## OpenAI-compatible development endpoint

`POST /v1/chat/completions` accepts a closed, non-streaming subset. The only model ids are:

| Model | Behavior |
|---|---|
| `ash-fake-safe` | Returns a constant synthetic assistant response. |
| `ash-fake-tool-allow` | Requests and executes `synthetic.lookup` after policy allow. |
| `ash-fake-tool-deny` | Requests `system.shell`; policy blocks before execution. |
| `ash-fake-tool-approval` | Requests `external.send`; gateway stops at approval-required. |

Example:

```bash
curl -sS http://127.0.0.1:8787/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"ash-fake-tool-allow","messages":[{"role":"user","content":"fixture"}]}'
```

Authorization, cookie, and proxy-authorization headers are rejected in this credential-free
mode. Streaming, chunked transfer, duplicate JSON keys, non-finite numbers, oversized
bodies, and unknown request fields fail closed.

## MCP 2026-07-28 development endpoint

`POST /mcp` implements a deliberately narrow, stateless subset of MCP `2026-07-28`:
`server/discover`, `tools/list`, and `tools/call`. The removed legacy
`initialize`/`initialized` handshake and protocol sessions are not accepted. Every request
must include the three standard request `_meta` fields plus matching
`MCP-Protocol-Version`, `Mcp-Method`, and, for `tools/call`, `Mcp-Name` headers. The
transport also requires `Accept: application/json, text/event-stream`; this implementation
returns only bounded JSON responses and does not implement SSE or MRTR.

`tools/list` exposes only:

- `synthetic.lookup`, which returns one of two fixed public metadata values;
- `synthetic.sha256`, which hashes one bounded in-memory string and returns only its digest.

Unknown tools, process execution, external sends, malformed arguments, and additional
fields never reach an executor. Approval-required produces a stable, privacy-minimized
request digest with status `pending_non_executable`; it remains a terminal gateway decision
in this contour. There is no approval grant, bypass, or consent-minting API.

Example discovery request:

```bash
curl -sS http://127.0.0.1:8787/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' \
  -H 'Mcp-Method: server/discover' \
  -d '{"jsonrpc":"2.0","id":"discover-1","method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"ash-local-example","version":"1.0.0"},"io.modelcontextprotocol/clientCapabilities":{}}}}'
```

The endpoint validates an incoming `Origin` and permits only the exact loopback origin for
its listener port. It intentionally rejects authorization/cookie headers because this is a
credential-free local contour, not an authenticated remote MCP deployment.

The wire contract follows the official [MCP 2026-07-28 release](https://blog.modelcontextprotocol.io/posts/2026-07-28/),
[discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover),
[tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools), and
[Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
specification pages. This narrow implementation is not a claim of full SDK or extension
conformance.

## Audit and privacy contract

`gateway-audit.jsonl` is a canonical JSON hash chain with one exclusive writer. Records
contain sequence/time, protocol, operation, disposition, reason code, policy digest, and
ledger-local HMAC commitments to request/tool identities and payloads. The random HMAC key
is a private local ledger file and is never returned by the API. Records do not retain raw
prompts, messages, tool arguments, tool output, headers, credentials, usernames, or local
paths. `/v1/gateway/audit` and `/dashboard` expose aggregate counts and the verified chain
head only. `/v1/gateway/policy` exposes the closed rule table and exact policy digest but
cannot change policy or grant approval. The dashboard shows the same policy identity and
explicitly labels approval requests as non-executable.

The ledger detects modification and partial writes but is not a remote transparency log,
hardware-backed attestation, or protection against an administrator deleting all local
state. Back up operational evidence according to your own retention and access policy.

## What comes next

Later, separately reviewed increments can add authenticated approval grants, real MCP
upstream isolation, durable operator identity, policy bundles, and production deployment
guidance. The current approval request digest is not an authenticated approval receipt and
does not grant execution authority.
