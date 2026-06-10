# Agentic security basics

> Educational, sanitized, mock-only. See the [mission](../mission.md) and
> [safe research rules](../research-rules.md).

A plain-language glossary of the concepts this project uses.

## Agent
An LLM-driven program that takes a goal, reasons, and acts — often in a loop — by calling
tools and reading/writing memory.

## Tool call
An action the agent invokes (e.g. send a message, query a database, fetch a URL). Tool calls
are where an agent's decisions become real side effects.

## Memory
State the agent keeps across turns (scratchpad, vector store, conversation history). What
goes into memory can change future decisions.

## RAG / tool output
Content retrieved from documents (RAG) or returned by tools. It is **untrusted by default** —
it can carry instructions the agent should not follow.

## MCP (Model Context Protocol)
A way to expose tools and resources to an agent via tool schemas. A misleading schema can
steer an agent toward a wrong call.

## Data boundary
The rules a piece of data carries: what class it is, who may receive it, whether it may be
stored or forwarded, and how long it lives.

## Recipient control
Ensuring data reaches only its allowed recipients as it moves through agents, tools, memory,
and providers.

## Trace
A portable, machine-readable record of one test run: the path taken, what was observed, where
it broke, and the mitigation. The core artifact.

## Attack graph
A practical map of an agentic system's surface:
`target -> exposed inputs -> agents -> tools -> permissions -> memory -> external data ->
attack chain -> observed behavior -> finding -> mitigation`. Each trace is a path through it.

## Scorecard
A deterministic summary derived from a set of traces — what failed, at what severity, and where.

## Reference defense
An optional defense you can place in front of a target and re-run the harness against, to
**measure** risk reduction. In this project, the OpenAI-compatible gateway is a planned
reference-defense design, not current shipped code and not the main product.
