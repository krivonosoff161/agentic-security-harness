# RAG Context Sanitized Campaign

Sanitized deterministic artifact for the retrieved-context / RAG authority campaign.

The campaign models whether retrieved context can propagate through an agentic workflow
and become authority across summaries, planners, memory, handoff, or reports.

No local models, external APIs, live RAG systems, credentials, or raw prompt chains are
used.

Rebuild:

```bash
ash rag-context-campaign --write --out examples/rag-context-sanitized
```

Validate:

```bash
ash validate examples/rag-context-sanitized
```

This artifact measures only the declared synthetic contract. It is not proof that a
deployed RAG agent, provider model, or production workflow is safe or unsafe.
