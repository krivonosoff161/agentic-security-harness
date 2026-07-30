# Runtime Guard source map

> Reviewed: 2026-07-26. Primary sources only; vendor claims are not independent proof.

## Standards and protocols

| Source | Foundation use | Limitation |
|---|---|---|
| [NIST AI RMF and GenAI Profile](https://www.nist.gov/itl/ai-risk-management-framework) | Governance, TEVV, provenance, privacy, IP, supply-chain diligence. | No per-action authorization protocol. |
| [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative) | Future compatibility for agent identity and security. | Initiative, not a completed certification profile. |
| [NIST NCCoE Agent Identity and Authorization concept paper](https://www.nccoe.nist.gov/sites/default/files/2026-02/accelerating-the-adoption-of-software-and-ai-agent-identity-and-authorization-concept-paper.pdf) | Least privilege, intent, delegation, human binding, audit, non-repudiation questions. | Concept paper, not a standard. |
| [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | Threat taxonomy for goal, tool, identity, memory, handoff, and cascade tests. | Guidance, not enforcement proof. |
| [MITRE ATLAS](https://atlas.mitre.org/) | Threat/mitigation classification and case-study references. | Knowledge base, not a control standard. |
| [MCP authorization](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) | OAuth resource binding and token-passthrough defenses. | Transport authorization does not prove current user intent. |
| [A2A specification](https://a2a-protocol.org/dev/specification/) | Identity/capability discovery and signed metadata direction. | Declared capabilities can still be false or overbroad. |
| [Google AP2](https://github.com/google-agentic-commerce/AP2) | Intent, authorization, and receipt separation as an adjacent pattern. | Payment-specific v0.1 reference; not a universal authority standard. |

## Vendor mechanisms reviewed as adjacent art

- [Google Model Armor](https://cloud.google.com/security/products/model-armor):
  vendor-claimed inline prompt/response/agent inspection.
- [DeepMind AI Control roadmap](https://deepmind.google/blog/securing-the-future-of-ai-agents/):
  treat agents as potentially untrusted, use supervisors and sandboxing.
- [Microsoft Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/agent-identities):
  separate agent identity and sponsor accountability.
- [Microsoft Task Adherence](https://learn.microsoft.com/en-us/azure/ai-services/content-safety/concepts/task-adherence):
  preview advisory risk signal before tool execution.
- [AWS AgentCore runtime security](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-security-best-practices.html):
  gateway-only paths, external policy engines, least privilege, and isolation.
- [NVIDIA NeMo Guardrails rail types](https://docs.nvidia.com/nemo/guardrails/about-nemo-guardrails-library/rail-types):
  input/retrieval/dialog/execution/output interception points.
- [Anthropic safe and trustworthy agents framework](https://www.anthropic.com/news/our-framework-for-developing-safe-and-trustworthy-agents):
  layered controls for tools and subagents.

These sources support the architectural direction but do not prove that the ASH
foundation or any vendor product blocks real attacks. No external code, schema, table,
figure, or long text was copied.

## Existing ASH components reused

- `models.py`: `DataEnvelope` and synthetic `CapabilityToken`;
- `handoff_integrity.py`: canonical handoff hash and fail-closed toy verifier;
- `memory_governance.py`: hash-only values, scope, trust precedence, and TTL;
- `envelope_policy.py`: non-weakening data-label checks;
- `secret_hygiene.py` and `safe_io.py`: defense-in-depth redaction and safe publication;
- `validation.py` and `run_manifest.py`: filesystem topology and content-bound artifacts;
- `external_openai_compatible.py`: experimental secret-safe transport boundaries.

The foundation does not promote any of these synthetic objects into production
credentials or attestations.

## License handling

Only ideas and independently written summaries were used. Any future code/schema import
requires an exact upstream commit, license/NOTICE review, SPDX expression, compatibility
decision, SBOM entry, and attribution. ISO/IEC and ETSI text, OWASP share-alike material,
vendor documentation, figures, and tables must not be reproduced casually.
