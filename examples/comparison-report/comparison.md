# Agentic Security Harness - risk-reduction comparison

| | Baseline | Protected |
|---|---|---|
| Target | `demo-local-agent` | `protected-demo-agent` |
| Patterns failed | 22 | 0 |
| Patterns passed | 0 | 22 |
| Total findings | 22 | 0 |

## Findings by severity

| Severity | Baseline | Protected |
|---|---|---|
| high | 20 | 0 |
| medium | 2 | 0 |

Findings reduced: 22 -> 0 (-22).

## Recommended control priorities

See `baseline/remediation.md` for the full control recommendation list.
The baseline findings indicate these control families need attention:

- ambient_authority
- approval_laundering
- audit_bypass
- audit_integrity
- budget_exhaustion
- capability_delegation
- data_boundary
- indirect_prompt_injection
- mcp_tool_schema
- memory_governance
- memory_poisoning
- perception_boundary
- sleeping_prompt
- tool_permission

> Risk reduction is measured from deterministic synthetic traces; not a guarantee of real-world protection.
