# Agentic Security Harness - executive summary

Target: `protected-demo-agent`

## Scope

- Corpus patterns: 22
- Categories covered: 17
- Run mode: deterministic synthetic local benchmark
- Network/provider calls: none in the built-in demo targets

## Headline result

- Findings present: 0
- Patterns with no findings: 22

## Boundary categories

- ambient_authority
- approval_laundering
- audit
- budget
- capability
- data_boundary_classification_mutation
- data_boundary_handoff_label_stripping
- data_boundary_recipient_confusion
- indirect_instruction
- indirect_prompt_injection_via_tool_output
- mcp
- memory_governance
- memory_poisoning_sanitized
- perception_boundary
- provider_boundary_leakage_sanitized
- sleeping_prompt
- tool_permission_abuse_sanitized

## Findings by severity

- (none)

## Highest-priority failures

- No findings in this deterministic run.

## Residual risk

- This report measures deterministic synthetic scenarios only.
- Passing the corpus is not evidence of complete real-world protection.
- Non-synthetic adapters must add authorization, redaction, metadata, and repeat-run reporting before public artifacts are shared.
