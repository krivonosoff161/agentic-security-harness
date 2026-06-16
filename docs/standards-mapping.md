# Standards mapping

> Last reviewed: 2026-06-16 (v0.13 + unreleased docs).
>
> Scope: implemented local corpus only (22 deterministic seed patterns across 14
> categories). This page maps each pattern **category** to external security frameworks
> at a coarse, defensive level. It helps reviewers understand what each category
> exercises; it does **not** imply certification, complete coverage, or real-world
> protection.

## Source frameworks

- **OWASP Top 10 for Agentic Applications 2026** - per-pattern `owasp_agentic` mapping in
  [`src/agentic_security_harness/corpus.py`](../src/agentic_security_harness/corpus.py).
- **OWASP Top 10 for LLM Applications 2025** - category-level `owasp_llm` mapping in
  [`src/agentic_security_harness/standards_mapping.py`](../src/agentic_security_harness/standards_mapping.py).
- **NIST AI RMF (core functions GOVERN / MAP / MEASURE / MANAGE)** - category-level
  `nist_ai_rmf` mapping in the same module (function level only, not sub-categories).
- **MITRE ATLAS** - conservative category-level IDs verified against the official
  [`mitre-atlas/atlas-data`](https://github.com/mitre-atlas/atlas-data) distribution,
  content version `2026.05`, format version `6.0.0`
  ([source YAML](https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v6/ATLAS-2026.05.yaml)).
  IDs stay empty where a mapping would be speculative.

The machine-readable mapping is the source of truth; `ash validate` runs a self-check
(`validate_standards_mapping`) so this page and the code cannot silently drift.

For legitimate use paths around local labs, owned-system assessments, provider programs,
and standards-aligned benchmarking, see
[authorized-testing-paths.md](authorized-testing-paths.md). Framework mappings are analyst
orientation, not certification or endorsement.

## Category-level mapping

`status` is honest about completeness. A row is `mapped` only when OWASP Agentic,
OWASP LLM, NIST AI RMF, and a verified MITRE ATLAS technique are present. A row remains
`partial` when one of those mappings is intentionally deferred.

| Category | OWASP Agentic | OWASP LLM 2025 | NIST AI RMF | MITRE ATLAS | Status |
|---|---|---|---|---|---|
| `ambient_authority` | ASI02, ASI03 | LLM06 | MEASURE, MANAGE | [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053) | mapped |
| `approval_laundering` | ASI05 | LLM06 | GOVERN, MANAGE | (deferred) | partial |
| `audit_bypass` | ASI03 | (deferred) | GOVERN, MANAGE | (deferred) | partial |
| `audit_integrity` | ASI03 | (deferred) | GOVERN, MANAGE | (deferred) | partial |
| `budget_exhaustion` | ASI02 | LLM10 | MEASURE, MANAGE | [AML.T0034.002](https://atlas.mitre.org/techniques/AML.T0034.002) | mapped |
| `capability_delegation` | ASI02, ASI07 | LLM06 | MEASURE, MANAGE | (deferred) | partial |
| `data_boundary` | ASI03, ASI04, ASI06, ASI07 | LLM02 | MAP, MEASURE, MANAGE | [AML.T0057](https://atlas.mitre.org/techniques/AML.T0057) | mapped |
| `indirect_prompt_injection` | ASI01, ASI02 | LLM01 | MEASURE, MANAGE | [AML.T0051.001](https://atlas.mitre.org/techniques/AML.T0051.001) | mapped |
| `mcp_tool_schema` | ASI02, ASI06 | LLM06 | MEASURE, MANAGE | [AML.T0110](https://atlas.mitre.org/techniques/AML.T0110) | mapped |
| `memory_governance` | ASI01, ASI03, ASI06 | LLM04, LLM02 | MEASURE, MANAGE | [AML.T0080](https://atlas.mitre.org/techniques/AML.T0080), [AML.T0080.000](https://atlas.mitre.org/techniques/AML.T0080.000) | mapped |
| `memory_poisoning` | ASI06 | LLM04 | MEASURE, MANAGE | [AML.T0080.000](https://atlas.mitre.org/techniques/AML.T0080.000) | mapped |
| `perception_boundary` | ASI01 | LLM01 | MEASURE | [AML.T0051.001](https://atlas.mitre.org/techniques/AML.T0051.001) | mapped |
| `sleeping_prompt` | ASI01, ASI06 | LLM01 | MEASURE | [AML.T0094](https://atlas.mitre.org/techniques/AML.T0094) | mapped |
| `tool_permission` | ASI02, ASI03 | LLM06 | MEASURE, MANAGE | [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053) | mapped |

Rationale for each row lives next to the mapping in `standards_mapping.py`. Per-pattern
OWASP Agentic (ASI) codes remain in `corpus.py`; the table above aggregates them by
category.

## Why the project focuses on label propagation

The crowded part of the market is live red-teaming and vulnerability scanning. This
repository intentionally focuses on a narrower measurement problem:

```text
Does a data envelope survive agent decisions, memory writes, tool calls,
provider routing, and handoffs?
```

That makes the project closer to a conformance-style benchmark for data-boundary and
information-flow behavior than to a general red-team scanner.

Recent defenses such as CaMeL and FIDES show that information-flow control and label
propagation are becoming mainstream design patterns for agent security. This harness does
not replace those defenses; it provides a small, deterministic way to measure whether an
agent stack preserves the relevant labels in known failure shapes.

## Mapping rules

- Prefer a small number of framework IDs per category; map at category level, not by
  guessing per-pattern sub-IDs.
- OWASP Agentic (per pattern) is authored in `corpus.py`; OWASP LLM and NIST (per
  category) in `standards_mapping.py`. Keep both in sync - `validate_standards_mapping`
  enforces id formats and that empty fields are explicit, not accidental omissions.
- Do not add MITRE ATLAS IDs unless they are checked against the current official ATLAS
  data release and added to the allow-list in `standards_mapping.py`; leaving the field
  empty with status `partial`/`deferred` is the honest default.
- Do not add standards mappings for planned patterns before the pattern exists in code.
- Treat mappings as reviewer navigation, not as proof of security.

## MITRE ATLAS verification decision

The project now asserts a small verified subset of MITRE ATLAS IDs, using the official
ATLAS data release `2026.05` as the review anchor. The verified subset covers the current
agentic failure shapes that have direct ATLAS matches:

| ATLAS ID | ATLAS name | Used for |
|---|---|---|
| [AML.T0034.002](https://atlas.mitre.org/techniques/AML.T0034.002) | Agentic Resource Consumption | `budget_exhaustion` |
| [AML.T0051.001](https://atlas.mitre.org/techniques/AML.T0051.001) | LLM Prompt Injection: Indirect | `indirect_prompt_injection`, `perception_boundary` |
| [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053) | AI Agent Tool Invocation | `ambient_authority`, `tool_permission` |
| [AML.T0057](https://atlas.mitre.org/techniques/AML.T0057) | LLM Data Leakage | `data_boundary` |
| [AML.T0080](https://atlas.mitre.org/techniques/AML.T0080) | AI Agent Context Poisoning | `memory_governance` |
| [AML.T0080.000](https://atlas.mitre.org/techniques/AML.T0080.000) | AI Agent Context Poisoning: Memory | `memory_governance`, `memory_poisoning` |
| [AML.T0094](https://atlas.mitre.org/techniques/AML.T0094) | Delay Execution of LLM Instructions | `sleeping_prompt` |
| [AML.T0110](https://atlas.mitre.org/techniques/AML.T0110) | AI Agent Tool Poisoning | `mcp_tool_schema` |

The following categories intentionally remain MITRE-deferred:

- `approval_laundering`: human-approval context omission is related to agent misuse, but
  the current ATLAS techniques do not give a precise category-level fit.
- `audit_bypass` and `audit_integrity`: the harness tests oversight and trace integrity,
  while ATLAS primarily describes adversary techniques against AI systems.
- `capability_delegation`: delegation-chain drift is a harness-specific boundary failure;
  mapping it to generic tool invocation would overclaim.
