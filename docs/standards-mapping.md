# Standards mapping

> Last reviewed: 2026-06-14 (v0.12).
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
- **MITRE ATLAS** - **deferred**: technique IDs are not asserted until verified against
  the current ATLAS matrix. The field exists and is intentionally empty.

The machine-readable mapping is the source of truth; `ash validate` runs a self-check
(`validate_standards_mapping`) so this page and the code cannot silently drift.

## Category-level mapping

`status` is honest about completeness. Because MITRE ATLAS is deferred everywhere, no
category is fully `mapped`; everything with OWASP LLM + NIST coverage is `partial`, and
categories with no clean OWASP LLM Top 10 fit mark that field `(deferred)` explicitly.

| Category | OWASP Agentic | OWASP LLM 2025 | NIST AI RMF | MITRE ATLAS | Status |
|---|---|---|---|---|---|
| `ambient_authority` | ASI02, ASI03 | LLM06 | MEASURE, MANAGE | (deferred) | partial |
| `approval_laundering` | ASI05 | LLM06 | GOVERN, MANAGE | (deferred) | partial |
| `audit_bypass` | ASI03 | (deferred) | GOVERN, MANAGE | (deferred) | partial |
| `audit_integrity` | ASI03 | (deferred) | GOVERN, MANAGE | (deferred) | partial |
| `budget_exhaustion` | ASI02 | LLM10 | MEASURE, MANAGE | (deferred) | partial |
| `capability_delegation` | ASI02, ASI07 | LLM06 | MEASURE, MANAGE | (deferred) | partial |
| `data_boundary` | ASI03, ASI04, ASI06, ASI07 | LLM02 | MAP, MEASURE, MANAGE | (deferred) | partial |
| `indirect_prompt_injection` | ASI01, ASI02 | LLM01 | MEASURE, MANAGE | (deferred) | partial |
| `mcp_tool_schema` | ASI02, ASI06 | LLM06 | MEASURE, MANAGE | (deferred) | partial |
| `memory_governance` | ASI01, ASI03, ASI06 | LLM04, LLM02 | MEASURE, MANAGE | (deferred) | partial |
| `memory_poisoning` | ASI06 | LLM04 | MEASURE, MANAGE | (deferred) | partial |
| `perception_boundary` | ASI01 | LLM01 | MEASURE | (deferred) | partial |
| `sleeping_prompt` | ASI01, ASI06 | LLM01 | MEASURE | (deferred) | partial |
| `tool_permission` | ASI02, ASI03 | LLM06 | MEASURE, MANAGE | (deferred) | partial |

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
- Do not add MITRE ATLAS IDs until they are checked against the current official ATLAS
  technique pages; leaving the field empty with status `partial`/`deferred` is the
  honest default.
- Do not add standards mappings for planned patterns before the pattern exists in code.
- Treat mappings as reviewer navigation, not as proof of security.
