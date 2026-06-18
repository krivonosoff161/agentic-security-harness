# Theory docs

> Architecture note: 2026-06-18.
>
> This directory holds cleaned, conservative theory documents for Agentic Security Harness
> research tracks. It is not an academic archive.

## What belongs here

- **Public, cleaned invariant statements** for a research track.
- **Formal objects** (types, predicates, rules) that the code implements.
- **Deterministic checks** and their pass/fail conditions.
- **Claim boundaries** (what this proves, what it does NOT prove).
- **Links to code, tests, and evidence artifacts.**

## What does NOT belong here

- Heavy calculations, scratch derivations, or exploratory notes.
- Private literature reviews or uncurated source maps.
- Machine-specific runtime captures.
- Anything that reads like an operational abuse guide.
- Overclaiming ("mathematically proven security", "complete protection").

## Public vs private boundary

| Public (this directory) | Private / local only |
|---|---|
| Cleaned invariant statements. | Scratch derivations. |
| Formal object definitions. | Exploratory literature notes. |
| Deterministic check specifications. | Machine-specific captures. |
| Claim boundaries. | Private organizational details. |
| Links to code, tests, evidence. | Uncurated experiment logs. |

## Structure

| File | Status | Description |
|---|---|---|
| `handoff-integrity.md` | Active | Pilot theory module for inter-agent handoff integrity. |
| `data-boundary.md` | Planned | Theory for data envelope / label preservation. |
| `authority-delegation.md` | Planned | Theory for capability delegation and authority non-expansion. |
| `audit-integrity.md` | Planned | Theory for append-only audit hash-chain integrity. |
| `memory-governance.md` | Planned | Theory for memory provenance, TTL, and cross-user isolation. |

## Rules

- Every theory doc must have a claim boundary section.
- No theory doc may claim "mathematically proven security" or equivalent.
- Theory docs link to code, tests, and evidence artifacts — they are not standalone.
- Planned files are stubs only; they describe the intended scope, not a finished model.
- Heavy research stays in private/local scratch until it is ready for public cleaning.
