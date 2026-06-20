# Agentic Security Harness - risk-reduction comparison

| | Baseline | Protected |
|---|---|---|
| Target | `demo-local-agent` | `protected-demo-agent` |
| Patterns failed | 23 | 0 |
| Patterns passed | 0 | 23 |
| Total findings | 23 | 0 |

## Findings by severity

| Severity | Baseline | Protected |
|---|---|---|
| high | 21 | 0 |
| medium | 2 | 0 |

Findings reduced: 23 -> 0 (-23).

## Recommended control priorities

See `baseline/remediation.md` for the full control recommendation list.
The baseline findings indicate control families need attention.


> Risk reduction is measured from deterministic synthetic traces; not a guarantee of real-world protection.
