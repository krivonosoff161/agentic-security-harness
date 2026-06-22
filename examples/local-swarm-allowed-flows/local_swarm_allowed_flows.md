# Local Swarm Allowed-Flow Suite

Allowed-flow checks demonstrate that the deterministic bounded-swarm contracts can pass valid synthetic transfers. They do not prove production availability, semantic truthfulness, or complete false-positive behavior.

## Metrics

| Metric | Value |
| --- | ---: |
| Flows | 6 |
| Allowed passes | 6 |
| Unexpected blocks | 0 |
| False-positive rate | 0.00% |
| Handoff flows | 5 |
| Memory flows | 1 |

## Flow Results

| Flow | Boundary | Passed | Blocked reasons | Evidence |
| --- | --- | ---: | --- | --- |
| `valid_label_preserved_handoff` | `handoff` | True | `-` | verify_handoff verdict=pass<br>structural_score=0.0 |
| `valid_bounded_capability_delegation` | `handoff` | True | `-` | verify_handoff verdict=pass<br>structural_score=0.0 |
| `valid_tool_output_with_provenance` | `handoff` | True | `-` | verify_handoff verdict=pass<br>structural_score=0.0 |
| `valid_approval_same_purpose` | `handoff` | True | `-` | verify_handoff verdict=pass<br>structural_score=0.0 |
| `valid_fresh_memory_read` | `memory` | True | `-` | validate_memory_read returned ok=True |
| `valid_multi_hop_label_preserved` | `handoff` | True | `-` | verify_handoff verdict=pass<br>structural_score=0.0 |

## Non-Claims

- Passing these benign examples does not prove a production false-positive rate.
- The suite is synthetic and deterministic; it does not execute real tools.
- Model prose is not part of the pass decision.
