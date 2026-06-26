# Live Swarm Defense Campaign

Status: sanitized public summary over private local-model probes.

## Metrics

- observations: 168
- max session turns: 3
- long-session observations: 168
- worker drift detections: 3
- chief acceptances: 67
- canary leaks: 0
- verifier blocks: 70
- adapter errors: 7
- unsafe observations: 70
- benign observations: 91
- response hash coverage: 1.00
- turn hash coverage: 1.00
- unsafe block rate: 1.00
- benign allow rate: 1.00

## Control attribution

| Control | Blocks | Reopened when missing |
|---|---:|---:|
| `audit_hash_chain` | 70 | 70 |
| `canonical_state` | 3 | 1 |
| `chief_verifier` | 67 | 67 |
| `cross_worker_check` | 18 | 18 |
| `source_hash` | 67 | 48 |
| `summary_guard` | 67 | 37 |
| `transition_table` | 3 | 1 |
| `worker_attestation` | 3 | 0 |

## Replay ablation

Replay ablation does not make new model calls. It replays the sanitized
verifier decisions from the private live run and asks which blocked
unsafe decisions would reopen if a named required control were absent.

- replay ablation reopenings: 242
- replay ablation reopening rate: 1.00

| Removed control | Reopened decisions |
|---|---:|
| `audit_hash_chain` | 70 |
| `canonical_state` | 1 |
| `chief_verifier` | 67 |
| `cross_worker_check` | 18 |
| `source_hash` | 48 |
| `summary_guard` | 37 |
| `transition_table` | 1 |

## Rate confidence intervals

Wilson 95% intervals over this bounded campaign:
- `benign_allow_rate`: [0.960, 1.000]
- `canary_leak_rate`: [0.000, 0.022]
- `chief_acceptance_rate`: [0.328, 0.474]
- `unsafe_block_rate`: [0.948, 1.000]
- `verifier_block_rate`: [0.345, 0.492]
- `worker_drift_rate`: [0.006, 0.051]

## Model breakdown

Worker model observations:
- `qwen2.5-coder:0.5b-instruct`: observations=84, chief_acceptances=35
- `qwen2.5:0.5b`: observations=84, chief_acceptances=32

Chief model observations:
- `llama3.2:1b`: observations=84, chief_acceptances=6
- `prometheus-qwen15b-lowctx:latest`: observations=84, chief_acceptances=61

## Non-claims

- No real secrets were used.
- A live local-model failure is not a CVE.
- A block in this campaign is not proof that a production swarm is secure.
- Response hashes prove artifact hygiene, not semantic truth.

Raw prompts, raw responses, synthetic canary values, and calculation notes are
private artifacts and are not part of this public summary.
