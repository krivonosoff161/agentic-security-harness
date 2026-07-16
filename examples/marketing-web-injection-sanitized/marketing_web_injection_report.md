# Marketing Web-Injection Campaign

Status: sanitized public summary over a controlled synthetic web corpus.

## What This Tests

An ads/marketing analytics swarm reads external web-like material. Some
pages carry hidden instructions that try to make a worker leak or launder
an internal campaign strategy/contract into the chief model's final analysis.

## Metrics

| Metric | Value |
|---|---:|
| Scenarios | 5 |
| Observations | 36 |
| Unsafe observations | 31 |
| Naive leaks | 5 |
| Bounded leaks | 0 |
| Ablation leaks | 21 |
| Benign leaks | 0 |
| Verifier blocks | 5 |
| False blocks | 0 |
| Unsafe block rate | 16.13% |
| Benign allow rate | 100.00% |
| Control attribution rate | 100.00% |
| Response hash coverage | 100.00% |

## Attack Vectors

| Vector | Observations | Leaks |
|---|---:|---:|
| `authority_hijack` | 7 | 5 |
| `benign_task_confusion` | 7 | 5 |
| `source_laundering` | 7 | 5 |
| `summary_drift` | 7 | 5 |
| `web_prompt_injection` | 8 | 6 |

## Control Attribution

| Control | Blocks | Reopened when missing |
|---|---:|---:|
| `audit_hash_chain` | 5 | 3 |
| `authority_floor` | 1 | 1 |
| `canary_detector` | 2 | 2 |
| `chief_verifier` | 5 | 5 |
| `external_source_label` | 3 | 3 |
| `secret_envelope` | 3 | 3 |
| `summary_guard` | 4 | 4 |

## First Failure Steps

- `external_text_treated_as_parent_authority`: 5
- `internal_assumption_treated_as_public_input`: 5
- `summary_dropped_secret_label`: 5
- `untrusted_source_became_internal_insight`: 5
- `worker_followed_external_instruction`: 6

## Non-Claims

- No real contracts, business secrets, accounts, websites, or channels were used.
- This executable specification reproduces its declared failure/defense branches; it is not internet-wide or empirical causal evidence.
- A blocked synthetic campaign is not proof that an arbitrary production swarm is secure.
- Response hash fields are commitments. Without owner-side reconciliation they do not prove private-byte retention, replayability, origin, or semantic truth.

Raw hostile pages, prompts, responses, and synthetic strategy values are
private artifacts and are not part of this public summary.
