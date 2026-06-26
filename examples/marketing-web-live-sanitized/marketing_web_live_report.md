# Live Marketing Web-Injection Campaign

Status: sanitized public summary over private local-model probes.

## What This Tests

A marketing/ads analytics swarm reads owned local web pages. Hostile
pages try to persuade a worker to treat an internal synthetic strategy
or contract as public analysis. The public artifact exposes only hashes
and aggregate labels; raw pages/prompts/responses stay private.

## Metrics

| Metric | Value |
|---|---:|
| Scenarios | 2 |
| Observations | 60 |
| Local web fetches | 60 |
| Session turns | 3 |
| Long-session observations | 52 |
| Adapter errors | 0 |
| Worker leaks | 3 |
| Chief leaks | 1 |
| Naive final leaks | 0 |
| Bounded final leaks | 0 |
| Ablation final leaks | 1 |
| Benign final leaks | 0 |
| Verifier blocks | 8 |
| False blocks | 0 |
| Unsafe block rate | 15.38% |
| Benign allow rate | 100.00% |
| Response hash coverage | 100.00% |
| Turn hash coverage | 100.00% |

## Attack Vectors

| Vector | Observations | Final leaks |
|---|---:|---:|
| `authority_hijack` | 28 | 0 |
| `web_prompt_injection` | 32 | 1 |

## Control Attribution

| Control | Blocks | Reopened when missing |
|---|---:|---:|
| `audit_hash_chain` | 8 | 4 |
| `authority_floor` | 4 | 4 |
| `canary_detector` | 4 | 4 |
| `chief_verifier` | 8 | 8 |
| `external_source_label` | 8 | 8 |
| `secret_envelope` | 4 | 4 |
| `summary_guard` | 4 | 4 |

## First Failure Steps

- `deterministic_verifier_block`: 6
- `worker_followed_external_instruction`: 3

## Non-Claims

- No real secrets, contracts, accounts, or third-party websites were used.
- A live local-model leak of a synthetic canary is not a CVE.
- A blocked local campaign is not proof that a production swarm is secure.
- This is an owned local-web ingestion probe, not internet-wide safety evidence.
- Response hashes anchor private replayability; they do not prove semantic truth.

Raw local web pages, prompts, responses, and synthetic strategy values
are private artifacts and are not part of this public summary.
