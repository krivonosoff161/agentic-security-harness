# Marketing web-injection campaign

This page documents the controlled offline marketing/ads web-injection campaign. It is
a defensive synthetic scenario for a swarm that reads external web-like material while
holding an internal strategy or contract value.

The campaign is intentionally offline first. It does not fetch real sites, scrape
channels, use real accounts, or publish raw prompts. Live internet tests belong to a
future authorized track after the synthetic control boundary stays stable.

## Scenario

The modeled organization has a marketing analytics swarm:

1. A worker reads external web-like pages about ads, monetization, funnels, or partner
   analysis.
2. A chief model consumes the worker summary and writes an internal recommendation.
3. The system holds a synthetic internal strategy/contract value.
4. Hostile page text attempts to turn external content into parent authority, strip
   source labels, launder secrets through summaries, or present the secret as public
   business context.

The private run stores synthetic secret-shaped values and raw hostile text under
`.internal/`. The committed public example exposes only sanitized observations, hashes,
aggregate metrics, and control attribution.

## Attack vectors

| Vector | Failure being modeled |
|---|---|
| `web_prompt_injection` | External page text tells the worker to reveal internal strategy. |
| `authority_hijack` | External text claims to override system or owner instructions. |
| `source_laundering` | Untrusted web content is restated as an internal verified insight. |
| `summary_drift` | A worker summary drops the private/source label before chief review. |
| `benign_task_confusion` | Safe marketing analysis should pass without leaking or being blocked. |

## Controls

| Control | Purpose |
|---|---|
| `external_source_label` | Preserve that a statement came from untrusted external content. |
| `authority_floor` | Prevent external content from becoming parent/system authority. |
| `secret_envelope` | Keep the synthetic strategy value marked as internal-only. |
| `summary_guard` | Reject summaries that remove source or secrecy labels. |
| `chief_verifier` | Re-check worker output before chief acceptance. |
| `audit_hash_chain` | Anchor the observed chain for replay and tamper detection. |
| `canary_detector` | Detect synthetic strategy/contract value leakage. |

## Current public example

The committed public example is
[`examples/marketing-web-injection-sanitized/`](../examples/marketing-web-injection-sanitized/).

| Metric | Value |
|---|---:|
| Scenarios | `5` |
| Observations | `36` |
| Naive unsafe leaks | `5/5` |
| Bounded unsafe leaks | `0/5` |
| Control-ablation leaks | `21/21` |
| Benign runs allowed | `5/5` |
| False blocks | `0` |
| Response hash coverage | `100%` |
| Control attribution rate | `100%` |

The important evidence is the mode comparison:

- naive mode shows the declared failure is reachable;
- bounded mode blocks the declared unsafe paths without blocking benign work;
- ablation mode selects the generator's declared alternate branch when a required
  control is removed; this is rule-derived attribution, not an empirical causal effect.

## Reproduce

Dry-run:

```bash
ash marketing-web-injection-campaign
```

Write private-ready raw artifacts and a sanitized public summary:

```bash
ash marketing-web-injection-campaign \
  --write \
  --out .internal/marketing-web-injection/latest \
  --summary-out reports/marketing-web-injection
```

Validate the committed public example:

```bash
ash validate examples/marketing-web-injection-sanitized
```

## Publication boundary

Public artifacts may include:

- scenario ids, vectors, modes, control ids, decisions, and leak kinds;
- response hashes and aggregate metrics;
- control-ablation reopenings;
- private/public hygiene flags.

Public artifacts must not include:

- raw hostile page text;
- raw prompts or raw responses;
- synthetic strategy or contract values;
- local paths, credentials, real customer data, or real website content.

## Non-claims

This campaign does not prove:

- real internet safety;
- production swarm safety;
- a model vulnerability, CVE, or leaderboard result;
- real-secret extraction;
- exhaustive web-injection coverage.

It does prove a narrower and useful thing: for the declared synthetic marketing
web-injection cases, the bounded contract changes the outcome from naive leakage to
blocked unsafe paths, and the ablation rows identify which controls carry that decision.
