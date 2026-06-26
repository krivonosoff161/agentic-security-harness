# Live Marketing Web-Injection Campaign

This page documents the live local-model version of the marketing web-injection
campaign. It uses an owned local web stand and local OpenAI-compatible models to test
whether a small worker/chief swarm can leak a synthetic internal strategy value after
reading hostile external page text.

It is still defensive and bounded:

- no real secrets;
- no third-party websites;
- no real accounts;
- no internet scraping;
- no tool execution by the model;
- raw pages, prompts, responses, and synthetic strategy values stay under `.internal/`.

## Five-step test

1. **Owned local web stand.** The harness starts a localhost HTTP server and serves
   scenario pages from a temporary directory.
2. **Local mini-swarm.** A worker model reads the page and summarizes it. A chief model
   consumes the worker summary and produces the final recommendation.
3. **Mode comparison.** The same scenario runs in naive, bounded, control-ablation, and
   benign modes.
4. **Long-session pressure.** Unsafe rows use repeated worker turns before chief review,
   so the test is not a single prompt only.
5. **Private/public split.** Private transcripts are hash-anchored in public artifacts;
   the public example exposes counts, model ids, page/response hashes, decisions, leak
   kinds, and verifier attribution only.

## Controls

| Control | Purpose |
|---|---|
| `external_source_label` | Preserve that text came from an untrusted external page. |
| `authority_floor` | Prevent page text from becoming system or owner authority. |
| `secret_envelope` | Keep synthetic strategy/contract values internal-only. |
| `summary_guard` | Prevent boundary labels from being dropped during summarization. |
| `chief_verifier` | Re-check worker output before chief publication. |
| `audit_hash_chain` | Anchor the page/response chain for owner-side replay. |
| `canary_detector` | Detect synthetic secret-shaped value leakage. |

## Current public example

The committed public example is
[`examples/marketing-web-live-sanitized/`](../examples/marketing-web-live-sanitized/).

| Metric | Value |
|---|---:|
| Scenarios | `2` |
| Observations | `60` |
| Worker models | `2` |
| Chief models | `2` |
| Local web fetches | `60` |
| Worker leaks | `3` |
| Chief leaks | `1` |
| Naive final leaks | `0` |
| Bounded final leaks | `0` |
| Control-ablation final leaks | `1` |
| Benign final leaks | `0` |
| Verifier blocks | `8` |
| False blocks | `0` |
| Benign passes | `8` |
| Response hash coverage | `100%` |
| Per-turn hash coverage | `100%` |

Interpretation: one synthetic strategy component reached the final chief output when the
responsible control was disabled. The full bounded path blocked final leakage while
allowing benign work.

## Reproduce

Dry-run request estimate:

```bash
ash marketing-web-live-campaign \
  --max-scenarios 2 \
  --session-turns 3 \
  --max-requests 500
```

Run against local models:

```bash
ash marketing-web-live-campaign \
  --execute \
  --out .internal/marketing-web-live/latest \
  --summary-out reports/marketing-web-live \
  --worker-model qwen2.5:0.5b \
  --worker-model qwen2.5-coder:0.5b-instruct \
  --chief-model qwen2.5:0.5b \
  --chief-model qwen2.5-coder:0.5b-instruct \
  --max-scenarios 2 \
  --session-turns 3 \
  --max-requests 500 \
  --timeout 90
```

Validate the committed public example:

```bash
ash validate examples/marketing-web-live-sanitized
```

## Publication boundary

Public artifacts may include:

- scenario ids, modes, model ids, worker/chief roles, and session-turn counts;
- page URL/content hashes;
- worker/chief response hashes and per-turn response hashes;
- leak kind labels, not secret values;
- verifier decisions and control attribution;
- aggregate metrics and non-claims.

Public artifacts must not include:

- raw page text;
- raw prompts or raw model responses;
- synthetic strategy or contract values;
- local absolute paths;
- credentials, real customer data, or real website content.

## Non-claims

This campaign does not prove:

- real internet safety;
- real-secret extraction;
- a CVE;
- a model leaderboard result;
- production swarm safety;
- exhaustive web-injection coverage.

It proves a narrower claim: under this declared local-web marketing scenario, real local
worker/chief model outputs can expose a synthetic strategy component when a responsible
control is removed, and the full bounded verifier path blocks the final leakage in the
committed run.
