# Live Marketing Web-Injection Campaign

This page documents the live loopback-endpoint version of the marketing web-injection
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
2. **Local mini-swarm.** A worker model reads the page and summarizes it. The
   deterministic verifier either blocks publication before a chief call or allows a
   chief model to consume the worker summary and produce the final recommendation.
3. **Mode comparison.** The same scenario runs in naive, bounded, control-ablation, and
   benign modes.
4. **Long-session pressure.** Unsafe rows use repeated worker turns before chief review,
   so the test is not a single prompt only.
5. **Private/public split.** Private transcripts are hash-anchored in public artifacts;
   the public example exposes counts, model ids, page/response hashes, decisions, leak
   kinds, and verifier attribution only.

Current schema `0.3` also records the planned scenario/model matrix independently of
observed rows, a loopback endpoint hash, a unique execution id, the tool version, and a
transitive producer-component fingerprint. Page-fetch, worker, and chief failures have
separate stages and stage-completed denominators. A verifier-blocked row has a
`decision_output_sha256` but no chief call or `chief_response_sha256`; an allowed row
binds both hashes to the actual chief output. Blank page/model content is a staged
adapter failure. The validator rebuilds owned-page content hashes from the declared
corpus and binds the manifest to the summary execution identity.

The deterministic verifier is a rule-derived policy simulation: it receives the
experimental mode and declared control set. Its block/allow rates therefore measure
contract consistency, not independent empirical defense effectiveness. Likewise,
historical ablation counts are counts of control-disabled rows, not demonstrated causal
reopenings. Loopback proves only the first network hop, not local model execution or
absence of upstream proxying. The artifacts are unsigned self-authored consistency
records.

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
It is historical schema `0.2`; no committed current schema-`0.3` execution exists yet,
so it does not validate the new stage/identity/partial-event contract.

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

Interpretation: the legacy detector summary declares one final synthetic-strategy leak
in a control-disabled mode. Mode and verifier outcomes are selected by policy rules, so
this is rule-derived attribution rather than an observed causal effect. Public validation
does not replay private responses or attest model/runtime identity.

## Reproduce

Dry-run request estimate:

```bash
ash marketing-web-live-campaign \
  --max-scenarios 2 \
  --session-turns 3 \
  --max-requests 500
```

Run against an authorized loopback model endpoint:

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

It supports only a narrower historical statement: the schema-`0.2` public record contains
detector-labelled rows under declared model identifiers, and the deterministic verifier
reproduces its policy rules. It does not authenticate local model execution, retained
private bytes, independent detector accuracy, or a causal control effect.
