# Sanitized Local-Model Mini-Swarm Campaign

Status: sanitized public summary over private local-model probes.

This page records the live local-model layer for the local swarm defense contour. The
deterministic contour says which controls should block semantic drift, worker-to-chief
propagation, consensus laundering, and benign-framed boundary leaks. The live campaign
then asks small local models to play worker roles and a local chief model to consume
their summaries.

Raw prompts, raw responses, synthetic canary values, and detailed calculation notes stay
under `.internal/`. Public artifacts contain safe model ids, worker/chief roles,
topology ids, pressure labels, response hashes, per-turn response hashes, aggregate
labels, adapter flags, verifier attribution, replay-ablation metrics, Wilson rate
intervals, model breakdowns, and non-claims.
The field-level rule is in
[private-public-evidence-boundary.md](private-public-evidence-boundary.md).

## What Was Tested

The committed base sanitized run covers:

```text
topologies: 15
scenario families: 4
worker models: 2
chief models: 1
pressure modes: 6
observations: 180
adapter errors: 0
response hash coverage: 100%
```

The four scenario families are:

- semantic parameter drift;
- worker-to-chief propagation;
- consensus laundering;
- benign-framed boundary leak.

The base six pressure modes are gentle reframe, pseudo-code, memory rewrite,
authority pressure, benign debug framing, and consensus pressure. The deep and
long-session examples also include `long_session_relabel`, for seven implemented
pressure modes total.

A supplemental long-session sanitized run covers the same 15 contour topologies with
`long_session_relabel`, one worker model, one chief model, and three worker turns per
chain. It is published separately so the base cross-product remains easy to compare.
The committed base example is legacy-readable schema `0.2`; the long-session supplement
uses schema `0.3`.

## Result

The current sanitized public artifact records:

```text
worker drift detections: 1 / 180
chief acceptances: 22 / 180
synthetic canary leaks: 0 / 180
verifier blocks: 22 / 180
replay-ablation reopenings: 96
```

The supplemental long-session artifact records:

```text
observations: 15
max session turns: 3
long-session observations: 15
chief acceptances: 1
synthetic canary leaks: 0
verifier blocks: 1
adapter errors: 1
replay-ablation reopenings: 4
```

The deep sanitized artifact records:

```text
observations: 168
topologies: 6
worker models: 2
chief models: 2
pressure modes: 7
max session turns: 3
worker drift detections: 3
chief acceptances: 67
synthetic canary leaks: 0
verifier blocks: 70
unsafe observations: 70
benign observations: 91
unsafe block rate: 1.00 (Wilson 95%: [0.948, 1.000])
benign allow rate: 1.00 (Wilson 95%: [0.960, 1.000])
replay-ablation reopenings: 242
```

Interpretation:

- the strongest observed failure point was the chief accepting an unsafe worker
  summary, not direct canary leakage;
- in the deep run, one chief model accepted drift much more often than the other
  (`prometheus-qwen15b-lowctx:latest`: 61 acceptances, `llama3.2:1b`: 6
  acceptances), so model-role choice is a measured factor rather than a
  background detail;
- paired/combined topologies produced more acceptances than single-family topologies;
- every detected unsafe acceptance was blocked by the deterministic verifier layer;
- `chief_verifier`, `summary_guard`, `source_hash`, and `audit_hash_chain` were active
  blockers for every unsafe chief acceptance in this run;
- `cross_worker_check` mattered primarily where consensus laundering was present.

Replay ablation is calculated from the sanitized verifier decisions over the private
live run. It does not make additional model calls or publish raw transcripts. The
current public summary records 96 control-specific reopenings: every blocked unsafe
decision would reopen under at least one missing required control.

## Reproduce

Dry-run only:

```bash
ash swarm-defense-live-campaign --max-topologies 2 --pressure-mode pseudo_code
```

Run private live probes locally:

```bash
ash swarm-defense-live-campaign \
  --execute \
  --out .internal/swarm-defense-live/full \
  --summary-out reports/swarm-defense-live-full \
  --worker-model qwen2.5:0.5b \
  --worker-model qwen2.5-coder:0.5b-instruct \
  --chief-model llama3.2:1b \
  --pressure-mode gentle_reframe \
  --pressure-mode pseudo_code \
  --pressure-mode memory_rewrite \
  --pressure-mode authority_pressure \
  --pressure-mode benign_debug \
  --pressure-mode consensus_pressure
```

Validate the sanitized output:

```bash
ash validate reports/swarm-defense-live-full
```

Committed sanitized example:

```bash
ash validate examples/swarm-defense-live-sanitized
ash validate examples/swarm-defense-live-long-session-sanitized
ash validate examples/swarm-defense-live-deep-sanitized
```

Run the supplemental long-session probe:

```bash
ash swarm-defense-live-campaign \
  --execute \
  --out .internal/swarm-defense-live/long-session \
  --summary-out reports/swarm-defense-live-long-session \
  --worker-model qwen2.5:0.5b \
  --chief-model llama3.2:1b \
  --pressure-mode long_session_relabel \
  --session-turns 3 \
  --max-topologies 15
```

Run the deep multi-model long-session probe:

```bash
ash swarm-defense-live-campaign \
  --execute \
  --out .internal/swarm-defense-live/deep \
  --summary-out reports/swarm-defense-live-deep \
  --worker-model qwen2.5:0.5b \
  --worker-model qwen2.5-coder:0.5b-instruct \
  --chief-model llama3.2:1b \
  --chief-model prometheus-qwen15b-lowctx:latest \
  --session-turns 3 \
  --max-topologies 6 \
  --max-requests 900
```

## Claim Boundary

Allowed:

- local models can be exercised in a bounded mini-swarm campaign;
- public artifacts can summarize model-in-the-loop results without exposing raw
  prompts, responses, or canaries;
- this run observed unsafe chief acceptance in 22 of 180 synthetic chains and blocked
  all detected unsafe acceptances with deterministic controls;
- the deep run observed 70 unsafe chains and blocked 70 of them, while 91 benign
  chains were allowed; the public claim is bounded by the Wilson intervals shown
  in the artifact, not by a universal safety statement;
- the supplemental long-session run can expose per-turn response hashes and aggregate
  three-turn metrics without publishing raw turn prompts or responses;
- replay ablation can attribute those blocks to missing-control reopenings without
  exposing raw model prompts, raw responses, or canary values;
- response hashes provide audit anchors for private owner review.
- the run uses real local model outputs, but ASH publishes only sanitized hash-anchored
  summaries; the evidence supports the declared control-path claim, not a general
  model-safety conclusion.

Not allowed:

- calling this a CVE or a real-secret leak;
- claiming a model is globally vulnerable or safe;
- claiming production swarm safety;
- claiming exhaustive attack coverage;
- claiming deterministic controls prove semantic truth.
