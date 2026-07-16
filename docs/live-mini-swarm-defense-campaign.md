# Sanitized Local-Model Mini-Swarm Campaign

Status: historical, unreconciled detector-observation summaries. Current schema `0.5`
is unexecuted in committed artifacts.

This page records the live loopback-endpoint layer for the local swarm defense contour. The
deterministic contour says which controls should block semantic drift, worker-to-chief
propagation, consensus laundering, and benign-framed boundary leaks. The live campaign
then asks configured endpoint models to play worker roles and a chief model to consume
their summaries.

Raw prompts, raw responses, synthetic canary values, and detailed calculation notes stay
under `.internal/`. Public artifacts contain safe model ids, worker/chief roles,
topology ids, pressure labels, response hashes, per-turn response hashes, aggregate
labels, adapter flags, verifier attribution, replay-ablation metrics, Wilson rate
intervals, model breakdowns, and non-claims.
The field-level rule is in
[private-public-evidence-boundary.md](private-public-evidence-boundary.md).

Current schema `0.5` records the planned Cartesian axes independently of returned
observations, a loopback endpoint hash, a unique execution id, the tool version, and a
fingerprint over the transitive producer components. Worker, counter-worker, and chief
adapter failures are distinct stages. Worker rates include rows whose worker completed
before a later failure; chief/canary/verifier rates include only rows whose corresponding
stage completed. Blank model content is an adapter failure, not a successful response.
Canary kinds use the detector's actual `partial/full/encoded/recombined` contract.
Security events are accumulated after every successful response, so a later adapter
failure cannot erase an earlier drift/leak. Loopback proves only the authorized first
network hop; it does not attest that a gateway executed the model locally or avoided
upstream provider egress. The artifacts are unsigned self-authored consistency records,
not tamper-authentic attestations.

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

All committed swarm-live examples are historical and predate schema `0.5`; they do not
exercise the new stage, execution-identity, or partial-event contracts. Their published
`canary leaks: 0` values are not reliable absence evidence: the historical aggregator
collapsed `full`, `partial`, and `recombined` detector results to `none`. Without the
private transcripts, those canary rates cannot be repaired and are withdrawn.

Hash coverage uses expected response slots as the denominator. The base run has
`100%` expected-slot coverage; the long-session supplement has `35/38` (`92.11%`),
and the deep run has `375/392` (`95.66%`). Missing slots therefore remain visible
instead of disappearing from the denominator.

## Result

The legacy sanitized public artifact declares:

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
expected response hash coverage: 35 / 38 (92.11%)
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
detector-positive observations: 70
expected response hash coverage: 375 / 392 (95.66%)
detector-negative observations: 91
adapter errors: 7
independent-label coverage: 0%
detector-positive block rate: 1.00 (Wilson 95%: [0.948, 1.000])
detector-negative allow rate: 1.00 (Wilson 95%: [0.960, 1.000])
replay-ablation reopenings: 242
```

Interpretation:

- within the legacy detector labels, the largest declared count is chief acceptance;
  the withdrawn canary-zero result cannot support a comparative failure claim;
- in the deep summary, one declared model identifier has more detector-labelled
  acceptances than the other
  (`prometheus-qwen15b-lowctx:latest`: 61 acceptances, `llama3.2:1b`: 6
  acceptances); this is a historical association, not an authenticated model effect;
- paired/combined topology labels have more declared acceptances than single-family labels;
- deterministic verifier rules classify every detector-positive acceptance as blocked;
- `chief_verifier`, `summary_guard`, `source_hash`, and `audit_hash_chain` were active
  blockers for every unsafe chief acceptance in this run;
- `cross_worker_check` mattered primarily where consensus laundering was present.

The historical “replay ablation reopenings” are rule-attribution counts calculated from
stored verifier blockers. They do not replay a paired counterfactual and do not prove
that removing one control would reopen a decision while other blockers remain. Treat
the count as named-control attribution only.

The unsafe/benign split in historical artifacts was detector-derived, not independent
ground truth. These rows are now explicitly `not_adjudicated`; precision, recall, and
specificity remain unclaimed until private responses receive independent review labels.

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

- models behind a loopback endpoint can be exercised in a bounded mini-swarm campaign;
- public artifacts can summarize model-in-the-loop results without exposing raw
  prompts, responses, or canaries;
- the legacy artifact declares 22 chief-acceptance labels in 180 chains and matching
  deterministic verifier decisions; public validation does not replay private responses;
- the deep artifact declares 70 detector-positive and 91 detector-negative rows;
  these are not independently adjudicated safety labels;
- the supplemental long-session run can expose per-turn response hashes and aggregate
  three-turn metrics without publishing raw turn prompts or responses;
- replay-ablation rules attribute those blocks to declared missing-control dependencies without
  exposing raw model prompts, raw responses, or canary values;
- response hash fields are commitments requiring owner-side byte reconciliation;
- historical documentation reports endpoint outputs, but the public repository does
  not authenticate model/runtime origin or retained private bytes.

Not allowed:

- calling this a CVE or a real-secret leak;
- claiming a model is globally vulnerable or safe;
- claiming production swarm safety;
- claiming exhaustive attack coverage;
- claiming deterministic controls prove semantic truth.
