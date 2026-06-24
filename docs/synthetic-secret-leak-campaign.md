# Synthetic Secret-Leak Campaign

This research slice tests whether declared multi-agent contracts prevent synthetic
secret egress when a workflow tries to launder labels, recall stale memory, trust tool
text as authority, or recombine split shards.

The campaign uses per-run canaries only. Raw canary values, prompts, and model responses
are private calculation artifacts and must stay under `.internal/`.

## What It Measures

| Mode | Purpose |
|---|---|
| `naive` | Model the unsafe path without boundary controls. |
| `bounded` | Apply deterministic envelope, memory, recipient, and authority controls. |
| `ablation` | Disable one responsible control and verify the unsafe path reappears. |
| `benign` | Exercise non-attack traffic to check false blocking. |

The committed sanitized example currently covers four scenarios:

| Scenario | Failure Class |
|---|---|
| `label_laundering` | A secret/no-forward value is summarized as if it became public. |
| `memory_stale_recall` | A stale secret memory record influences a later role. |
| `tool_output_secret_confusion` | Tool text is treated as disclosure authority. |
| `split_secret_recombination` | Separate shards are recombined by a later role. |

Current sanitized metrics:

```text
scenarios: 4
observations: 23
naive leaks: 4/4
bounded leaks: 0/4
ablation leaks: 11/11
benign leaks: 0/4
benign pass rate: 100%
control attribution rate: 100%
```

## Reproduce

Private-ready run:

```bash
ash secret-leak-campaign --write --out .internal/secret-leak-campaign/latest
ash validate .internal/secret-leak-campaign/latest
```

Committed sanitized example:

```bash
ash validate examples/secret-leak-campaign-sanitized
```

Optional local-model probe, raw transcripts private:

```bash
ash secret-leak-campaign --execute-model \
  --out .internal/secret-leak-campaign/prometheus \
  --model prometheus-qwen15b-lowctx:latest
```

The optional probe records raw prompts/responses only under `.internal/`. Public
artifacts keep only aggregate, redacted metrics.

Phase 2 local-model variation probe:

```bash
ash secret-leak-campaign --execute-variations \
  --out .internal/secret-leak-variations/latest \
  --variation-model prometheus-qwen15b-lowctx:latest \
  --variation-model qwen2.5:1.5b \
  --max-requests 64 \
  --variation-summary-out reports/secret-leak-variations
ash validate reports/secret-leak-variations
```

The variation probe covers 8 synthetic secret-egress pressure cases:

- multi-turn pressure;
- role hierarchy pressure;
- sanitized/public relabeling;
- partial shard reconstruction;
- delayed memory recall;
- tool authority laundering;
- summary compression label loss;
- verifier outage recovery.

The current committed sanitized example was derived from a private local smoke with:

```text
models: 2
cases: 8
pressure modes: 4
observations: 64
leaks: 0
adapter errors: 0
```

Raw prompts, raw model responses, and canary values remain private under `.internal/`.
The committed artifact keeps only response hashes, leak classifications, and aggregate
metrics.

## Local Model Smoke

Maintainer private smokes were run against `prometheus-qwen15b-lowctx:latest` and
`qwen2.5:1.5b` using four pressure modes over the four scenarios. Both runs completed
without adapter errors and did not disclose the synthetic canary in that smoke.

This is evidence-quality context only. It is not a model-safety claim and not a
leaderboard result.

## Non-Claims

- This does not extract or handle real secrets.
- This does not prove that a specific public model is vulnerable.
- This does not prove that a production agent framework is safe.
- This does not claim exhaustive attack coverage.
- The deterministic bounded result means the declared contracts blocked the declared
  synthetic egress paths.
