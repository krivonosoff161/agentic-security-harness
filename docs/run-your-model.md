# Run your model or mini-swarm

> **Agentic Security Harness.** This is the public operator path for someone who
> found the repository and wants to run the benchmark against a local model, a
> local OpenAI-compatible server, or a small local model swarm.

This page is intentionally practical. It does not replace the deeper references:

- [connect-models.md](connect-models.md) - connector recipes by runtime.
- [test-your-model.md](test-your-model.md) - external adapter details.
- [bounded-local-swarm.md](bounded-local-swarm.md) - deterministic swarm model.
- [private-public-evidence-boundary.md](private-public-evidence-boundary.md) -
  what can be published and what stays private.

## What this run can prove

These commands can show whether a target behaved correctly on the **declared
synthetic benchmark situations** under a specific configuration. They can produce
traceable artifacts, scorecards, sanitized summaries, response hashes, and control
recommendations.

They do **not** prove that a model, deployed agent, provider, or company system is
generally safe. A clean run means "no finding in this modeled slice", not
"secure".

## 0. Install and verify the local harness

Linux/macOS:

```bash
python -m pip install -e ".[dev]"
ash validate examples/
ash scenarios
```

Windows PowerShell:

```powershell
python -m pip install -e ".[dev]"
ash validate examples/
ash scenarios
```

Expected baseline:

- `ash validate examples/` reports 0 errors.
- `ash scenarios` reports `all` with 24 patterns.
- The named scenario families, excluding `all`, cover those same 24 patterns.

## 1. No-model deterministic demo

Run this first. It proves the harness is installed and that committed artifacts can
be regenerated locally without an LLM, API key, or network call.

Linux/macOS:

```bash
ash compare --baseline demo-agent --protected protected-demo-agent --out reports/comparison
ash validate reports/comparison
ash report --root reports/comparison
```

Windows PowerShell:

```powershell
ash compare --baseline demo-agent --protected protected-demo-agent --out reports/comparison
ash validate reports/comparison
ash report --root reports/comparison
```

Expected modeled demo result:

- vulnerable `demo-agent`: 24 modeled findings;
- `protected-demo-agent`: 0 modeled findings;
- this is a deterministic synthetic before/after comparison, not a real-world
  safety certificate.

## 2. Run one local or remote OpenAI-compatible model

Start with a preflight and dry-run. They do not make benchmark calls.

Linux/macOS:

```bash
ash external-check --preset ollama --model llama3.1 --scenario data-boundary
ash run-external --preset ollama --model llama3.1 --scenario data-boundary --dry-run
ash run-external --preset ollama --model llama3.1 --scenario data-boundary --execute --out .internal/external-ollama/latest
ash validate .internal/external-ollama/latest
```

Windows PowerShell:

```powershell
ash external-check --preset ollama --model llama3.1 --scenario data-boundary
ash run-external --preset ollama --model llama3.1 --scenario data-boundary --dry-run
ash run-external --preset ollama --model llama3.1 --scenario data-boundary --execute --out .internal/external-ollama/latest
ash validate .internal/external-ollama/latest
```

For an authenticated OpenAI-compatible endpoint, set an environment variable and
pass its **name**:

Linux/macOS:

```bash
export ASH_EXTERNAL_API_KEY=REDACTED_VALUE
ash external-check --base-url https://YOUR-ENDPOINT/v1 --model your-model \
  --scenario data-boundary --credential-env ASH_EXTERNAL_API_KEY
ash run-external --base-url https://YOUR-ENDPOINT/v1 --model your-model \
  --scenario data-boundary --credential-env ASH_EXTERNAL_API_KEY \
  --execute \
  --out .internal/external-your-model/latest
```

Windows PowerShell:

```powershell
$env:ASH_EXTERNAL_API_KEY = "REDACTED_VALUE"
ash external-check --base-url https://YOUR-ENDPOINT/v1 --model your-model `
  --scenario data-boundary --credential-env ASH_EXTERNAL_API_KEY
ash run-external --base-url https://YOUR-ENDPOINT/v1 --model your-model `
  --scenario data-boundary --credential-env ASH_EXTERNAL_API_KEY `
  --execute `
  --out .internal/external-your-model/latest
```

Keep raw model responses under `.internal/` unless they are synthetic fake-server
fixtures intended for public examples. Publish only sanitized summaries and hashes.

## 3. Run a deterministic local swarm comparison

This path does not require model calls. It compares monolith, naive swarm, and
bounded swarm behavior against local contracts.

Linux/macOS:

```bash
ash local-swarm --write-dry-run --out reports/local-swarm
ash validate reports/local-swarm
```

Windows PowerShell:

```powershell
ash local-swarm --write-dry-run --out reports/local-swarm
ash validate reports/local-swarm
```

The deterministic committed example is under
[`examples/local-swarm-report/`](../examples/local-swarm-report/).

## 4. Run a local-model mini-swarm campaign

This path calls local models and therefore writes private raw artifacts under
`.internal/`. Use small request caps first.

Linux/macOS:

```bash
ash swarm-defense-live-campaign \
  --out .internal/swarm-defense-live/latest \
  --summary-out reports/swarm-defense-live-sanitized \
  --base-url http://localhost:11434/v1 \
  --worker-model qwen2.5:0.5b \
  --chief-model llama3.2:1b \
  --max-topologies 4 \
  --max-requests 40 \
  --session-turns 1 \
  --execute
ash validate reports/swarm-defense-live-sanitized
```

Windows PowerShell:

```powershell
ash swarm-defense-live-campaign `
  --out .internal/swarm-defense-live/latest `
  --summary-out reports/swarm-defense-live-sanitized `
  --base-url http://localhost:11434/v1 `
  --worker-model qwen2.5:0.5b `
  --chief-model llama3.2:1b `
  --max-topologies 4 `
  --max-requests 40 `
  --session-turns 1 `
  --execute
ash validate reports/swarm-defense-live-sanitized
```

Public summaries may include model ids, topology ids, pressure labels, response
hashes, aggregate labels, verifier attribution, and replay-ablation metrics. Do not
publish raw prompts, raw responses, synthetic canary values, local absolute paths,
or private calculation notes.

## 5. Read the result

For deterministic runs, start with:

- `summary.md`
- `executive.md`
- `scorecard.json`
- `traces.json`

For external/model runs, start with:

- `external_report.md`
- `external_summary.json`
- `run_config.json`

For local mini-swarm campaigns, start with the sanitized report and digest:

- `swarm_defense_live_report.md`
- `swarm_defense_live_summary.json`
- `swarm_defense_live_digest.json`

If a model returns prose instead of valid JSON, the harness records
`inconclusive`, not `pass` or `finding`. If a local server is down, the result is
`adapter_error`, not a security verdict.

## 6. Publish an evidence update

Use [evidence-pack-format.md](evidence-pack-format.md) before opening a public PR.
At minimum, a public evidence update should include:

1. a sanitized `examples/<pack-name>/` or `reports/<pack-name>/` summary;
2. no raw transcripts or synthetic canaries;
3. SHA-256 hashes anchoring private local responses where applicable;
4. a row in [research-claims.md](research-claims.md);
5. a row or link in [showcase/evidence-map.md](showcase/evidence-map.md);
6. a validation command record;
7. explicit non-claims.

Run before publishing:

```bash
ash validate examples/
python -m pytest
python -m ruff check .
python -m mypy src tests tools
git diff --check
```
