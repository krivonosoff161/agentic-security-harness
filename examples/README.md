# Examples - committed, validated benchmark artifacts

These directories are **curated, deterministic snapshots** of real `ash` output. They are
checked by `ash validate examples/` in CI, so they always match the current corpus and
report format. Nothing here contains secrets, real payloads, or local absolute paths.
Each report directory has its own README that explains what produced it, how to read it,
how to validate it, and what it does not prove.

```bash
# validate every example in one shot
ash validate examples/
# expected: errors: 0  warnings: 0  -> OK
```

> The CLI also writes a `run_index.json` run manifest into real run directories (see
> [docs/getting-started.md](../docs/getting-started.md#run-history)). It carries a
> timestamp, so it is intentionally **not** committed in these snapshots to keep them
> byte-deterministic. Live runs you create under `reports/` will include it.

## What each example shows

| Directory | What it demonstrates | Regenerate with |
|---|---|---|
| [`demo-report/`](demo-report/) | A single run against the deterministic `mock` target (findings + remediation). | `ash run --target mock --out reports/demo` |
| [`demo-agent-report/`](demo-agent-report/) | A run against the vulnerable-by-design local `demo-agent`. | `ash run --target demo-agent --out reports/demo-agent` |
| [`protected-demo-agent-report/`](protected-demo-agent-report/) | The protected agent passing all patterns (no findings, no remediation). | `ash run --target protected-demo-agent --out reports/protected` |
| [`comparison-report/`](comparison-report/) | Baseline vs protected risk-reduction comparison. See its own [README](comparison-report/README.md). | `ash compare --baseline demo-agent --protected protected-demo-agent --out reports/comparison` |
| [`external-demo-report/`](external-demo-report/) | An external OpenAI-compatible run against the bundled fake server. | see below |
| [`fake_openai_server.py`](fake_openai_server.py) | A deterministic local OpenAI-compatible server for the external path (no key, localhost only). | `python examples/fake_openai_server.py` |

## Reading a report directory

Open files in this order:

1. `executive.md` - scope, headline result, top control families, residual risk. **Start here.**
2. `summary.md` - per-pattern pass/fail table.
3. `remediation.md` - control recommendations (only present when there are findings).
4. `traces.json` / `scorecard.json` - machine-readable detail.

For comparisons start with `comparison.md`; for matrix runs start with `matrix.md`; for
external runs start with `external_report.md`.

Or render any example as a single static HTML page (no network):

```bash
ash report --root examples/comparison-report   # writes examples/comparison-report/report.html
```

What PASS / FINDING / INCONCLUSIVE / FLAKY / ADAPTER_ERROR mean, and what validation does
and does not prove, is in [docs/benchmark-semantics.md](../docs/benchmark-semantics.md).

## Reproduce the external example (free, no API key)

```bash
# terminal 1 - start the deterministic fake server (Ctrl+C to stop)
python examples/fake_openai_server.py

# terminal 2 - run the external path against it
ash external-check --base-url http://127.0.0.1:8766/v1 --model fake-model --scenario data-boundary
ash run-external  --base-url http://127.0.0.1:8766/v1 --model fake-model --scenario data-boundary --out reports/external-demo
ash validate reports/external-demo
```

Expected: the run reports 4 checks / 4 requests / 0 findings (the fake server always
preserves the boundary), and `ash validate` returns `OK`. On Windows, start the server in
a separate PowerShell window (no trailing `&`).

See [docs/connect-models.md](../docs/connect-models.md) for recipes with vLLM, DeepSeek,
Alibaba/Qwen, Ollama, LM Studio, and generic OpenAI-compatible gateways.

> All artifacts here are deterministic and synthetic. Passing validation means they
> conform to the corpus manifest - **not** that any system is secure.
