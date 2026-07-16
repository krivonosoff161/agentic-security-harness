# Getting started

Goal: from a fresh clone to your first validated benchmark report in **10-30 minutes**,
with no API keys and no network.

> **What this is:** a defensive **benchmark / evaluation toolkit** that reproduces
> agentic AI failure modes on synthetic targets and measures risk reduction.
> **What this is not:** a sandbox, a runtime firewall, or a security certification. A
> clean result means the synthetic patterns passed - not that a real system is safe.

## 1. Install

```bash
git clone https://github.com/krivonosoff161/agentic-security-harness
cd agentic-security-harness
python -m pip install -e ".[dev]"
ash --help
```

Requires Python 3.11+. Pure Python; the only runtime dependency is `pydantic`.

Confirm your environment is ready (no network):

```bash
ash doctor
```

## 2. See what is available

```bash
ash targets                # built-in local targets (all deterministic, no network)
ash scenarios --verbose    # scenario families, pattern counts, and variants
```

## 3. Run the built-in benchmark

```bash
ash run --target demo-agent --out reports/demo
```

(`--target` defaults to the minimal `mock`; we pass `demo-agent` here to exercise the
richer vulnerable-by-design agent.) This runs the seed corpus against the local
`demo-agent` and writes
a report directory. The command prints a `Start here:` pointer and a run id. Open
`reports/demo/executive.md` first, or render a shareable static HTML page (no network):

```bash
ash report --root reports/demo        # validates first, then writes report.html
```

## 4. Measure risk reduction (baseline vs protected)

```bash
ash compare --baseline demo-agent --protected protected-demo-agent --out reports/comparison
```

Open `reports/comparison/comparison.md` to see findings drop from the vulnerable agent to
the protected one.

## 5. Run a scenario matrix

```bash
ash run-matrix --target demo-agent --scenario data-boundary --max-variants 3 --out reports/matrix
```

Open `reports/matrix/matrix.md` for the per-variant table and pattern stability.

## 6. Test your own model (free, local, no key)

The external path evaluates any authorized OpenAI-compatible endpoint. Try it for free
against the bundled fake server:

```bash
# terminal 1
python examples/fake_openai_server.py

# terminal 2
ash external-check --base-url http://127.0.0.1:8766/v1 --model fake-model --scenario data-boundary
ash run-external --base-url http://127.0.0.1:8766/v1 --model fake-model --scenario data-boundary --execute --out reports/external-demo
```

On Windows PowerShell, start the fake server in a separate window (no trailing `&`) and
use `` ` `` for line continuation - see [connect-models.md Section 5](connect-models.md) for the
PowerShell recipes.

Then point it at your own stack (vLLM, DeepSeek, Alibaba/Qwen, Ollama, LM Studio, or any
gateway) using the recipes in [connect-models.md](connect-models.md). `run-external`
refuses to exceed `--max-requests` (default 50), and the API key is read from an env var
by name - never logged or stored.

## 7. Validate any report

```bash
ash validate reports/demo
ash validate examples/      # the committed, curated examples
```

Validation re-derives reports from the corpus and rejects malformed or tampered
artifacts. It checks conformance, **not** real-world safety.

## Run history

Every run writes a `run_index.json` manifest (run id, kind, target/model, scenario,
variants, repeats, outcome counts, artifact paths). List your runs:

```bash
ash list-runs --root reports
```

The run id is deterministic for a given configuration, so re-running the same command
produces the same id. Manifests are validated by `ash validate` when present.

## Where to read next

- [examples/README.md](../examples/README.md) - what each committed example shows.
- [connect-models.md](connect-models.md) - connector recipes per stack.
- [test-your-model.md](test-your-model.md) - the external path in depth.
- [reporting-flow.md](reporting-flow.md) - what each artifact contains.
- [threat-model.md](threat-model.md) - limitations and honest residual risk.
- [project-map.md](project-map.md) - the full repository map.
