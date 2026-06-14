# User journey — one happy path

A single, complete walkthrough: install → local benchmark → report → validate, then the
external model check against a free local fake server. Everything here is offline except
the explicitly-marked external steps, which only ever call `http://127.0.0.1:8766`.

> Quicker version: [getting-started.md](getting-started.md). Result words and what
> `ash validate` proves: [benchmark-semantics.md](benchmark-semantics.md).

Commands are shown for Linux/macOS **bash** and Windows **PowerShell** where they differ.

## 1. Install

```bash
git clone https://github.com/krivonosoff161/agentic-security-harness
cd agentic-security-harness
python -m pip install -e ".[dev]"
```

Requires Python 3.11+. Only runtime dependency: `pydantic`.

## 2. Check your environment

```bash
ash doctor
```

No network. Expect `Result: ready` and a list of next commands.

## 3. Run a local benchmark

```bash
ash run --target toy-rag --out reports/demo
```

`toy-rag` is a deterministic local toy adapter (no network, no model). It prints a
`Start here:` pointer and a run id, and writes `traces.json`, `scorecard.json`,
`summary.md`, `executive.md`, `run_index.json`, and — because `toy-rag` produces findings
— `remediation.json` / `remediation.md` (these two appear only when findings exist).

## 4. Render an HTML report

```bash
ash report --root reports/demo
```

Writes a self-contained `reports/demo/report.html` (no JS, no network). Open it in a
browser.

## 5. Validate the artifacts

```bash
ash validate reports/demo
```

Expect `OK`. This checks artifact integrity, **not** real-world safety
(see [benchmark-semantics.md](benchmark-semantics.md)).

## 6. List your runs

```bash
ash list-runs --root reports
```

Reads the `run_index.json` manifest from each run directory.

## 7. Start the local fake model server (external steps begin)

The external path is the only part that uses the network, and only against this local
fake server here.

**Linux/macOS (bash):**

```bash
python examples/fake_openai_server.py &
```

**Windows (PowerShell)** — start it in a **separate** window (do not use a trailing `&`):

```powershell
python examples/fake_openai_server.py
```

It listens on `http://127.0.0.1:8766/v1` and returns deterministic responses.

## 8. Preflight the external config (no network)

```bash
ash external-check --base-url http://127.0.0.1:8766/v1 --model fake-model --scenario data-boundary
```

Shows the request estimate, cost cap, and a copy-pasteable next command. No request is
sent.

## 9. Dry-run the external benchmark (no network, no files)

```bash
ash run-external --base-url http://127.0.0.1:8766/v1 --model fake-model --scenario data-boundary --dry-run
```

Prints `No network call. No files written.` and the exact request count.

Tip: `ash external-presets` lists shortcuts that fill the `base_url` for you, e.g.
`ash run-external --preset fake-local --model fake-model --scenario data-boundary --dry-run`.

## 10. Live run against the fake server

```bash
ash run-external --base-url http://127.0.0.1:8766/v1 --model fake-model --scenario data-boundary --repeats 2 --out reports/external-demo
```

This is the first step that makes requests — all to localhost. For a real endpoint you
would add `--api-key-env ASH_EXTERNAL_API_KEY` after exporting the key:

- bash: `export ASH_EXTERNAL_API_KEY=your_key`
- PowerShell: `$env:ASH_EXTERNAL_API_KEY = "your_key"`

The key value is never logged or stored — only the env var name is recorded.

## 11. Render the external HTML report

```bash
ash report --root reports/external-demo
```

## 12. Validate the external artifacts

```bash
ash validate reports/external-demo
```

## 13. Interpret the result

- Local runs report **PASS** / **FINDING** per pattern.
- External runs report a per-`(pattern, variant)` **status**: `stable_pass`,
  `stable_finding`, `flaky`, `inconclusive`, or `adapter_error`.
- `flaky` / `inconclusive` mean "not enough signal", not pass or fail.
- The fake server always preserves the boundary, so you will see `stable_pass` and 0
  findings — expected for a deterministic fake.

Full definitions: [benchmark-semantics.md](benchmark-semantics.md).

## 14. Stop the server and go further

Stop the fake server (Ctrl+C in its window, or close the background job). Then:

- Point `run-external` at your own stack with the recipes in
  [connect-models.md](connect-models.md) (vLLM, DeepSeek, Alibaba/Qwen, Ollama,
  LM Studio, generic gateway).
- Compare a vulnerable vs protected baseline:
  `ash compare --baseline demo-agent --protected protected-demo-agent --out reports/comparison`.
- Explore variant stability: `ash run-matrix --target toy-tools --scenario tool-selection --max-variants 3 --out reports/matrix`.
- Read the [capability matrix](capability-matrix.md) to pick the right target/mode.

> A clean run means the modelled patterns passed — not that any real system is secure.
