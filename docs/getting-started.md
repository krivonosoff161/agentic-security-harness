# Getting started

Goal: from an installed package to your first validated benchmark report in
**10-30 minutes**, with no API keys, model, or network after installation.

> **What this is:** a defensive **benchmark / evaluation toolkit** that reproduces
> agentic AI failure modes on synthetic targets and measures risk reduction.
> **What this is not:** a production sandbox, production runtime firewall, or security certification. A
> clean result means the synthetic patterns passed - not that a real system is safe.

## 1. Install

These commands use the published [1.13.1 package](https://pypi.org/project/agentic-security-harness/1.13.1/).
Its exact subjects and verification status are recorded in the
[release evidence](releases/v1.13.1.md). The prior
[1.13.0 release](releases/v1.13.0.md) retains its own verified subjects. The
[1.12.0 release](releases/v1.12.0.md) retains its own verified subjects.
The 1.11.0 release retains its initial
production lookup failure and passing read-only verification in its own record.
The failed, unpublished
[1.10.0 tag](releases/v1.10.0.md) and prior 1.9.1 release retain their own records.
The prior 1.8.0 release and its retained
initial production Linux 3.11 index-lookup failure remain [historical evidence](releases/v1.8.0.md).
For exact companion binding and negative controls, use the separate
[hash-locked installed example](../examples/installed-ecosystem/README.md).
Installation does not automatically activate companions or grant action authority.

```bash
python -m pip install agentic-security-harness==1.13.1
ash --help
```

Installing from PyPI needs package-index access unless you already have the exact
wheel and dependencies locally. The first benchmark run below is offline.

For source development, clone the repository and use `python -m pip install -e .[dev]`.

To create a guarded short document from your own UTF-8 source after installation,
follow the [document-workflow operator guide](document-workflow.md). Its preview,
host-owned output policy and exact-byte review are separate from benchmark quickstart.

Requires Python 3.11+. Pure Python; the only runtime dependency is `pydantic`.
Ubuntu/Linux is the primary clean-install and first-user contour; Windows remains an
explicit compatibility target in CI.

Confirm your environment is ready (no network):

```bash
ash quickstart --out reports/quickstart
ash validate reports/quickstart
```

The quickstart command performs an installed-package preflight, compares the
vulnerable and protected local demos on the same 24-pattern corpus, validates the evidence,
and writes `reports/quickstart/report.html`. The second command validates that
generated bundle; it does not require checkout examples.
Since 1.10.1, `ash doctor` checks installed-package readiness without
requiring a source checkout. Use `ash doctor --source-assets` to additionally
require checkout examples and the example fake server. Network remains opt-in
with `--live-local`. The flag/default are absent from immutable 1.9.1;
its `doctor` still reports absent source assets on pip-only installs.

To exercise the provider-neutral owned-workflow contour shipped in v1.1.0, run:

```bash
ash agent-host-quickstart --out reports/agent-host-quickstart
ash validate reports/agent-host-quickstart
```

This no-network command drives the built-in synthetic workflow through explicit
instrumentation, 48 canonical recordings/evaluations, atomic publication, and the common
validator. It stores digest-only public evidence and does not load an external agent,
credential, prompt, tool payload, or plugin.

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

## 4. Reproduce the baseline/protected conformance difference

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

## 6. Validate generated reports

```bash
ash validate reports/quickstart
ash validate reports/demo
ash validate reports/comparison
```

Validation re-derives reports from the corpus and rejects malformed or tampered
artifacts. It checks conformance, **not** real-world safety.

## Optional: test your own model

The external path evaluates an authorized OpenAI-compatible endpoint. It is not
part of the offline first run. Follow [Connect your model](connect-models.md) for
local or remote service setup, a no-request preview, a bounded executed run,
credential handling, and its separate evidence limits. `run-external` refuses
to exceed `--max-requests` (default 50); an API key is read from an environment
variable by name, never logged or stored.

### Source-checkout fake-server example

This optional, keyless loopback example requires a **repository checkout**: the
published wheel does not install `examples/fake_openai_server.py` or the curated
`examples/` directory. From the checkout root, start the server in a separate
terminal and leave it running only while you try the external path:

```bash
# terminal 1, from the repository checkout
python examples/fake_openai_server.py

# terminal 2, from the same checkout
ash external-check --base-url http://127.0.0.1:8766/v1 --model fake-model --scenario data-boundary
ash run-external --base-url http://127.0.0.1:8766/v1 --model fake-model --scenario data-boundary --execute --out .internal/external-demo
ash validate .internal/external-demo
ash validate examples/
```

Stop the server with Ctrl+C after the example. On Windows PowerShell, use a
second terminal window rather than a trailing `&`; see the
[PowerShell recipes](connect-models.md#5-windows-powershell-quickstart).

## Optional: local synthetic Gateway

The Gateway is a separate, long-running demonstration, not a prerequisite for
the benchmark steps above. In a fresh working directory, run these commands in
a separate terminal:

```bash
ash gateway-init --out gateway.toml
ash gateway-check --config gateway.toml
ash gateway-serve --config gateway.toml
```

While it is serving, open <http://127.0.0.1:8787/dashboard>; stop it with Ctrl+C
before reusing that terminal. This credential-free development contour has only
fixed synthetic tools, not a live provider connection or production firewall.
See [runtime-gateway.md](runtime-gateway.md) for HTTP examples and Docker Compose.

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
- [agent-host-adapter.md](agent-host-adapter.md) - explicit owned-workflow integration and
  its privacy boundary.
- [runtime-gateway.md](runtime-gateway.md) - local policy gateway, MCP/OpenAI-compatible
  demo, safe audit, and Docker operator path.
- [test-your-model.md](test-your-model.md) - the external path in depth.
- [reporting-flow.md](reporting-flow.md) - what each artifact contains.
- [threat-model.md](threat-model.md) - limitations and honest residual risk.
- [project-map.md](project-map.md) - the full repository map.
