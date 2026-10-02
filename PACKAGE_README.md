# Agentic Security Harness

Distribution version: **1.9.1**. Python 3.11 or newer. Apache-2.0.

A local defensive benchmark and toolkit for testing agent boundary failures:
untrusted input, authority confusion, retained history and controlled file actions.
It produces replayable traces, scorecards and separately verifiable evidence.

This description belongs to the distribution you are viewing. For live publication
status, exact artifact hashes and verification runs, see the
[release records](https://github.com/krivonosoff161/agentic-security-harness/releases)
and [current project state](https://github.com/krivonosoff161/agentic-security-harness/blob/main/docs/current-state.md).

## Install this version

```bash
python -m pip install agentic-security-harness==1.9.1
ash quickstart --out reports/quickstart
```

Use a fresh output directory. The quickstart runs fixed offline scenarios against
vulnerable and protected fixtures; it does not call a model or an external target.

## Check a controlled file boundary

```bash
ash controlled-file-workflow --out reports/file-boundary
ash controlled-file-verify --out reports/file-boundary
```

This opt-in workflow performs actual writes to newly created synthetic files.
Report-only Runtime Guard authority permits the report file and denies the
protected file. A separate read-only verifier checks disk bytes and captured
history. Model output cannot supply a filesystem path or executable code.
The default run is offline. An existing local Ollama model can be selected
explicitly using the documented options; installing this package starts no model.

[Versioned instructions and limits](https://github.com/krivonosoff161/agentic-security-harness/blob/v1.9.1/docs/controlled-file-workflow.md)
explain the guarded/ablated fixed control separately from model observations.
Permission enforcement and correctness of the generated report are different
measurements. This is not an arbitrary tool executor or a hostile-code sandbox.

## Other included surfaces

- Portable trace validation, scorecards and deterministic comparison reports.
- Retained ancestry admission and the closed synthetic Runtime Gateway.
- An experimental single-plan garak adapter, not an official NVIDIA integration
  or support for every garak detector.
- Separately versioned optional Transfer, Handoff, Playbooks, Router and Filter
  packages. Installation does not automatically activate them.

## Evidence and scope

This patch changes package presentation and release checks, not protection
behavior. It introduces no new model experiment or security-effectiveness claim.
The historical eight-call observation used a specific installed 1.9.0 candidate:
four protected proposals were denied, four reports were written, and two reports
were correct. It is not a measurement of this patch or a reliability estimate.

[Historical observation](https://github.com/krivonosoff161/agentic-security-harness/blob/v1.9.0/docs/controlled-file-observation-20261001.md)
and [methodology](https://github.com/krivonosoff161/agentic-security-harness/blob/v1.9.1/docs/benchmark-semantics.md)
separate controlled evidence from broader claims. Production-wide containment,
arbitrary host protection and independent human review are not established.

Author: Dmitry Krivonosov ([krivonosoff161](https://github.com/krivonosoff161)).
Questions and reproducible reports: [GitHub issues](https://github.com/krivonosoff161/agentic-security-harness/issues).
