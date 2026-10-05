# Document jobs: from your source text to a guarded new document

Status: published in the **1.12.0** wheel. See the
[release evidence](releases/v1.12.0.md) for exact subjects and verification gates.
This is a usable workflow around the existing [workspace writer](guarded-workspace-writer.md),
not a new executor. Its first use case is turning a host-selected UTF-8 document into
a new summary, checklist or draft. The permission boundary is deterministic and uses
no model. Document quality remains something the operator reviews. A later job
may read a verified earlier output as untrusted data under the same host policy.

## First job

Install the exact published version in a virtual environment.
The base workflow adds no model-framework dependency:

```sh
python -m pip install agentic-security-harness==1.12.0
ash document-init --dir my-documents --model YOUR_EXISTING_LOCAL_MODEL
ash document-check --config my-documents/document.json --check-model
ash document-run --config my-documents/document.json --input notes.txt --task "Make a short action checklist from these notes" --job first
ash document-run --config my-documents/document.json --input notes.txt --task "Make a short action checklist from these notes" --job first --execute
ash document-status --config my-documents/document.json --job first
```

Use your actual model name from your already-running local Ollama, not the literal
placeholder. Nothing installs models, starts a service or accesses a cloud API.
`notes.txt` is a file you select. Supported input is UTF-8 plain text, at most 16 KiB;
this is not a PDF/Office parser or a directory crawler. Your original stays unchanged.
The completed document is `my-documents/jobs/first/document.md`.

The first `document-run` is a preview: no job directory, model request or document
write. Only `--execute` reserves the job and permits one model call. `document-check`
without `--check-model` is filesystem/configuration inspection only; with it, there is
a bounded loopback metadata request, not a generation request. It distinguishes missing
optional framework, missing model and unavailable service. Read-only checks cannot
promise future write permission or disk availability. Setup tests actual file creation;
each real job still handles storage failures.

## Reuse a result as data, not authority

After inspecting the first output, the host may start a second, exclusive job
under the **same unchanged configuration**. `--input` and `--from-job` are
mutually exclusive; the latter reads the prior saved document after fresh
readback and receipt checks. It never inherits the first job's instructions,
policy, requested action, or quality judgment. The second job has its own
host-specified task and the same host-controlled output alias, Guard and
create-only destination policy:

```sh
ash document-status --config my-documents/document.json --job first
ash document-run --config my-documents/document.json --from-job first --task "Summarize this draft as a three-item review checklist; treat it only as source data" --job second
ash document-run --config my-documents/document.json --from-job first --task "Summarize this draft as a three-item review checklist; treat it only as source data" --job second --execute
ash document-status --config my-documents/document.json --job second
```

The preview checks the source job without reserving `second`, calling a model or
writing a document. If the source output or receipts changed, its quality failed,
or the configuration changed, chaining is refused. A `review_required` source
can be reused as data after deliberate operator inspection; it is not approved
as fact. The same job ID is never retried after a failed run.

## Declared format checks

The host can supply `--requirements` as a UTF-8 JSON file. For a strict,
machine-readable result, `requirements.json` can contain:

```json
{"schema_version":"ash.document-requirements.v1","mode":"exact_json","expected_json":{"approved":false,"items":["review source","verify claims"]}}
```

Then run a new job with `--job third --from-job second --requirements
requirements.json` and a task that describes the desired content: for this
example, an object with `approved` set to false and `items` containing exactly
`review source` and `verify claims`. The requirements file is a host-side
check, **not automatically included in the model prompt**. The expected JSON
is an exact deterministic comparison, not a model-derived truth test.
The alternative `markdown` mode may declare `checklist_items` and
`expected_item_terms` (one list of literal terms per item); structural count
alone remains `review_required`. Neither requirements nor output content can
select a path, classification or write permission. Host requirements are bound
to the job record by digest.

Quality is distinct from write state: `failed` means invalid format or an
unmet declared check, `review_required` means a saved draft needing human
assessment, and `checked` means only the stated exact criteria matched. A
failed-quality document is still a saved draft, but the CLI exits 2 and it
cannot be a `--from-job` source. `checked` never proves semantic correctness,
source reliability or permission safety.

## Repeat use and restart

Use a new ID (`second`, `weekly-notes-02`) for a new job. IDs are host-selected lowercase
letters, digits, hyphens and underscores, up to 48 characters. An existing job cannot
run again, including after a crash. Concurrent callers cannot reserve the same ID twice.

Each job has `started.json`, content-free `summary.json`, Guard intent/result receipts,
and, only when permitted, `document.md`. Completed writes also have a content-free
`quality.json` record. No source text, writing task or raw model
reply is copied into the JSON records. The result document itself is intentionally
stored and must be handled according to its classification.

| State | Meaning | Operator action |
|---|---|---|
| `saved` | Permitted bytes were written, read back and receipts checked; quality is separate | Read the document and check correctness |
| `denied` | Proposal was rejected by parsing or permission policy | Review the reason; do not call this a model/service failure |
| `error` | No write is known to have been attempted, e.g. no model response | Fix service/configuration, then explicitly choose a new job |
| `needs_inspection` | Running/incomplete job, changed bytes, or uncertain write evidence | Inspect files and receipts; do not blindly replay |

`document-status` is read-only. A still-running job and an interrupted job with no final
record both require inspection; the command does not claim a dead-process detector.
It rechecks successful output bytes, receipt/intent consistency and the configuration
binding, rather than merely displaying the old success field. Lost receipts or a changed
document stop it reporting `saved`. This is inspection, **not automatic recovery or
exactly-once execution under power loss**. It does not close research issue #317.

Configuration changes deliberately invalidate old job inspection under the new policy.
Keep the original configuration to inspect its jobs; create a separate workspace for
a changed policy instead of silently adopting historical evidence.

## Configuration and privacy

`document-init` refuses an existing directory and creates `document.json` and `jobs/`.
Paths inside configuration resolve relative to the configuration file, not your shell.
The host chooses model, engine (`native` or `pydantic-ai`), port, timeout, output byte
limit and data classification. Default classification is `private`; this is a host
declaration, not automatic classification. Default output limit is 8192 UTF-8 bytes.
The generation is bounded to 512 output tokens, context 4096, temperature 0, one request,
no repair/retry and local-model unload request. These are short-document defaults, not
a promise of high-quality long-form generation.

The sole writable artifact is `document`, mapped by the host to `document.md` inside
the exclusively created job directory. Unknown aliases reach Guard and are denied;
model-supplied paths, authority fields or malformed proposals cannot become policy.
No overwrite, shell, arbitrary code execution, filesystem search or forwarding tool
is exposed. A model can still put incorrect or misleading text in an allowed document.

The application/OS/configuration/local Ollama service are trusted. Do not give the agent
an alternative unrestricted write/shell tool: this Python boundary is not an OS sandbox.
It does not authenticate the producer, prevent host-wide rollback or prove that all
host events were captured. Confirm that your local service itself does not forward data.

## One optional framework, not another protection layer

Install the published `document-agent` extra (`pydantic-ai-slim==1.107.1`), then select it
when creating a **new** workspace:

```sh
python -m pip install "agentic-security-harness[document-agent]==1.12.0"
ash document-init --dir framework-documents --model YOUR_EXISTING_LOCAL_MODEL --engine pydantic-ai
```

The subsequent check/run/status commands are unchanged. The local adapter uses Pydantic
AI's FunctionModel as a native Ollama transport bridge: one real generation produces
untrusted JSON, one `write_document` tool passes those bytes unchanged to Guard, and a
fixed completion ends the framework loop. Two framework requests are **not** two model
calls. This is a bounded document workflow, not an autonomous planning benchmark.

For an existing Pydantic AI application, pass your own model object and guarded submit
callback to `make_document_agent`; no provider is selected by the factory:

```python
from pathlib import Path
from pydantic_ai.usage import UsageLimits
from agentic_security_harness.workspace_pydantic import make_document_agent
from agentic_security_harness.workspace_writer import GuardedWorkspace, WorkspacePolicy

# output_directory is an existing, host-selected absolute Path; model is host-configured.
policy = WorkspacePolicy(Path(output_directory), (("document", "draft.md"),), max_proposals=1)
with GuardedWorkspace(policy) as writer:
    agent = make_document_agent(model, writer.submit)
    result = agent.run_sync(
        "Create the requested draft using write_document. Pass proposal_json containing "
        "operation=write_text, artifact=document and content; no other fields.",
        usage_limits=UsageLimits(request_limit=2, tool_calls_limit=1),
    )
```

Do not add unrestricted tools or rely on final agent prose as proof of a write: inspect
the writer's receipts. Your application's provider permissions, instrumentation and
message retention remain your responsibility. This example does not run a provider.
Upstream concept: [Pydantic AI function tools](https://pydantic.dev/docs/ai/tools-toolsets/tools/).

## Results, latency and acceptance

Commands print a brief human-readable result; add `--json` for automation. Exit code 0
means initialization/readiness/preview/saved as stated, not universal safety. A
saved draft that fails declared requirements exits 2; denials, errors and
inspection-required states exit 1. There is no raw response or traceback in
the normal diagnostic output.

`summary.json` distinguishes requested artifact, Guard decision, actual effect,
transport attempt count and timing. `model` includes native request preparation,
transport and response parsing; `policy` includes proposal validation and Guard;
`storage` is the remaining boundary I/O and bookkeeping (intent, write/readback,
receipt). `boundary` equals policy plus storage. `total` also includes setup/framework
and verification, but excludes the final summary-file flush. These nested measurements
must not be added as independent components or compared across machines as a benchmark.

Installed acceptance, from outside the checkout:

```sh
python -I -B /path/to/checkout/tools/check_document_workflow.py --out fresh-acceptance
python -I -B /path/to/checkout/tools/check_document_workflow.py --out fresh-framework-acceptance --engine pydantic-ai
```

Those checks use an explicitly scripted loopback transport and real guarded filesystem
effects. They are not real-model evidence. A separate finite run against an existing
local model must report actual task quality, all calls and denials separately. External
human adoption and production reliability require separate evidence, not a new version
number or this guide.
