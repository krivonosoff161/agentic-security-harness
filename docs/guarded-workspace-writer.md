# Save an agent's document through a configured file boundary

**Published in 1.11.0.** The [release record](releases/v1.11.0.md)
binds the verified package subjects and checks.

Use this when your application needs an agent to draft a summary, note or other
UTF-8 text file. You choose the output directory and filenames. The agent can
propose text under an alias; it cannot choose a filesystem path or grant itself
write access. A permitted write creates a new file. It never replaces an existing
file, even in a later process.

This is an in-process tool boundary, not a sandbox for an agent that can already
execute Python, run a shell, or write files through another tool. Give the agent
only the guarded tool for this operation. The host, its configuration and OS must
be trusted. A permitted document may still contain false or malicious text.

## First useful output, without a model

Install the exact published package in your own environment with
`python -m pip install agentic-security-harness==1.11.0`, or install from the
v1.11.0 tag source with `python -m pip install .`. No additional runtime
dependencies are introduced. These commands are absent from the historical
PyPI 1.10.1 wheel.

In an empty working directory create an `output` directory. Save `policy.json`:

```json
{
  "schema_version": "ash.workspace-write.v1",
  "output_dir": "output",
  "outputs": {"draft": "summary.md"},
  "max_bytes": 8192,
  "max_proposals": 4,
  "data_class": "public"
}
```

Paths are relative to the config file, not your shell's current directory. Output
directories must already exist; each configured filename is a single basename.
Links, junctions/reparse points, traversal, alternate data streams, reserved
device names and case-colliding destinations are rejected. `.ash-` names belong
to receipts and cannot be configured as agent outputs. Use a dedicated directory
whose contents are not automatically executed or published.

Save `proposal.json` containing a real document you want the application to save:

```json
{"operation":"write_text","artifact":"draft","content":"# Summary\n\nDraft for review.\n"}
```

```text
ash workspace-check --config policy.json
ash workspace-write --config policy.json --proposal proposal.json
```

`output/summary.md` now contains that exact text. The second command returns
`applied: true`, `reason: write_completed` and a receipt filename. Check it with:

```text
ash workspace-verify --config policy.json --receipt output/<returned-receipt-name>
```

`workspace-write` also accepts UTF-8 JSON on stdin. The equivalent ready-to-copy
input files are in `examples/workspace-write/`; create its `output` directory
yourself before running them. No generated outputs belong in public Git.

## Connect an existing agent loop

The host loads configuration once. Keep the workspace alive for the loop and
register a closure as the agent's text-output tool:

```python
from pathlib import Path
from agentic_security_harness.workspace_writer import GuardedWorkspace, WorkspacePolicy

policy = WorkspacePolicy.load(Path("policy.json"))
with GuardedWorkspace(policy) as workspace:
    def save_document(proposal_json: str) -> dict:
        return workspace.submit(proposal_json.encode("utf-8"))

    # Register save_document with your agent framework and run its loop here.
    # The model sees only operation, artifact and content, not config or paths.
```

`WorkspacePolicy` can also be constructed directly with an absolute `Path` and
an immutable tuple of `(alias, filename)` pairs. `text_proposal_schema()` exposes
the JSON tool shape. The schema is not the permission gate: the session validates
every proposal and evaluates the deterministic Runtime Guard before file creation.

Unknown aliases are denied by Guard; malformed JSON, duplicate keys, added
authority/path fields, NUL text and excessive bytes are rejected. Classifications
come from the host's declared policy (default `private`), not model labels or a
claim that the content has been semantically inspected. This workflow grants only
local creation, never forwarding, code execution or general directory access.

## Existing local Ollama, one request

For an application that needs a built-in model adapter:

```text
ash workspace-run --config policy.json --input source.txt --task "Write a short factual summary" --artifact draft --model YOUR_LOCAL_MODEL
```

Without `--execute` this validates the inputs and prints a content-free preview:
no model call or file write. Add `--execute` for one request to the existing native
Ollama service at `127.0.0.1:11434`. `--port` and `--timeout` are bounded options.
The adapter does not start services, download models, use credentials, follow
redirects or retry. Explicit `:cloud` model aliases are refused. The operator must
also ensure the selected local service/model is not configured to forward data.

Only the explicitly selected input file (at most 16 KiB of UTF-8) and task text
are sent. Configured paths and unrelated files are not sent. The proposed output
must match the requested alias and pass the same guard as `workspace-write`.
An existing destination is rejected before spending a model call. Generation is
bounded to 512 tokens; incomplete responses fail rather than being repaired.

## Results, failures and receipts

- Exit 0: configuration check/preview succeeded, output plus receipt completed,
  or read-only verification passed. Exit 1: rejection or operational failure.
- `applied` distinguishes actual file creation from a rejected proposal.
- Before creation, a content-free intent is flushed to disk. Afterwards, a result
  receipt records the policy/decision and output hashes. Receipts and outputs are
  in the configured directory. Raw proposal/document text is not logged there
  beyond the deliberately created output document itself.
- A storage or readback error makes the session unusable. Partial evidence and
  possibly partial output are kept. `effect: unknown_inspect_output` means inspect
  before deciding what to do; never automatically replay.
- If the output succeeded but the result receipt could not be stored, the result
  says `applied: true`, `receipt_complete: false`, `result_storage_unavailable`.
  It is **not** a successful completed transaction; the CLI exits 1.
- The one-shot budget belongs to a session. The no-overwrite rule also holds
  across processes through exclusive file creation. This is not durable global
  permission accounting, rollback protection, or a multi-file transaction.

The read-only verifier checks output bytes, intent/result consistency and the
configured policy. Local hashes do not authenticate a remote producer or prove
document accuracy. This new tool does not run the old six-case corpus or claim its
ancestry graph as evidence for arbitrary documents. The existing fixture-only
`ControlledFileSession` and its historical measurements remain unchanged.

## Scope of this increment

The usable path is **config → real text proposal → Guard → create-only output →
readback/receipt**. It does not require a model in the policy decision, extra
connectors, a semantic labeler, training or a cloud subscription.
Use the focused workspace tests and existing file/Guard regressions when changing
it. Platform-specific checks require their actual platform; a skipped link test
is not a pass.
