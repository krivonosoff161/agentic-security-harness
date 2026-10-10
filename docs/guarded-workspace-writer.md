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

For this version-bound guide, verify the published
[v1.13.1 release record](releases/v1.13.1.md) and package index, then install
`python -m pip install agentic-security-harness==1.13.1` in your own environment.
The writer first shipped in 1.11.0 and adds no
extra runtime dependency; it was absent from the historical PyPI 1.10.1 wheel.

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

## Development candidate: recover the same bound operation

The unmerged #343/#317 candidate adds `workspace_operation.WorkspaceOperation` for
an application that must retain one operation's spent permissions across a process
interruption. It is not part of the published package described above. It wraps
the existing writer; it does not change its create-only permission or content rules.

The host chooses the original operation ID, policy, alias, exact text and total
attempt budget. Keep those trusted inputs outside the candidate state: `open`
requires them again and rejects changed inputs, root identity or budget. The model
does not choose an operation database, output path, permission or recovery action.

```python
from pathlib import Path
from agentic_security_harness.workspace_operation import WorkspaceOperation
from agentic_security_harness.workspace_writer import WorkspacePolicy

root = Path("output").absolute()  # Existing dedicated output directory.
policy = WorkspacePolicy(root, (("draft", "summary.md"),), data_class="public")
original = dict(operation_id="summary-001", artifact="draft",
                content="# Summary\n\nDraft for review.\n", max_attempts=3)
# Operator-owned state outside output; state and output files must not exist.
state = Path("summary-001.sqlite").absolute()
operation = WorkspaceOperation.create(state, policy, **original)
permission = operation.authorize()  # Commits spend before attempting the file.
result = operation.deliver(permission)
```

After a process interruption, use `WorkspaceOperation.open(state, policy,
**original)`, not `create`, a changed operation ID or a new state file. Call
`reconcile()` to distinguish an exact retained result from an unknown outcome:

| State | Meaning and next step |
| --- | --- |
| `DELIVERED_RECEIPT` | Exact file and original persisted writer receipt still verify; no new write. |
| `RECONCILED_POSTCONDITION` | Exact bound bytes recovered after prior spend; this does **not** prove the old call returned. No new write. |
| `UNKNOWN` | Insufficient, partial or changed evidence; preserve it, do not overwrite or treat it as absence. |
| `FENCED_ABSENT` | Only `fence()` returns this after serialized absence checking and invalidating older deliveries. The host may obtain a **new** permission under the same policy and remaining budget. |

`reconcile()` may persist a recovered postcondition; it is not a read-only verifier.
`fence()` shares the delivery lock: a delayed old-generation request cannot write
after the fence; if a delivery completed first, the fence returns that result.
The fresh permission still requires an existing Guard decision and unexpired source
restriction. Fencing does not refund spent permissions or authorize an action.
After an attempted delivery with no outcome, replay of the same permission refuses;
a competing delivery may receive this refusal while the first is still finishing.
Repeated delivery after a verified completion returns the retained result only.

The SQLite coordinator and its parent directory are trusted operator state. Use one
coordinator for a destination, with normal filesystem locking. All supported writes
for that operation must use it. It does not control unrelated host writers, detect a
coordinated rollback, make a document and SQLite commit atomic, or prove power-loss
durability. Missing/corrupt/changed state is retained and refused, not recreated.
Only hashes and permission metadata are stored in the coordinator, not document text.

This is distinct from [document data recovery](document-workflow.md#development-contract-recover-data-without-replaying-an-action),
which transfers reviewed recovered bytes into a **new** job without resuming the old
action. Existing `document-run` behavior is unchanged. Broader model-workflow
acceptance remains tracked in #343.

### Development candidate: require sources and pre-action history

An application can additionally pass a host-created `WorkspaceAdmission` as the
`admission=` argument to `WorkspaceOperation.create` and `open`. The coordinator
binds that context to the original operation and checks it before issuing a grant
and again before a new write. Omitting or replacing a previously bound context
refuses; admission does not replace the writer's Runtime Guard decision.

`WorkspaceSources.bind` accepts one to eight `WorkspaceSource` values with the
closed host-selected kinds `input`, `tool_output`, `memory` and `handoff`. Each
contains an ID, exact UTF-8 bytes and existing `DocumentSourceRestrictions` or
`DocumentMultiSourceRestrictions`. Composition preserves all original leaf
restrictions, binds kinds and bytes, and refuses ambiguous or duplicate leaves.
`sources.bind_policy(policy)` binds the source restrictions and earliest expiry;
`sources.input_bytes(bound_policy)` checks current restrictions before returning
framed **untrusted data** to the application's existing model adapter. It neither
calls a model nor turns text into instructions or permission. A derived handoff
uses `sources.restrictions.for_output(exact_output_bytes)` without renewing TTL.

The host supplies `WorkspaceAdmission` with that source bundle, an `AncestryStore`,
`expected_checkpoint`, `expected_profile`, SHA-256 `logical_operation_id`, the
bound `policy_sha256`, independently retained `expected_manifest_sha256`, host
phase and candidate manifest. Unlike the optional-context-free example above,
the operation ID must match the telemetry API's lowercase SHA-256 identity.
Use the [retained telemetry contract](ancestry-store.md#development-candidate-retained-telemetry-admission-316)
to construct the host capture window. Do **not** turn a producer's supplied
manifest into its own expected digest: the host must independently admit the
expectation, checkpoint and manifest anchor.

For local source capture, the adapter audit identifies its input model as
`harness.workspace_source_capture`. It must describe the host's actual capture
metadata and its projection into canonical observations, not relabel those records
as Runtime Guard decisions or external producer events. This source-model name
does not authenticate the host: observations remain unattested and authority-free.
Older validators without this development source model reject it; they must not be
worked around by substituting another producer label. Existing source models and
their validation rules are unchanged.

Complete, sealed, exactly matched **pre-action** history is required. Pending,
incomplete, changed or unavailable history prevents a new write. This still does
not authenticate a remote producer, prove unobserved host events were captured,
establish semantic truth or describe post-action completion. Source kinds are
host assignments, not a semantic labeler. The returned telemetry assessment
continues to have `operational_authority="none"`.

Expiry after a grant prevents a new effect while keeping the permission spent.
A completed operation can still be reopened and its retained result checked after
source expiry; that path performs no new write. Snapshot assessment may perform
the ancestry store's documented local witness recovery. Neither the host context
nor the coordinator protects against coordinated rollback by its trusted operator.
The additional composition is a development candidate, not whole-issue closure
or evidence that generated content is accurate or injection-free.
