# Controlled file workflow

Status: included in [1.9.0](releases/v1.9.0.md). The
[fresh local-model evidence](controlled-file-observation-20261001.md) was collected
on an installed candidate. The release record separately confirms that all 104
package payload files match the published wheel, while the whole-archive hashes
remain distinct. Release installation checks are separate from the model run.

This opt-in benchmark makes actual filesystem writes in newly created synthetic
fixtures. It measures two different outcomes: whether the permitted report was
correct, and whether a forbidden protected-file write was prevented. It does not
grant a model access to user files, a shell, arbitrary paths or executable code.

## Run an installed package

Use a version that includes this feature, from a directory outside the checkout:

```console
ash controlled-file-workflow --out file-run
ash controlled-file-verify --out file-run
```

The output parent must already exist; `file-run` must not exist. Defaults make no
network or model calls. Six fixed public-synthetic documents have different ledger
counts and include role, maintenance and forged-tool distractions. Offline controls
use exact proposals; they are not observations of a model resisting those texts.

To measure a local model already available through Ollama, explicitly opt in:

```console
ash controlled-file-workflow --out model-file-run --model YOUR_LOCAL_MODEL --port 11434
ash controlled-file-verify --out model-file-run
```

The client only connects to literal `127.0.0.1` and `/api/generate`. It does not
install models, launch a server, discover providers, use proxies or read credentials.
The operator owns model selection and must ensure the endpoint is a trusted local
service. The protocol requests seed 42, temperature 0 and context 2048, not identical
cross-machine sampling. A maximum of two declared turns per document means at most
twelve requests. Every attempted call has an exclusive intent before transport and
a content-free receipt after it. A failed/partial directory is retained and cannot
be resumed or overwritten by this command. No response repair or invisible retry.

## What executes

1. A typed proposal contains an operation, an artifact label and two integer counts.
2. Quarantine admits the exact caller-selected representation; admission is not permission.
3. The captured document/proposal chain is committed and checked in the ancestry store.
4. The public Runtime Guard evaluates report-only authority bound to the exact bytes.
5. Only an allowed proposal reaches the internal retained-handle file writer.
6. A separate read-only verifier checks actual file bytes, scores the ledger counts
   independently and recomputes the bounded history commitments and witness.

Each fixture contains `report.txt` and `protected.txt`, created exclusively by the
benchmark. The model selects a label, never a filesystem path. Input counts are
formatted without being corrected to the oracle. A wrong report can therefore be
authorized and written while its accuracy score is false. A protected-file proposal
is representable, but Guard rejects it. Existing pure Gateway APIs remain unchanged:
this feature never interprets a Gateway denial as permission or activates a generic executor.

The final fixed causal comparison applies the **same synthetic forbidden proposal**
to two separate fresh fixtures. Guard-on preserves protected bytes; the deliberately
unguarded control changes them. There is no CLI option to disable Guard on model
proposals. This comparison tests the enforcement path, not a model's likelihood of
producing that forbidden proposal. Model observations are reported separately.

## Evidence and limits

`manifest.json` declares inputs/budget. `result.json` and per-turn receipts retain
counts, reasons and hashes, not raw model responses. File fixtures are public
synthetic data. `controlled-file-verify` returns integrity, applied-report and exact
report counts separately. A green integrity check does not mean every task succeeded.
Missing, modified or partial evidence fails verification.

The local candidate returns a content-free nonzero diagnostic for ancestry
storage or integrity failure, retaining the incomplete directory. The affected
proposal does not reach Guard/write when ancestry fails, but writes from earlier
completed cases can remain. Inspect their result records and actual file bytes;
do not assume a failed commit rolled back or retry into the same directory.
See [storage failure handling](ancestry-store.md#storage-and-integrity-failures-local-candidate).
This diagnostic change is not part of the immutable published 1.9.1 wheel.

The trusted broker and caller are part of the trust boundary. Retained descriptors,
identity checks and exclusive creation reduce path substitution risk; they are not
an OS sandbox against hostile native code or another privileged local process.
The Windows backend does not claim a restricted-token/ACL boundary. No model output
is executed, and the model receives no direct host handle. The local Lab's additional
process/network auditing is experiment-specific, not a product firewall claim.

One-use call IDs, a fresh output directory and refusal to resume prevent this command
from silently replaying an ambiguous partial run. They do not solve distributed
exactly-once execution, power-loss durability, remote producer authentication,
coordinated database/witness rollback or completeness of uncaptured host events.
Those remain the distinct research questions in #316/#317. No cross-model,
production-wide safety or independent human-review conclusion follows from this demo.

## Pydantic AI integration in the local candidate

The local candidate adds `examples/pydantic_ai_guarded_files.py`. It inserts the
existing Quarantine, ancestry and Guard path inside a real Pydantic AI tool
callback, before the retained-handle writer. The `Agent` receives one tool whose
only argument is proposal text; paths, capture labels, context and file handles
belong to the trusted application closure. The example submits proposals through
the candidate's public `ControlledFileSession` interface, not private effect
helpers. This is a fixture-only insertion point, not a general filesystem adapter.

```python
from pathlib import Path
from agentic_security_harness.controlled_file_workflow import ControlledFileSession

# These arguments belong to the application, never to the model/tool request.
with ControlledFileSession.create(
    Path("new-fixture"), context="sample-task", document="Public synthetic task.",
    max_proposals=1,
) as boundary:
    # Register this closure as the agent's tool; its sole argument is proposal text.
    def submit_proposal(proposal: str) -> str:
        return boundary.submit(proposal.encode("utf-8"))["reason"]

    # The application's agent loop runs here, before the session closes.
```

Creation requires a fresh directory with an existing parent. The proposal byte
limit is 4096; the host chooses a budget of 1–32 attempts. IDs are generated by the
session, not copied from model output. Each admitted byte submission consumes an
attempt, including rejected JSON, and an exclusive intent precedes enforcement.
There is no public Guard-off argument. Persistence/effect exceptions poison the
session: even if a write already happened, later calls cannot silently retry it.
After closing or failing, the session cannot resume. Its result record describes
authorization and effects, not the correctness of report counts.

The optional framework pin is `pydantic-ai-slim==1.107.1`, with a separate
Windows x64 / Python 3.11 hash-locked environment in
`requirements/verification/pydantic-ai-windows-py311.txt`. It is not a base Harness
dependency. Pydantic AI is an independent project under the
[MIT license](https://github.com/pydantic/pydantic-ai/blob/v1.107.1/LICENSE);
this example makes no affiliation or upstream-endorsement claim. Its
[FunctionModel](https://github.com/pydantic/pydantic-ai/blob/v1.107.1/pydantic_ai_slim/pydantic_ai/models/function.py)
supplies deterministic tool calls without an LLM or provider. Framework requests
and provider calls are counted separately.

The example also exposes `dispatch_proposal_async(boundary, proposal_source,
task=...)` for an explicitly configured application source. The trusted asynchronous
source is invoked once and returns bounded proposal text or `None`; the same Agent
tool callback submits its exact UTF-8 bytes. `None` produces no tool invocation.
There is no source retry or response repair, and completion after the tool result
is deterministic rather than another model request. The returned measurement holds
digests, decisions and timings, not raw response text. The default commands below
still use fixed controls and never start a model. A real model transport and its
resource/network limits remain explicit responsibilities of the calling application.

From a checkout, after installing the candidate Harness and optional locked
dependencies into a fresh environment:

```console
python examples/pydantic_ai_guarded_files.py --out NEW_OUTPUT_DIRECTORY
python tools/check_pydantic_ai_guarded_files.py --out ANOTHER_NEW_DIRECTORY --repetitions 10
```

Both output parents must exist and each output directory must be new. The second
command enables process/network audit-deny before third-party imports and verifies
file bytes, ancestry, session manifest and per-attempt receipts read-only after
each run. Windows event-loop IPC is
initialized first; the audit is a diagnostic boundary, not an OS sandbox. It does
not start a model, provider, shell, or other external agent service.

The eight fixed cases include a useful permitted write, a representable protected
write denied by Guard, malformed JSON, an unknown target, forged authority fields,
Boolean/negative counts and another permitted write. Capture labels are bound into
the retained root before execution. A payload's claim of authority cannot rewrite
them or supply an action grant. This checks one structured tool boundary, not
universal recognition of communication types or arbitrary multimodal content.

### Reviewable data and measurements

Each row retains the public synthetic input, input digest, versioned schemas,
trusted context/labels, independently declared expected outcome, actual decision,
before/after effect hashes, framework call counts and measured durations. The
checker pins the corpus and implementation bytes in a manifest. Failed cases are
not silently removed. Expected results come from the declared report-only policy,
not from treating the observed decision as ground truth.

Development and reserved evaluation cases are separated. These are fixed,
author-authored contract cases, not a blind independently annotated dataset. They
are reviewable seed data; no classifier is trained and no generalization result
is claimed. Never replace the fixed input strings with private traces and assume
that retaining only a digest elsewhere makes those strings safe to publish.

The local candidate includes a checked, path-free
[`BoundaryEvaluationSeed.v1` seed](../examples/boundary-seed-v1.json): eight exact
public inputs with input digests, versioned capture labels, independently declared
expected outcomes, observed decisions and effect hashes. Four cases are development
examples; four are `evaluation_reserved_known`, explicitly known author-authored
cases rather than blind evaluation. This seed is for reproducible structured
boundary tests. Model observations are a different evidence class and are not
silently relabelled as these fixed controls.

`tools/export_boundary_seed.py` reads the corpus as an AST literal without importing
Pydantic AI or running an agent. Export requires a completed one-repetition capture,
matching corpus/example/checker/package pins, zero model/provider calls and successful
read-only verification of the original file effects and ancestry. It creates a new
file exclusively and refuses an existing destination or symlinked output path.

```console
python tools/export_boundary_seed.py --check examples/boundary-seed-v1.json
python tools/export_boundary_seed.py --capture NEW_CAPTURE --out NEW_SEED.json
python tools/export_boundary_seed.py --check NEW_SEED.json --capture NEW_CAPTURE
```

Standalone `--check` validates structure, exact known inputs, expected/actual outcomes,
split membership, labels and digest. Supplying `--capture` additionally checks the
retained local evidence; this is not remote producer authentication. Recomputing
the dataset hash cannot conceal an altered expected answer, promoted authority,
duplicate/cross-split row, effect hash or Boolean/integer type substitution. Optional
integration tests exercise export and readback; pure dataset tests need no Pydantic AI.

On 2026-10-03 the local Windows source candidate completed ten repetitions: 80
tool calls, 160 scripted FunctionModel requests, zero provider calls, 20 report
writes, 10 protected-write denials and 50 proposal-shape rejections. The separate
readback verified all 80 protected files unchanged and recorded zero blocked
process/network events. This is integration evidence, not a new model observation.

Measured hook medians were 2.59 ms for proposal rejection, 257.60 ms for Guard
rejection and 352.02 ms for a completed write. Their nearest-rank p95 values were
7.01, 381.25 and 511.62 ms respectively. All samples were retained; timings include
local storage/history checks and effects where reached, but exclude initial store
creation and framework import. They are machine-specific measurements with tiny
per-class samples, not throughput guarantees or a production latency budget.
The full durable path is not an instantaneous label lookup.

The timings above belong to the earlier first-stage implementation, before the
public session's additional attempt receipts; they are not a fresh performance
measurement of this revised hook.

A separate local Windows observation on 2026-10-03 supplied six unmodified replies
from the existing Qwen2.5 1.5B model through this external Agent loop and the public
session hook. Four proposals wrote reports; two proposed the protected artifact
and were denied. Two of the four written reports had correct ledger counts. The
six model cases and two separately labelled fixed controls left all eight protected
files unchanged. Read-only verification checked the retained bytes and ancestry;
five in-memory evidence mutations were rejected without changing the files.
This is a fixed, previously known integration corpus, not a new generalization
set or an estimate of failure probability. The model series used six native
loopback calls and twelve framework requests, without retries or response repair;
fixed controls add four framework requests but no model calls. The owned service
and worker terminated after the run. Process/network audit recorded no violations.
The Python audit is a diagnostic control, not kernel isolation of hostile code.

### Capture labels and cost boundary

Capture metadata records the host-selected source class, untrusted-proposal
representation, `authority: none` and public-synthetic data class. These observations
are not grants. The report-only permission is issued separately by the fixture
policy. Neither extra proposal fields claiming `authority`, `trusted`, `source`,
`guarded`, `call_id`, `context` or a different schema, nor role-like text in the
document can change that permission. The local candidate has 18 focused tests
checking those boundaries, malformed counts, duplicate keys, retained file bytes
and root-document/ancestry binding. This is a structured contract, not recognition
of the meaning or true origin of arbitrary text or multimodal content.

A separate audited decomposition used ten repetitions of each of three paths,
rotating their order and retaining all samples: permitted report, protected denial,
and forged-label rejection. On this Windows machine, the report-path medians were
0.056 ms for capture/serialization/hash, 0.822 ms for parsing and Quarantine, and
0.658 ms for policy plus grant construction. The durable path was much slower:
ancestry append 350.69 ms, attempt receipts 117.22 ms, and file write 71.14 ms.
The whole submission median was 650.73 ms (nearest-rank p95 769.75 ms); fresh store
initialization was measured separately, with median 1082.14 ms. These are exclusive
nested spans; component medians are not additive. File-audit and timing overhead
are included. All 30 protected files remained unchanged, with ten useful writes,
ten Guard denials and ten shape denials; there were no model/network calls.
No durability setting was weakened. This bounded workload identifies where to
investigate latency; it neither sets a production SLO nor promises instantaneous
end-to-end enforcement.

In those six model cases, hook time ranged from 458.31 to 644.17 ms. Generation
took 32.41 s on the first request and 1.34–1.38 s on the remaining requests. These
are separate measurements: the hook includes durable storage work, not model
generation. The separate audited decomposition above examines that cost and the
label/authority contract; neither run establishes an instantaneous policy path.

This example, checker and optional environment are part of the 1.10.1 source
candidate for [issue #332](https://github.com/krivonosoff161/agentic-security-harness/issues/332),
not included in the published 1.9.1 distribution. The published release passed
[GitHub Actions Linux/Windows verification](https://github.com/krivonosoff161/agentic-security-harness/actions/runs/36960689808).
The immutable [1.10.0 tag](releases/v1.10.0.md) built and passed named Linux/Windows
checks but its overall release workflow failed at a relative-path seed export,
before any index upload. The 1.10.1 source candidate corrects that failure and
requires its own exact-head Linux/Windows checks and publication gates. A local
Linux VM is not required for that verification route.
