# Retained ancestry store

This opt-in local reference implementation preserves exact captured bytes and
their declared ancestry before an application passes them to adapters. It is
not enabled automatically, a remote-provider authenticator, or an action permit.

This API was introduced in 1.8.0, not in the immutable published 1.7.1 package.
See [release status and evidence](releases/v1.8.0.md) before selecting an installed
package; source version metadata alone does not establish publication.

## Acceptance map for issue #315

| Obligation | Implementation and public checks |
|---|---|
| Trusted root and prior state | Explicit `create` / `open` contract; expected context/root and an existing witness are required, with no bootstrap from an untrusted DB. |
| Exact identity, bytes and parents | Frozen records and `snapshot`; `verify_candidate` requires the retained ordered ancestor closure, not a self-consistent caller replacement. |
| Cycle, rebinding and scope resistance | Only admitted parents may be referenced; duplicate identifiers and expanding scopes are rejected. Parent-before-child admission makes this store a DAG. |
| Local event / recovery join | Each admitted record is bound to the checked event chain and separately retained witness; pending local appends are finalized or aborted only when their exact states match. |
| No authority promotion | Valid ancestry may still receive a Gateway denial; rejected candidates reach zero synthetic executions. |

Public regression entry points are `tests/test_ancestry_store.py`,
`tests/test_ancestry_store_integrity.py`, and `tests/test_ancestry_chain.py`.
The installed-wheel check is `examples/installed-ecosystem/check_ancestry.py`.
This acceptance map does not close the separately linked #316 / #317 obligations.

## Ownership and persistence

Issue [#315](https://github.com/krivonosoff161/agentic-security-harness/issues/315)
is evaluated against this captured-local-history contract. The caller owns initial
root admission and the trusted capture boundary. Independent expectations for
uncaptured host events remain [#316](https://github.com/krivonosoff161/agentic-security-harness/issues/316);
spent permission and ambiguous action outcomes remain [#317](https://github.com/krivonosoff161/agentic-security-harness/issues/317).
Local database/witness recovery below is not closure of either broader question.

The trusted caller explicitly creates one root, context and scope label set.
It owns three stable paths: the SQLite database, a separately retained JSON
witness, and the database's `.lock` sidecar. Protect these files and their parent
directories from the agent and unrelated writers. Keep private captured data in
an access-controlled local evidence area, never in source control.

Creation refuses existing paths. Opening requires all three existing files and
the caller's expected context and root digest. It never bootstraps a missing
witness from an untrusted database. A simultaneous compromise or rollback of both
database and witness is outside this local trust boundary. A separate pathname
on the same host is not an independent hardware trust anchor.

## Data admission

`AncestryRecord` contains a bounded identifier, context, exact payload bytes,
sorted unique parent identifiers and sorted unique scope labels. A child must
refer only to already admitted parents. Its scope must be a subset of every
parent's scope. An existing identifier cannot be rebound to different bytes.

`append(record, expected=checkpoint)` compares the complete current checkpoint
under a cross-process lock. Concurrent callers cannot both append against the
same old checkpoint. Checkpoints bind the context, root, version, sequence and
event-chain head. Every positive read verifies the full stored graph and event
chain against the witness; a caller cannot replace that witness with a newly
computed database hash.

`snapshot(expected=checkpoint)` returns frozen records. `verify_candidate` accepts
only the exact ordered ancestor closure for the requested target. It rejects
missing, extra, reordered, rebound or cyclic candidate records. These are data
integrity and ancestry checks; they do not establish the truth of payload claims.

## Development candidate: retained telemetry admission (#316)

The candidate `trajectory_admission` module composes this store with the existing
coverage profile and telemetry manifest. It does not introduce another writer,
executor, permission or logging service. It is not in the published 1.13.1 package.

The host admits the coverage profile, logical operation and policy before accepting
producer evidence. Data-only root/event builders bind those values, each captured
observation and its channel to records appended through `AncestryStore`. The host
retains the expected checkpoint and canonical manifest digest separately from the
supplied candidate. The manifest anchor also covers verdict-driving metadata such
as censoring, dropped/rejected counts, the observation window and adapter audit.
`assess_retained_telemetry` revalidates the supplied contract objects, checks the
manifest against `expected_manifest_sha256`, checks the snapshot against the
checkpoint, and compares the manifest with the exact retained observations and
channels. A self-consistent replacement manifest cannot select its own anchors.
The host must admit the manifest from its capture/accounting process; hashing an
untrusted incoming manifest and immediately passing that hash is not independent
admission or producer authentication.

This composition supports 1–4095 captured events plus its root. A root-only store
cannot yet supply the existing trajectory contract, which requires an observation;
do not fabricate an event to represent an unstarted run. Invalid inputs are refused
before snapshot access. Snapshot access is observational with respect to actions,
but is not strictly filesystem-read-only: the existing store may reconcile its
pending witness during recovery. Typed storage/checkpoint failures propagate.

| Result component | Meaning |
|---|---|
| Retained binding | The candidate matches the host-selected profile, context and retained bytes. |
| Coverage | The declared event/channel requirements are met within the captured boundary. |
| Host phase | Pending remains pending even when the expected number of events exists. |
| Authority | Always none; completion is not a tool permission or evidence of successful effects. |

The host owns both the choice of the latest checkpoint and the pending/sealed
phase. Merely passing an old anchor, a generation number or a timestamp does not
authenticate freshness. If an attacker can roll back both the history and every
reference available to the verifier, the old consistent view is indistinguishable
from a run that genuinely ended there. Events outside the configured capture
boundary are likewise not discovered by hashing the events that were captured.
Two files on the same writable host are not an independent witness.

This is a bounded composition under explicit host-ownership assumptions, not remote
producer authentication, whole-host completeness, or closure of #316/#317/#343.
Research calculations and model transcripts are not part of this public contract.

## Recovery

An append prepares a pending witness, commits the SQLite transaction, then
finalizes the witness. The same operating-system lock spans all three steps,
including the gap after the database commit. SQLite's transaction lock alone
does not cover that final gap.

After process termination, a pending witness matching the old database state
aborts the uncommitted intent. A pending witness matching the exact new database
state finalizes that commit. An unmatched, missing or corrupt pair raises
`IntegrityError`; a stale caller checkpoint raises `CheckpointConflict`.
Recovery never resets action-spend state or grants operational authority.

Lock waiting is bounded. This implementation uses SQLite `synchronous=FULL` and
an fsynced temporary witness replaced atomically. Process-crash tests are not
whole-machine power-loss tests. Filesystem, flush and atomic-replacement
assumptions must be assessed for the deployment platform.

### Storage and integrity failures (local candidate)

The local candidate classifies OS/SQLite creation failures as `StorageError`, an
`IntegrityError` subclass, with a fixed stage and numeric error codes. It omits
the underlying error text, which may contain paths. `controlled-file-workflow`
reports this as `ancestry_storage_unavailable` and exits nonzero; it does not
continue to a model call or report write when initial store creation fails.
Post-create reads, append preparation, commit, verification, witness finalization
and lock operations also stop on storage failure. Their fixed `stage` identifies
the failed operation. Extended SQLite availability codes preserve their numeric
value; database corruption/schema errors and invalid witness contents remain
integrity failures rather than being diagnosed as a bad filesystem.

The CLI reports `ancestry_integrity_failure` separately. Neither failure response
includes the underlying exception text. If cleanup fails during an existing
failure, the first failure remains primary and fixed `cleanup_stages` identify
secondary errors. Closing a handle must not hide an ambiguous commit failure.
These changes are not in the immutable 1.9.1 package.

The partial database, witness, lock and run manifest are retained. A failed
commit is not proof of rollback: commit may have completed before an I/O error
was returned. Do not delete that evidence, silently retry, resume the same output
directory, weaken `synchronous=FULL`, or switch to an in-memory store. Inspect
the storage environment and choose a new output directory for a separately
recorded attempt. An incomplete run is not a passing verification.

All ancestry operations for a controlled-file proposal precede Guard and the
file writer. A failure there blocks that proposal's effect. A later case can
still fail after earlier cases completed: the diagnostic explicitly leaves
`completed_effects` unknown until retained evidence is inspected. It does not
claim that the whole run wrote nothing. Explicit data recovery can reconcile
a pending witness with an already committed record; it does not replay an action.

Injected read, pre/post-commit, pre/post-witness-replacement, cleanup and recovery
failures are regression
checks. They do not reproduce an external reporter's unidentified filesystem
or certify operation on all filesystems; no filesystem diagnosis is inferred
from the text `disk I/O error` alone.

## Composition example

`examples/installed-ecosystem/ancestry_chain.py` demonstrates the opt-in path:
retained snapshot, Quarantine Connector, Filter, in-memory Router transport,
Transfer, Handoff, Playbooks and Gateway. Exact target-payload digest equality is
checked at ancestry, Quarantine Connector, Router, Transfer and final Handoff.
Playbooks consumes a derived observation; Gateway independently evaluates the
derived request. Handoff's sequence describes retained capture order, not the
ancestry graph's edge semantics. Transfer's structural PASS and Playbooks advice
remain authority-free observations.

The example uses fixed Filter/Playbooks signals and fake Router transport. Only
Gateway's built-in, in-memory lookup or digest may execute. A valid ancestry
chain cannot override a Gateway denial. Applications still need their own
task-specific authorization, receipt issuance and action replay prevention.
The Router receipt's provider-success and provider-reported-usage fields are
synthetic fixture assertions for schema conformance, not actual provider telemetry.
No OpenAI or other model provider is called by this example.

## Resource and verification limits

The store currently allows at most 4096 records, 65536 payload bytes per record,
32 parents and 64 scope labels. Reads verify the complete history, so append and
snapshot costs grow with retained history; this is not a high-throughput service
or an unbounded event archive. Empty scope is valid data but admits no capability.

Focused tests cover exact closure, corruption, schema/index changes, bounded
input handling, lost-witness rejection and lock contention. The separate local
research campaign checks real process termination, concurrent processes and
installed-component composition. Neither test class proves universal safety,
semantic correctness of model output, or authenticity of a remote model's
internal reasoning. New changes still require separate publication/release gates.

The `Ancestry readiness` CI workflow runs the store and installed-companion
composition tests on Linux and Windows, together with the filesystem link
regressions. Linux also runs the POSIX path/descriptor identity regression.
`tools/check_readiness_junit.py` rejects reports containing any skip, failure,
error, duplicate identity or missing required test. Its JSON summary and JUnit
report are retained as per-run artifacts. This gate does not treat a test skipped
for missing host capability as a pass or pretend the POSIX-specific case ran on
Windows. The normal complete repository suite remains a separate CI job.
