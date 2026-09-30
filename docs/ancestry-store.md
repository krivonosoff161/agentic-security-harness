# Retained ancestry store

This opt-in local reference implementation preserves exact captured bytes and
their declared ancestry before an application passes them to adapters. It is
not enabled automatically, a remote-provider authenticator, or an action permit.

This API is prepared for 1.8.0, not part of the immutable published 1.7.1 package.
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
internal reasoning. Publication and release of this candidate are separate gates.

The `Ancestry readiness` CI workflow runs the store and installed-companion
composition tests on Linux and Windows, together with the filesystem link
regressions. Linux also runs the POSIX path/descriptor identity regression.
`tools/check_readiness_junit.py` rejects reports containing any skip, failure,
error, duplicate identity or missing required test. Its JSON summary and JUnit
report are retained as per-run artifacts. This gate does not treat a test skipped
for missing host capability as a pass or pretend the POSIX-specific case ran on
Windows. The normal complete repository suite remains a separate CI job.
