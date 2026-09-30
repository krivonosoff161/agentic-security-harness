# Retained ancestry store

This opt-in local reference implementation preserves exact captured bytes and
their declared ancestry before an application passes them to adapters. It is
not enabled automatically, a remote-provider authenticator, or an action permit.

This is a source candidate, not part of the published 1.7.1 package. A separate
release decision is required before an installed public package can provide it.

## Ownership and persistence

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
