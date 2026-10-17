ACTION AUTHORITY — EXPERIMENTAL CANDIDATE, NOT A RELEASE

Purpose
Bind a human-operated approval to ONE exact public document, target, source capture,
host policy, deadline and request challenge. Execute through the installed Harness
create-only writer. After interruption, inspect/fence instead of blindly retrying.
No model or network API is in the runtime path. This does not judge text truth or
remove prompt injection from a document. An agent may propose text; only host and
operator decide whether these exact bytes may be stored at this destination.

Trust boundary
The host owns configuration, filesystem, state, trusted time and public-key enrollment.
Give an agent only the content-only submit callback, never host/CLI/key capabilities.
Keep the signing secret and its passphrase outside the agent environment. File mode
0600 alone is NOT a Windows isolation policy. Use an operator-controlled account/device
and appropriate OS permissions. Same-OS administrator compromise and coordinated state
rollback are outside this candidate. A signature proves key possession, not good judgment.

Install
This package is intentionally separate from the main Harness distribution and its
release workflows. It is not published on PyPI. Do not install its name from an index.
Evaluate this exact source revision in a fresh environment, without administrator/root.
The reproducible dependency locks target CPython 3.11 x64 on Windows and Linux
x86_64/glibc 2.28+. Use a local filesystem supporting SQLite locks, not network/FUSE mounts.

From the repository root, build with the locked build toolchain:
  python -m venv .venv-action
  # Windows: .venv-action/Scripts/python.exe; Linux: .venv-action/bin/python
  <venv-python> -m pip --isolated install --require-hashes -r requirements/build.txt
  <venv-python> -m build --no-isolation --wheel --outdir packages/action-authority/dist packages/action-authority
  <venv-python> -m pip --isolated install --only-binary=:all: --require-hashes -r packages/action-authority/requirements/<windows-or-linux>.txt
  <venv-python> -m pip --isolated install --no-deps packages/action-authority/dist/ash_action_authority_candidate-0.1.0.dev0-py3-none-any.whl
  <venv-python> -m pip check

Use that environment's Python for all commands below. The component pins the published
Harness 1.14.1 wheel and cryptography 50.0.2; it does not import the repository's source
checkout or activate a model/provider. In offline environments, download and verify the
locked wheels beforehand, then install with --no-index --find-links <wheel-directory>.
The dedicated CI builds one candidate wheel, then tests the same wheel on Windows/Linux.
Its CI artifacts contain test results and package hashes, not real operator approvals.

Installed checks
Change to a new directory OUTSIDE the checkout. Use absolute paths for the interpreter,
source and wheel; source is <checkout>/packages/action-authority. These commands verify
the installed package, not a source-path import. Each output destination must be new.
  <venv-python> <source>/tools/check_installed_wheel.py --wheel <wheel> --source <source> --out wheel-check.json
  <venv-python> <source>/tools/run_checks.py --source <source> --out checks
Expected: exact wheel/source/install bytes and 53 tests, no failures/errors/skips.
Test keys and confirmation answers are synthetic; do not confuse them with approval
by the operator. Four deliberate child-process exits affect only temporary fixtures.

One public-document workflow
Use real paths of your choice, all in your own new task directory except the operator key.
The commands below are templates; the operator alone runs the key and signing commands.
Do not paste the private key or passphrase into chat, a model prompt, or command arguments.

1. OPERATOR, outside the agent environment, creates an encrypted dedicated key:
  python -m ash_action_authority.operator keygen --private operator.pem --public operator.hex
   Pass only the public file/fingerprint to the host. The host independently enrolls it;
   possession of an arbitrary public file does not make its signer trusted.

2. HOST prepares one fresh public-source task (no action yet):
  python -m ash_action_authority.host setup --home new-task --public-key operator.hex --source source.txt --document proposed.txt --host-revision HOST_CODE_COMMIT_SHA --allow-local-source-use
   host-revision is the actual host-selected source revision, not an invented identifier.
   The source MUST be public and authorized for this local reuse. The explicit flag grants
   source use inside this workflow, not network access.
   The installed Harness admission calls this recipient local-model; the example performs
   no model call. The host flag explicitly permits this existing local document contract.
   Other classifications need a proper host integration using the API.
   Request lifetime is3600seconds by default; maximum86400.
   Source capture is local/unattested; it does not prove discovery of hidden dependencies.

3. OPERATOR receives new-task/request.json AND new-task/document.txt and reviews both:
  python -m ash_action_authority.operator sign --private operator.pem --request new-task/request.json --content new-task/document.txt --decision approve --out approved.json
   Review displays escaped exact bytes, not an agent summary. Type the requested action
   and digest prefix, then enter the private-key passphrase locally. No --yes bypass.
   The detached decision is not a secret key. Signing does not execute the action.

4. HOST applies the decision, runs, and independently reads back:
  python -m ash_action_authority.host apply-decision --home new-task --decision approved.json
  python -m ash_action_authority.host run --home new-task
  python -m ash_action_authority.host status --home new-task --recover
   Exact output is new-task/output/document.md; no overwrite. A repeated run is refused.
   status WITHOUT --recover is explicitly historical; it does not verify current bytes.
   Shell exits:0 for a successful command,1 for a refused request,2 for an uncertain
   outcome or busy coordinator. A timeout never acknowledges approval or cancellation.
   Read the JSON reason/next_step. A nonzero run does not prove that no file was written.

Revoke / recover
Before BEGIN, sign the current request with --decision revoke and apply that decision.
It invalidates the old challenge. To review a fresh request after revocation:
  python -m ash_action_authority.host request --home new-task --out next-request.json
BEGIN is the durable outer EXECUTING commit; it is earlier than physical file I/O.
A revoke that loses that race returns too_late_or_in_flight. A lock timeout acknowledges
nothing. Expiry limits admission at BEGIN, not the wall-clock completion of a started I/O.

After interruption run status --recover. No implicit execution occurs during recovery.
DELIVERED_RECEIPT means an exact file plus bound retained receipt was observed.
RECONCILED_POSTCONDITION means exact supported target bytes were observed after ambiguity;
it is not proof of the original successful return. FENCED_ABSENT means old delivery was
disabled and absence observed. UNKNOWN means stop and inspect; do not overwrite/replay.
Missing/changed files after a past success are UNKNOWN now, with historical outcome kept.
After fenced absence, any fresh action requires a new task directory and new approval.
An incomplete setup is preserved and refused: inspect it and use a new directory, never
delete it merely to force the same logical operation through.

Embedding
ActionGate.create/open accept a host WorkspacePolicy, exact content, operation identity,
public key, deadline, declared dependency digests and optional WorkspaceAdmission.
Use request() for operator review; apply_decision() verifies an external signature.
Only submit(content) belongs in the agent tool table. Your host must persist and restore
the same trusted inputs, as host.py demonstrates. Supply WorkspaceAdmission whenever
captured-source eligibility/history is a prerequisite. Bare digests are version pins,
not an automatic live-dependency discovery or freshness system.

Evidence / remaining acceptance
Finite tests distinguish synthetic approvals, actual child-process termination, real file
effects, injected storage errors and target-side readback. Test signatures are NOT owner
consent. Actual operator enrollment/signing and an external developer handoff remain
separate acceptance gates. A CI pass is a platform/test result, not human acceptance.
Tests cover two-process contention, four real child-process terminations, revocation
ordering, changed bytes, bounded control-log capacity and uncertain outcomes.
A successful historical receipt is reported separately from current target readback.
There is no claim of enterprise readiness, universal exactly-once delivery or novel crypto.
Work item: https://github.com/krivonosoff161/agentic-security-harness/issues/373
