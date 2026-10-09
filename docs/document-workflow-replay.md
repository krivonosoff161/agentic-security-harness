# Replaying the 1.13.1 document workflow

This is a reproducibility protocol for the **1.13.1 workflow**, not a claim
that a wheel is already published or that an outside operator has run it. The
[release record](releases/v1.13.1.md) reports actual publication and verification
status separately. Use only public synthetic inputs and a fresh, disposable
workspace. The existing
[operator guide](document-workflow.md#development-operator-path-runtime-decisions)
has the CLI sequence for a root plan, an admission decision, a reviewed
follow-up, and sealing. No new API or runner is required here.

## 1. Record the exact version and install it cleanly

Record the exact Git commit, dirty-tree status, Python/OS versions, wheel
SHA-256, and lockfile hashes. For a source candidate, build from the chosen
commit in a fresh Python 3.11 virtual environment with the repository's
hash-locked build and runtime requirements. Install **that wheel** without
dependency resolution; a matching filename alone does not bind its source.
If a 1.13.1 artifact has been published, instead verify its index, provenance
and hashes against the release record before installation. Until then,
v1.13.0 remains the current published version. For a source build,
after activating the fresh environment:

```sh
python -m pip install --require-hashes -r requirements/build.txt -r requirements/runtime.txt
python -m build --no-isolation --wheel --outdir dist
python -m pip install --no-index --no-deps EXACT_WHEEL_PATH
python -I -B -c "import pathlib,sys,agentic_security_harness as ash; p=pathlib.Path(ash.__file__).resolve(); assert p.is_relative_to(pathlib.Path(sys.prefix).resolve()); print(p)"
```

`EXACT_WHEEL_PATH` is the single 1.13.1 wheel just built in `dist/`; record
its digest before installing. Use a newly created output directory for each replay; the
acceptance tool refuses an existing one. Do not add the checkout's `src/` to
`PYTHONPATH`. The `-I` checks and child CLI processes import the installed
package, while the tool file itself remains in the checkout.

## 2. Run the deterministic installed acceptance

The public tool starts its own scripted HTTP server on an ephemeral
`127.0.0.1` port. It neither contacts Ollama nor measures a real model:

```sh
python -I -B tools/check_document_workflow.py --out replay-native --engine native
```

For the optional bridge, install the exact hash-locked Python 3.11 optional
environment, then use a different fresh directory:

```sh
python -m pip --isolated install --index-url https://pypi.org/simple --no-compile --only-binary=:all: --require-hashes -r requirements/verification/pydantic-ai-ci-py311.txt
python -I -B tools/check_document_workflow.py --out replay-pydantic --engine pydantic-ai
```

Successful 1.13.1 scripted-fixture expectations are `passed=true`,
`checks=47`, `metadata_gets=1`, and `generation_posts=14` **per engine**.
Keep each `acceptance.json` and the exact wheel digest. Its rows are
content-free case/state/reason summaries; source and document fixtures under
the output directory are intentionally public synthetic text. These counts
are scripted transport accounting, not model quality or independent review.

The checks include admission-head previews and stale-head refusal without a
generation call, pending and unsealed coverage remaining incomplete, a normal
supervised child with no false fence, a two-source restriction binding carried
into a reviewed follow-up, and sealed declared history. The protected sibling
must remain byte-identical. In the host-bound text path, a control-shaped
reply is saved only as literal document content; separate lower-level Guard
controls reject a forbidden alias or forged authority. Do not describe a
literal saved string as a permission failure or as proof of prompt-injection
resistance.

## 3. Review negative outcomes and recovery separately

Use `document-status --json` on the relevant job and
`document-coverage --json` with the independently retained admission head.
Expected interpretations are:

| Observation | Required interpretation |
|---|---|
| `quality.status=failed` on a saved draft | Write happened, declared format/value check failed; a dependent `--from-job` is refused before generation. No automatic repair or retry. |
| Protected sibling unchanged | Fixed output scope held in this fixture; it says nothing about tools the host may have exposed elsewhere. |
| Pending choice, unsealed ledger, or missing expected job | `complete=false` / exit 1. Do not fill a gap with a model-supplied decision or treat the plan marker as execution. |
| Interrupted original job | `needs_inspection`; original ID is spent and its completion is not inferred. A valid `--inspect-recovery` may report `recoverable_data` only for exact authorized bytes with a valid closure/fence. |

The scripted acceptance covers normal supervision, **not** a process crash.
The source tests `tests/test_document_supervisor.py` and
`tests/test_document_supervised_recovery.py` exercise owned-child exit windows:
pre-create and partial bytes stay non-recoverable, while complete exact bytes
can become reviewed data. Even then the original outcome remains unknown;
inspect the actual bytes and their digest, then use a **new** admitted job ID
with `recover_source=True` only when that recovery choice was host-bound in
its expected-job record. Never rerun the interrupted ID. Those process tests
are not power-loss or hostile-host proofs.

## 4. Keep real-model and human review claims separate

An actual local-model run is a separate, explicitly authorized experiment:
record its model name and digest, request settings, exact source/task/check
files, attempted calls and terminal failures before interpreting output.
The scripted counts above cannot stand in for it. A `checked` exact-JSON result
means only that the declared host-side comparison matched. An operator must
read the actual document, verify task usefulness and facts, and retain the
SHA-256 of the exact reviewed bytes before acknowledging a downstream source.
Model output and automated checks are not independent human validation.

Safe public replay evidence is the source commit and wheel digest, declared
synthetic fixtures, content-free `acceptance.json`, test names/results, and
bounded operator conclusions. Keep raw model requests/responses, private
source documents, local service details, machine-specific paths, and any
credentials outside public Git and shared reports. Redact paths if needed;
do not replace a missing run with an assertion that someone else reproduced it.

## CI scope on a task pull request

At this source snapshot, `.github/workflows/ci.yml` builds an installed
candidate on Ubuntu and Windows and runs the **native** scripted acceptance.
`.github/workflows/ecosystem-integration.yml` does the same for the optional
Pydantic bridge on both OSes. The ecosystem exact-source matrix runs the full
pytest suite on both OSes, including the new admissions, multi-source,
supervisor, and supervised-recovery tests. Both explicit installed integration
test lists include those new modules as well; the installed scripted acceptance
and the installed process-crash tests are separate checks. No CI lane calls a
real local model, performs an independent
operator review, or proves power-loss recovery. A green PR would establish
only the checks actually reported for its exact commit.
