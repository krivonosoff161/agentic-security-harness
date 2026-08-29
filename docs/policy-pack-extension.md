# Policy Pack V1 extension

Status: published in the `v1.3.0` Harness core. It is not a runtime enforcement control
and does not execute playbook code. Harness `v1.4.0` can passively install the Playbooks
distribution through an explicit extra, but installation does not bind or activate it.

The optional Policy Pack extension turns one exact reviewed
`llm-safety-playbooks` declarative pack into deterministic Harness Extension SDK
findings. Production Harness does not import or execute Playbooks code. It parses only
the explicitly supplied canonical JSON pack bytes, checks the caller-approved raw-file
digest and the compiled source/artifact pins, and evaluates caller-supplied content-free
signals bound to one `CanonicalObservationEventV1`.

```text
explicit canonical observation ─┐
content-free signal binding ─────┼─> exact data-only Policy Pack V1 evaluator
explicit pack bytes + digest ────┘      -> ExtensionFindingV1
                                           -> ExtensionRunReceiptV1
```

## Source and trust boundary

The reviewed upstream source is fixed to commit
`190769a15a44f5a5af790b33fc37724e6417c27f`, tree
`e3a5601a779c8b2e2f92516da30cf2750d320b5b`. The generated Harness manifest binds the
exact pack, pack schema, pack manifest, component manifest, input schema and output
schema digests. Cross-repository CI checks those bytes and the exact Git identity on
Linux and Windows.

The boundary is deliberately narrow:

- no package discovery, dynamic loading or Playbooks runtime import;
- no `eval`, `exec`, subprocess, network, DNS, provider, proxy or credential access;
- no prompt, response, secret, file path or model-output field in a signal binding;
- exact canonical JSON, closed fields, bounded size/depth/integer syntax and no floats;
- explicit local regular single-link files with link/reparse and read-race rejection;
- duplicate event ids and event/binding/pack mismatches fail closed;
- a missing pack produces `inconclusive`, never pass or allow;
- every finding and run receipt is advisory and has operational authority `none`.

The SHA-256 commitments are integrity bindings, not signatures, producer
authentication, independent attestation or permission to act.

## Explicit local CLI

The operator supplies every input path and the expected reviewed pack digest. The CLI
does not search directories or download a pack.

```bash
ash policy-pack-evaluate \
  --pack ./policy-pack.v1.json \
  --expected-pack-sha256 1c8ca14e6ab83d92742f6fba0b0d1b1bc422ebe30163c6619e9c80f5413b8915 \
  --observation ./portfolio-observation.v1.json \
  --signals ./policy-pack-signal-binding.v1.json \
  --format json
```

If the explicit pack path is absent, the command completes with an inconclusive receipt.
Malformed, drifted or unsafe inputs return a sanitized error without echoing paths or
bytes. JSON output is a closed Extension SDK receipt containing the content-free
observation metadata, commitments and advisory findings; it contains no raw prompt or
model output.

## Contracts and verification

`tools/policy_pack_extension_contracts.py generate` owns the six closed shape schemas
and `schemas/policy-pack-extension.v1.manifest.json`. The manifest also binds the
implementation, public exports, CLI, component declaration, tests, workflow and this
page. Semantic state rules remain enforced by the Python models; the JSON Schemas alone
are not advertised as semantic validators.

Focused verification:

```bash
python tools/policy_pack_extension_contracts.py check
python -m pytest -q tests/test_policy_pack_extension.py \
  tests/test_cross_repo_policy_pack_compatibility.py
python -m ruff check src tests tools
python -m mypy src tests tools
```

## Honest limits

This integration evaluates seven reviewed advisory signal rules. It does not infer
signals from raw content, execute playbook instructions, authenticate the signal
producer, prove rule effectiveness, provide a sandbox, lower a gateway decision, or
enforce policy. Broader packs require a new reviewed source pin and contract revision.
