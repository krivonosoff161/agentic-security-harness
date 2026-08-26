# Corpus Pack SDK V1

Corpus Pack SDK V1 lets an optional package publish additional **sanitized boundary
invariant descriptors** without changing the frozen Harness corpus 1.0.0. It is an
offline metadata contract and registry composer, not a plugin loader or scenario runner.

## Trust boundary

A pack is untrusted input. The SDK accepts either exact canonical JSON bytes or a fixed
`corpus-pack.v1.json` file below an explicitly selected directory. Every filesystem load
requires an expected canonical manifest SHA-256 supplied separately by the operator or
trusted caller. The directory loader
rejects symlinks, Windows reparse points, non-regular files, hard links, unstable reads,
oversized content, duplicate JSON keys, noncanonical encoding, unknown fields and digest
drift. JSON nesting, integer digits and numeric forms are bounded before model validation,
independent of process-global interpreter limits. It does not scan packages, import entry
points, execute pack code, access the
network or read credentials.

The file loader proves the opened descriptor matches the inspected path, reads the bounded
file twice through that descriptor, requires identical bytes, rechecks topology and
metadata, and matches the loaded bytes against that external digest pin. The pin closes
stable same-size replacement ambiguity that Windows metadata alone cannot detect. It is
still not publisher authentication or an operating-system access-control boundary.

All pack string surfaces are identifiers, versions, enums or digests. There is no field
for prompts, tool arguments, model output, credentials, private paths or raw evidence.
That closed shape reduces accidental disclosure; it does not authenticate a publisher or
prove that a supplied digest corresponds to a public artifact.

## Core immutability and composition

Every manifest binds:

- core corpus version `1.0.0` and its exact semantic digest;
- pack id/version and namespaced, sorted pattern ids;
- source component, repository revision, component-manifest, implementation and
  distribution digests;
- producer-declared supported and tested Linux/Windows platforms;
- the Extension SDK observation contract and per-pattern evidence requirements;
- fixed terminal meanings: preserved -> `pass`, violated -> `finding`, missing evidence
  -> `inconclusive`, invalid contract -> `error`;
- `may_lower_security_decision=false` and `operational_authority=none`.

`compose_corpus_packs_v1()` requires an exact external digest pin for every pack, sorts
packs by id and rejects missing/extra pins, digest mismatch, repeated packs, pattern-id
collisions and core overrides. Its result starts with the unchanged 24 core ids and adds
identity-only optional pattern references. It does **not** modify `corpus_manifest()`,
`seed_patterns()`, Agent Host rules or benchmark execution.

## Observation compatibility

Patterns declare source surfaces, activities, terminal activity, minimum event count,
telemetry completeness and optional lineage/authority-envelope requirements for
`ExtensionObservationEnvelopeV1`. `assess_corpus_pack_evidence_v1()` checks only whether
those prerequisites are present. Even a complete assessment remains `inconclusive`; a
separate reviewed deterministic rule would be required to decide the invariant.

```python
from pathlib import Path

from agentic_security_harness import (
    assess_corpus_pack_evidence_v1,
    compose_corpus_packs_v1,
    load_corpus_pack_directory_v1,
)

expected_sha256 = "<operator-supplied-lowercase-sha256>"
pack = load_corpus_pack_directory_v1(
    Path("optional-pack"), expected_manifest_sha256=expected_sha256
)
composition = compose_corpus_packs_v1(
    (pack,), expected_manifest_sha256s={pack.pack_id: expected_sha256}
)
# assessment = assess_corpus_pack_evidence_v1(pack.patterns[0], envelope)
print(composition.composition_id)
```

The committed fixture at
`examples/corpus-packs/example-boundary-pack/corpus-pack.v1.json` is synthetic and
unattested. It demonstrates interchange only; it is not an independently reviewed
security pattern or installable third-party package.

The platform tuples are supplied by an `unattested` producer. They are compatibility
claims only: the SDK does not verify CI provenance or prove that tests ran on either
platform.

## Contract maintenance

Generate or verify schemas, fixture and the digest-bound contract manifest:

```powershell
$env:PYTHONPATH = "src"
python tools/corpus_pack_contracts.py generate
python tools/corpus_pack_contracts.py check
python -m pytest tests/test_corpus_packs.py
```

The committed JSON Schemas describe closed shape. Cross-field identity, core
immutability, ordering, filesystem and Extension SDK semantics remain owned by the
Python validator and adversarial tests. The generated contract manifest binds the
implementation plus its core-corpus, Extension SDK, model, portfolio, safe-I/O and public
API runtime closure so a dependency change cannot leave the SDK claim apparently current.

## Explicit non-claims

- No automatic discovery or installation of optional packages.
- No pack-code sandbox or execution.
- No proof of producer identity, review quality, telemetry completeness or security.
- No live provider, tool, target, deployment, enforcement or release authority.
