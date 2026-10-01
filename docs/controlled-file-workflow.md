# Controlled file workflow

Status: 1.9.0 candidate; [fresh local-model evidence](controlled-file-observation-20261001.md)
is complete, while publication remains a separate gate.

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
