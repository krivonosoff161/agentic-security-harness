# Extension Operator Lifecycle V1

Status: stacked source candidate above Extension Distribution Discovery V1. It is not in
the published `v1.2.0` package and grants no operational authority.

## What this closes

Distribution Discovery V1 already verifies an explicitly selected installed distribution,
reinspects the exact bytes before approval, and can bind an object that the operator has
already constructed. The lifecycle adds the missing operator-facing path:

1. inspect one explicit installed-distribution search root;
2. reverify the exact canonical inspection and issue an approval receipt;
3. bind an already constructed object in application code;
4. derive list, disable, and rollback-plan artifacts from explicit canonical receipts.

Harness never enumerates all installed packages, opens a wheel archive, installs or
downloads a package, resolves dependencies, imports an entry point, invokes a factory, or
executes extension code. A local wheel must be installed or safely unpacked by the operator
into a dedicated search root before V1 inspection. Direct wheel-archive inspection is not
claimed.

## Safe CLI path

All input paths remain process-local and are never echoed. JSON output is canonical and
contains bounded public package identity plus digests—not filesystem paths, raw metadata,
configuration bytes, or operator action ids.

```bash
ash extension-distribution-inspect \
  --distribution-name example-extension \
  --extension-id example.extension \
  --search-path /absolute/path/to/dedicated/site-packages \
  --configuration /absolute/path/to/config.json \
  --configuration-sha256 <sha256-of-exact-config-bytes> \
  --format json > inspection.json

ash extension-distribution-approve \
  --inspection inspection.json \
  --inspection-sha256 <sha256-of-exact-inspection-bytes> \
  --inspection-id <exact-inspection-id> \
  --search-path /absolute/path/to/dedicated/site-packages \
  --configuration /absolute/path/to/config.json \
  --configuration-sha256 <sha256-of-exact-config-bytes> \
  --format json > approval.json

ash extension-lifecycle-disable \
  --approval approval.json \
  --approval-sha256 <sha256-of-exact-approval-bytes> \
  --operator-action-id local-ticket-123 \
  --format json > disable.json

ash extension-lifecycle-list \
  --approval approval.json \
  --approval-sha256 <sha256-of-exact-approval-bytes> \
  --disable disable.json \
  --disable-sha256 <sha256-of-exact-disable-bytes> \
  --format text
```

PowerShell uses the same commands with backticks instead of backslashes. Compute each
expected digest before the command (`sha256sum FILE` on Linux or
`(Get-FileHash -Algorithm SHA256 FILE).Hash.ToLower()` in PowerShell). The approval
command rereads the distribution and configuration; drift fails closed. Receipt readers
require caller-pinned exact bytes plus bounded stable regular files and reject links/reparse
points, persistent equal-length replacement, duplicate JSON keys, deep nesting, floats,
oversized integers, noncanonical bytes, and semantic digest drift.

## Application embedding boundary

The CLI cannot construct or bind extension code. After a separate code review and import
decision, the embedding application constructs the object and calls:

```python
from agentic_security_harness import bind_active_operator_extension_v1

bound = bind_active_operator_extension_v1(
    approval,
    already_constructed_extension,
    disable_receipts=known_disable_receipts,
)
```

The wrapper revalidates the manifest before and after each evaluation. A matching supplied
disable receipt blocks a new binding. The application must still stop and discard any
already-held object when it accepts a disable receipt; Harness has no process registry or
kill switch.

A rollback plan requires the exact current approval, its exact disable receipt, and a
different target approval:

```bash
ash extension-lifecycle-rollback-plan \
  --current-approval current-approval.json \
  --current-approval-sha256 <sha256-of-current-approval-bytes> \
  --disable current-disable.json \
  --disable-sha256 <sha256-of-current-disable-bytes> \
  --target-approval target-approval.json \
  --target-approval-sha256 <sha256-of-target-approval-bytes> \
  --operator-action-id local-ticket-124 \
  --format json > rollback-plan.json
```

Any additional known disable receipts must be supplied as paired `--known-disable` and
`--known-disable-sha256` options; a matching target disable fails closed. The plan is
deliberately non-executable. The embedding application must independently
construct the target object and bind it against the target approval. No automatic rollback
occurs. Harness also does not interpret package version ordering: the target must be a
different exact approval, while `version_direction_verified=false` records that the
operator—not this metadata contract—decided it is a rollback target.

## Receipt truth boundary

- Approval proves deterministic binding to exact locally read bytes, not signer, publisher,
  provenance, safety, or authenticity.
- Disable and rollback artifacts are self-digested operator declarations. They do not
  authenticate an operator and do not prove executable state changed.
- List output is a projection of only the receipts explicitly supplied on that command. It
  does not discover installed or running state.
- Rollback target availability is checked only against the explicit disable-receipt set;
  the embedding application owns completeness of that set. Projections reject a supplied
  disabled target and rollback cycles.
- Digests are content-minimizing, not anonymizing; low-entropy values can be guessed.
- `operational_authority` remains `none`; there is no sandbox, signature verification,
  provider call, network path, enforcement claim, or security `PASS`.

## Verification

```bash
python tools/extension_distribution_contracts.py check
python tools/extension_lifecycle_contracts.py check
python -m pytest -q tests/test_extension_distribution.py tests/test_extension_lifecycle.py
```

The workflow runs the same synthetic local-wheel-to-installed-metadata fixtures on Linux
and Windows. Fixtures are never imported by the inspection/approval/CLI path.
