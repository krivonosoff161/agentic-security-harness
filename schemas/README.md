# JSON Schemas

These JSON Schema files are public integration aids for tools that need to inspect
Agentic Security Harness artifacts without importing the Python package.

The authoritative in-process validator is still `ash validate`, backed by the Pydantic
models and `src/agentic_security_harness/schema_versions.py`. Legacy artifact schemas may
allow additional properties while the package remains pre-v1.0. The stable portfolio
observation and R4 companion contracts are strict and reject unknown fields.

| File | Artifact |
|---|---|
| `trace.schema.json` | Frozen schema 1.0 for one item inside `traces.json`; closed typed fields with `reproducibility` as the explicit extension map. |
| `corpus-manifest.v1.json` | Exact corpus 1.0.0 projection with 24 ordered pattern contracts. |
| `corpus-manifest.v1.schema.json` | Closed portable shape schema for the corpus manifest. |
| `scorecard.schema.json` | `scorecard.json`. |
| `remediation.schema.json` | `remediation.json`. |
| `run-manifest.schema.json` | `run_index.json`. |
| `portfolio-observation.v1.schema.json` | Stable authority-free portfolio observation. |
| `portfolio-outcome.v1.schema.json` | Layer-discriminated authority-free outcome. |
| `mcp-redaction-receipt.v1.schema.json` | Secret-safe structural MCP receipt. |
| `portfolio-trajectory-accounting.v1.schema.json` | Bounded DAG and completeness accounting. |
| `portfolio-telemetry-manifest.v1.schema.json` | Expected/observed telemetry proof. |
| `portfolio-coverage-expectation.v1.schema.json` | Precommitted expected channels and event count. |
| `agent-host-recording.v1.schema.json` | Closed provider-neutral Agent Host V1 recording. |
| `agent-host-evaluation.v1.schema.json` | Closed deterministic Agent Host V1 evaluation result. |
| `agent-host-evaluation-ruleset.v1.schema.json` | Closed ruleset shape for all 24 frozen corpus patterns. |
| `agent-host-evaluation-ruleset.v1.json` | Exact content-bound Agent Host V1 ruleset. |
| `controlled-local-adapter-config.v1.schema.json` | Closed literal-loopback transport limits for the controlled local adapter. |
| `controlled-local-tool-receipt.v1.schema.json` | Digest-only Runtime Gateway policy/tool decision receipt. |
| `controlled-local-invocation-receipt.v1.schema.json` | Digest-only local invocation, response and audit binding. |
| `controlled-local-adapter.v1.manifest.json` | Content-bound implementation, policy, schema, test, workflow and documentation contract. |

The R4 companion schemas are strict (`additionalProperties: false`) shape checks only.
Cross-field and graph semantics require the Python validator plus the positive/negative
fixtures bound in `r4-companion-contracts.v1.manifest.json`. The manifest records exact
digests for schemas, validator source and fixtures; it does not authenticate a producer or
prove telemetry completeness by itself. Regenerate or check the bundle with:

```powershell
$env:PYTHONPATH = "src"
python tools/r4_companion_schemas.py --root . --check
```

Use `ash validate <path>` for full corpus consistency, standards mapping, secret-marker
scans, and cross-artifact checks.

Regenerate or verify the corpus projection and shape schema with:

```powershell
$env:PYTHONPATH = "src"
python tools/corpus_contract.py --root . --check
```

Generate or verify the controlled local adapter bundle with:

```powershell
$env:PYTHONPATH = "src"
python tools/controlled_local_adapter_contracts.py check
```

The trace v1 schema is closed at every typed object boundary. Historical trace schema
`0.1` remains readable by `ash validate` during the v1 compatibility window and can be
normalized with `migrate_trace_payload_to_v1`; the public schema file describes only the
version current writers emit.
