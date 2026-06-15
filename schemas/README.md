# JSON Schemas

These JSON Schema files are public integration aids for tools that need to inspect
Agentic Security Harness artifacts without importing the Python package.

The authoritative in-process validator is still `ash validate`, backed by the Pydantic
models and `src/agentic_security_harness/schema_versions.py`. These schemas intentionally
cover the stable top-level contract and allow additional properties while the project is
pre-v1.0.

| File | Artifact |
|---|---|
| `trace.schema.json` | One item inside `traces.json`. |
| `scorecard.schema.json` | `scorecard.json`. |
| `remediation.schema.json` | `remediation.json`. |
| `run-manifest.schema.json` | `run_index.json`. |

Use `ash validate <path>` for full corpus consistency, standards mapping, secret-marker
scans, and cross-artifact checks.
