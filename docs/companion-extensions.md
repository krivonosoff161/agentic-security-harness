# Companion Extension adapters

Status: published in the `v1.3.0` Harness core. The built-in adapters do not publish or
install companion distributions, and current source extras remain absent from published
`v1.3.0` package metadata.

The adapters turn three previously separate public projects into one executable,
offline producer-to-consumer path:

```text
agentic-transfer-verifier report + observation ─┐
ai-agent-handoff metadata + observation ─────────┼─> ObservationEnvelope V1
llm-safety-playbooks reviewed guidance ──────────┘      -> Extension SDK V1
                                                            -> findings/receipts
```

## What is integrated

- **Transfer Verifier:** a real `VerificationReport` is privacy-minimized to status,
  codes and severities. Raw finding messages do not enter Harness findings. Its event
  id must equal the event id produced by Transfer Verifier's portfolio adapter.
- **AI Agent Handoff:** the adapter consumes canonical metadata and digests only. It
  checks ordered parent bindings against the exact observations produced by Handoff;
  task/session bodies are not accepted.
- **Safety Playbooks:** the strict public guidance contract becomes executable advisory
  configuration. It may produce `inconclusive` or `finding`; it cannot produce an allow
  receipt, enforcement effect, authenticated identity or authority promotion.

Each adapter is explicitly constructed by the operator. It binds the reviewed companion
commit, canonical component-manifest digest, contract digest, Harness implementation
digest and configuration digest. CI checks the exact companion producers on Linux and
Windows rather than copying their behavior into Harness fixtures.

The extension implementation and emitted extension manifest remain owned by
`agentic-security-harness`; the separately embedded companion pin identifies the exact
external producer contract. The external repository is not presented as the owner of
Harness adapter code.

Text contract digests use `sha256_lf_normalized_text_v1`: CRLF is normalized to LF and
bare carriage returns are rejected before hashing. This keeps a reviewed Git text object
identical across Windows and Linux checkouts.

## Trust boundary

This is a deterministic integration and compatibility contour, not a plugin sandbox or
a production trust root.

- no package auto-discovery or dynamic loading;
- no runtime import of companion packages by production code;
- no network, subprocess, provider or credential access in an adapter;
- no raw handoff artifact or raw Transfer message retention;
- no operational authority;
- self-measured implementation hashes are operator-verifiable pins, not signatures or
  independent attestations.

The generated contract manifest is
[`schemas/companion-extensions.v1.manifest.json`](../schemas/companion-extensions.v1.manifest.json).
It binds the closed schemas, implementation, tests, workflow and reviewed public source
commits. `tools/companion_extension_contracts.py check` fails if those committed bytes
drift.

The generated JSON Schemas are closed **shape** contracts. Cross-field rules such as
Transfer status/severity agreement, Handoff sequence/timestamp continuity and exact
Playbooks disposition sets are enforced by the content-bound Python semantic validator;
the JSON Schemas are not advertised as standalone semantic validators.

## Honest limits

This closes the old dataflow gap for three reviewed contract surfaces. It does not make
the companion repositories installable packages, turn Playbooks into enforcement,
authenticate producers, calibrate Transfer risk against incidents, sandbox extension
code or prove effectiveness against live agents. Those remain later roadmap work.
