# Security Policy

> **Agentic Security Harness.** This project does **risk reduction**, not guaranteed
> protection. See [docs/threat-model.md](docs/threat-model.md) for scope and explicit
> limitations.

## Supported Versions

The `main` branch is the currently supported development line for security fixes.

## Responsible Use

This project is an **authorized defensive testing harness**, not a hacking tool. It ships
sanitized offensive **test content** so you can find agentic failure modes in systems you
own or are explicitly authorized to test.

By using the harness you agree to:

- run it **only** against **mock / demo / your own / authorized** targets, never against
  third-party systems without written permission;
- keep payloads **sanitized**: "sensitive" data in tests are **synthetic markers**, never
  real credentials or secrets;
- treat multimodal / sensor patterns as defensive testing of systems that accept
  voice / image / audio, **not** signal weaponization. The project provides **no
  instructions for generating ultrasonic / adversarial audio**, and none for abusing
  third-party systems.

The harness measures risk; it does not authorize attacking anyone.

## Reporting a Vulnerability

Please report security issues **privately**. Do not open a public issue for a
vulnerability.

- Preferred: open a private security advisory via GitHub
  ("Security" -> "Report a vulnerability"), when available.
- Alternative: contact the maintainer through the address or profile links listed on the
  GitHub project owner profile.

Please include the affected version or commit, a clear description, reproduction steps or
a proof of concept, and the impact you observed. Do not include live credentials, private
API keys, personal data, or third-party confidential data in reports. Synthetic
reproduction cases are preferred.

## What to Expect

- Acknowledgement of your report within a reasonable time.
- An assessment and, where applicable, a fix and coordinated disclosure.
- Credit for the finding if you would like it.

> These are good-faith targets for an early-stage open-source project, not a contractual
> SLA.

## Scope

**In scope:** vulnerabilities in this project's own code: the harness, artifact writers,
validation logic, scanners / detectors, reports, GitHub Actions hardening, dependency
provenance, and unsafe examples.

**Out of scope** (by design; see the threat model):

- Detector **false negatives** (a missed prompt injection, PII token, or leak) are
  tracked as **detection-quality** issues, **unless** they bypass a documented
  deterministic guarantee or cause unsafe gateway behavior, in which case they are
  in-scope security issues. The project does not claim to catch every injection; novel
  evasions are expected.
- Weaknesses in the underlying LLM provider or model.
- Host / OS compromise, or attacks assuming database access.
- Treating the system prompt as a secret store: it is **not** a security boundary.
- Requests to enable live exploitation, credential collection, or unauthorized testing.

## Safe Harbor

We support good-faith security research. If you make a genuine effort to comply with this
policy, avoid privacy violations and service disruption, and give us reasonable time to
respond before disclosure, we will not pursue action against you for that research.
