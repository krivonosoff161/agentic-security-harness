# Contributing

> **Agentic Security Harness.** Thanks for considering a contribution.

This is an early-stage project. The most valuable contributions right now are new
**sanitized defensive test patterns**, target adapters, and honest measurement of detector
quality (including false negatives).

## Getting started

```bash
python -m venv .venv && . .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python -m pytest
python -m ruff check .
python -m mypy src tests
ash validate examples/
```

See [docs/development.md](docs/development.md) for the full layout and extension points.
Project decision gates are in [GOVERNANCE.md](GOVERNANCE.md). Pattern proposals should
use the GitHub "Defensive pattern proposal" template before code is written.

## Ways to contribute

- **Add a sanitized defensive test pattern** via `patterns.py` + `corpus.py` + tests —
  with expected vulnerable behavior + mitigation + OWASP/MITRE mapping. The mock target
  is expected to fail the new pattern, and the protected override is expected to pass it.
  Then regenerate the committed examples and run `ash validate examples/`.
- **Add a target adapter** — LLM agent, MCP / tool chain, multi-agent, voice / multimodal
  (sanitized fixtures), or an AI gateway.
- **Add a trace detector / scanner** — deterministic; returns findings, does not decide.
- **Reference gateway** — provider adapters, policy, and related defense code.
- **Docs** — clarity, accuracy, and removing any overclaiming.

## Ground rules

- **No overclaiming.** This project does risk reduction, not 100% protection. PRs that
  imply guaranteed protection will be revised. Report detector quality honestly,
  including false negatives.
- **The simple path stays simple** — the default must run with zero extra services
  (SQLite, no Redis, no classifier). Heavy dependencies (e.g. Presidio) go behind extras.
- **No secrets in code or config** — provider keys come from env only.
- **No self-learning shortcuts** — rules do not mutate at runtime; feedback labels are
  collected for future, human-reviewed adaptive rules only.
- **Responsible use** — patterns are sanitized and run only against mock / authorized
  targets; no real credentials, no third-party abuse ([policy](SECURITY.md#responsible-use)).
- **Study, don't copy** — you may study and cite other open-source projects, but don't
  copy code blindly; respect licenses, cite sources, implement our own minimal adapters/tests.

## Pull requests

- One logical change per PR; conventional commit style (`feat:`, `fix:`, `docs:`, `test:`).
- Use the pull request template and keep issue templates aligned with the change type.
- Include tests; keep `python -m pytest`, `python -m ruff check .`, and
  `python -m mypy src tests` green.
- Keep the committed examples synchronized — if your change affects output, regenerate
  the examples and confirm `ash validate examples/` passes.
- Update `CHANGELOG.md` under `[Unreleased]`.
- For anything security-sensitive, see [SECURITY.md](SECURITY.md) — do not disclose
  vulnerabilities in a public PR.

## License of contributions

By contributing, you agree your contributions are licensed under the project's
[Apache-2.0](LICENSE) license.
