"""Onboarding diagnostics for `ash doctor`.

Read-only environment checks so a new user can tell whether the toolkit is ready to
run. No network by default; `--live-local` makes exactly one request to a local
endpoint. API key values are never read or printed - only the env-var name and whether
it is set.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

_SUPPORTED_EXTERNAL_ADAPTERS = ["openai-compatible"]
_DEFAULT_KEY_ENV = "ASH_EXTERNAL_API_KEY"
_MIN_PY = (3, 11)


class DoctorCheck(BaseModel):
    """One diagnostic line. ``ok=None`` means informational (not pass/fail)."""

    model_config = ConfigDict(extra="forbid")

    name: str
    ok: bool | None
    detail: str = ""


class DoctorReport(BaseModel):
    """Aggregated diagnostics."""

    model_config = ConfigDict(extra="forbid")

    ok: bool
    checks: list[DoctorCheck] = Field(default_factory=list)
    next_commands: list[str] = Field(default_factory=list)


def _check_python() -> DoctorCheck:
    v = sys.version_info
    ok = (v.major, v.minor) >= _MIN_PY
    return DoctorCheck(
        name="python_version",
        ok=ok,
        detail=f"{v.major}.{v.minor}.{v.micro} (require >= {_MIN_PY[0]}.{_MIN_PY[1]})",
    )


def _check_import() -> DoctorCheck:
    try:
        from agentic_security_harness import __version__

        return DoctorCheck(name="package_import", ok=True, detail=f"version {__version__}")
    except Exception as exc:  # pragma: no cover - defensive
        return DoctorCheck(name="package_import", ok=False, detail=str(exc))


def _check_cli_commands() -> DoctorCheck:
    import argparse

    try:
        from agentic_security_harness.cli import build_parser

        names: list[str] = []
        for action in build_parser()._actions:
            if isinstance(action, argparse._SubParsersAction):
                names = sorted(action.choices)
                break
        return DoctorCheck(name="cli_commands", ok=bool(names), detail=", ".join(names))
    except Exception as exc:  # pragma: no cover - defensive
        return DoctorCheck(name="cli_commands", ok=False, detail=str(exc))


def _check_examples(root: Path) -> DoctorCheck:
    examples = root / "examples"
    if not examples.is_dir():
        return DoctorCheck(
            name="examples_dir",
            ok=False,
            detail="examples/ not found (run ash doctor from the repository root)",
        )
    have = [d.name for d in examples.iterdir() if d.is_dir()]
    return DoctorCheck(
        name="examples_dir", ok=len(have) > 0, detail=f"{len(have)} example dir(s)"
    )


def _check_fake_server(root: Path) -> DoctorCheck:
    path = root / "examples" / "fake_openai_server.py"
    return DoctorCheck(
        name="fake_server",
        ok=path.is_file(),
        detail=(
            "examples/fake_openai_server.py present"
            if path.is_file()
            else "not found (needed for the free local demo)"
        ),
    )


def _check_build_tool() -> DoctorCheck:
    try:
        import build  # noqa: F401

        return DoctorCheck(name="build_tool", ok=None, detail="python -m build available")
    except Exception:
        return DoctorCheck(
            name="build_tool", ok=None, detail="not installed (optional; pip install build)"
        )


def _check_writable(root: Path) -> DoctorCheck:
    try:
        with tempfile.NamedTemporaryFile(dir=root, prefix=".ash_doctor_", delete=True):
            pass
        return DoctorCheck(name="cwd_writable", ok=True, detail=f"{root.as_posix()} writable")
    except OSError as exc:
        return DoctorCheck(name="cwd_writable", ok=False, detail=f"not writable: {exc}")


def _check_credential_env(credential_env_var: str) -> DoctorCheck:
    # Presence only; never read or print the value.
    is_set = bool(os.environ.get(credential_env_var))
    return DoctorCheck(
        name="credential_env_var",
        ok=None,
        detail=(
            f"{credential_env_var}: SET (value hidden)"
            if is_set
            else f"{credential_env_var}: not set (only needed for authenticated endpoints)"
        ),
    )


def _check_external_adapters() -> DoctorCheck:
    return DoctorCheck(
        name="external_adapters",
        ok=None,
        detail=", ".join(_SUPPORTED_EXTERNAL_ADAPTERS) + " (native provider adapters: future)",
    )


def _check_presets() -> DoctorCheck:
    """Validate external presets resolve - no network."""
    try:
        from agentic_security_harness.presets import apply_preset, list_presets

        presets = list_presets()
        for p in presets:
            # Non-template presets must resolve cleanly with no key value involved.
            _url, _key, err = apply_preset(p.name, None, "")
            if err and "placeholder" not in (err or ""):
                return DoctorCheck(
                    name="external_presets", ok=False,
                    detail=f"preset '{p.name}' failed to resolve: {err}",
                )
        names = ", ".join(p.name for p in presets)
        return DoctorCheck(
            name="external_presets", ok=True, detail=f"{len(presets)} presets: {names}"
        )
    except Exception as exc:  # pragma: no cover - defensive
        return DoctorCheck(name="external_presets", ok=False, detail=str(exc))


def _check_reports_writable(reports_root: Path) -> DoctorCheck:
    """Check we can create/write the chosen reports directory (no network)."""
    try:
        reports_root.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            dir=reports_root, prefix=".ash_doctor_", delete=True
        ):
            pass
        return DoctorCheck(
            name="reports_writable", ok=True, detail=f"{reports_root.as_posix()} writable"
        )
    except OSError as exc:
        return DoctorCheck(
            name="reports_writable", ok=False,
            detail=f"{reports_root.as_posix()} not writable: {exc}",
        )


def _check_live_local(base_url: str, credential_env_var: str) -> DoctorCheck:
    from agentic_security_harness.external_openai_compatible import chat_completion

    try:
        resp = chat_completion(
            base_url=base_url,
            model="doctor-probe",
            messages=[{"role": "user", "content": "ping"}],
            timeout_seconds=5,
            credential_env_var=(
                credential_env_var if os.environ.get(credential_env_var) else ""
            ),
        )
        return DoctorCheck(
            name="live_local",
            ok=True,
            detail=f"reached {base_url} (model {resp.get('model', 'unknown')})",
        )
    except Exception as exc:
        return DoctorCheck(name="live_local", ok=False, detail=f"{base_url}: {exc}")


def run_doctor(
    *,
    root: Path | None = None,
    reports_root: Path | None = None,
    live_local: bool = False,
    base_url: str = "http://127.0.0.1:8766/v1",
    credential_env_var: str = _DEFAULT_KEY_ENV,
    api_key_env: str | None = None,
) -> DoctorReport:
    """Run all diagnostics. Network is only touched when ``live_local`` is true."""
    if api_key_env is not None:
        credential_env_var = api_key_env
    root = root or Path.cwd()
    reports_root = reports_root or (root / "reports")
    checks = [
        _check_python(),
        _check_import(),
        _check_cli_commands(),
        _check_examples(root),
        _check_fake_server(root),
        _check_writable(root),
        _check_reports_writable(reports_root),
        _check_build_tool(),
        _check_credential_env(credential_env_var),
        _check_external_adapters(),
        _check_presets(),
    ]
    if live_local:
        checks.append(_check_live_local(base_url, credential_env_var))

    blocking = [c for c in checks if c.ok is False]
    ok = not blocking
    next_commands = [
        "ash targets",
        "ash run --target demo-agent --out reports/demo",
        "ash report --root reports/demo",
        "python examples/fake_openai_server.py   # free local model demo",
        "ash external-check --base-url http://127.0.0.1:8766/v1 --model fake-model",
    ]
    return DoctorReport(ok=ok, checks=checks, next_commands=next_commands)
