"""Verify exact Gitleaks suppressions without exposing matched bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


class RegressionError(RuntimeError):
    """A secret-scanner regression described without scanner output."""


def _run(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _redacted_report(result: subprocess.CompletedProcess[str]) -> list[dict[str, Any]]:
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RegressionError("Gitleaks did not return a JSON report") from exc
    if not isinstance(payload, list) or not all(isinstance(item, dict) for item in payload):
        raise RegressionError("Gitleaks returned an unexpected report shape")
    if any(item.get("Secret") not in (None, "REDACTED") for item in payload):
        raise RegressionError("Gitleaks report was not fully redacted")
    return payload


def _scan_command(gitleaks: str, target: Path) -> list[str]:
    return [
        gitleaks,
        "git",
        "--no-banner",
        "--no-color",
        "--redact=100",
        "--log-level",
        "error",
        "--report-format",
        "json",
        "--report-path",
        "-",
        str(target),
    ]


def _verify_repository_history(gitleaks: str) -> None:
    result = _run(_scan_command(gitleaks, ROOT), cwd=ROOT)
    report = _redacted_report(result)
    if result.returncode != 0 or report:
        raise RegressionError(
            "repository history contains an unsuppressed finding "
            f"(exit={result.returncode}, count={len(report)})"
        )


def _verify_fresh_synthetic_finding(gitleaks: str) -> None:
    with tempfile.TemporaryDirectory(prefix="ash-gitleaks-regression-") as raw_dir:
        repo = Path(raw_dir)
        shutil.copyfile(ROOT / ".gitleaksignore", repo / ".gitleaksignore")
        for command in (
            ["git", "init", "--quiet"],
            ["git", "config", "user.email", "synthetic@example.invalid"],
            ["git", "config", "user.name", "Synthetic Gitleaks Regression"],
        ):
            result = _run(command, cwd=repo)
            if result.returncode != 0:
                raise RegressionError("could not initialize synthetic Git fixture")

        field_name = "_".join(("api", "key"))
        synthetic_value = hashlib.sha256(
            b"agentic-security-harness-gitleaks-negative-control-v1"
        ).hexdigest()
        fixture_name = "fresh-synthetic-fixture.txt"
        (repo / fixture_name).write_text(
            f'{field_name} = "{synthetic_value}"\n',
            encoding="utf-8",
        )
        for command in (
            ["git", "add", ".gitleaksignore", fixture_name],
            ["git", "commit", "--quiet", "-m", "synthetic negative control"],
        ):
            result = _run(command, cwd=repo)
            if result.returncode != 0:
                raise RegressionError("could not commit synthetic Git fixture")

        command = _scan_command(gitleaks, repo)
        command[2:2] = ["--enable-rule", "generic-api-key"]
        result = _run(command, cwd=repo)
        report = _redacted_report(result)
        if result.returncode != 1 or len(report) != 1:
            raise RegressionError(
                "fresh synthetic secret shape was not detected exactly once "
                f"(exit={result.returncode}, count={len(report)})"
            )
        finding = report[0]
        if (
            finding.get("RuleID") != "generic-api-key"
            or finding.get("File") != fixture_name
            or finding.get("StartLine") != 1
            or finding.get("Secret") != "REDACTED"
        ):
            raise RegressionError("fresh synthetic finding metadata was unexpected")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gitleaks", default=shutil.which("gitleaks"))
    args = parser.parse_args()
    if not args.gitleaks:
        raise RegressionError("Gitleaks executable was not supplied or found")
    _verify_repository_history(args.gitleaks)
    _verify_fresh_synthetic_finding(args.gitleaks)
    print("Gitleaks occurrence-level regression: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
