import subprocess
from pathlib import Path

from agentic_security_harness.validation import _SECRET_PATTERNS

_RAW_RESPONSE_ALLOWLIST_PREFIXES = ("examples/external-demo-report/raw_responses/",)


def test_private_research_paths_are_not_tracked() -> None:
    result = subprocess.run(
        ["git", "ls-files"],
        check=True,
        capture_output=True,
        text=True,
    )
    tracked = {line.strip().replace("\\", "/") for line in result.stdout.splitlines()}

    assert not any(path.startswith(".internal/") for path in tracked)
    assert not any(path.startswith("reports/") for path in tracked)

    raw_paths = {path for path in tracked if "/raw_" in path or path.endswith("_private.json")}
    assert all(
        any(path.startswith(prefix) for prefix in _RAW_RESPONSE_ALLOWLIST_PREFIXES)
        for path in raw_paths
    )


def test_tracked_public_artifacts_do_not_contain_secret_shaped_tokens() -> None:
    result = subprocess.run(
        ["git", "ls-files"],
        check=True,
        capture_output=True,
        text=True,
    )
    tracked = [Path(line.strip()) for line in result.stdout.splitlines() if line.strip()]

    offenders: list[str] = []
    for path in tracked:
        if not (
            path.as_posix().startswith("examples/")
            or path.as_posix().startswith("docs/")
            or path.name in {"README.md", "SECURITY.md", "CONTRIBUTING.md"}
        ):
            continue
        if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".ico"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for name, pattern in _SECRET_PATTERNS:
            if pattern.search(text):
                offenders.append(f"{path.as_posix()}:{name}")
                break

    assert offenders == []
