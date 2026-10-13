"""The offline checker's stdlib bootstrap must not permit process or network effects."""

from typing import Any

import pytest
from tools import check_pydantic_ai_guarded_files as checker


def test_platform_probe_denied_before_strict_third_party_phase(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hooks: list[Any] = []
    monkeypatch.setattr(checker.sys, "addaudithook", hooks.append)

    def probe() -> str:
        with pytest.raises(PermissionError, match="subprocess probe denied"):
            hooks[0]("subprocess.Popen", ())
        return "Windows"

    monkeypatch.setattr(checker.platform, "system", probe)
    bootstrap, blocked = checker.install_audit_gate()
    assert bootstrap == ["subprocess.Popen"]
    assert blocked == []
    for event in ("subprocess.Popen", "socket.connect", "os.system"):
        with pytest.raises(RuntimeError, match="audit denied"):
            hooks[0](event, ())
    assert blocked == ["subprocess.Popen", "socket.connect", "os.system"]
    assert bootstrap == ["subprocess.Popen"]


def test_platform_bootstrap_never_allows_network(monkeypatch: pytest.MonkeyPatch) -> None:
    hooks: list[Any] = []
    monkeypatch.setattr(checker.sys, "addaudithook", hooks.append)
    monkeypatch.setattr(checker.platform, "system", lambda: hooks[0]("socket.connect", ()))
    with pytest.raises(RuntimeError, match="audit denied: socket.connect"):
        checker.install_audit_gate()
    # Even a failed bootstrap must leave process denial in the strict phase.
    with pytest.raises(RuntimeError, match="audit denied: subprocess.Popen"):
        hooks[0]("subprocess.Popen", ())
