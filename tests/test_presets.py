"""Tests for the external connection presets."""

from unittest.mock import patch

import pytest

from agentic_security_harness import cli
from agentic_security_harness.presets import (
    apply_preset,
    infer_runtime_profile,
    list_presets,
    preset_names,
    resolve_preset,
)


def test_presets_registered() -> None:
    names = preset_names()
    for expected in (
        "fake-local", "vllm", "ollama", "lm-studio", "deepseek",
        "alibaba-qwen-compatible", "generic-openai-compatible",
    ):
        assert expected in names


def test_presets_carry_no_key_values() -> None:
    for p in list_presets():
        # default_key_env is a NAME, never a value.
        assert "sk-" not in p.default_key_env
        assert p.default_key_env in ("", "ASH_EXTERNAL_API_KEY")


def test_apply_preset_fills_base_url() -> None:
    url, key_env, err = apply_preset("ollama", None, "")
    assert err is None
    assert url == "http://localhost:11434/v1"
    assert key_env == ""


def test_infer_runtime_profile_local_presets() -> None:
    for preset in ("ollama", "lm-studio", "vllm"):
        profile = infer_runtime_profile(preset, "http://localhost:1/v1")
        assert profile.runtime_name == preset
        assert profile.runtime_family == "local-runtime"
        assert profile.network_mode == "local-only"
        assert profile.authorization_mode == "local_runtime"
        assert profile.local_only is True
        assert profile.recovery_guidance


def test_infer_runtime_profile_localhost_without_preset() -> None:
    profile = infer_runtime_profile(None, "http://127.0.0.1:8000/v1")
    assert profile.runtime_name == "local-openai-compatible"
    assert profile.network_mode == "local-only"
    assert profile.authorization_mode == "local_runtime"


def test_infer_runtime_profile_remote_without_preset() -> None:
    profile = infer_runtime_profile(None, "https://example.invalid/v1")
    assert profile.runtime_name == "generic-openai-compatible"
    assert profile.network_mode == "authorized-external"
    assert profile.local_only is False


def test_apply_preset_explicit_base_url_wins() -> None:
    url, _key, err = apply_preset("ollama", "http://other:9/v1", "")
    assert err is None and url == "http://other:9/v1"


def test_apply_preset_fills_default_key_env_when_needed() -> None:
    _url, key_env, err = apply_preset("deepseek", None, "")
    assert err is None
    assert key_env == "ASH_EXTERNAL_API_KEY"


def test_apply_preset_template_requires_base_url() -> None:
    _url, _key, err = apply_preset("generic-openai-compatible", None, "")
    assert err is not None and "placeholder" in err


def test_apply_preset_none_requires_base_url() -> None:
    _url, _key, err = apply_preset(None, None, "")
    assert err is not None and "--base-url or --preset" in err


def test_resolve_unknown_preset_raises() -> None:
    with pytest.raises(KeyError, match="unknown preset"):
        resolve_preset("does-not-exist")


def test_cli_external_presets_lists(capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(["external-presets"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "ollama" in out and "deepseek" in out
    assert "network is still opt-in" in out


def test_cli_external_check_preset_no_network(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with patch("urllib.request.urlopen") as mock_open:
        rc = cli.main([
            "external-check", "--preset", "ollama", "--model", "llama3.1",
            "--scenario", "data-boundary",
        ])
        assert rc == 0
        mock_open.assert_not_called()
    assert "Using preset 'ollama'" in capsys.readouterr().out


def test_cli_run_external_preset_dry_run_no_network() -> None:
    with patch("urllib.request.urlopen") as mock_open:
        rc = cli.main([
            "run-external", "--preset", "fake-local", "--model", "fake-model",
            "--scenario", "data-boundary", "--dry-run",
        ])
        assert rc == 0
        mock_open.assert_not_called()


def test_cli_generic_preset_requires_base_url() -> None:
    rc = cli.main([
        "external-check", "--preset", "generic-openai-compatible", "--model", "m",
        "--scenario", "data-boundary",
    ])
    assert rc == 1
