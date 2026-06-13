"""Tests for the external model/runtime adapter path."""

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agentic_security_harness.external_openai_compatible import (
    ExternalAPIError,
    _get_api_key,
    chat_completion,
    extract_content,
)
from agentic_security_harness.external_prompt import render_pattern_prompt
from agentic_security_harness.external_runner import (
    _classify_outcome,
    _parse_decision,
    _result_id,
    run_external,
)
from agentic_security_harness.models import DataEnvelope, DefensivePattern
from agentic_security_harness.run_config import (
    RunConfig,
    _redact_url,
)

# --- run_config tests ---


def test_redact_url_no_credentials() -> None:
    assert _redact_url("http://localhost:8000/v1") == "http://localhost:8000/v1"


def test_redact_url_with_credentials() -> None:
    url = "http://user:secret@localhost:8000/v1"
    result = _redact_url(url)
    assert "secret" not in result
    assert "[REDACTED]" in result
    assert "localhost:8000/v1" in result


def test_redact_url_bearer_token_style() -> None:
    url = "http://token:abc123@myhost.com/v1"
    result = _redact_url(url)
    assert "abc123" not in result
    assert "[REDACTED]" in result


def test_run_config_never_stores_api_key() -> None:
    config = RunConfig(
        api_key_env="MY_API_KEY",
        model="test-model",
    )
    dump = config.model_dump(mode="json")
    assert "MY_API_KEY" in dump["api_key_env"]
    # Key value should never appear
    assert "secret" not in json.dumps(dump).lower()


def test_run_config_safety_note() -> None:
    config = RunConfig()
    assert "experimental" in config.safety_note.lower()


# --- external_openai_compatible tests ---


def test_get_api_key_missing_env() -> None:
    with pytest.raises(ExternalAPIError, match="not set"):
        _get_api_key("ASH_NONEXISTENT_KEY_FOR_TEST")


def test_get_api_key_empty_name() -> None:
    assert _get_api_key("") is None


def test_get_api_key_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ASH_TEST_KEY", "test_value_123")
    assert _get_api_key("ASH_TEST_KEY") == "test_value_123"


def test_extract_content_valid() -> None:
    resp = {"choices": [{"message": {"content": "hello"}}]}
    assert extract_content(resp) == "hello"


def test_extract_content_empty() -> None:
    assert extract_content({}) == ""
    assert extract_content({"choices": []}) == ""


def test_chat_completion_sends_correct_body() -> None:
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps({
        "choices": [{"message": {"content": "test"}}]
    }).encode()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_response) as mock_open:
        result = chat_completion(
            base_url="http://localhost:8000/v1",
            model="test-model",
            messages=[{"role": "user", "content": "hi"}],
            temperature=0.5,
        )
        assert result["choices"][0]["message"]["content"] == "test"
        # Verify the request was made
        mock_open.assert_called_once()
        req = mock_open.call_args[0][0]
        assert req.full_url == "http://localhost:8000/v1/chat/completions"
        body = json.loads(req.data)
        assert body["model"] == "test-model"
        assert body["temperature"] == 0.5


def test_chat_completion_sends_api_key() -> None:
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps({
        "choices": [{"message": {"content": "ok"}}]
    }).encode()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)

    with patch.dict(os.environ, {"ASH_TEST_KEY": "sk-test123"}):
        with patch("urllib.request.urlopen", return_value=mock_response) as mock_open:
            chat_completion(
                base_url="http://localhost:8000/v1",
                model="m",
                messages=[],
                api_key_env="ASH_TEST_KEY",
            )
            req = mock_open.call_args[0][0]
            assert req.get_header("Authorization") == "Bearer sk-test123"


def test_chat_completion_handles_http_error() -> None:
    import urllib.error

    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("network error")):
        with pytest.raises(ExternalAPIError):
            chat_completion(
                base_url="http://localhost:8000/v1",
                model="m",
                messages=[],
            )


# --- external_prompt tests ---


def test_render_pattern_prompt_no_secrets() -> None:
    pattern = DefensivePattern(
        pattern_id="test_pattern",
        name="Test",
        category="test",
        description="A test pattern",
        graph_path=["a", "b"],
        expected_vulnerable_behavior="agent does X",
        mitigation="do Y",
    )
    messages = render_pattern_prompt(pattern)
    assert len(messages) == 2
    assert messages[0]["role"] == "system"
    assert messages[1]["role"] == "user"
    # Should contain pattern info
    assert "test_pattern" in messages[1]["content"]
    # Should not contain real secrets
    for msg in messages:
        assert "sk-" not in msg["content"]
        assert "AKIA" not in msg["content"]


def test_render_pattern_prompt_with_envelope() -> None:
    pattern = DefensivePattern(
        pattern_id="test_pattern",
        name="Test",
        category="test",
        description="A test pattern",
        graph_path=["a", "b"],
        expected_vulnerable_behavior="agent does X",
        mitigation="do Y",
        data_envelope=DataEnvelope(
            data_class="confidential",
            allowed_recipients=["agent_a"],
        ),
    )
    messages = render_pattern_prompt(pattern)
    content = messages[1]["content"]
    assert "confidential" in content
    assert "agent_a" in content


def test_render_pattern_prompt_with_knobs() -> None:
    pattern = DefensivePattern(
        pattern_id="test",
        name="Test",
        category="test",
        description="desc",
        graph_path=["a"],
        expected_vulnerable_behavior="X",
        mitigation="Y",
    )
    messages = render_pattern_prompt(pattern, {"memory_mode": "session"})
    assert "memory_mode" in messages[1]["content"]


# --- external_runner tests ---


def test_result_id_deterministic() -> None:
    a = _result_id("pat1", "var1", 0)
    b = _result_id("pat1", "var1", 0)
    assert a == b
    assert a.startswith("ext_")


def test_result_id_unique_per_repeat() -> None:
    a = _result_id("pat1", "var1", 0)
    b = _result_id("pat1", "var1", 1)
    assert a != b


def test_parse_decision_valid_json() -> None:
    raw = '{"decision": "block", "reason": "ok", "would_preserve_boundary": true}'
    parsed = _parse_decision(raw)
    assert parsed["decision"] == "block"
    assert parsed["would_preserve_boundary"] is True


def test_parse_decision_invalid_json() -> None:
    assert _parse_decision("not json") == {}
    assert _parse_decision("") == {}


def test_parse_decision_markdown_code_block() -> None:
    raw = '```json\n{"decision": "allow", "would_preserve_boundary": false}\n```'
    parsed = _parse_decision(raw)
    assert parsed["decision"] == "allow"


def test_classify_outcome_pass() -> None:
    parsed = {"decision": "block", "would_preserve_boundary": True}
    outcome, _ = _classify_outcome(parsed)
    assert outcome == "pass"


def test_classify_outcome_finding() -> None:
    parsed = {"decision": "allow", "would_preserve_boundary": False}
    outcome, _ = _classify_outcome(parsed)
    assert outcome == "finding"


def test_classify_outcome_inconclusive_empty() -> None:
    outcome, _ = _classify_outcome({})
    assert outcome == "inconclusive"


def test_classify_outcome_inconclusive_unclear() -> None:
    parsed = {"decision": "unclear"}
    outcome, _ = _classify_outcome(parsed)
    assert outcome == "inconclusive"


def test_run_external_dry_run(tmp_path: Path) -> None:
    summary = run_external(
        base_url="http://localhost:8000/v1",
        model="test",
        scenario_id="data-boundary",
        out_dir=tmp_path / "ext",
        dry_run=True,
    )
    assert summary.total_checks == 4
    assert summary.total_repeats == 1
    # Dry run should not create output dir
    assert not (tmp_path / "ext").exists()


def test_run_external_dry_run_with_repeats(tmp_path: Path) -> None:
    summary = run_external(
        base_url="http://localhost:8000/v1",
        model="test",
        scenario_id="data-boundary",
        out_dir=tmp_path / "ext",
        repeats=3,
        max_variants=2,
        dry_run=True,
    )
    assert summary.total_checks == 4 * 2  # 4 patterns x 2 variants
    assert summary.total_repeats == 3


def test_run_external_mock_endpoint(tmp_path: Path) -> None:
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps({
        "choices": [{"message": {"content":
            '{"decision": "block", "reason": "boundary preserved", '
            '"would_preserve_boundary": true}'
        }}]
    }).encode()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_response):
        summary = run_external(
            base_url="http://localhost:8000/v1",
            model="test",
            scenario_id="data-boundary",
            out_dir=tmp_path / "ext",
            repeats=1,
            max_variants=1,
        )

    assert summary.total_checks == 4
    assert len(summary.patterns_with_findings) == 0
    assert (tmp_path / "ext" / "run_config.json").exists()
    assert (tmp_path / "ext" / "external_results.json").exists()
    assert (tmp_path / "ext" / "external_summary.json").exists()
    assert (tmp_path / "ext" / "external_report.md").exists()


def test_run_external_finding_result(tmp_path: Path) -> None:
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps({
        "choices": [{"message": {"content":
            '{"decision": "allow", "reason": "ignored", '
            '"would_preserve_boundary": false}'
        }}]
    }).encode()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_response):
        summary = run_external(
            base_url="http://localhost:8000/v1",
            model="test",
            scenario_id="data-boundary",
            out_dir=tmp_path / "ext",
            repeats=1,
        )

    assert len(summary.patterns_with_findings) == 4


def test_run_external_api_error(tmp_path: Path) -> None:
    with patch("urllib.request.urlopen", side_effect=ExternalAPIError("timeout")):
        summary = run_external(
            base_url="http://localhost:8000/v1",
            model="test",
            scenario_id="data-boundary",
            out_dir=tmp_path / "ext",
            repeats=1,
        )

    assert len(summary.error_patterns) == 4


def test_run_external_flaky_detection(tmp_path: Path) -> None:
    """Test flaky detection: same pattern returns different outcomes across repeats."""
    call_count = 0

    def _mock_open(*args, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal call_count
        call_count += 1
        resp = MagicMock()
        if call_count % 2 == 1:
            content = '{"decision": "block", "would_preserve_boundary": true}'
        else:
            content = '{"decision": "allow", "would_preserve_boundary": false}'
        resp.read.return_value = json.dumps({
            "choices": [{"message": {"content": content}}]
        }).encode()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    with patch("urllib.request.urlopen", side_effect=_mock_open):
        summary = run_external(
            base_url="http://localhost:8000/v1",
            model="test",
            scenario_id="perception-boundary",  # 1 pattern
            out_dir=tmp_path / "ext",
            repeats=2,
        )

    assert len(summary.flaky_patterns) > 0


# --- CLI dry-run test ---


def test_cli_dry_run_no_network() -> None:
    from agentic_security_harness import cli

    with patch("urllib.request.urlopen") as mock_open:
        rc = cli.main([
            "run-external",
            "--adapter", "openai-compatible",
            "--base-url", "http://localhost:8000/v1",
            "--model", "test",
            "--scenario", "data-boundary",
            "--dry-run",
        ])
        assert rc == 0
        mock_open.assert_not_called()


def test_cli_run_external_missing_base_url() -> None:
    from agentic_security_harness import cli

    with pytest.raises(SystemExit):
        cli.main(["run-external", "--model", "test"])


def test_cli_run_external_repeats_too_high() -> None:
    from agentic_security_harness import cli

    rc = cli.main([
        "run-external",
        "--adapter", "openai-compatible",
        "--base-url", "http://localhost:8000/v1",
        "--model", "test",
        "--scenario", "data-boundary",
        "--repeats", "99",
        "--dry-run",
    ])
    assert rc == 1


def test_cli_run_external_unsupported_adapter() -> None:
    from agentic_security_harness import cli

    rc = cli.main([
        "run-external",
        "--adapter", "unsupported",
        "--base-url", "http://localhost:8000/v1",
        "--model", "test",
        "--scenario", "data-boundary",
        "--dry-run",
    ])
    assert rc == 1


# --- Regression tests ---


def test_builtin_ash_run_still_works(tmp_path: Path) -> None:
    from agentic_security_harness import cli

    rc = cli.main(["run", "--target", "mock", "--out", str(tmp_path / "run")])
    assert rc == 0
    assert (tmp_path / "run" / "traces.json").exists()


def test_builtin_ash_compare_still_works(tmp_path: Path) -> None:
    from agentic_security_harness import cli

    rc = cli.main([
        "compare",
        "--baseline", "demo-agent",
        "--protected", "protected-demo-agent",
        "--out", str(tmp_path / "cmp"),
    ])
    assert rc == 0
    assert (tmp_path / "cmp" / "comparison.md").exists()
