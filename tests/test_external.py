"""Tests for the external model/runtime adapter path."""

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from collections.abc import Callable
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agentic_security_harness.external_openai_compatible import (
    ExternalAPIError,
    _get_api_key,
    _NoRedirectHandler,
    chat_completion,
    extract_content,
    extract_verified_content,
)
from agentic_security_harness.external_prompt import render_pattern_prompt
from agentic_security_harness.external_runner import (
    _classify_outcome,
    _parse_decision,
    _recovery_hint_for_error,
    _recovery_hint_for_verdict,
    _result_id,
    run_external,
)
from agentic_security_harness.external_validation import validate_external_verdict
from agentic_security_harness.models import DataEnvelope, DefensivePattern
from agentic_security_harness.patterns import seed_patterns
from agentic_security_harness.remediation import _FAMILY_MAP
from agentic_security_harness.run_config import (
    RunConfig,
    _redact_url,
)
from agentic_security_harness.validation import validate_path


def _pattern_id_from_request(req: object) -> str:
    body = json.loads(req.data.decode("utf-8"))  # type: ignore[attr-defined]
    for message in body.get("messages", []):
        for line in str(message.get("content", "")).splitlines():
            if line.startswith("Pattern: "):
                return line.split("Pattern: ", 1)[1].strip()
    return "unknown"


def _mock_chat_open(
    *,
    decision: str = "block",
    boundary_assertion: str = "preserve_boundary",
    would_preserve_boundary: bool = True,
    reason: str = "boundary preserved",
) -> Callable[..., MagicMock]:
    def _open(req: object, *args: object, **kwargs: object) -> MagicMock:
        pattern_id = _pattern_id_from_request(req)
        request_data = req.data  # type: ignore[attr-defined]
        requested_model = json.loads(request_data.decode("utf-8"))["model"]
        resp = MagicMock()
        content = json.dumps(
            {
                "pattern_id": pattern_id,
                "decision": decision,
                "boundary_assertion": boundary_assertion,
                "reason": reason,
                "control_family": _FAMILY_MAP.get(pattern_id, "data_boundary"),
                "would_preserve_boundary": would_preserve_boundary,
            }
        )
        resp.read.return_value = json.dumps(
            {
                "model": requested_model,
                "choices": [{"message": {"content": content}}],
            }
        ).encode()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    return _open


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


def test_run_config_never_stores_credential_value() -> None:
    config = RunConfig(
        credential_env_var="MY_CREDENTIAL_ENV",
        model="test-model",
    )
    dump = config.model_dump(mode="json")
    assert dump["credential_env_var"] == "[CREDENTIAL_ENV_VAR_CONFIGURED]"
    assert "api_key_env" not in dump
    # Credential value should never appear
    assert "secret" not in json.dumps(dump).lower()


def test_run_config_accepts_legacy_api_key_env_field() -> None:
    config = RunConfig.model_validate(
        {
            "api_key_env": "ASH_EXTERNAL_API_KEY",
            "model": "test-model",
        }
    )
    assert config.credential_env_var == "[CREDENTIAL_ENV_VAR_CONFIGURED]"


def test_run_config_safety_note() -> None:
    config = RunConfig()
    assert "experimental" in config.safety_note.lower()
    assert config.runtime.prompt_only is True
    assert config.runtime.tool_execution is False


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


def test_extract_verified_content_requires_exact_model_and_nonblank_text() -> None:
    response = {
        "model": "expected",
        "choices": [{"message": {"content": " usable "}}],
    }
    assert extract_verified_content(response, expected_model="expected") == " usable "


@pytest.mark.parametrize(
    "response,error",
    [
        ({"choices": [{"message": {"content": "answer"}}]}, "identity mismatch"),
        (
            {"model": "wrong", "choices": [{"message": {"content": "answer"}}]},
            "identity mismatch",
        ),
        ({"model": "expected", "choices": [{"message": {"content": "   "}}]}, "blank"),
        ({"model": "expected", "choices": []}, "blank"),
        ([], "JSON object"),
    ],
)
def test_extract_verified_content_fails_closed(
    response: object,
    error: str,
) -> None:
    with pytest.raises(ExternalAPIError, match=error):
        extract_verified_content(response, expected_model="expected")


def test_chat_completion_sends_correct_body() -> None:
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(
        {"choices": [{"message": {"content": "test"}}]}
    ).encode()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)

    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect",
        return_value=mock_response,
    ) as mock_open:
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


def test_chat_completion_refuses_redirects_by_default_before_second_hop() -> None:
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(
        {"choices": [{"message": {"content": "test"}}]}
    ).encode()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)
    opener = MagicMock()
    opener.open.return_value = mock_response

    with patch("urllib.request.build_opener", return_value=opener) as build_opener:
        result = chat_completion(
            base_url="http://127.0.0.1:8000/v1",
            model="test-model",
            messages=[{"role": "user", "content": "hi"}],
        )

    assert result["choices"][0]["message"]["content"] == "test"
    build_opener.assert_called_once()
    handlers = build_opener.call_args.args
    assert any(isinstance(handler, _NoRedirectHandler) for handler in handlers)
    proxy = next(
        handler for handler in handlers if isinstance(handler, urllib.request.ProxyHandler)
    )
    assert vars(proxy)["proxies"] == {}
    opener.open.assert_called_once()


def test_chat_completion_rejects_non_http_route_before_open() -> None:
    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect"
    ) as mock_open:
        with pytest.raises(ValueError, match="scheme must be http or https"):
            chat_completion(
                base_url="file://localhost/private",
                model="test-model",
                messages=[],
            )
    mock_open.assert_not_called()


def test_chat_completion_sends_api_key() -> None:
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(
        {"choices": [{"message": {"content": "ok"}}]}
    ).encode()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)

    with patch.dict(os.environ, {"ASH_TEST_KEY": "sk-test123"}):
        with patch(
            "agentic_security_harness.external_openai_compatible.urlopen_no_redirect",
            return_value=mock_response,
        ) as mock_open:
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

    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect",
        side_effect=urllib.error.URLError("network error"),
    ):
        with pytest.raises(ExternalAPIError):
            chat_completion(
                base_url="http://localhost:8000/v1",
                model="m",
                messages=[],
            )


def test_chat_completion_retries_transient_network_error() -> None:
    import urllib.error

    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(
        {"choices": [{"message": {"content": "ok"}}]}
    ).encode()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)

    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect",
        side_effect=[urllib.error.URLError("temporary"), mock_response],
    ) as mock_open:
        result = chat_completion(
            base_url="http://localhost:8000/v1",
            model="m",
            messages=[],
            max_retries=1,
        )

    assert result["choices"][0]["message"]["content"] == "ok"
    assert mock_open.call_count == 2


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


def test_parse_decision_rejects_non_object_json() -> None:
    assert _parse_decision("2") == {}
    assert _parse_decision("[1, 2, 3]") == {}
    assert _parse_decision('"decision"') == {}


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


def test_run_external_dry_run(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    summary = run_external(
        base_url="http://localhost:8000/v1",
        model="test\n[OK] forged\x1b[31m\u202e",
        scenario_id="data-boundary",
        out_dir=tmp_path / ".internal" / "ext",
        dry_run=True,
    )
    assert summary.total_checks == 6
    assert summary.total_repeats == 1
    output = capsys.readouterr().out
    assert "\n[OK] forged" not in output
    assert "\x1b" not in output
    assert "\u202e" not in output
    assert r"\n[OK] forged\x1b[31m\u202e" in output
    # Dry run should not create output dir
    assert not (tmp_path / ".internal" / "ext").exists()


def test_run_external_dry_run_with_repeats(tmp_path: Path) -> None:
    summary = run_external(
        base_url="http://localhost:8000/v1",
        model="test",
        scenario_id="data-boundary",
        out_dir=tmp_path / ".internal" / "ext",
        repeats=3,
        max_variants=2,
        dry_run=True,
    )
    assert summary.total_checks == 6 * 2  # 6 patterns x 2 variants
    assert summary.total_repeats == 3


def test_run_external_refuses_public_live_output_before_network(tmp_path: Path) -> None:
    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect"
    ) as mock_open:
        with pytest.raises(ValueError, match=r"under \.internal"):
            run_external(
                base_url="http://localhost:8000/v1",
                model="test",
                scenario_id="data-boundary",
                out_dir=tmp_path / "public-external",
            )

    mock_open.assert_not_called()
    assert not (tmp_path / "public-external").exists()


def test_run_external_mock_endpoint(tmp_path: Path) -> None:
    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect",
        side_effect=_mock_chat_open(),
    ):
        summary = run_external(
            base_url="http://localhost:8000/v1",
            model="test",
            scenario_id="data-boundary",
            out_dir=tmp_path / ".internal" / "ext",
            repeats=1,
            max_variants=1,
        )

    assert summary.total_checks == 6
    assert len(summary.patterns_with_findings) == 0
    assert (tmp_path / ".internal" / "ext" / "run_config.json").exists()
    assert (tmp_path / ".internal" / "ext" / "external_results.json").exists()
    assert (tmp_path / ".internal" / "ext" / "external_summary.json").exists()
    assert (tmp_path / ".internal" / "ext" / "external_report.md").exists()
    assert (tmp_path / ".internal" / "ext" / "run_index.json").exists()
    results = json.loads((tmp_path / ".internal" / "ext" / "external_results.json").read_text())
    config = json.loads((tmp_path / ".internal" / "ext" / "run_config.json").read_text())
    summary_data = json.loads(
        (tmp_path / ".internal" / "ext" / "external_summary.json").read_text()
    )
    manifest = json.loads((tmp_path / ".internal" / "ext" / "run_index.json").read_text())
    execution_id = config["execution_id"]
    assert execution_id.startswith("run_")
    assert len(execution_id) == 36
    assert config["runtime"]["execution_id"] == execution_id
    assert config["runtime"]["run_id"] == execution_id
    assert summary_data["execution_id"] == execution_id
    assert manifest["execution_id"] == execution_id
    assert manifest["run_id"] == execution_id
    assert all(item["execution_id"] == execution_id for item in results)
    assert config["runtime"]["runtime_name"] == "local-openai-compatible"
    assert config["runtime"]["network_mode"] == "local-only"
    assert config["runtime"]["prompt_only"] is True
    assert config["runtime"]["tool_execution"] is False
    assert config["runtime"]["model_id"] == "test"
    assert config["network_mode"] == "local-only"
    raw_path = tmp_path / ".internal" / "ext" / results[0]["raw_response_path"]
    assert raw_path.exists()
    assert results[0]["raw_response_sha256"]
    assert results[0]["assertion_result"] == "pass"
    assert "recovery_hint" in results[0]
    assert validate_path(tmp_path / ".internal" / "ext").ok


def test_current_external_validation_rejects_missing_manifest(tmp_path: Path) -> None:
    out = tmp_path / ".internal" / "ext"
    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect",
        side_effect=_mock_chat_open(),
    ):
        run_external(
            base_url="http://localhost:8000/v1",
            model="test",
            scenario_id="perception-boundary",
            out_dir=out,
        )
    (out / "run_index.json").unlink()

    result = validate_path(out)

    assert not result.ok
    assert any("missing for current external bundle" in item for item in result.errors)


def test_current_external_validation_rejects_execution_identity_mismatch(
    tmp_path: Path,
) -> None:
    out = tmp_path / ".internal" / "ext"
    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect",
        side_effect=_mock_chat_open(),
    ):
        run_external(
            base_url="http://localhost:8000/v1",
            model="test",
            scenario_id="perception-boundary",
            out_dir=out,
        )
    summary_path = out / "external_summary.json"
    summary_data = json.loads(summary_path.read_text(encoding="utf-8"))
    summary_data["execution_id"] = "run_" + ("0" * 32)
    summary_path.write_text(json.dumps(summary_data, indent=2) + "\n", encoding="utf-8")

    result = validate_path(out)

    assert not result.ok
    assert any("execution_id does not match run_config" in item for item in result.errors)


def test_run_external_finding_result(tmp_path: Path) -> None:
    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect",
        side_effect=_mock_chat_open(
            decision="allow",
            boundary_assertion="vulnerable_behavior",
            would_preserve_boundary=False,
            reason="vulnerable behavior allowed",
        ),
    ):
        summary = run_external(
            base_url="http://localhost:8000/v1",
            model="test",
            scenario_id="data-boundary",
            out_dir=tmp_path / ".internal" / "ext",
            repeats=1,
        )

    assert len(summary.patterns_with_findings) == 6


def test_classify_outcome_allow_but_preserve_is_inconclusive() -> None:
    # Contradictory model self-report is weak evidence and must not become PASS.
    parsed = {"decision": "allow", "would_preserve_boundary": True}
    outcome, _ = _classify_outcome(parsed)
    assert outcome == "inconclusive"


def test_pattern_level_validator_requires_pattern_id() -> None:
    pattern = seed_patterns()[0]
    verdict = validate_external_verdict(
        pattern,
        {
            "decision": "block",
            "boundary_assertion": "preserve_boundary",
            "would_preserve_boundary": True,
        },
    )
    assert verdict.outcome == "inconclusive"
    assert verdict.assertion_result == "pattern_id_mismatch"


def test_pattern_level_validator_pass() -> None:
    pattern = seed_patterns()[0]
    verdict = validate_external_verdict(
        pattern,
        {
            "pattern_id": pattern.pattern_id,
            "decision": "block",
            "boundary_assertion": "preserve_boundary",
            "control_family": _FAMILY_MAP[pattern.pattern_id],
            "would_preserve_boundary": True,
        },
    )
    assert verdict.outcome == "pass"
    assert verdict.assertion_result == "pass"


def test_run_external_writes_request_count(tmp_path: Path) -> None:
    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect",
        side_effect=_mock_chat_open(),
    ):
        run_external(
            base_url="http://localhost:8000/v1",
            model="test",
            scenario_id="data-boundary",
            out_dir=tmp_path / ".internal" / "ext",
            repeats=1,
            max_variants=1,
        )

    config = json.loads((tmp_path / ".internal" / "ext" / "run_config.json").read_text())
    assert config["request_count"] == 6  # 6 patterns x 1 variant x 1 repeat


def test_run_external_raw_response_limit_keeps_full_raw_artifact(tmp_path: Path) -> None:
    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect",
        side_effect=_mock_chat_open(reason="x" * 200),
    ):
        run_external(
            base_url="http://localhost:8000/v1",
            model="test",
            scenario_id="perception-boundary",
            out_dir=tmp_path / ".internal" / "ext",
            raw_response_limit=40,
        )

    results = json.loads((tmp_path / ".internal" / "ext" / "external_results.json").read_text())
    result = results[0]
    raw_text = (
        tmp_path / ".internal" / "ext" / result["raw_response_path"]
    ).read_text(encoding="utf-8")
    assert result["raw_response_truncated"] is True
    assert len(result["raw_response"]) == 40
    assert len(raw_text) == result["raw_response_chars"]
    assert len(raw_text) > 40


def test_run_external_preset_writes_local_runtime_metadata(tmp_path: Path) -> None:
    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect",
        side_effect=_mock_chat_open(),
    ):
        run_external(
            base_url="http://localhost:11434/v1",
            model="llama3.1",
            scenario_id="perception-boundary",
            out_dir=tmp_path / ".internal" / "ext",
            preset_name="ollama",
        )

    config = json.loads((tmp_path / ".internal" / "ext" / "run_config.json").read_text())
    report = (tmp_path / ".internal" / "ext" / "external_report.md").read_text(encoding="utf-8")
    assert config["runtime"]["runtime_name"] == "ollama"
    assert config["runtime"]["authorization_mode"] == "local_runtime"
    assert config["runtime"]["local_only"] is True
    assert config["runtime"]["model_license_note"]
    assert config["runtime"]["recovery_guidance"]
    assert "Runtime: `ollama`" in report
    assert "Prompt-only: True" in report
    assert "Tool execution: False" in report
    assert "Local runtime execution does not remove model-license" in report


def test_run_external_redacts_mistaken_credential_env_value(tmp_path: Path) -> None:
    secret = "sk-ABCDEFGHIJ0123456789"
    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect",
        side_effect=_mock_chat_open(),
    ):
        run_external(
            base_url="http://localhost:8000/v1",
            model="test",
            scenario_id="perception-boundary",
            out_dir=tmp_path / ".internal" / "ext",
            credential_env_var=secret,
        )

    config_text = (tmp_path / ".internal" / "ext" / "run_config.json").read_text(encoding="utf-8")
    report_text = (
        tmp_path / ".internal" / "ext" / "external_report.md"
    ).read_text(encoding="utf-8")
    assert secret not in config_text
    assert secret not in report_text
    config = json.loads(config_text)
    assert config["credential_env_var"] == "[CREDENTIAL_ENV_VAR_CONFIGURED]"
    assert config["runtime"]["credential_env_var"] == "[CREDENTIAL_ENV_VAR_CONFIGURED]"


def test_run_external_dry_run_redacts_mistaken_credential_env_value(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    secret = "sk-ABCDEFGHIJ0123456789"

    run_external(
        base_url="http://localhost:8000/v1",
        model="test",
        scenario_id="perception-boundary",
        out_dir=tmp_path / ".internal" / "ext",
        credential_env_var=secret,
        dry_run=True,
    )

    out = capsys.readouterr().out
    assert secret not in out
    assert "credential_env_var: configured (value hidden)" in out


def test_run_external_adapter_error_has_recovery_hint(tmp_path: Path) -> None:
    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect",
        side_effect=ExternalAPIError("HTTP 404 from local: model not found"),
    ):
        run_external(
            base_url="http://localhost:11434/v1",
            model="missing-model",
            scenario_id="perception-boundary",
            out_dir=tmp_path / ".internal" / "ext",
            preset_name="ollama",
        )

    results = json.loads((tmp_path / ".internal" / "ext" / "external_results.json").read_text())
    assert "pull or load the model" in results[0]["recovery_hint"]
    report = (tmp_path / ".internal" / "ext" / "external_report.md").read_text(encoding="utf-8")
    assert "## Recovery guidance" in report


def test_external_recovery_hints_cover_common_failures() -> None:
    assert "Start Ollama" in _recovery_hint_for_error("connection refused")
    assert "increase --timeout" in _recovery_hint_for_error("timeout")
    assert "pull or load the model" in _recovery_hint_for_error("HTTP 404 model not found")
    assert "chat completions" in _recovery_hint_for_error("Invalid JSON response")
    assert "required JSON contract" in _recovery_hint_for_verdict(
        "inconclusive", "no valid JSON response"
    )


def test_reproduce_command_includes_knobs_no_secret() -> None:
    from agentic_security_harness.external_runner import _reproduce_command_lines
    from agentic_security_harness.run_config import RunConfig

    cfg = RunConfig(
        base_url_label="http://user:[REDACTED]@host/v1",
        model="m",
        scenario_id="data-boundary",
        repeats=3,
        temperature=0.0,
        timeout_seconds=20,
        max_variants=2,
        selected_variants=["a", "b"],
        credential_env_var="ASH_EXTERNAL_API_KEY",
        request_count=30,
    )
    cmd = "\n".join(_reproduce_command_lines(cfg))
    for flag in (
        "--repeats 3",
        "--temperature 0.0",
        "--timeout 20",
        "--retries 1",
        "--raw-response-limit 0",
        "--max-variants 2",
        "--credential-env <ENV_VAR_NAME>",
        "--execute",
        "--out .internal/external-rerun",
    ):
        assert flag in cmd, flag
    # Single variant -> --variant; large request_count -> --max-requests.
    cfg2 = cfg.model_copy(update={"selected_variants": ["base-envelope"], "request_count": 99})
    cmd2 = "\n".join(_reproduce_command_lines(cfg2))
    assert "--variant base-envelope" in cmd2
    assert "--max-variants" not in cmd2
    assert "--max-requests 99" in cmd2


def test_external_report_reproduce_section_has_knobs(tmp_path: Path) -> None:
    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect",
        side_effect=_mock_chat_open(),
    ):
        run_external(
            base_url="http://localhost:8000/v1",
            model="demo-model",
            scenario_id="data-boundary",
            out_dir=tmp_path / ".internal" / "ext",
            repeats=2,
            credential_env_var="ASH_EXTERNAL_API_KEY",
        )
    report = (tmp_path / ".internal" / "ext" / "external_report.md").read_text(encoding="utf-8")
    assert "## How to reproduce / validate" in report
    assert "--temperature" in report and "--timeout" in report
    assert "--raw-response-limit" in report
    assert "--credential-env <ENV_VAR_NAME>" in report
    assert "run_config.json` is the authoritative" in report
    assert "## Recovery guidance" in report


def test_external_report_encodes_untrusted_configuration_markdown() -> None:
    from agentic_security_harness.external_runner import _build_external_report_md
    from agentic_security_harness.run_config import (
        ExternalRuntimeMetadata,
        ExternalSummary,
        RunConfig,
    )

    payload = "bad`model\n## forged\n![probe](https://example.invalid/p.gif)"
    config = RunConfig(
        base_url_label="https://example.invalid/<img src=x>",
        model=payload,
        scenario_id="data-boundary",
        runtime=ExternalRuntimeMetadata(
            runtime_name=payload,
            runtime_family="family<img src=x>",
            model_license_note=payload,
        ),
    )
    summary = ExternalSummary(model=payload, scenario_id="data-boundary")

    report = _build_external_report_md(summary, config)

    model_line = next(line for line in report.splitlines() if line.startswith("- Model:"))
    assert model_line.startswith("- Model: `` ")
    assert "## forged" in model_line  # text remains visible inside the safe code span
    assert "\n## forged" not in report
    policy_line = next(line for line in report.splitlines() if line.startswith("- Model license"))
    assert "![probe](" not in policy_line
    assert r"\!\[probe\]" in policy_line
    runtime_line = next(line for line in report.splitlines() if line.startswith("- Runtime:"))
    assert r"family\<img src=x>" in runtime_line
    endpoint_line = next(line for line in report.splitlines() if line.startswith("- Endpoint:"))
    assert endpoint_line.endswith("<img src=x>`")  # inert inside the code span


def test_run_external_findings_control_family_and_recommendations(
    tmp_path: Path,
) -> None:
    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect",
        side_effect=_mock_chat_open(
            decision="allow",
            boundary_assertion="vulnerable_behavior",
            would_preserve_boundary=False,
            reason="vulnerable behavior allowed",
        ),
    ):
        summary = run_external(
            base_url="http://localhost:8000/v1",
            model="test",
            scenario_id="data-boundary",
            out_dir=tmp_path / ".internal" / "ext",
            repeats=1,
        )

    # data-boundary patterns map to data_boundary + provider_boundary families.
    assert summary.findings_by_control_family.get("data_boundary", 0) == 5
    assert summary.findings_by_control_family.get("provider_boundary", 0) == 1

    report = (tmp_path / ".internal" / "ext" / "external_report.md").read_text(encoding="utf-8")
    assert "## Control recommendations" in report
    assert "### data_boundary" in report
    assert "Quick fix:" in report
    assert "Residual risk:" in report


def test_run_external_api_error(tmp_path: Path) -> None:
    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect",
        side_effect=ExternalAPIError("timeout"),
    ):
        summary = run_external(
            base_url="http://localhost:8000/v1",
            model="test",
            scenario_id="data-boundary",
            out_dir=tmp_path / ".internal" / "ext",
            repeats=1,
        )

    assert len(summary.error_patterns) == 6


@pytest.mark.parametrize(
    "response",
    [
        {"model": "wrong", "choices": [{"message": {"content": "answer"}}]},
        {"choices": [{"message": {"content": "answer"}}]},
        {"model": "test", "choices": [{"message": {"content": "   "}}]},
    ],
)
def test_run_external_invalid_identity_or_content_never_becomes_evidence(
    tmp_path: Path,
    response: dict[str, object],
) -> None:
    out = tmp_path / ".internal" / "ext"
    with patch(
        "agentic_security_harness.external_runner.chat_completion",
        return_value=response,
    ):
        summary = run_external(
            base_url="http://127.0.0.1:8000/v1",
            model="test",
            scenario_id="data-boundary",
            out_dir=out,
            repeats=1,
        )

    assert len(summary.error_patterns) == 6
    results = json.loads((out / "external_results.json").read_text(encoding="utf-8"))
    assert all(row["deterministic_cross_check"] == "adapter_error" for row in results)
    assert all(not row["raw_response_sha256"] for row in results)


def test_stability_status_stable_pass(tmp_path: Path) -> None:
    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect",
        side_effect=_mock_chat_open(),
    ):
        summary = run_external(
            base_url="http://localhost:8000/v1",
            model="m",
            scenario_id="data-boundary",
            out_dir=tmp_path / ".internal" / "ext",
            repeats=2,
        )
    assert all(rs.stability_status == "stable_pass" for rs in summary.repeat_summaries)


def test_stability_status_adapter_error(tmp_path: Path) -> None:
    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect",
        side_effect=ExternalAPIError("timeout"),
    ):
        summary = run_external(
            base_url="http://localhost:8000/v1",
            model="m",
            scenario_id="data-boundary",
            out_dir=tmp_path / ".internal" / "ext",
            repeats=2,
        )
    assert all(rs.stability_status == "adapter_error" for rs in summary.repeat_summaries)


def test_stability_status_flaky(tmp_path: Path) -> None:
    call_count = 0

    def _mock_open(req, *args, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal call_count
        call_count += 1
        resp = MagicMock()
        pattern_id = _pattern_id_from_request(req)
        payload = {
            "pattern_id": pattern_id,
            "control_family": _FAMILY_MAP.get(pattern_id, "perception_boundary"),
            "reason": "flaky synthetic response",
        }
        if call_count % 2 == 1:
            payload.update(
                {
                    "decision": "block",
                    "boundary_assertion": "preserve_boundary",
                    "would_preserve_boundary": True,
                }
            )
        else:
            payload.update(
                {
                    "decision": "allow",
                    "boundary_assertion": "vulnerable_behavior",
                    "would_preserve_boundary": False,
                }
            )
        content = json.dumps(payload)
        resp.read.return_value = json.dumps(
            {
                "model": json.loads(req.data.decode("utf-8"))["model"],
                "choices": [{"message": {"content": content}}],
            }
        ).encode()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect",
        side_effect=_mock_open,
    ):
        summary = run_external(
            base_url="http://localhost:8000/v1",
            model="m",
            scenario_id="perception-boundary",
            out_dir=tmp_path / ".internal" / "ext",
            repeats=2,
        )
    assert any(rs.stability_status == "flaky" for rs in summary.repeat_summaries)


def test_run_external_flaky_detection(tmp_path: Path) -> None:
    """Test flaky detection: same pattern returns different outcomes across repeats."""
    call_count = 0

    def _mock_open(req, *args, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal call_count
        call_count += 1
        resp = MagicMock()
        pattern_id = _pattern_id_from_request(req)
        payload = {
            "pattern_id": pattern_id,
            "control_family": _FAMILY_MAP.get(pattern_id, "perception_boundary"),
            "reason": "flaky synthetic response",
        }
        if call_count % 2 == 1:
            payload.update(
                {
                    "decision": "block",
                    "boundary_assertion": "preserve_boundary",
                    "would_preserve_boundary": True,
                }
            )
        else:
            payload.update(
                {
                    "decision": "allow",
                    "boundary_assertion": "vulnerable_behavior",
                    "would_preserve_boundary": False,
                }
            )
        content = json.dumps(payload)
        resp.read.return_value = json.dumps(
            {
                "model": json.loads(req.data.decode("utf-8"))["model"],
                "choices": [{"message": {"content": content}}],
            }
        ).encode()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect",
        side_effect=_mock_open,
    ):
        summary = run_external(
            base_url="http://localhost:8000/v1",
            model="test",
            scenario_id="perception-boundary",  # 1 pattern
            out_dir=tmp_path / ".internal" / "ext",
            repeats=2,
        )

    assert len(summary.flaky_patterns) > 0


# --- CLI dry-run test ---


def test_cli_dry_run_no_network() -> None:
    from agentic_security_harness import cli

    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect"
    ) as mock_open:
        rc = cli.main(
            [
                "run-external",
                "--adapter",
                "openai-compatible",
                "--base-url",
                "http://localhost:8000/v1",
                "--model",
                "test",
                "--scenario",
                "data-boundary",
                "--dry-run",
            ]
        )
        assert rc == 0
        mock_open.assert_not_called()


def test_cli_run_external_defaults_to_dry_run_no_network() -> None:
    from agentic_security_harness import cli

    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect"
    ) as mock_open:
        rc = cli.main(
            [
                "run-external",
                "--adapter",
                "openai-compatible",
                "--base-url",
                "http://localhost:8000/v1",
                "--model",
                "test",
                "--scenario",
                "data-boundary",
            ]
        )

    assert rc == 0
    mock_open.assert_not_called()


def test_cli_run_external_requires_execute_for_live_handler() -> None:
    from agentic_security_harness import cli

    with patch.object(cli, "_run_external", return_value=0) as run_external:
        rc = cli.main(
            [
                "run-external",
                "--base-url",
                "http://localhost:8000/v1",
                "--model",
                "test",
                "--execute",
            ]
        )

    assert rc == 0
    assert run_external.call_args.args[12] is False


def test_cli_run_external_rejects_execute_and_dry_run_together() -> None:
    from agentic_security_harness import cli

    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(
            [
                "run-external",
                "--base-url",
                "http://localhost:8000/v1",
                "--model",
                "test",
                "--execute",
                "--dry-run",
            ]
        )


def test_cli_external_check_no_live_no_network(capsys: pytest.CaptureFixture[str]) -> None:
    from agentic_security_harness import cli

    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect"
    ) as mock_open:
        rc = cli.main(
            [
                "external-check",
                "--adapter",
                "openai-compatible",
                "--base-url",
                "http://localhost:8000/v1",
                "--model",
                "test",
                "--scenario",
                "data-boundary",
                "--api-key-env",
                "ASH_TEST_KEY_NOT_SET",
                "--repeats",
                "2",
                "--max-variants",
                "2",
            ]
        )
        assert rc == 0
        mock_open.assert_not_called()

    out = capsys.readouterr().out
    assert "Estimated requests: 24" in out
    assert "Runtime: local-openai-compatible" in out
    assert "Network mode: local-only" in out
    assert "Prompt-only: yes; tool execution: no" in out
    assert "Credential env var (ASH_TEST_KEY_NOT_SET): NOT SET" in out
    assert "Set this environment variable in your shell before a live run." in out
    assert "your_key" not in out


def test_cli_external_check_live_success(capsys: pytest.CaptureFixture[str]) -> None:
    from agentic_security_harness import cli

    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(
        {
            "model": "fake-model",
            "choices": [{"message": {"content": "pong"}}],
        }
    ).encode()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)

    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect",
        return_value=mock_response,
    ):
        rc = cli.main(
            [
                "external-check",
                "--adapter",
                "openai-compatible",
                "--base-url",
                "http://localhost:8000/v1",
                "--model",
                "fake-model",
                "--live",
            ]
        )

    assert rc == 0
    assert "Live request: SUCCESS" in capsys.readouterr().out


def test_cli_run_external_missing_base_url() -> None:
    from agentic_security_harness import cli

    # --base-url is now optional (a --preset can fill it); with neither, the handler
    # returns a clean error (rc 1) instead of an argparse SystemExit.
    rc = cli.main(["run-external", "--model", "test"])
    assert rc == 1


def test_cli_run_external_repeats_too_high() -> None:
    from agentic_security_harness import cli

    rc = cli.main(
        [
            "run-external",
            "--adapter",
            "openai-compatible",
            "--base-url",
            "http://localhost:8000/v1",
            "--model",
            "test",
            "--scenario",
            "data-boundary",
            "--repeats",
            "99",
            "--dry-run",
        ]
    )
    assert rc == 1


def test_cli_run_external_unsupported_adapter() -> None:
    from agentic_security_harness import cli

    rc = cli.main(
        [
            "run-external",
            "--adapter",
            "unsupported",
            "--base-url",
            "http://localhost:8000/v1",
            "--model",
            "test",
            "--scenario",
            "data-boundary",
            "--dry-run",
        ]
    )
    assert rc == 1


def test_cli_run_external_exceeds_request_cap(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agentic_security_harness import cli

    # 24 patterns x 4 variants x 1 repeat = 96 > default cap 50. The cap is
    # checked before any network call, even with --dry-run.
    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect"
    ) as mock_open:
        rc = cli.main(
            [
                "run-external",
                "--base-url",
                "http://localhost:8000/v1",
                "--model",
                "test",
                "--scenario",
                "all",
                "--max-variants",
                "4",
                "--dry-run",
            ]
        )
        assert rc == 1
        mock_open.assert_not_called()
    assert "exceeds the safety cap" in capsys.readouterr().out


def test_cli_run_external_dry_run_reports_no_files(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agentic_security_harness import cli

    with patch(
        "agentic_security_harness.external_openai_compatible.urlopen_no_redirect"
    ) as mock_open:
        rc = cli.main(
            [
                "run-external",
                "--base-url",
                "http://localhost:8000/v1",
                "--model",
                "test",
                "--scenario",
                "data-boundary",
                "--dry-run",
            ]
        )
        assert rc == 0
        mock_open.assert_not_called()
    out = capsys.readouterr().out
    assert "Estimated requests: 6" in out
    assert "runtime: local-openai-compatible" in out
    assert "network_mode: local-only" in out
    assert "No network call. No files written." in out


def test_cli_external_check_shows_cost_cap(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agentic_security_harness import cli

    rc = cli.main(
        [
            "external-check",
            "--base-url",
            "http://localhost:8000/v1",
            "--model",
            "test",
            "--scenario",
            "all",
            "--max-variants",
            "4",
        ]
    )
    assert rc == 0
    assert "exceeds the safety cap" in capsys.readouterr().out


def test_cli_external_check_emits_copy_pasteable_next_command(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agentic_security_harness import cli

    rc = cli.main(
        [
            "external-check",
            "--base-url",
            "http://localhost:8000/v1",
            "--model",
            "deepseek-chat",
            "--scenario",
            "data-boundary",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "Next steps:" in out
    # The suggested next command must be a real run-external invocation.
    assert "ash run-external --base-url http://localhost:8000/v1" in out
    assert "--model deepseek-chat" in out
    assert "--dry-run" in out
    assert "--execute --out .internal/external-run" in out
    assert "ash validate .internal/external-run" in out


def _wait_port(host: str, port: int, timeout_s: float = 5.0) -> None:
    deadline = time.time() + timeout_s
    last_error: OSError | None = None
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(0.05)
    raise AssertionError(f"server did not listen on {host}:{port}: {last_error}")


def test_fake_openai_server_responds_to_chat_completion() -> None:
    fake_server = Path(__file__).resolve().parent.parent / "examples" / "fake_openai_server.py"
    proc = subprocess.Popen(
        [sys.executable, str(fake_server)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_port("127.0.0.1", 8766)
        resp = chat_completion(
            base_url="http://127.0.0.1:8766/v1",
            model="fake-model",
            messages=[{"role": "user", "content": "ping"}],
            timeout_seconds=5,
        )
        content = extract_content(resp)
        parsed = json.loads(content)
        assert parsed["decision"] == "block"
        assert parsed["would_preserve_boundary"] is True
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


# --- Regression tests ---


def test_builtin_ash_run_still_works(tmp_path: Path) -> None:
    from agentic_security_harness import cli

    rc = cli.main(["run", "--target", "mock", "--out", str(tmp_path / "run")])
    assert rc == 0
    assert (tmp_path / "run" / "traces.json").exists()


def test_builtin_ash_compare_still_works(tmp_path: Path) -> None:
    from agentic_security_harness import cli

    rc = cli.main(
        [
            "compare",
            "--baseline",
            "demo-agent",
            "--protected",
            "protected-demo-agent",
            "--out",
            str(tmp_path / "cmp"),
        ]
    )
    assert rc == 0
    assert (tmp_path / "cmp" / "comparison.md").exists()
