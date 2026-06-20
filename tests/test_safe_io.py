from pathlib import Path

from agentic_security_harness.safe_io import (
    redact_artifact_text,
    safe_credential_env_var_name,
    write_text_artifact,
)


def test_redact_artifact_text_covers_secret_shapes() -> None:
    text = "\n".join(
        [
            "openai sk-ABCDEFGHIJ0123456789",
            "aws AKIAIOSFODNN7EXAMPLE",
            "github ghp_abcdefghijklmnopqrstuvwxyz123456",
            "auth Bearer abcdefghijklmnopqrstuvwxyz123456",
            "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
        ]
    )

    redacted = redact_artifact_text(text)

    assert "sk-ABCDEFGHIJ0123456789" not in redacted
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "ghp_abcdefghijklmnopqrstuvwxyz123456" not in redacted
    assert "Bearer abcdefghijklmnopqrstuvwxyz123456" not in redacted
    assert "BEGIN RSA PRIVATE KEY" not in redacted
    assert "sk-[REDACTED]" in redacted
    assert "AKIA[REDACTED]" in redacted
    assert "ghp_[REDACTED]" in redacted
    assert "Bearer [REDACTED]" in redacted


def test_write_text_artifact_creates_parent_and_redacts(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "artifact.txt"

    written = write_text_artifact(path, "token sk-ABCDEFGHIJ0123456789\r\n")

    assert written == path
    raw = path.read_bytes()
    assert b"\r\n" not in raw
    assert path.read_text(encoding="utf-8") == "token sk-[REDACTED]\n"


def test_safe_credential_env_var_name_rejects_values_and_invalid_labels() -> None:
    assert safe_credential_env_var_name("ASH_EXTERNAL_API_KEY") == "ASH_EXTERNAL_API_KEY"
    assert safe_credential_env_var_name("") == ""
    assert safe_credential_env_var_name("sk-ABCDEFGHIJ0123456789") == "sk-[REDACTED]"
    assert safe_credential_env_var_name("sk-[REDACTED]") == "sk-[REDACTED]"
    assert (
        safe_credential_env_var_name("http://user:secret@example.test")
        == "[INVALID_CREDENTIAL_ENV_VAR_NAME]"
    )
    assert safe_credential_env_var_name("not a name") == "[INVALID_CREDENTIAL_ENV_VAR_NAME]"
