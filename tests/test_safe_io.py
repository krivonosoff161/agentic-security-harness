import ast
import os
import tempfile
from pathlib import Path

import pytest

from agentic_security_harness.safe_io import (
    PublishedBundleDurabilityError,
    atomic_evidence_bundle,
    atomic_private_bundle,
    canonical_persisted_text,
    credential_env_var_lookup_name,
    is_internal_output_dir,
    is_staging_path,
    redact_artifact_text,
    require_disjoint_output_dirs,
    require_fresh_output_dir,
    safe_credential_env_var_name,
    staged_evidence_bundle,
    write_text_artifact,
)


def test_every_private_directory_writer_uses_atomic_publication() -> None:
    package = Path(__file__).resolve().parents[1] / "src" / "agentic_security_harness"
    private_writers: list[str] = []
    for path in sorted(package.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            calls = {
                child.func.id
                for child in ast.walk(node)
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Name)
            }
            if not {
                "is_internal_output_dir",
                "require_fresh_output_dir",
                "write_text_artifact",
            }.issubset(calls):
                continue
            label = f"{path.name}:{node.name}"
            private_writers.append(label)
            assert any(
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Name)
                and decorator.func.id == "atomic_private_bundle"
                for decorator in node.decorator_list
            ), label

    assert len(private_writers) == 9


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


def test_canonical_persisted_text_is_the_hashable_redacted_scalar() -> None:
    original = "model output sk-ABCDEFGHIJ0123456789"
    persisted = canonical_persisted_text(original)

    assert persisted == "model output sk-[REDACTED]"
    assert persisted == redact_artifact_text(original)


def test_write_text_artifact_creates_parent_and_redacts(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "artifact.txt"

    written = write_text_artifact(path, "token sk-ABCDEFGHIJ0123456789\r\n")

    assert written == path
    raw = path.read_bytes()
    assert b"\r\n" not in raw
    assert path.read_text(encoding="utf-8") == "token sk-[REDACTED]\n"


def test_write_text_artifact_uses_a_bounded_temporary_name(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    observed: dict[str, object] = {}
    original_mkstemp = tempfile.mkstemp

    def capture_mkstemp(
        suffix: str | None = None,
        prefix: str | None = None,
        dir: str | os.PathLike[str] | None = None,
        text: bool = False,
    ) -> tuple[int, str]:
        observed.update({"suffix": suffix, "prefix": prefix, "dir": dir, "text": text})
        return original_mkstemp(suffix=suffix, prefix=prefix, dir=dir, text=text)

    monkeypatch.setattr(tempfile, "mkstemp", capture_mkstemp)
    destination = tmp_path / ("long-artifact-name-" * 6 + ".json")

    write_text_artifact(destination, "complete\n")

    assert observed["prefix"] == ".ash-"
    assert destination.read_text(encoding="utf-8") == "complete\n"


def test_write_text_artifact_failure_keeps_existing_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "artifact.txt"
    path.write_bytes(b"committed-generation\n")

    def fail_replace(
        source: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        destination: str | bytes | os.PathLike[str] | os.PathLike[bytes],
    ) -> None:
        del source, destination
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(os, "replace", fail_replace)

    with pytest.raises(OSError, match="synthetic replace failure"):
        write_text_artifact(path, "next-generation\n")

    assert path.read_bytes() == b"committed-generation\n"
    assert list(tmp_path.glob(".ash-*.tmp")) == []


def test_write_text_artifact_refuses_existing_symlink(tmp_path: Path) -> None:
    target = tmp_path / "outside.txt"
    target.write_text("outside\n", encoding="utf-8")
    link = tmp_path / "artifact.txt"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are unavailable in this environment")

    with pytest.raises(ValueError, match="must not be a link or reparse point"):
        write_text_artifact(link, "replacement\n")

    assert target.read_text(encoding="utf-8") == "outside\n"


def test_write_text_artifact_refuses_symlink_parent(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    linked_parent = tmp_path / "linked"
    try:
        linked_parent.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symbolic links are unavailable in this environment")

    with pytest.raises(ValueError, match="link or reparse point"):
        write_text_artifact(linked_parent / "artifact.txt", "must not escape")

    assert not (outside / "artifact.txt").exists()


def test_require_fresh_output_dir_accepts_missing_and_empty_paths(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    empty = tmp_path / "empty"
    empty.mkdir()

    require_fresh_output_dir(missing)
    require_fresh_output_dir(empty)


def test_require_fresh_output_dir_rejects_file_and_nonempty_dir(tmp_path: Path) -> None:
    file_path = tmp_path / "file.txt"
    file_path.write_text("file\n", encoding="utf-8")
    nonempty = tmp_path / "nonempty"
    nonempty.mkdir()
    (nonempty / "artifact.txt").write_text("artifact\n", encoding="utf-8")

    with pytest.raises(ValueError, match="not a directory"):
        require_fresh_output_dir(file_path)
    with pytest.raises(ValueError, match="must be empty"):
        require_fresh_output_dir(nonempty)


def test_staged_evidence_bundle_hides_partial_output_until_publish(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    final = tmp_path / "bundle"

    def accept_staging(path: Path) -> None:
        assert is_staging_path(path)
        assert (path / "artifact.txt").read_text(encoding="utf-8") == "complete\n"

    monkeypatch.setattr(
        "agentic_security_harness.safe_io._validate_staged_bundle",
        accept_staging,
    )

    with staged_evidence_bundle(final) as staging:
        assert staging.parent == final.parent
        assert is_staging_path(staging)
        assert not final.exists()
        write_text_artifact(staging / "artifact.txt", "complete\n")
        assert not final.exists()

    assert not staging.exists()
    assert (final / "artifact.txt").read_text(encoding="utf-8") == "complete\n"


def test_staged_evidence_bundle_cleans_failed_generation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    final = tmp_path / "bundle"

    def reject_staging(path: Path) -> None:
        assert path.exists()
        raise ValueError("synthetic validation failure")

    monkeypatch.setattr(
        "agentic_security_harness.safe_io._validate_staged_bundle",
        reject_staging,
    )

    with pytest.raises(ValueError, match="synthetic validation failure"):
        with staged_evidence_bundle(final) as staging:
            write_text_artifact(staging / "partial.txt", "partial\n")

    assert not final.exists()
    assert list(tmp_path.glob(".bundle.ash-staging-*")) == []


def test_staged_evidence_bundle_rejects_nested_only_artifact_contract(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from agentic_security_harness.validation import ValidationResult

    final = tmp_path / "bundle"
    monkeypatch.setattr(
        "agentic_security_harness.validation.validate_artifact_path",
        lambda _path: ValidationResult(report_dirs=["nested"]),
    )

    with pytest.raises(ValueError, match="no recognized root artifact contract"):
        with staged_evidence_bundle(final) as staging:
            write_text_artifact(staging / "run_index.json", "{}\n")

    assert not final.exists()


def test_staged_evidence_bundle_names_post_publish_durability_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    final = tmp_path / "bundle"
    calls = 0

    monkeypatch.setattr(
        "agentic_security_harness.safe_io._validate_staged_bundle",
        lambda _path: None,
    )

    def fail_parent_sync(_path: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("synthetic directory fsync failure")

    monkeypatch.setattr(
        "agentic_security_harness.safe_io._fsync_directory",
        fail_parent_sync,
    )

    with pytest.raises(PublishedBundleDurabilityError, match="was published"):
        with staged_evidence_bundle(final) as staging:
            write_text_artifact(staging / "artifact.txt", "complete\n")

    assert (final / "artifact.txt").is_file()


def test_atomic_evidence_bundle_remaps_return_paths(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "agentic_security_harness.safe_io._validate_staged_bundle",
        lambda _path: None,
    )

    @atomic_evidence_bundle("out_dir")
    def write_bundle(out_dir: Path) -> dict[str, Path]:
        require_fresh_output_dir(out_dir)
        path = write_text_artifact(out_dir / "artifact.txt", "complete\n")
        return {"artifact": path}

    final = tmp_path / "bundle"
    returned = write_bundle(final)

    assert returned == {"artifact": final / "artifact.txt"}
    assert returned["artifact"].is_file()


def test_atomic_private_bundle_cleans_partial_generation_and_remaps_paths(
    tmp_path: Path,
) -> None:
    private_root = tmp_path / ".internal"

    @atomic_private_bundle("out_dir")
    def write_private(out_dir: Path, *, fail: bool) -> list[Path]:
        require_fresh_output_dir(out_dir)
        first = write_text_artifact(out_dir / "raw.json", "{}\n")
        if fail:
            raise RuntimeError("synthetic private write failure")
        second = write_text_artifact(out_dir / "raw.md", "private\n")
        return [first, second]

    failed = private_root / "failed"
    with pytest.raises(RuntimeError, match="synthetic private write failure"):
        write_private(failed, fail=True)
    assert not failed.exists()
    assert list(private_root.glob(".failed.ash-staging-*")) == []

    final = private_root / "complete"
    returned = write_private(final, fail=False)
    assert returned == [final / "raw.json", final / "raw.md"]
    assert all(path.is_file() for path in returned)


def test_staged_evidence_bundle_refuses_existing_final_path(tmp_path: Path) -> None:
    final = tmp_path / "bundle"
    final.mkdir()

    with pytest.raises(ValueError, match="must not already exist"):
        with staged_evidence_bundle(final):
            pass


def test_is_staging_path_requires_exact_generated_component(tmp_path: Path) -> None:
    assert is_staging_path(tmp_path / f".bundle.ash-staging-{'a' * 32}" / "run_index.json")
    assert not is_staging_path(tmp_path / "bundle.ash-staging-readable-name")
    assert not is_staging_path(tmp_path / ".bundle.ash-staging-interrupted")


def test_staged_evidence_bundle_rejects_ambiguous_or_reserved_final_path(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="final path component"):
        with staged_evidence_bundle(tmp_path / "missing-parent" / ".." / "bundle"):
            pass
    reserved = tmp_path / f".bundle.ash-staging-{'a' * 32}"
    with pytest.raises(ValueError, match="reserved ASH staging name"):
        with staged_evidence_bundle(reserved):
            pass

    assert not (tmp_path / "missing-parent").exists()


def test_require_disjoint_output_dirs_rejects_equal_or_nested_roots(
    tmp_path: Path,
) -> None:
    private = tmp_path / "private"
    public = tmp_path / "public"

    require_disjoint_output_dirs(private, public)
    with pytest.raises(ValueError, match="must be disjoint"):
        require_disjoint_output_dirs(private, private)
    with pytest.raises(ValueError, match="must be disjoint"):
        require_disjoint_output_dirs(private, private / "sanitized")


def test_is_internal_output_dir_uses_normalized_path_components(tmp_path: Path) -> None:
    assert is_internal_output_dir(tmp_path / ".internal" / "private")
    assert not is_internal_output_dir(tmp_path / "not.internal" / "private")
    assert not is_internal_output_dir(tmp_path / ".internal" / ".." / "public")


def test_safe_credential_env_var_name_rejects_values_and_invalid_labels() -> None:
    assert safe_credential_env_var_name("ASH_EXTERNAL_API_KEY") == "[CREDENTIAL_ENV_VAR_CONFIGURED]"
    assert safe_credential_env_var_name("") == ""
    assert (
        safe_credential_env_var_name("sk-ABCDEFGHIJ0123456789") == "[CREDENTIAL_ENV_VAR_CONFIGURED]"
    )
    assert safe_credential_env_var_name("sk-[REDACTED]") == "[CREDENTIAL_ENV_VAR_CONFIGURED]"
    assert (
        safe_credential_env_var_name("http://user:secret@example.test")
        == "[CREDENTIAL_ENV_VAR_CONFIGURED]"
    )
    assert safe_credential_env_var_name("not a name") == "[CREDENTIAL_ENV_VAR_CONFIGURED]"


def test_credential_env_var_lookup_name_accepts_only_safe_names() -> None:
    assert credential_env_var_lookup_name("ASH_EXTERNAL_API_KEY") == "ASH_EXTERNAL_API_KEY"
    assert credential_env_var_lookup_name("") == ""
    assert credential_env_var_lookup_name("sk-ABCDEFGHIJ0123456789") == ""
    assert credential_env_var_lookup_name("sk-[REDACTED]") == ""
    assert credential_env_var_lookup_name("http://user:secret@example.test") == ""
    assert credential_env_var_lookup_name("not a name") == ""
