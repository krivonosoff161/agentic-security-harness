from __future__ import annotations

import importlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import cast

import pytest

from agentic_security_harness.extension_distribution import (
    ExtensionDistributionInspectionV1,
    approve_extension_distribution_v1,
    inspect_extension_distribution_v1,
)
from agentic_security_harness.extension_lifecycle import (
    bind_active_operator_extension_v1,
)
from agentic_security_harness.extension_sdk import (
    ExtensionV1,
    build_extension_envelope_v1,
    run_extension_v1,
)
from agentic_security_harness.portfolio_contract import (
    CanonicalObservationEventV1,
    SafeEvidencePointer,
)
from agentic_security_harness.safe_io import is_link_or_reparse

TRANSFER_HEAD = "240f3081b6614439e03d61479114e330fe7c3d52"
TRANSFER_TREE = "8e2e3319776a48fb96e04a2cd34ed83bb5d3d191"
HANDOFF_HEAD = "f4e51e0603497f63c62453fc4030319fdfc5ac04"
HANDOFF_TREE = "78311595f72469748469a1dfd4dc4a286244159f"
TRANSFER_HARNESS_BASELINE = "6354635c6411830de95dd3b68c962eb887cb5edb"
HANDOFF_HARNESS_BASELINE = "285d05ad64239dd55271e5c534041b235db0e243"
ROOT = Path(__file__).resolve().parents[1]
COMPANION_MODULE_PREFIXES = (
    "agentic_transfer_verifier",
    "agentic_transfer_verifier_extension",
    "agent_guard",
    "ai_agent_handoff_harness_extension",
)


def _source_root(name: str) -> Path:
    value = os.environ.get(name)
    if value is None:
        pytest.skip(f"{name} is required for the exact ecosystem integration gate")
    root = Path(value)
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        pytest.fail(f"{name} must identify a safe absolute directory")
    return root.resolve()


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "--no-optional-locks", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
    ).stdout.strip()


def _assert_source(root: Path, *, head: str, tree: str) -> None:
    assert _git(root, "rev-parse", "HEAD") == head
    assert _git(root, "show", "-s", "--format=%T", "HEAD") == tree
    assert _git(root, "status", "--porcelain=v1", "--untracked-files=no") == ""


def _is_companion_module(name: str) -> bool:
    return any(
        name == prefix or name.startswith(f"{prefix}.")
        for prefix in COMPANION_MODULE_PREFIXES
    )


def _take_companion_modules() -> dict[str, ModuleType]:
    saved: dict[str, ModuleType] = {
        name: module
        for name, module in tuple(sys.modules.items())
        if _is_companion_module(name)
    }
    for name in saved:
        sys.modules.pop(name, None)
    return saved


def _restore_companion_modules(saved: dict[str, ModuleType]) -> None:
    for name in tuple(sys.modules):
        if _is_companion_module(name):
            sys.modules.pop(name, None)
    sys.modules.update(saved)


def _explicit_factory(
    inspection: ExtensionDistributionInspectionV1, site: Path
) -> Callable[..., object]:
    site_root = site.resolve(strict=True)
    expected = (site_root / inspection.module_path).resolve(strict=True)
    info = expected.lstat()
    if (
        expected.parent != site_root
        or not stat.S_ISREG(info.st_mode)
        or is_link_or_reparse(expected)
    ):
        raise AssertionError("inspected implementation origin is not a regular site file")

    implementation = importlib.import_module(inspection.module_name)
    module_file = getattr(implementation, "__file__", None)
    spec = getattr(implementation, "__spec__", None)
    spec_origin = None if spec is None else spec.origin
    if module_file is None or spec_origin is None:
        raise AssertionError("imported implementation has no bound origin")
    resolved_file = Path(module_file).resolve(strict=True)
    resolved_spec = Path(spec_origin).resolve(strict=True)
    if (
        resolved_file != expected
        or resolved_spec != expected
        or not os.path.samefile(resolved_file, expected)
        or not os.path.samefile(resolved_spec, expected)
    ):
        raise AssertionError("imported implementation origin differs from inspection")

    factory = getattr(implementation, inspection.factory_attribute)
    if (
        not callable(factory)
        or getattr(factory, "__module__", None) != inspection.module_name
    ):
        raise AssertionError("factory origin differs from inspected module")
    return cast(Callable[..., object], factory)


def _build_wheel(source: Path, output: Path) -> Path:
    output.mkdir(parents=True)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            str(output),
            str(source),
        ],
        check=True,
        timeout=180,
    )
    wheels = tuple(output.glob("*.whl"))
    assert len(wheels) == 1
    return wheels[0]


def _git_source_snapshot(source: Path, destination: Path) -> Path:
    archive_path = destination.with_suffix(".tar")
    subprocess.run(
        ["git", "archive", "--format=tar", f"--output={archive_path}", "HEAD"],
        check=True,
        cwd=source,
        timeout=120,
    )
    destination.mkdir()
    with tarfile.open(archive_path, mode="r:") as archive:
        for member in archive.getmembers():
            relative = Path(member.name)
            if relative.is_absolute() or ".." in relative.parts:
                raise AssertionError("git archive member is not a safe relative path")
            output = destination / relative
            if member.isdir():
                output.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise AssertionError("git archive contains a non-file member")
            output.parent.mkdir(parents=True, exist_ok=True)
            source_stream = archive.extractfile(member)
            assert source_stream is not None
            with source_stream, output.open("wb") as target_stream:
                shutil.copyfileobj(source_stream, target_stream)
    return destination


def _install_no_deps(wheels: tuple[Path, ...], target: Path) -> None:
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-index",
            "--no-deps",
            "--no-compile",
            "--target",
            str(target),
            *(str(wheel) for wheel in wheels),
        ],
        check=True,
        timeout=180,
    )


def _event(
    *,
    project_id: str,
    repository_id: str,
    activity: str,
    with_artifact: bool,
) -> CanonicalObservationEventV1:
    refs = (
        (SafeEvidencePointer(kind="artifact", digest="d" * 64, locator_id="e" * 64),)
        if with_artifact
        else ()
    )
    return CanonicalObservationEventV1(
        schema_version="portfolio-observation-v1.0",
        event_id="a" * 64,
        project_id=project_id,
        repository_id=repository_id,
        repository_sha="b" * 40,
        occurred_at=datetime(2026, 8, 24, tzinfo=UTC),
        producer_id_hash="c" * 64,
        producer_attestation="unattested",
        source_surface="agent",
        activity=activity,
        entity_refs=refs,
        parent_event_ids=(),
        data_envelope_ref="f" * 64,
        authority_envelope_ref=None,
        telemetry_state="complete",
        operational_authority="none",
    )


def _inspect_approve_construct_bind_run(
    *,
    site: Path,
    distribution_name: str,
    extension_id: str,
    configuration: bytes,
    event: CanonicalObservationEventV1,
    expected_reason: str,
) -> None:
    inspection = inspect_extension_distribution_v1(
        distribution_name=distribution_name,
        extension_id=extension_id,
        search_paths=(site,),
        configuration_bytes=configuration,
    )
    assert inspection.code_loaded is False
    assert inspection.signature_verified is False
    assert inspection.sandboxed is False
    assert inspection.operational_authority == "none"
    assert inspection.module_name not in sys.modules

    approval = approve_extension_distribution_v1(
        approved_inspection=inspection,
        approved_inspection_id=inspection.inspection_id,
        search_paths=(site,),
        configuration_bytes=configuration,
    )
    assert approval.code_loaded is False
    assert approval.operational_authority == "none"
    assert inspection.module_name not in sys.modules

    factory = _explicit_factory(inspection, site)
    if distribution_name == "agentic-transfer-verifier-harness-extension":
        manifest_bytes = (site / inspection.manifest_path).read_bytes()
        extension = cast(
            ExtensionV1,
            factory(
                manifest_bytes=manifest_bytes,
                configuration_bytes=configuration,
            ),
        )
    else:
        extension = cast(ExtensionV1, factory())
    bound = bind_active_operator_extension_v1(approval, extension)
    envelope = build_extension_envelope_v1(
        source_component_id=event.project_id,
        source_commitment_sha256="1" * 64,
        events=(event,),
    )
    receipt = run_extension_v1(cast(ExtensionV1, bound), envelope)
    assert receipt.result.findings[0].outcome == "pass"
    assert receipt.result.findings[0].reason_code == expected_reason
    assert receipt.operational_authority == "none"


def test_exact_source_wheels_complete_explicit_forward_compatibility_lifecycle(
    tmp_path: Path,
) -> None:
    transfer = _source_root("ASH_TRANSFER_ROOT")
    handoff = _source_root("ASH_HANDOFF_ROOT")
    _assert_source(transfer, head=TRANSFER_HEAD, tree=TRANSFER_TREE)
    _assert_source(handoff, head=HANDOFF_HEAD, tree=HANDOFF_TREE)
    transfer_contract = json.loads(
        (transfer / "contracts" / "transfer-harness-extension.v1.manifest.json").read_text(
            encoding="utf-8"
        )
    )
    handoff_contract = json.loads(
        (handoff / "contracts" / "harness-extension-v1.manifest.json").read_text(
            encoding="utf-8"
        )
    )
    assert transfer_contract["harness_source"]["commit"] == TRANSFER_HARNESS_BASELINE
    assert handoff_contract["harness_reference"]["head"] == HANDOFF_HARNESS_BASELINE
    assert _git(ROOT, "merge-base", "--is-ancestor", TRANSFER_HARNESS_BASELINE, "HEAD") == ""
    assert _git(ROOT, "merge-base", "--is-ancestor", HANDOFF_HARNESS_BASELINE, "HEAD") == ""
    saved_companion_modules = _take_companion_modules()
    transfer_snapshot = _git_source_snapshot(transfer, tmp_path / "transfer-source")
    handoff_snapshot = _git_source_snapshot(handoff, tmp_path / "handoff-source")

    wheels = (
        _build_wheel(transfer_snapshot, tmp_path / "transfer-core"),
        _build_wheel(
            transfer_snapshot / "extensions" / "transfer_harness_extension_v1",
            tmp_path / "transfer-extension",
        ),
        _build_wheel(handoff_snapshot, tmp_path / "handoff-core"),
        _build_wheel(
            handoff_snapshot / "extensions" / "harness-v1",
            tmp_path / "handoff-extension",
        ),
    )
    site = tmp_path / "site"
    _install_no_deps(wheels, site)
    sys.path.insert(0, str(site))
    try:
        _inspect_approve_construct_bind_run(
            site=site,
            distribution_name="agentic-transfer-verifier-harness-extension",
            extension_id="agentic-transfer-verifier.verification",
            configuration=(
                transfer
                / "extensions"
                / "transfer_harness_extension_v1"
                / "configuration.json"
            ).read_bytes(),
            event=_event(
                project_id="agentic-transfer-verifier",
                repository_id="krivonosoff161/agentic-transfer-verifier",
                activity="transfer.verification",
                with_artifact=False,
            ),
            expected_reason="transfer.digest_projection_valid",
        )
        _inspect_approve_construct_bind_run(
            site=site,
            distribution_name="ai-agent-handoff-harness-extension",
            extension_id="ai-agent-handoff.validation",
            configuration=(
                handoff / "extensions" / "harness-v1" / "ash-extension-config.json"
            ).read_bytes(),
            event=_event(
                project_id="ai-agent-handoff",
                repository_id="example/synthetic-handoff",
                activity="handoff.task",
                with_artifact=True,
            ),
            expected_reason="handoff.observation_valid",
        )
    finally:
        sys.path.remove(str(site))
        _restore_companion_modules(saved_companion_modules)


def test_explicit_factory_origin_rejects_import_collision(tmp_path: Path) -> None:
    site = tmp_path / "site"
    site.mkdir()
    expected = site / "candidate_extension.py"
    expected.write_text("def build_extension(): pass\n", encoding="utf-8")
    collision = tmp_path / "collision.py"
    collision.write_text("def build_extension(): pass\n", encoding="utf-8")
    inspection = type(
        "Inspection",
        (),
        {
            "module_name": "candidate_extension",
            "module_path": "candidate_extension.py",
            "factory_attribute": "build_extension",
        },
    )()
    fake = ModuleType("candidate_extension")
    fake.__file__ = str(collision)
    fake.__spec__ = importlib.util.spec_from_file_location("candidate_extension", collision)
    fake.build_extension = lambda: None  # type: ignore[attr-defined]
    sys.modules["candidate_extension"] = fake
    try:
        with pytest.raises(AssertionError, match="origin differs"):
            _explicit_factory(cast(ExtensionDistributionInspectionV1, inspection), site)
    finally:
        sys.modules.pop("candidate_extension", None)


def test_integration_workflow_preserves_first_party_ruff_scope() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ecosystem-integration.yml").read_text(
        encoding="utf-8"
    )
    assert any(
        line.strip() == "python -m ruff check . --exclude components"
        for line in workflow.splitlines()
    )
    assert any(
        line.strip() == "python -m bandit -q -ll -r src"
        for line in workflow.splitlines()
    )
    assert "python -m ruff check src tests tools" not in workflow
    assert "python -m bandit -q -r src" not in workflow
    tracked_first_party = _git(
        ROOT,
        "ls-files",
        "--",
        "examples/*.py",
        "fuzz/*.py",
    ).splitlines()
    assert "examples/fake_openai_server.py" in tracked_first_party
    assert any(path.startswith("fuzz/") for path in tracked_first_party)
