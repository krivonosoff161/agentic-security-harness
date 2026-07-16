from pathlib import Path

import pytest

import agentic_security_harness.marketing_web_live_campaign as marketing_live
import agentic_security_harness.swarm_defense_live_campaign as swarm_live
from agentic_security_harness.source_identity import (
    component_fingerprint,
    package_source_root,
)


def test_component_fingerprint_is_order_independent_and_sha256() -> None:
    first = component_fingerprint(("validation.py", "cli.py"))
    second = component_fingerprint(("cli.py", "validation.py", "cli.py"))

    assert first == second
    assert len(first) == 64
    assert first == first.lower()


def test_component_fingerprint_rejects_package_escape() -> None:
    with pytest.raises(ValueError, match="escapes package root"):
        component_fingerprint(("../pyproject.toml",))


def test_package_source_root_is_the_imported_package() -> None:
    root = package_source_root()

    assert root == Path(root).resolve()
    assert (root / "__init__.py").is_file()


def test_live_fingerprints_cover_identity_algorithm_and_artifact_sink() -> None:
    required = {"source_identity.py", "safe_io.py"}

    assert required <= set(swarm_live._IMPLEMENTATION_COMPONENTS)
    assert required <= set(marketing_live._IMPLEMENTATION_COMPONENTS)
