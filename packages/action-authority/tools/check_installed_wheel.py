"""Check one wheel's RECORD and exact source/wheel/venv package bytes."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import importlib
import importlib.metadata
import io
import json
import platform
import sys
import zipfile
from pathlib import Path

PACKAGE = "ash_action_authority"
DIST = "ash-action-authority-candidate"


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def _installed(name: str) -> Path:
    module = importlib.import_module(name)
    path = Path(module.__file__).resolve()
    _require(sys.prefix != sys.base_prefix, "isolated_venv_required")
    _require(Path(sys.prefix).resolve() in path.parents, "venv_import_required")
    _require("site-packages" in path.parts or "dist-packages" in path.parts,
             "site_packages_import_required")
    return path.parent


def check(wheel: Path, source: Path) -> dict:
    wheel = wheel.resolve(strict=True)
    source = source.resolve(strict=True)
    _require(wheel.is_file() and wheel.stat().st_size <= 10_000_000, "wheel_size_invalid")
    installed = _installed(PACKAGE)
    _installed("agentic_security_harness")
    harness_version = importlib.metadata.version("agentic-security-harness")
    _require(harness_version == "1.14.1", "wrong_installed_harness_version")
    source_files = sorted((source / "src" / PACKAGE).glob("*.py"))
    _require(bool(source_files), "source_package_missing")
    expected_members = {f"{PACKAGE}/{path.name}" for path in source_files}
    checked = {}
    with zipfile.ZipFile(wheel) as archive:
        members = archive.namelist()
        _require(len(members) == len(set(members)), "duplicate_wheel_members")
        _require(len(members) <= 100, "wheel_member_count_invalid")
        _require(all(not name.startswith("/") and ".." not in Path(name).parts
                     for name in members), "wheel_path_invalid")
        records = [name for name in members if name.endswith(".dist-info/RECORD")]
        _require(len(records) == 1, "record_count_invalid")
        _require(archive.getinfo(records[0]).file_size <= 100_000, "record_size_invalid")
        rows = list(csv.reader(io.StringIO(archive.read(records[0]).decode("utf-8"))))
        _require(all(len(row) == 3 for row in rows), "record_shape_invalid")
        _require({row[0] for row in rows} == set(members), "record_members_differ")
        _require(len(rows) == len(members), "record_duplicate_member")
        for name, encoded, length in rows:
            if name == records[0]:
                _require(not encoded and not length, "record_self_hash_invalid")
                continue
            _require(archive.getinfo(name).file_size <= 2_000_000, "wheel_member_oversize")
            data = archive.read(name)
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest())
            digest = digest.decode("ascii").rstrip("=")
            _require(encoded == f"sha256={digest}" and length == str(len(data)),
                     "wheel_record_integrity_failed")
        package_members = {name for name in members if name.startswith(f"{PACKAGE}/")}
        _require(package_members == expected_members, "wheel_source_members_differ")
        _require({path.name for path in installed.glob("*.py")}
                 == {path.name for path in source_files}, "installed_members_differ")
        for path in source_files:
            data = archive.read(f"{PACKAGE}/{path.name}")
            _require(data == path.read_bytes() == (installed / path.name).read_bytes(),
                     "source_wheel_install_bytes_differ")
            checked[f"src/{PACKAGE}/{path.name}"] = hashlib.sha256(data).hexdigest()
    return {
        "schema": "action-authority-wheel-check-v1",
        "success": True,
        "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "candidate_version": importlib.metadata.version(DIST),
        "harness_version": harness_version,
        "record_integrity": True,
        "exact_source_wheel_install": True,
        "source_files": checked,
        "python": platform.python_version(),
        "platform": platform.system(),
        "machine": platform.machine(),
        "synthetic_approvals_are_not_human_consent": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = check(args.wheel, args.source)
        code = 0
    except (ValueError, OSError, zipfile.BadZipFile, KeyError, UnicodeError) as exc:
        # Only a fixed reason is retained; no paths, source content, or exception trace.
        known = str(exc)
        reasons = {
            "wheel_size_invalid", "isolated_venv_required", "venv_import_required",
            "site_packages_import_required", "wrong_installed_harness_version",
            "source_package_missing", "duplicate_wheel_members", "wheel_member_count_invalid",
            "wheel_path_invalid", "record_count_invalid", "record_size_invalid",
            "record_shape_invalid", "record_members_differ", "record_duplicate_member",
            "record_self_hash_invalid", "wheel_member_oversize", "wheel_record_integrity_failed",
            "wheel_source_members_differ", "installed_members_differ",
            "source_wheel_install_bytes_differ",
        }
        result = {"schema": "action-authority-wheel-check-v1", "success": False,
                  "reason": known if known in reasons else "wheel_check_failed"}
        code = 1
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x", encoding="ascii") as stream:
        json.dump(result, stream, sort_keys=True, indent=2, ensure_ascii=True)
    print(json.dumps({"success": code == 0, "reason": result.get("reason", "verified")}))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
