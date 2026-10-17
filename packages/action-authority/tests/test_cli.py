"""Content-free host CLI results; all paths and keys are synthetic fixtures."""

from __future__ import annotations

import json
import sqlite3
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from ash_action_authority import host
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class HostCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / "new-home"

    def cli(self, *arguments: str) -> tuple[int, dict, str]:
        shown = StringIO()
        with redirect_stdout(shown):
            code = host.main(list(arguments))
        raw = shown.getvalue()
        return code, json.loads(raw), raw

    def test_missing_setup_input_returns_content_free_nonzero_json(self) -> None:
        code, result, raw = self.cli(
            "setup",
            "--home",
            str(self.home),
            "--public-key",
            str(self.root / "absent.hex"),
            "--source",
            str(self.root / "absent-source"),
            "--document",
            str(self.root / "absent-document"),
            "--host-revision",
            "a" * 40,
            "--allow-local-source-use",
        )
        self.assertEqual(code, 1)
        self.assertEqual(set(result), {"ok", "reason", "next_step"})
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "input_or_state_refused")
        self.assertIn("public input paths", result["next_step"])
        self.assertNotIn(str(self.root), raw)
        self.assertFalse(self.home.exists())

    def test_existing_home_requires_new_directory(self) -> None:
        self.home.mkdir()
        code, result, raw = self.cli(
            "setup",
            "--home",
            str(self.home),
            "--public-key",
            str(self.root / "absent.hex"),
            "--source",
            str(self.root / "absent-source"),
            "--document",
            str(self.root / "absent-document"),
            "--host-revision",
            "a" * 40,
            "--allow-local-source-use",
        )
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "home_exists_use_new_directory")
        self.assertIn("new empty directory", result["next_step"])
        self.assertNotIn(str(self.root), raw)

    def test_malformed_detached_decision_refuses_without_echo(self) -> None:
        decision = self.root / "malformed-decision.json"
        decision.write_bytes(b'{"private":"SENSITIVE-FIXTURE",broken}')
        code, result, raw = self.cli(
            "apply-decision", "--home", str(self.home), "--decision", str(decision)
        )
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "decision_invalid_or_unverified")
        self.assertIn("operator review", result["next_step"])
        self.assertNotIn("SENSITIVE-FIXTURE", raw)
        self.assertNotIn(str(decision), raw)

    def test_refused_run_exits_nonzero_without_creating_target(self) -> None:
        signer = Ed25519PrivateKey.generate()
        public = signer.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        public_path = self.root / "synthetic-public.hex"
        public_path.write_text(public.hex(), encoding="ascii")
        source = self.root / "declared-public-source.txt"
        source.write_bytes(b"Synthetic public source.\n")
        document = self.root / "proposal.txt"
        document.write_bytes(b"Synthetic proposed document.\n")
        setup_code, _, _ = self.cli(
            "setup",
            "--home",
            str(self.home),
            "--public-key",
            str(public_path),
            "--source",
            str(source),
            "--document",
            str(document),
            "--host-revision",
            "a" * 40,
            "--allow-local-source-use",
        )
        self.assertEqual(setup_code, 0)
        code, result, raw = self.cli("run", "--home", str(self.home))
        self.assertEqual(code, 1)
        self.assertFalse(result["applied"])
        self.assertEqual(result["reason"], "not_approved")
        self.assertIn("status --recover", result["next_step"])
        self.assertNotIn("Synthetic proposed document", raw)
        self.assertFalse((self.home / "output" / "document.md").exists())

    def test_synthetic_post_effect_sql_failure_reports_unknown_not_no_effect(self) -> None:
        target = self.root / "synthetic-target.txt"

        class EffectThenStorageFailure:
            content = "Synthetic public document."

            def submit(self, content: str) -> dict:
                target.write_text(content, encoding="utf-8")
                raise sqlite3.OperationalError("SENSITIVE-FIXTURE storage detail")

        with patch("ash_action_authority.host._restore", return_value=EffectThenStorageFailure()):
            code, result, raw = self.cli("run", "--home", str(self.home))
        self.assertEqual(code, 2)
        self.assertEqual(result["reason"], "effect_outcome_unknown")
        self.assertIn("status --recover", result["next_step"])
        self.assertIn("do not replay", result["next_step"])
        self.assertEqual(target.read_text(encoding="utf-8"), "Synthetic public document.")
        self.assertNotIn("SENSITIVE-FIXTURE", raw)
        self.assertNotIn("no_effect", raw)

    def test_busy_approval_reports_no_acknowledgement(self) -> None:
        with patch(
            "ash_action_authority.host.apply", side_effect=host.AuthorityBusy("SENSITIVE-FIXTURE")
        ):
            code, result, raw = self.cli(
                "apply-decision",
                "--home",
                str(self.home),
                "--decision",
                str(self.root / "decision.json"),
            )
        self.assertEqual(code, 2)
        self.assertEqual(result["reason"], "busy_no_decision_acknowledged")
        self.assertIn("No decision was acknowledged", result["next_step"])
        self.assertNotIn("SENSITIVE-FIXTURE", raw)


if __name__ == "__main__":
    unittest.main()
