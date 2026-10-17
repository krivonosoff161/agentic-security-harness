"""Actual finite child-process races/deaths on owned fixture files, no model."""

import hashlib
import multiprocessing as mp
import os
import tempfile
import time
import unittest
from pathlib import Path

from ash_action_authority import ActionGate, AuthorityBusy, canonical, decision_message
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentic_security_harness.workspace_writer import GuardedWorkspace, WorkspacePolicy


def child(root, policy, config, mode, start, entered, release, results):
    gate = ActionGate.open(root, policy, **config)
    if mode == "after_begin":
        original = gate._save

        def save(state, **kwargs):
            original(state, **kwargs)
            if kwargs.get("kind") == "begin":
                os._exit(81)

        gate._save = save
    elif mode == "after_permission":
        factory = gate._operation

        def operation():
            op = factory()
            authorize = op.authorize

            def crash_authorize():
                authorize()
                os._exit(82)

            op.authorize = crash_authorize
            return op

        gate._operation = operation
    elif mode == "after_file_before_core_commit":
        submit = GuardedWorkspace.submit

        def crash_submit(self, proposal):
            result = submit(self, proposal)
            if result.get("applied"):
                os._exit(83)
            return result

        GuardedWorkspace.submit = crash_submit
    elif mode == "before_outer_outcome":
        original = gate._save

        def save(state, **kwargs):
            if kwargs.get("kind") == "outcome":
                os._exit(84)
            return original(state, **kwargs)

        gate._save = save
    elif mode == "slow_delivery":
        factory = gate._operation

        def operation():
            op = factory()
            deliver = op.deliver

            def blocked(permission):
                entered.set()
                if not release.wait(20):
                    raise RuntimeError("fixture_release_timeout")
                return deliver(permission)

            op.deliver = blocked
            return op

        gate._operation = operation
    if start is not None and not start.wait(20):
        raise RuntimeError("fixture_start_timeout")
    results.put(gate.submit(config["content"]))


class ProcessChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ash-signed-process-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.ctx = mp.get_context("spawn")

    def fixture(self, name):
        base = self.base / name
        base.mkdir()
        output = base / "output"
        output.mkdir()
        (output / "protected.txt").write_bytes(b"unchanged")
        policy = WorkspacePolicy(output, (("report", "report.md"),), data_class="public")
        key = Ed25519PrivateKey.generate()
        config = dict(
            content="Actual process fixture report.\n",
            operation_id=hashlib.sha256(name.encode()).hexdigest(),
            artifact="report",
            public_key=key.public_key().public_bytes_raw(),
            key_id="fixture-key",
            app_id="process-test",
            task_id=name,
            initiator="fixture-agent",
            expires_at=int(time.time()) + 3600,
        )
        root = base / "authority"
        gate = ActionGate.create(root, policy, **config)
        message = decision_message(gate.request(), decision="approve", issued_at=int(time.time()))
        gate.apply_decision(message, key.sign(canonical(message)))
        return root, policy, config, gate, key

    def launch(self, root, policy, config, mode, start=None, entered=None, release=None):
        results = self.ctx.Queue()
        p = self.ctx.Process(
            target=child, args=(root, policy, config, mode, start, entered, release, results)
        )
        p.start()

        def cleanup():
            if p.is_alive():
                p.terminate()
                p.join(5)
            results.close()

        self.addCleanup(cleanup)
        return p, results

    def test_two_real_processes_admit_only_one_effect(self):
        root, policy, config, gate, _ = self.fixture("race")
        start = self.ctx.Event()
        first, one = self.launch(root, policy, config, "normal", start=start)
        second, two = self.launch(root, policy, config, "normal", start=start)
        start.set()
        first.join(20)
        second.join(20)
        self.assertEqual((first.exitcode, second.exitcode), (0, 0))
        observed = [one.get(timeout=2), two.get(timeout=2)]
        self.assertEqual(sum(v["applied"] for v in observed), 1)
        self.assertEqual(
            sorted(v["reason"] for v in observed), ["already_consumed", "writer_receipt_durable"]
        )
        self.assertTrue(gate.recover()["current_verified"])

    def test_actual_crash_points_recover_without_delivery_replay(self):
        variants = [
            ("after_begin", 81, "FENCED_ABSENT"),
            ("after_permission", 82, "FENCED_ABSENT"),
            ("after_file_before_core_commit", 83, "RECONCILED_POSTCONDITION"),
            ("before_outer_outcome", 84, "DELIVERED_RECEIPT"),
        ]
        for mode, exitcode, expected in variants:
            with self.subTest(mode=mode):
                root, policy, config, gate, _ = self.fixture(mode)
                process, _ = self.launch(root, policy, config, mode)
                process.join(20)
                self.assertEqual(process.exitcode, exitcode)
                reopened = ActionGate.open(root, policy, **config)
                recovered = reopened.recover()
                self.assertEqual(recovered["state"], expected)
                self.assertTrue(recovered["current_verified"])
                self.assertEqual(reopened.submit(config["content"])["reason"], "already_consumed")
                for _ in range(35):
                    self.assertTrue(reopened.recover()["current_verified"])
                target = policy.output_dir / "report.md"
                self.assertEqual(target.exists(), expected != "FENCED_ABSENT")
                if target.exists():
                    self.assertEqual(target.read_bytes(), config["content"].encode())
                self.assertEqual((policy.output_dir / "protected.txt").read_bytes(), b"unchanged")

    def test_inflight_revoke_is_never_acknowledged_as_cancellation(self):
        root, policy, config, gate, key = self.fixture("slow")
        revoke = decision_message(gate.request(), decision="revoke", issued_at=int(time.time()))
        signature = key.sign(canonical(revoke))
        entered, release = self.ctx.Event(), self.ctx.Event()
        process, results = self.launch(
            root, policy, config, "slow_delivery", entered=entered, release=release
        )
        self.assertTrue(entered.wait(10))
        try:
            with self.assertRaises(AuthorityBusy):
                gate.apply_decision(revoke, signature)
        finally:
            release.set()
        process.join(20)
        self.assertEqual(process.exitcode, 0)
        self.assertTrue(results.get(timeout=2)["applied"])
        observed = gate.apply_decision(revoke, signature)
        self.assertFalse(observed["accepted"])
        self.assertEqual(observed["reason"], "too_late_or_in_flight")


if __name__ == "__main__":
    unittest.main()
