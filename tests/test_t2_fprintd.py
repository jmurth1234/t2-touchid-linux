#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Hardware-free lifecycle tests for the T2 fprintd facade."""

import asyncio
import importlib.util
from pathlib import Path
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "src/t2-fprintd.py"
SPEC = importlib.util.spec_from_file_location("t2_fprintd", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class FakeBackend:
    def __init__(self, verdict="verify-match"):
        self.verdict = verdict
        self.cancel_count = 0

    async def verify(self):
        await asyncio.sleep(0)
        return self.verdict, {}

    async def cancel(self):
        self.cancel_count += 1


class DeviceLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_terminal_verdict_remains_stoppable(self):
        backend = FakeBackend()
        device = MODULE.FprintDevice(backend)
        statuses = []
        device.VerifyStatus = lambda result, done: statuses.append((result, done))

        device.Claim(MODULE.LINUX_USER)
        device.VerifyStart("any")
        task = device.verify_task
        self.assertIsNotNone(task)
        await task

        self.assertEqual(statuses, [("verify-match", True)])
        self.assertIs(device.verify_task, task)
        await MODULE.FprintDevice.VerifyStop.__wrapped__(device)
        self.assertIsNone(device.verify_task)
        self.assertEqual(backend.cancel_count, 1)

    async def test_release_cleans_up_completed_verification(self):
        backend = FakeBackend("verify-no-match")
        device = MODULE.FprintDevice(backend)
        device.VerifyStatus = lambda _result, _done: None

        device.Claim(MODULE.LINUX_USER)
        device.VerifyStart("any")
        await device.verify_task
        await MODULE.FprintDevice.Release.__wrapped__(device)

        self.assertIsNone(device.claimed_user)
        self.assertIsNone(device.verify_task)


class VerdictTests(unittest.TestCase):
    def test_accepts_only_explicit_enrolled_identity_match(self):
        result = {
            "match_events": [
                {
                    "event_kind": "match_result",
                    "matched": True,
                    "matches_enrolled_identity": True,
                }
            ]
        }
        self.assertEqual(MODULE.verdict_from_result(result), "verify-match")

    def test_unenrolled_identity_fails_closed(self):
        result = {
            "match_events": [
                {
                    "event_kind": "match_result",
                    "matched": True,
                    "matches_enrolled_identity": False,
                }
            ]
        }
        self.assertEqual(MODULE.verdict_from_result(result), "verify-no-match")

    def test_missing_or_explicit_no_match_fails_closed(self):
        self.assertEqual(
            MODULE.verdict_from_result({"match_events": []}), "verify-no-match"
        )
        self.assertEqual(
            MODULE.verdict_from_result(
                {"match_events": [{"event_kind": "match_result", "matched": False}]}
            ),
            "verify-no-match",
        )

    def test_rejected_or_malformed_result_is_an_error(self):
        with self.assertRaises(RuntimeError):
            MODULE.verdict_from_result({"match_rejected": True})
        with self.assertRaises(RuntimeError):
            MODULE.verdict_from_result([])
        with self.assertRaises(RuntimeError):
            MODULE.verdict_from_result({"match_events": {}})


if __name__ == "__main__":
    unittest.main()
