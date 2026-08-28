#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Hardware-free lifecycle tests for the T2 fprintd facade."""

import asyncio
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock


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

    async def test_second_claim_is_rejected(self):
        device = MODULE.FprintDevice(FakeBackend())
        device.Claim(MODULE.LINUX_USER)
        with self.assertRaises(MODULE.DBusError) as raised:
            device.Claim(MODULE.LINUX_USER)
        self.assertTrue(raised.exception.type.endswith(".AlreadyInUse"))
        await MODULE.FprintDevice.Release.__wrapped__(device)

    async def test_unstarted_claim_expires(self):
        old_timeout = MODULE.UNSTARTED_CLAIM_SECONDS
        MODULE.UNSTARTED_CLAIM_SECONDS = 0.001
        try:
            device = MODULE.FprintDevice(FakeBackend())
            device.Claim(MODULE.LINUX_USER)
            await asyncio.sleep(0.01)
            self.assertIsNone(device.claimed_user)
        finally:
            MODULE.UNSTARTED_CLAIM_SECONDS = old_timeout

    async def test_verify_stop_cancels_inflight_backend(self):
        started = asyncio.Event()

        class SlowBackend(FakeBackend):
            async def verify(self):
                started.set()
                await asyncio.Event().wait()

        backend = SlowBackend()
        device = MODULE.FprintDevice(backend)
        device.VerifyStatus = lambda _result, _done: None
        device.Claim(MODULE.LINUX_USER)
        device.VerifyStart("any")
        await started.wait()
        await MODULE.FprintDevice.VerifyStop.__wrapped__(device)
        self.assertEqual(backend.cancel_count, 1)
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


class BackendRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_failed_cached_endpoint_is_rediscovered_once(self):
        with tempfile.TemporaryDirectory() as directory:
            port_file = Path(directory) / "port"
            port_file.write_text("50001\n")
            old_port_file = os.environ.get("T2_TOUCHID_PORT_FILE")
            os.environ["T2_TOUCHID_PORT_FILE"] = str(port_file)
            try:
                backend = MODULE.T2Backend(Path(directory), 1)
            finally:
                if old_port_file is None:
                    os.environ.pop("T2_TOUCHID_PORT_FILE", None)
                else:
                    os.environ["T2_TOUCHID_PORT_FILE"] = old_port_file

        backend.notify_finger_requested = AsyncMock()
        backend.notify_feedback = AsyncMock()
        backend._run_probe = AsyncMock(
            side_effect=[
                RuntimeError("stale endpoint"),
                {
                    "match_events": [
                        {
                            "event_kind": "match_result",
                            "matched": True,
                            "matches_enrolled_identity": True,
                        }
                    ]
                },
            ]
        )

        async def discover_fresh():
            backend.port = 50002
            backend.port_from_cache = False
            return backend.port

        original_discover = backend.discover
        calls = 0

        async def discover():
            nonlocal calls
            calls += 1
            if calls == 1:
                return await original_discover()
            return await discover_fresh()

        backend.discover = discover
        verdict, _result = await backend.verify()
        self.assertEqual(verdict, "verify-match")
        self.assertEqual(backend._run_probe.await_count, 2)
        self.assertEqual(calls, 2)

    async def test_valid_negative_match_does_not_rediscover(self):
        backend = MODULE.T2Backend.__new__(MODULE.T2Backend)
        backend.port = 50001
        backend.port_from_cache = True
        backend.notify_finger_requested = AsyncMock()
        backend.notify_feedback = AsyncMock()
        backend.discover = AsyncMock(return_value=50001)
        backend._run_probe = AsyncMock(
            return_value={
                "match_events": [
                    {"event_kind": "match_result", "matched": False}
                ]
            }
        )
        verdict, _result = await backend.verify()
        self.assertEqual(verdict, "verify-no-match")
        backend.discover.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
