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
MODULE.current_dbus_sender = lambda: ":1.100"


class FakeBackend:
    def __init__(self, verdict="verify-match"):
        self.verdict = verdict
        self.cancel_count = 0

    async def verify(self):
        await asyncio.sleep(0)
        return self.verdict, {}

    async def verify_fprint(self, _requested_finger):
        return await self.verify()

    async def list_fingers(self):
        return (MODULE.ENROLLED_FINGER,)

    async def cancel(self):
        self.cancel_count += 1


class FakePinnedCaller:
    def __init__(self, sender):
        self.sender = sender
        self.closed = False
        self.verify_count = 0

    def verify(self):
        if self.closed:
            raise MODULE.t2_dbus_identity.DBusIdentityError("closed")
        self.verify_count += 1

    def close(self):
        self.closed = True


class FakeClaimEvidence(MODULE.t2_fprint_claim.ClaimEvidence):
    def __init__(self):
        super().__init__("test", 1000, None, None, None, None, None)
        self.revalidate_count = 0
        self.invalid = False

    def revalidate(self, caller):
        caller.verify()
        if self.invalid:
            raise MODULE.t2_fprint_claim.FprintClaimError("changed")
        self.revalidate_count += 1


async def fake_caller_collector(_bus, sender):
    return FakePinnedCaller(sender)


def fake_claim_evidence_collector(_caller, _username):
    return FakeClaimEvidence()


def make_device(backend=None):
    return MODULE.FprintDevice(
        backend or FakeBackend(),
        object(),
        fake_caller_collector,
        fake_claim_evidence_collector,
    )


async def claim(device, username=None):
    await MODULE.FprintDevice.Claim.__wrapped__(
        device, username or MODULE.LINUX_USER
    )


class DeviceLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_complete_historical_property_set_is_available(self):
        device = make_device()
        device.finger_present = True
        request = MODULE.Message(
            destination=MODULE.BUS_NAME,
            path=MODULE.DEVICE_PATH,
            interface="org.freedesktop.DBus.Properties",
            member="GetAll",
            signature="s",
            body=["net.reactivated.Fprint.Device"],
            serial=1,
        )
        reply = MODULE.legacy_property_reply(request, device)
        values = reply.body[0]
        self.assertEqual(
            set(values),
            {
                "name",
                "num-enroll-stages",
                "scan-type",
                "finger-present",
                "finger-needed",
            },
        )
        self.assertEqual(values["num-enroll-stages"].value, -1)
        self.assertTrue(values["finger-present"].value)
        self.assertFalse(values["finger-needed"].value)

    async def test_listing_refreshes_backend_projection(self):
        backend = FakeBackend()
        backend.list_fingers = AsyncMock(
            return_value=("left-thumb", "right-index-finger")
        )
        device = make_device(backend)
        listed = await MODULE.FprintDevice.ListEnrolledFingers.__wrapped__(
            device, MODULE.LINUX_USER
        )
        self.assertEqual(listed, ["left-thumb", "right-index-finger"])
        self.assertEqual(
            device.enrolled_fingers,
            ("left-thumb", "right-index-finger"),
        )

    async def test_any_match_emits_exact_resolved_finger_before_status(self):
        backend = FakeBackend()
        backend.verify_fprint = AsyncMock(
            return_value=(
                "verify-match",
                {
                    "resolved_any_match_gate": {
                        "identity_count": 2,
                        "complete_named_inventory": True,
                        "all_identities_selected": True,
                        "same_connection_inventory_stable": True,
                        "local_live_reconciled": True,
                        "identifiers_redacted": True,
                    },
                    "resolved_any_match_post_attestation": {
                        "identity_state_unchanged": True,
                        "local_components_unchanged": True,
                        "per_user_inventory_unchanged": True,
                        "global_inventory_unchanged": True,
                        "identifiers_redacted": True,
                    },
                    "match_events": [
                        {
                            "event_kind": "match_result",
                            "matched": True,
                            "matches_enrolled_identity": True,
                            "matched_finger_name_present": True,
                            "matched_finger_name": "left-thumb",
                        }
                    ],
                },
            )
        )
        device = make_device(backend)
        emitted = []
        device.VerifyFingerSelected = lambda name: emitted.append(("finger", name))
        device.VerifyFingerMatched = lambda name: emitted.append(("matched", name))
        device.VerifyStatus = lambda result, done: emitted.append(
            ("status", result, done)
        )
        await claim(device)
        device.VerifyStart("any")
        await device.verify_task
        self.assertEqual(
            emitted,
            [
                ("finger", "left-thumb"),
                ("matched", "left-thumb"),
                ("status", "verify-match", True),
            ],
        )

    async def test_empty_listing_uses_upstream_no_prints_error(self):
        backend = FakeBackend()
        backend.list_fingers = AsyncMock(return_value=())
        device = make_device(backend)
        with self.assertRaises(MODULE.DBusError) as raised:
            await MODULE.FprintDevice.ListEnrolledFingers.__wrapped__(
                device, MODULE.LINUX_USER
            )
        self.assertTrue(raised.exception.type.endswith(".NoEnrolledPrints"))

    async def test_terminal_verdict_remains_stoppable(self):
        backend = FakeBackend()
        device = make_device(backend)
        statuses = []
        device.VerifyStatus = lambda result, done: statuses.append((result, done))

        await claim(device)
        device.VerifyStart("any")
        task = device.verify_task
        self.assertIsNotNone(task)
        await task

        self.assertEqual(statuses, [("verify-match", True)])
        self.assertIs(device.verify_task, task)
        await MODULE.FprintDevice.VerifyStop.__wrapped__(device)
        self.assertIsNone(device.verify_task)

    async def test_second_claim_is_rejected(self):
        device = make_device()
        await claim(device)
        with self.assertRaises(MODULE.DBusError) as raised:
            await claim(device)
        self.assertTrue(raised.exception.type.endswith(".AlreadyInUse"))
        await MODULE.FprintDevice.Release.__wrapped__(device)

    async def test_claim_is_bound_to_exact_dbus_sender(self):
        device = make_device()
        await claim(device)
        pinned = device.claimed_caller
        old = MODULE.current_dbus_sender
        MODULE.current_dbus_sender = lambda: ":1.101"
        try:
            with self.assertRaises(MODULE.DBusError) as raised:
                device.VerifyStart("any")
            self.assertTrue(raised.exception.type.endswith(".PermissionDenied"))
            await device.sender_departed(":1.100")
            self.assertIsNone(device.claimed_user)
            self.assertIsNone(device.claimed_sender)
            self.assertIsNone(device.claimed_caller)
            self.assertIsNone(device.claimed_evidence)
            self.assertTrue(pinned.closed)
        finally:
            MODULE.current_dbus_sender = old

    async def test_claim_revalidates_pinned_process_on_every_scoped_call(self):
        device = make_device()
        await claim(device)
        pinned = device.claimed_caller
        self.assertIsNotNone(pinned)
        pinned.closed = True
        with self.assertRaises(MODULE.DBusError) as raised:
            device.VerifyStart("any")
        self.assertTrue(raised.exception.type.endswith(".PermissionDenied"))

    async def test_claim_revalidates_session_and_account_on_scoped_calls(self):
        device = make_device()
        await claim(device)
        evidence = device.claimed_evidence
        self.assertIsNotNone(evidence)
        evidence.invalid = True
        with self.assertRaises(MODULE.DBusError) as raised:
            device.VerifyStart("any")
        self.assertTrue(raised.exception.type.endswith(".PermissionDenied"))

    async def test_departure_waiting_during_claim_clears_the_new_claim(self):
        collecting = asyncio.Event()
        proceed = asyncio.Event()
        pinned = FakePinnedCaller(":1.100")

        async def delayed_collector(_bus, _sender):
            collecting.set()
            await proceed.wait()
            return pinned

        device = MODULE.FprintDevice(
            FakeBackend(),
            object(),
            delayed_collector,
            fake_claim_evidence_collector,
        )
        claim_task = asyncio.create_task(claim(device))
        await collecting.wait()
        departure_task = asyncio.create_task(device.sender_departed(":1.100"))
        proceed.set()
        await claim_task
        await departure_task
        self.assertIsNone(device.claimed_user)
        self.assertTrue(pinned.closed)

    async def test_concurrent_claims_are_serialized(self):
        collecting = asyncio.Event()
        proceed = asyncio.Event()

        async def delayed_collector(_bus, sender):
            collecting.set()
            await proceed.wait()
            return FakePinnedCaller(sender)

        device = MODULE.FprintDevice(
            FakeBackend(),
            object(),
            delayed_collector,
            fake_claim_evidence_collector,
        )
        first = asyncio.create_task(claim(device))
        await collecting.wait()
        second = asyncio.create_task(claim(device))
        proceed.set()
        await first
        with self.assertRaises(MODULE.DBusError) as raised:
            await second
        self.assertTrue(raised.exception.type.endswith(".AlreadyInUse"))
        await MODULE.FprintDevice.Release.__wrapped__(device)

    async def test_failed_claim_evidence_closes_process_pin(self):
        pinned = FakePinnedCaller(":1.100")

        async def caller_collector(_bus, _sender):
            return pinned

        def evidence_collector(_caller, _username):
            raise MODULE.t2_fprint_claim.FprintClaimError("denied")

        device = MODULE.FprintDevice(
            FakeBackend(), object(), caller_collector, evidence_collector
        )
        with self.assertRaises(MODULE.DBusError) as raised:
            await claim(device)
        self.assertTrue(raised.exception.type.endswith(".PermissionDenied"))
        self.assertTrue(pinned.closed)
        self.assertIsNone(device.claimed_user)

    async def test_unstarted_claim_expires(self):
        old_timeout = MODULE.UNSTARTED_CLAIM_SECONDS
        MODULE.UNSTARTED_CLAIM_SECONDS = 0.001
        try:
            device = make_device()
            await claim(device)
            await asyncio.sleep(0.01)
            self.assertIsNone(device.claimed_user)
        finally:
            MODULE.UNSTARTED_CLAIM_SECONDS = old_timeout

    async def test_verify_stop_cancels_inflight_backend(self):
        started = asyncio.Event()

        class SlowBackend(FakeBackend):
            async def verify_fprint(self, _requested_finger):
                started.set()
                await asyncio.Event().wait()

        backend = SlowBackend()
        device = make_device(backend)
        device.VerifyStatus = lambda _result, _done: None
        await claim(device)
        device.VerifyStart("any")
        await started.wait()
        await MODULE.FprintDevice.VerifyStop.__wrapped__(device)
        self.assertEqual(backend.cancel_count, 1)
        self.assertIsNone(device.verify_task)
        self.assertEqual(backend.cancel_count, 1)

    async def test_release_cleans_up_completed_verification(self):
        backend = FakeBackend("verify-no-match")
        device = make_device(backend)
        device.VerifyStatus = lambda _result, _done: None

        await claim(device)
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

    def test_named_match_requires_selected_identity_and_both_attestations(self):
        result = {
            "targeted_match_gate": {
                "finger_name": "left-thumb",
                "single_identity_selected": True,
                "same_connection_inventory_stable": True,
                "local_live_reconciled": True,
                "identifiers_redacted": True,
            },
            "targeted_match_post_attestation": {
                "identity_state_unchanged": True,
                "local_components_unchanged": True,
                "per_user_inventory_unchanged": True,
                "global_inventory_unchanged": True,
                "identifiers_redacted": True,
            },
            "match_events": [
                {
                    "event_kind": "match_result",
                    "matched": True,
                    "matches_enrolled_identity": True,
                    "matches_selected_identity": True,
                }
            ],
        }
        self.assertEqual(
            MODULE.verdict_from_result(result, "left-thumb"),
            "verify-match",
        )
        wrong_identity = {
            **result,
            "match_events": [
                {
                    "event_kind": "match_result",
                    "matched": True,
                    "matches_enrolled_identity": True,
                    "matches_selected_identity": False,
                }
            ],
        }
        self.assertEqual(
            MODULE.verdict_from_result(wrong_identity, "left-thumb"),
            "verify-no-match",
        )

    def test_named_match_missing_or_rebound_attestation_is_error(self):
        base = {
            "targeted_match_gate": {
                "finger_name": "right-thumb",
                "single_identity_selected": True,
                "same_connection_inventory_stable": True,
                "local_live_reconciled": True,
                "identifiers_redacted": True,
            },
            "targeted_match_post_attestation": {
                "identity_state_unchanged": True,
                "local_components_unchanged": True,
                "per_user_inventory_unchanged": True,
                "global_inventory_unchanged": True,
                "identifiers_redacted": True,
            },
            "match_events": [],
        }
        for changed in (
            {**base, "targeted_match_gate": None},
            {**base, "targeted_match_post_attestation": None},
            base,
        ):
            with self.subTest(), self.assertRaises(RuntimeError):
                MODULE.verdict_from_result(changed, "left-thumb")

    def test_resolved_any_returns_only_attested_canonical_name(self):
        result = {
            "resolved_any_match_gate": {
                "identity_count": 2,
                "complete_named_inventory": True,
                "all_identities_selected": True,
                "same_connection_inventory_stable": True,
                "local_live_reconciled": True,
                "identifiers_redacted": True,
            },
            "resolved_any_match_post_attestation": {
                "identity_state_unchanged": True,
                "local_components_unchanged": True,
                "per_user_inventory_unchanged": True,
                "global_inventory_unchanged": True,
                "identifiers_redacted": True,
            },
            "match_events": [
                {
                    "event_kind": "match_result",
                    "matched": True,
                    "matches_enrolled_identity": True,
                    "matched_finger_name_present": True,
                    "matched_finger_name": "left-thumb",
                }
            ],
        }
        self.assertEqual(
            MODULE.resolved_any_finger_from_result(result), "left-thumb"
        )
        negative = {
            **result,
            "match_events": [
                {"event_kind": "match_result", "matched": False}
            ],
        }
        self.assertIsNone(MODULE.resolved_any_finger_from_result(negative))

    def test_resolved_any_malformed_name_or_attestation_is_error(self):
        gate = {
            "identity_count": 2,
            "complete_named_inventory": True,
            "all_identities_selected": True,
            "same_connection_inventory_stable": True,
            "local_live_reconciled": True,
            "identifiers_redacted": True,
        }
        post = {
            "identity_state_unchanged": True,
            "local_components_unchanged": True,
            "per_user_inventory_unchanged": True,
            "global_inventory_unchanged": True,
            "identifiers_redacted": True,
        }
        for candidate in (
            {"resolved_any_match_gate": None, "match_events": []},
            {
                "resolved_any_match_gate": gate,
                "resolved_any_match_post_attestation": post,
                "match_events": [
                    {
                        "event_kind": "match_result",
                        "matched": True,
                        "matches_enrolled_identity": True,
                        "matched_finger_name_present": True,
                        "matched_finger_name": "any",
                    }
                ],
            },
        ):
            with self.subTest(), self.assertRaises(RuntimeError):
                MODULE.resolved_any_finger_from_result(candidate)

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
    async def test_runtime_policy_routes_complete_named_and_legacy_alias(self):
        backend = MODULE.T2Backend.__new__(MODULE.T2Backend)
        backend.operation_lock = asyncio.Lock()
        backend.runtime_projection = AsyncMock()
        backend.verify = AsyncMock(return_value=("verify-match", {}))

        backend.runtime_projection.return_value = MODULE.t2_fprint_runtime.RuntimeProjection(
            ("left-thumb", "right-index-finger"),
            2,
            True,
            MODULE.ENROLLED_FINGER,
        )
        await backend.verify_fprint("left-thumb")
        backend.verify.assert_awaited_once_with(
            target_finger="left-thumb", resolve_any_finger=False
        )

        backend.verify.reset_mock()
        backend.runtime_projection.return_value = MODULE.t2_fprint_runtime.RuntimeProjection(
            (), 2, False, MODULE.ENROLLED_FINGER
        )
        await backend.verify_fprint(MODULE.ENROLLED_FINGER)
        backend.verify.assert_awaited_once_with(
            target_finger=None, resolve_any_finger=False
        )

        backend.verify.reset_mock()
        backend.runtime_projection.return_value = MODULE.t2_fprint_runtime.RuntimeProjection(
            ("left-thumb", "right-index-finger"),
            2,
            True,
            MODULE.ENROLLED_FINGER,
        )
        await backend.verify_fprint("any")
        backend.verify.assert_awaited_once_with(
            target_finger=None, resolve_any_finger=True
        )

    async def test_failed_cached_endpoint_is_rediscovered_once(self):
        with tempfile.TemporaryDirectory() as directory:
            port_file = Path(directory) / "port"
            port_file.write_text("50001\n")
            old_port_file = os.environ.get("T2_TOUCHID_PORT_FILE")
            old_linux_user = MODULE.LINUX_USER
            os.environ["T2_TOUCHID_PORT_FILE"] = str(port_file)
            MODULE.LINUX_USER = "test-user"
            try:
                backend = MODULE.T2Backend(Path(directory), 1)
            finally:
                MODULE.LINUX_USER = old_linux_user
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
