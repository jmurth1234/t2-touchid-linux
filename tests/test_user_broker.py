# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import fcntl
import json
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_ipc_session as ipc_session
import t2_linux_account as linux_account
import t2_polkit_grant as polkit_grant
import t2_user_broker as broker
import t2_user_mapping as mapping
import t2_user_mapping_admin as mapping_admin
import t2_user_policy as policy
import t2_user_readiness as readiness


def identifier(number: int) -> str:
    return str(uuid.UUID(int=number))


def persistent() -> readiness.PersistentEvidence:
    return readiness.PersistentEvidence(
        "a" * 64,
        "b" * 64,
        501,
        identifier(1),
        identifier(2),
        True,
    )


READY = readiness.AliasEvidence(
    True, -501, identifier(2), 0, identifier(1)
)
ABSENT = readiness.AliasEvidence(False, None, None, None, None)


class StepClock:
    def __init__(self, values=None):
        self.values = iter(values) if values is not None else None
        self.value = 1_000

    def __call__(self):
        if self.values is not None:
            return next(self.values)
        self.value += 10
        return self.value


class FakeAuthorizationSession:
    def __init__(self, uid: int, *, denied=(), revalidate_error=False):
        self.caller = policy.CallerEvidence(uid, "a" * 64, True, True)
        self._account = linux_account.AccountEvidence(uid, "a" * 64)
        self._session = ipc_session.SessionEvidence(
            "pidfd-session", "session-1", "wayland", "user", True, 1
        )
        self.denied = set(denied)
        self.revalidate_error = revalidate_error
        self.actions = []
        self.revalidations = 0
        self.entered = False
        self.exited = False

    @property
    def account(self):
        return self._account

    @property
    def session(self):
        return self._session

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, exception_type, exception, traceback):
        self.exited = True
        return False

    def revalidate(self):
        self.revalidations += 1
        if self.revalidate_error:
            raise ipc_session.IPCSessionError("peer changed")

    def collect(self, **arguments):
        self.actions.append(arguments["action"])
        issued = arguments["clock"]()
        authorized = arguments["action"] not in self.denied
        grant = policy.PolicyGrant(
            identifier(100 + len(self.actions)),
            arguments["action"],
            self.caller.linux_uid,
            self.caller.linux_account_generation,
            arguments["target_linux_uid"],
            arguments["mapping_generation"],
            arguments["operation_id"],
            arguments["linux_boot_uuid"],
            arguments["runtime_generation"],
            issued,
            issued + arguments["grant_lifetime_ns"],
            authorized,
        )
        result = polkit_grant.PolkitGrantResult(
            "authorized" if authorized else "denied", grant
        )
        return ipc_session.AuthorizationEvidence(
            self.caller,
            self._account,
            self._session,
            result,
        )


class FakeLiveSession:
    runtime_generation = identifier(20)

    def __init__(self, evidence):
        self.evidence = iter(evidence)
        self.calls = 0
        self.entered = False
        self.exited = False

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, exception_type, exception, traceback):
        self.exited = True
        return False

    def collect(self, selected, account_generation, keybag_sha256):
        if not self.entered or self.exited:
            raise AssertionError("live session is outside its lease")
        if (
            selected.linux_uid <= 0
            or account_generation != "a" * 64
            or keybag_sha256 != "b" * 64
        ):
            raise AssertionError("broker supplied wrong live target")
        self.calls += 1
        return next(self.evidence)


class UserBrokerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.path = self.root / "users.json"
        self.uid = os.getuid() if os.getuid() != 0 else 1000
        selected = mapping.UserMapping(
            self.uid,
            "a" * 64,
            501,
            identifier(1),
            identifier(2),
            f"/var/lib/t2-touchid/users/{self.uid}/user.kb",
            "b" * 64,
            "password-on-demand",
            frozenset({"enroll", "identity-management", "verify"}),
            True,
        )
        self.path.write_bytes(mapping.serialize((selected,)))
        self.path.chmod(0o600)
        self.owner_patches = (
            mock.patch.object(mapping_admin, "ROOT_UID", os.geteuid()),
            mock.patch.object(mapping, "ROOT_UID", os.geteuid()),
        )
        for patcher in self.owner_patches:
            patcher.start()

    def tearDown(self):
        for patcher in reversed(self.owner_patches):
            patcher.stop()
        self.temporary.cleanup()

    @staticmethod
    def keybag(_path):
        return "b" * 64

    def invoke(
        self,
        authorization,
        live,
        consumer,
        *,
        operation="enroll",
        modification_allowed=True,
        clock=None,
        grant_lifetime_ns=500,
        keybag_reader=None,
    ):
        return broker.run_self_service(
            object(),
            operation=operation,
            modification_allowed=modification_allowed,
            consumer=consumer,
            mapping_path=self.path,
            authorization_factory=lambda connection: authorization,
            live_factory=lambda: live,
            keybag_reader=keybag_reader or self.keybag,
            boot_reader=lambda: identifier(21),
            clock=clock or StepClock(),
            allow_user_interaction=False,
            grant_lifetime_ns=grant_lifetime_ns,
        )

    def test_ready_target_keeps_every_lease_through_consumer(self):
        evidence = (persistent(), READY)
        authorization = FakeAuthorizationSession(self.uid)
        live = FakeLiveSession((evidence, evidence, evidence))

        def consume(authority, session):
            self.assertTrue(authorization.entered)
            self.assertFalse(authorization.exited)
            self.assertTrue(live.entered)
            self.assertFalse(live.exited)
            self.assertIs(session, live)
            self.assertEqual(authority.stage, "operate")
            self.assertEqual(authority.selected.linux_uid, self.uid)
            self.assertEqual(authority.runtime_generation, identifier(20))
            lock = os.open(self.root / ".users.json.lock", os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(lock)
            return {"private": identifier(1)}

        result = self.invoke(authorization, live, consume)
        self.assertTrue(result.consumer_invoked)
        self.assertTrue(authorization.exited)
        self.assertTrue(live.exited)
        self.assertEqual(live.calls, 3)
        self.assertEqual(
            authorization.actions, ["org.t2linux.touchid.enroll"]
        )
        rendered = json.dumps(result.redacted(), sort_keys=True)
        self.assertNotIn(identifier(1), rendered)
        self.assertNotIn(str(self.uid), rendered)

    def test_absent_alias_requires_distinct_activation_grant(self):
        evidence = (persistent(), ABSENT)
        authorization = FakeAuthorizationSession(self.uid)
        live = FakeLiveSession((evidence, evidence, evidence))
        stages = []
        result = self.invoke(
            authorization,
            live,
            lambda authority, session: stages.append(authority.stage),
        )
        self.assertTrue(result.consumer_invoked)
        self.assertEqual(stages, ["activate"])
        self.assertEqual(
            authorization.actions,
            [
                "org.t2linux.touchid.enroll",
                "org.t2linux.touchid.activate-user",
            ],
        )

    def test_denied_operation_never_prompts_for_activation_or_calls_consumer(self):
        evidence = (persistent(), ABSENT)
        authorization = FakeAuthorizationSession(
            self.uid, denied={"org.t2linux.touchid.enroll"}
        )
        live = FakeLiveSession((evidence, evidence))
        result = self.invoke(
            authorization,
            live,
            lambda authority, session: self.fail("consumer must not run"),
        )
        self.assertFalse(result.consumer_invoked)
        self.assertEqual(result.decision.state, "operation-policy-denied")
        self.assertEqual(
            authorization.actions, ["org.t2linux.touchid.enroll"]
        )

    def test_denied_activation_or_modification_policy_never_calls_consumer(self):
        absent = (persistent(), ABSENT)
        activation_denied = FakeAuthorizationSession(
            self.uid, denied={"org.t2linux.touchid.activate-user"}
        )
        live = FakeLiveSession((absent, absent))
        result = self.invoke(
            activation_denied,
            live,
            lambda authority, session: self.fail("consumer must not run"),
        )
        self.assertFalse(result.consumer_invoked)
        self.assertEqual(result.decision.state, "activation-policy-denied")

        ready = (persistent(), READY)
        authorization = FakeAuthorizationSession(self.uid)
        live = FakeLiveSession((ready, ready))
        result = self.invoke(
            authorization,
            live,
            lambda authority, session: self.fail("consumer must not run"),
            modification_allowed=False,
        )
        self.assertFalse(result.consumer_invoked)
        self.assertEqual(
            result.decision.state, "fingerprint-modification-disabled"
        )

    def test_live_keybag_or_peer_drift_fails_before_consumer(self):
        first = (persistent(), READY)
        changed = (
            persistent(),
            readiness.AliasEvidence(
                True,
                -501,
                identifier(2),
                readiness.DEVICE_LOCKED,
                identifier(1),
            ),
        )
        cases = (
            (
                FakeAuthorizationSession(self.uid),
                FakeLiveSession((first, changed)),
                lambda: "b" * 64,
            ),
            (
                FakeAuthorizationSession(self.uid, revalidate_error=True),
                FakeLiveSession((first, first)),
                lambda: "b" * 64,
            ),
            (
                FakeAuthorizationSession(self.uid),
                FakeLiveSession((first, first)),
                iter(("b" * 64, "c" * 64)).__next__,
            ),
        )
        for authorization, live, reader in cases:
            with self.subTest(peer_error=authorization.revalidate_error):
                with self.assertRaises(broker.UserBrokerError):
                    self.invoke(
                        authorization,
                        live,
                        lambda authority, session: self.fail(
                            "consumer must not run"
                        ),
                        keybag_reader=lambda path, reader=reader: reader(),
                    )

    def test_expiry_between_decision_and_handoff_touches_no_consumer(self):
        evidence = (persistent(), READY)
        authorization = FakeAuthorizationSession(self.uid)
        live = FakeLiveSession((evidence, evidence, evidence))
        clock = StepClock((1_000, 1_000, 1_002))
        with self.assertRaisesRegex(broker.UserBrokerError, "expired"):
            self.invoke(
                authorization,
                live,
                lambda authority, session: self.fail("consumer must not run"),
                clock=clock,
                grant_lifetime_ns=1,
            )

    def test_root_supported_operation_and_enabled_mapping_are_required(self):
        evidence = (persistent(), READY)
        authorization = FakeAuthorizationSession(self.uid)
        live = FakeLiveSession((evidence, evidence, evidence))
        with mock.patch.object(mapping_admin, "ROOT_UID", os.geteuid() + 1):
            with self.assertRaisesRegex(broker.UserBrokerError, "requires root"):
                self.invoke(
                    authorization, live, lambda authority, session: None
                )
        with self.assertRaisesRegex(broker.UserBrokerError, "unsupported"):
            self.invoke(
                authorization,
                live,
                lambda authority, session: None,
                operation="raw-sep",
            )
        current = mapping.load(self.path)
        self.path.write_bytes(
            mapping.serialize(
                (
                    mapping.UserMapping(
                        **{
                            **current.mappings[0].__dict__,
                            "enabled": False,
                        }
                    ),
                )
            )
        )
        self.path.chmod(0o600)
        with self.assertRaisesRegex(broker.UserBrokerError, "no enabled mapping"):
            self.invoke(authorization, live, lambda authority, session: None)


if __name__ == "__main__":
    unittest.main()
