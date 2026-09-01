# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_dbus_identity as dbus_identity
import t2_fprint_broker as adapter
import t2_fprint_claim as claim
import t2_ipc_session as ipc
import t2_linux_account as account
import t2_polkit_grant as polkit
import t2_user_broker as broker


class FakeAuthorization:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class FprintBrokerTests(unittest.TestCase):
    def setUp(self):
        subject = polkit.read_process_subject(os.getpid(), os.getuid())
        self.caller = dbus_identity.PinnedDBusCaller(
            ":1.60", subject, os.pidfd_open(os.getpid())
        )
        self.evidence = claim.ClaimEvidence(
            "jess",
            os.getuid(),
            account.AccountEvidence(os.getuid(), "a" * 64),
            ipc.SessionEvidence(
                "pidfd-session", "session-1", "wayland", "user", True, 1
            ),
            SimpleNamespace(),
            lambda name: SimpleNamespace(pw_name=name, pw_uid=os.getuid()),
            lambda uid: account.AccountEvidence(uid, "a" * 64),
        )

    def tearDown(self):
        self.caller.close()

    def test_exact_claim_authorization_is_handed_to_broker_and_closed(self):
        authorization = FakeAuthorization()
        expected = mock.sentinel.result
        with mock.patch.object(
            claim.ClaimEvidence,
            "authorization_session",
            return_value=authorization,
        ), mock.patch.object(
            adapter.t2_user_broker,
            "run_self_service",
            return_value=expected,
        ) as run:
            result = adapter.run_mutation(
                self.caller,
                self.evidence,
                operation="enroll",
                consumer=lambda authority, session: None,
            )
        self.assertIs(result, expected)
        self.assertTrue(authorization.closed)
        arguments = run.call_args
        self.assertEqual(arguments.args, (None,))
        self.assertEqual(arguments.kwargs["operation"], "enroll")
        self.assertTrue(arguments.kwargs["modification_allowed"])
        self.assertIs(arguments.kwargs["authorization_manager"], authorization)

    def test_broker_failure_still_closes_authorization(self):
        authorization = FakeAuthorization()
        with mock.patch.object(
            claim.ClaimEvidence,
            "authorization_session",
            return_value=authorization,
        ), mock.patch.object(
            adapter.t2_user_broker,
            "run_self_service",
            side_effect=broker.UserBrokerError("denied"),
        ), self.assertRaises(adapter.FprintBrokerError):
            adapter.run_mutation(
                self.caller,
                self.evidence,
                operation="identity-management",
                consumer=lambda authority, session: None,
            )
        self.assertTrue(authorization.closed)

    def test_unsupported_or_malformed_requests_never_derive_authority(self):
        with mock.patch.object(
            claim.ClaimEvidence, "authorization_session"
        ) as derive:
            for operation in ("verify", "raw-sep", ""):
                with self.subTest(operation=operation), self.assertRaises(
                    adapter.FprintBrokerError
                ):
                    adapter.run_mutation(
                        self.caller,
                        self.evidence,
                        operation=operation,
                        consumer=lambda authority, session: None,
                    )
            derive.assert_not_called()


if __name__ == "__main__":
    unittest.main()
