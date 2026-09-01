# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import fcntl
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_dbus_identity as dbus_identity
import t2_fprint_claim as claim
import t2_ipc_session as ipc
import t2_linux_account as account
import t2_polkit_grant as polkit


class FakeBackend:
    def __init__(self, uid, *, direct=True):
        self.uid = uid
        self.direct = direct
        self.start = 10
        self.active_queries = 0

    def session_for_pidfd(self, _pidfd):
        return "session-1" if self.direct else None

    def active_sessions(self, _uid):
        self.active_queries += 1
        return ("session-1",)

    def describe(self, _session):
        return ipc.SessionDescription(
            self.uid, True, False, "wayland", "user", "seat0", self.start
        )


def resolver(username):
    return SimpleNamespace(pw_name=username, pw_uid=os.getuid())


def collect_account(uid):
    return account.AccountEvidence(uid, "a" * 64)


class FprintClaimTests(unittest.TestCase):
    def caller(self, uid=None):
        selected_uid = os.getuid() if uid is None else uid
        descriptor = os.pidfd_open(os.getpid())
        subject = polkit.read_process_subject(os.getpid(), os.getuid())
        if selected_uid != os.getuid():
            subject = polkit.ProcessSubject(
                subject.pid, selected_uid, subject.start_time_ticks
            )
        return dbus_identity.PinnedDBusCaller(
            ":1.42", subject, descriptor
        )

    def test_collects_and_revalidates_redacted_claim_evidence(self):
        caller = self.caller()
        backend = FakeBackend(os.getuid())
        try:
            evidence = claim.collect(
                caller,
                "jess",
                backend=backend,
                resolver=resolver,
                account_collector=collect_account,
            )
            evidence.revalidate(caller)
            authorization = evidence.authorization_session(caller)
            try:
                self.assertEqual(authorization.caller.linux_uid, os.getuid())
                authorization.revalidate()
            finally:
                authorization.close()
            rendered = str(evidence.redacted())
            self.assertNotIn("jess", rendered)
            self.assertNotIn(str(os.getuid()), rendered)
        finally:
            caller.close()

    def test_session_change_fails_revalidation(self):
        caller = self.caller()
        backend = FakeBackend(os.getuid())
        try:
            evidence = claim.collect(
                caller,
                "jess",
                backend=backend,
                resolver=resolver,
                account_collector=collect_account,
            )
            backend.start += 1
            with self.assertRaisesRegex(claim.FprintClaimError, "session changed"):
                evidence.revalidate(caller)
        finally:
            caller.close()

    def test_account_change_fails_revalidation(self):
        caller = self.caller()
        backend = FakeBackend(os.getuid())
        generation = ["a" * 64]

        def changing_account(uid):
            return account.AccountEvidence(uid, generation[0])

        try:
            evidence = claim.collect(
                caller,
                "jess",
                backend=backend,
                resolver=resolver,
                account_collector=changing_account,
            )
            generation[0] = "b" * 64
            with self.assertRaisesRegex(claim.FprintClaimError, "account changed"):
                evidence.revalidate(caller)
        finally:
            caller.close()

    def test_nonroot_cannot_bind_another_users_session(self):
        caller = self.caller()
        different_uid = os.getuid() + 1

        def other_resolver(username):
            return SimpleNamespace(pw_name=username, pw_uid=different_uid)

        try:
            with self.assertRaisesRegex(
                claim.FprintClaimError, "login assertion"
            ):
                claim.collect(
                    caller,
                    "another-user",
                    backend=FakeBackend(different_uid),
                    resolver=other_resolver,
                    account_collector=collect_account,
                )
        finally:
            caller.close()

    def test_root_requires_direct_session_binding_to_target_user(self):
        target_uid = os.getuid()
        original_subject = polkit.read_process_subject(os.getpid(), os.getuid())
        root_subject = polkit.ProcessSubject(
            original_subject.pid, 0, original_subject.start_time_ticks
        )

        def root_process_subject(_pid, _uid, **_kwargs):
            return root_subject

        def target_resolver(username):
            return SimpleNamespace(pw_name=username, pw_uid=target_uid)

        for direct, succeeds in ((True, True), (False, False)):
            caller = dbus_identity.PinnedDBusCaller(
                ":1.50", root_subject, os.pidfd_open(os.getpid())
            )
            backend = FakeBackend(target_uid, direct=direct)
            try:
                with mock.patch.object(
                    polkit, "read_process_subject", root_process_subject
                ):
                    if succeeds:
                        evidence = claim.collect(
                            caller,
                            "jess",
                            backend=backend,
                            resolver=target_resolver,
                            account_collector=collect_account,
                        )
                        self.assertEqual(evidence.linux_uid, target_uid)
                        self.assertEqual(backend.active_queries, 0)
                        with self.assertRaisesRegex(
                            claim.FprintClaimError, "cannot authorize mutation"
                        ):
                            evidence.authorization_session(caller)
                    else:
                        with self.assertRaisesRegex(
                            claim.FprintClaimError, "login assertion"
                        ):
                            claim.collect(
                                caller,
                                "jess",
                                backend=backend,
                                resolver=target_resolver,
                                account_collector=collect_account,
                            )
                        self.assertEqual(backend.active_queries, 0)
            finally:
                caller.close()
        self.assertEqual(original_subject.uid, os.getuid())


if __name__ == "__main__":
    unittest.main()
