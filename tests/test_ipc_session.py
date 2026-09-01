# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import fcntl
import os
import socket
import subprocess
import sys
import unittest
import uuid
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_ipc_session as ipc
import t2_linux_account as linux_account
import t2_polkit_grant


def identifier(number: int) -> str:
    return str(uuid.UUID(int=number))


class FakeBackend:
    def __init__(self, direct="session-1", sessions=(), descriptions=None):
        self.direct = direct
        self.sessions = tuple(sessions)
        self.descriptions = descriptions or {
            "session-1": ipc.SessionDescription(
                os.getuid(), True, False, "wayland", "user", "seat0"
            )
        }
        self.pidfd = None

    def session_for_pidfd(self, pidfd):
        self.pidfd = pidfd
        return self.direct

    def active_sessions(self, uid):
        return self.sessions

    def describe(self, session):
        value = self.descriptions[session]
        if isinstance(value, BaseException):
            raise value
        return value


class IPCSessionTests(unittest.TestCase):
    def setUp(self):
        self.left, self.right = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_STREAM
        )

    def tearDown(self):
        self.left.close()
        self.right.close()

    def test_peer_credentials_and_pidfd_are_kernel_pinned(self):
        with ipc.PinnedPeer.from_socket(self.left) as peer:
            self.assertEqual(peer.subject.pid, os.getpid())
            self.assertEqual(peer.subject.uid, os.getuid())
            self.assertGreater(peer.subject.start_time_ticks, 0)
            self.assertEqual(
                fcntl.fcntl(peer.pidfd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC,
                fcntl.FD_CLOEXEC,
            )
            self.assertEqual(peer.verify(), peer.subject)
            descriptor = peer.pidfd
        with self.assertRaises(OSError):
            fcntl.fcntl(descriptor, fcntl.F_GETFD)

    def test_direct_pidfd_session_must_be_active_local_user_on_a_seat(self):
        with ipc.PinnedPeer.from_socket(self.left) as peer:
            result = ipc.collect_session(peer, FakeBackend())
        self.assertEqual(result.binding, "pidfd-session")
        self.assertTrue(result.active_local_session)
        self.assertTrue(result.seat_attached)
        self.assertNotIn("session-1", str(result.redacted()))
        caller = result.caller("a" * 64, os.getuid())
        self.assertTrue(caller.authenticated)
        self.assertTrue(caller.active_local_session)

    def test_user_manager_process_uses_one_unique_active_uid_session(self):
        backend = FakeBackend(
            direct=None,
            sessions=("session-1", "remote"),
            descriptions={
                "session-1": ipc.SessionDescription(
                    os.getuid(), True, False, "wayland", "user", "seat0"
                ),
                "remote": ipc.SessionDescription(
                    os.getuid(), True, True, "tty", "user", None
                ),
            },
        )
        with ipc.PinnedPeer.from_socket(self.left) as peer:
            result = ipc.collect_session(peer, backend)
        self.assertEqual(result.binding, "uid-active-session")

    def test_stale_fallback_rows_are_ineligible_but_direct_errors_are_fatal(self):
        valid = ipc.SessionDescription(
            os.getuid(), True, False, "wayland", "user", "seat0"
        )
        backend = FakeBackend(
            direct=None,
            sessions=("stale", "session-1"),
            descriptions={
                "stale": ipc.SessionUnavailable("gone"),
                "session-1": valid,
            },
        )
        with ipc.PinnedPeer.from_socket(self.left) as peer:
            result = ipc.collect_session(peer, backend)
        self.assertEqual(result.session_id, "session-1")
        backend = FakeBackend(
            direct="stale",
            descriptions={"stale": ipc.SessionUnavailable("gone")},
        )
        with ipc.PinnedPeer.from_socket(self.left) as peer:
            with self.assertRaises(ipc.IPCSessionError):
                ipc.collect_session(peer, backend)
        backend = FakeBackend(
            direct=None,
            sessions=("broken", "session-1"),
            descriptions={
                "broken": ipc.IPCSessionError("backend failure"),
                "session-1": valid,
            },
        )
        with ipc.PinnedPeer.from_socket(self.left) as peer:
            with self.assertRaisesRegex(ipc.IPCSessionError, "backend failure"):
                ipc.collect_session(peer, backend)

    def test_ambiguous_or_unsafe_sessions_fail_closed(self):
        uid = os.getuid()
        unsafe = (
            ipc.SessionDescription(uid + 1, True, False, "wayland", "user", "seat0"),
            ipc.SessionDescription(uid, False, False, "wayland", "user", "seat0"),
            ipc.SessionDescription(uid, True, True, "wayland", "user", "seat0"),
            ipc.SessionDescription(uid, True, False, "unspecified", "user", "seat0"),
            ipc.SessionDescription(uid, True, False, "wayland", "greeter", "seat0"),
            ipc.SessionDescription(uid, True, False, "wayland", "user", None),
        )
        for description in unsafe:
            with self.subTest(description=description):
                backend = FakeBackend(descriptions={"session-1": description})
                with ipc.PinnedPeer.from_socket(self.left) as peer:
                    with self.assertRaises(ipc.IPCSessionError):
                        ipc.collect_session(peer, backend)

        valid = ipc.SessionDescription(
            uid, True, False, "wayland", "user", "seat0"
        )
        backend = FakeBackend(
            direct=None,
            sessions=("one", "two"),
            descriptions={"one": valid, "two": valid},
        )
        with ipc.PinnedPeer.from_socket(self.left) as peer:
            with self.assertRaisesRegex(ipc.IPCSessionError, "unique"):
                ipc.collect_session(peer, backend)

    def test_non_socket_and_invalid_account_generation_are_rejected(self):
        with self.assertRaises(ipc.IPCSessionError):
            ipc.PinnedPeer.from_socket(object())
        with ipc.PinnedPeer.from_socket(self.left) as peer:
            result = ipc.collect_session(peer, FakeBackend())
        with self.assertRaises(ipc.IPCSessionError):
            result.caller("not-a-digest", os.getuid())

    def test_live_libsystemd_backend_loads_and_validates_session_ids(self):
        backend = ipc.LibsystemdSessionBackend()
        with self.assertRaises(ipc.IPCSessionError):
            backend.describe("../unsafe")

    def test_join_keeps_pidfd_and_session_stable_across_policy_check(self):
        backend = FakeBackend()
        commands = []

        def account_collector(uid):
            return linux_account.AccountEvidence(uid, "a" * 64)

        def runner(command, timeout):
            commands.append((command, timeout))
            return subprocess.CompletedProcess(command, 0, b"", b"")

        result = ipc.collect_authorization(
            self.left,
            target_linux_uid=os.getuid(),
            action="org.t2linux.touchid.enroll",
            mapping_generation="b" * 64,
            operation_id=identifier(10),
            linux_boot_uuid=identifier(11),
            runtime_generation=identifier(12),
            allow_user_interaction=False,
            backend=backend,
            pkcheck=Path("/test/pkcheck"),
            runner=runner,
            clock=lambda: 1_000,
            grant_lifetime_ns=500,
            timeout_seconds=5,
            account_collector=account_collector,
        )
        self.assertTrue(result.caller.active_local_session)
        self.assertTrue(result.policy.grant.authorized)
        self.assertEqual(
            result.policy.grant.runtime_generation, identifier(12)
        )
        self.assertEqual(len(commands), 1)
        rendered = str(result.redacted())
        self.assertNotIn(identifier(10), rendered)
        self.assertNotIn(str(os.getuid()), rendered)

    def test_join_rejects_session_change_during_policy_interaction(self):
        backend = FakeBackend()

        def account_collector(uid):
            return linux_account.AccountEvidence(uid, "a" * 64)

        def runner(command, timeout):
            backend.descriptions["session-1"] = ipc.SessionDescription(
                os.getuid(), True, False, "wayland", "user", "seat0", 2
            )
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with self.assertRaises(ipc.IPCSessionError):
            ipc.collect_authorization(
                self.left,
                target_linux_uid=os.getuid(),
                action="org.t2linux.touchid.enroll",
                mapping_generation="b" * 64,
                operation_id=identifier(10),
                linux_boot_uuid=identifier(11),
                runtime_generation=identifier(12),
                allow_user_interaction=False,
                backend=backend,
                pkcheck=Path("/test/pkcheck"),
                runner=runner,
                clock=lambda: 1_000,
                account_collector=account_collector,
            )

    def test_join_rejects_account_change_during_policy_interaction(self):
        backend = FakeBackend()
        generations = iter(("a" * 64, "c" * 64))

        def account_collector(uid):
            return linux_account.AccountEvidence(uid, next(generations))

        def runner(command, timeout):
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with self.assertRaisesRegex(ipc.IPCSessionError, "account changed"):
            ipc.collect_authorization(
                self.left,
                target_linux_uid=os.getuid(),
                action="org.t2linux.touchid.enroll",
                mapping_generation="b" * 64,
                operation_id=identifier(10),
                linux_boot_uuid=identifier(11),
                runtime_generation=identifier(12),
                allow_user_interaction=False,
                backend=backend,
                pkcheck=Path("/test/pkcheck"),
                runner=runner,
                clock=lambda: 1_000,
                account_collector=account_collector,
            )

    def test_join_rejects_malformed_account_evidence_before_policy(self):
        backend = FakeBackend()

        for evidence in (
            object(),
            linux_account.AccountEvidence(os.getuid() + 1, "a" * 64),
            linux_account.AccountEvidence(os.getuid(), "bad"),
            linux_account.AccountEvidence(
                os.getuid(), "a" * 64, protected_password_record=False
            ),
        ):
            with self.subTest(evidence=repr(evidence)):
                with self.assertRaisesRegex(
                    ipc.IPCSessionError, "invalid evidence"
                ):
                    ipc.collect_authorization(
                        self.left,
                        target_linux_uid=os.getuid(),
                        action="org.t2linux.touchid.enroll",
                        mapping_generation="b" * 64,
                        operation_id=identifier(10),
                        linux_boot_uuid=identifier(11),
                        runtime_generation=identifier(12),
                        allow_user_interaction=False,
                        backend=backend,
                        pkcheck=Path("/test/pkcheck"),
                        runner=lambda command, timeout: self.fail(
                            "PolicyKit must not run"
                        ),
                        clock=lambda: 1_000,
                        account_collector=lambda uid, value=evidence: value,
                    )


if __name__ == "__main__":
    unittest.main()
