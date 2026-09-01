# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import asyncio
import os
import socket
import sys
import tempfile
import threading
import unittest
import uuid
from pathlib import Path
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))

import t2_dbus_identity as dbus_identity
import t2_fprint_claim as claim
import t2_fprint_enrollment_runtime as runtime
import t2_fprint_worker_client as client
import t2_fprint_worker_launcher as launcher
import t2_fprint_worker_protocol as protocol
import t2_ipc_session as ipc
import t2_linux_account as account
import t2_polkit_grant as polkit


class Backend:
    pass


class FprintWorkerClientTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        subject = polkit.read_process_subject(os.getpid(), os.getuid())
        self.caller = dbus_identity.PinnedDBusCaller(
            ":1.50", subject, os.pidfd_open(os.getpid())
        )
        self.evidence = claim.ClaimEvidence(
            "jess",
            subject.uid,
            account.AccountEvidence(subject.uid, "a" * 64),
            ipc.SessionEvidence(
                "pidfd-session", "session-1", "wayland", "user", True, 1
            ),
            Backend(),
            lambda _name: None,
            lambda _uid: None,
        )
        self.temporary = tempfile.TemporaryDirectory()
        self.endpoint = Path(self.temporary.name) / "worker.sock"
        self.client_socket, self.worker_socket = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET
        )
        self.session = launcher.WorkerConnection(
            str(uuid.UUID(int=50)),
            "test.service",
            self.endpoint,
            self.client_socket,
        )

    def tearDown(self):
        self.caller.close()
        self.worker_socket.close()
        self.session.close()
        self.temporary.cleanup()

    async def test_streams_ordered_terminal_and_retains_until_stop(self):
        def worker():
            request, descriptor = protocol.receive_start(self.worker_socket)
            os.close(descriptor)
            self.assertEqual(request.finger_name, "left-thumb")
            protocol.send_update(
                self.worker_socket,
                runtime.EnrollmentUpdate(None, False, False, True),
            )
            protocol.send_update(
                self.worker_socket,
                runtime.EnrollmentUpdate(
                    "enroll-completed", True, False, False
                ),
            )

        thread = threading.Thread(target=worker)
        thread.start()
        updates = []
        lifecycle = client.EnrollmentWorkerClient(
            launcher=lambda: self.session
        )
        with mock.patch.object(claim.ClaimEvidence, "revalidate") as revalidate:
            task = lifecycle.start(
                "left-thumb", self.caller, self.evidence, updates.append
            )
            final = await task
            self.assertEqual(final.status, "enroll-completed")
            self.assertIs(lifecycle.task, task)
            self.assertEqual((await lifecycle.stop()).status, "enroll-completed")
        thread.join(timeout=2)
        self.assertEqual(
            [update.status for update in updates],
            [None, "enroll-completed"],
        )
        self.assertEqual(revalidate.call_count, 2)

    async def test_stop_sends_cancel_and_waits_for_terminal(self):
        started = threading.Event()

        def worker():
            _request, descriptor = protocol.receive_start(self.worker_socket)
            os.close(descriptor)
            protocol.send_update(
                self.worker_socket,
                runtime.EnrollmentUpdate(None, False, False, True),
            )
            started.set()
            protocol.receive_cancel(self.worker_socket)
            protocol.send_update(
                self.worker_socket,
                runtime.EnrollmentUpdate(
                    "enroll-failed", True, False, False
                ),
            )

        thread = threading.Thread(target=worker)
        thread.start()
        updates = []
        lifecycle = client.EnrollmentWorkerClient(
            launcher=lambda: self.session
        )
        with mock.patch.object(claim.ClaimEvidence, "revalidate"):
            lifecycle.start(
                "right-thumb", self.caller, self.evidence, updates.append
            )
            await asyncio.to_thread(started.wait)
            final = await lifecycle.stop()
        thread.join(timeout=2)
        self.assertEqual(final.status, "enroll-failed")
        self.assertEqual(updates[-1].status, "enroll-failed")

    async def test_cross_user_or_launch_failure_never_sends_authority(self):
        lifecycle = client.EnrollmentWorkerClient(
            launcher=lambda: (_ for _ in ()).throw(RuntimeError("failed"))
        )
        wrong = claim.ClaimEvidence(
            "other",
            self.evidence.linux_uid + 1,
            account.AccountEvidence(self.evidence.linux_uid + 1, "b" * 64),
            self.evidence.session,
            Backend(),
            lambda _name: None,
            lambda _uid: None,
        )
        with self.assertRaises(client.FprintWorkerClientError):
            lifecycle.start("left-thumb", self.caller, wrong, lambda _update: None)
        updates = []
        with mock.patch.object(claim.ClaimEvidence, "revalidate"):
            final = await lifecycle.start(
                "left-thumb", self.caller, self.evidence, updates.append
            )
        self.assertEqual(final.status, "enroll-unknown-error")
        self.assertEqual(len(updates), 1)

    async def test_task_cancellation_becomes_worker_cancel(self):
        started = threading.Event()

        def worker():
            _request, descriptor = protocol.receive_start(self.worker_socket)
            os.close(descriptor)
            started.set()
            protocol.receive_cancel(self.worker_socket)
            protocol.send_update(
                self.worker_socket,
                runtime.EnrollmentUpdate(
                    "enroll-failed", True, False, False
                ),
            )

        thread = threading.Thread(target=worker)
        thread.start()
        lifecycle = client.EnrollmentWorkerClient(
            launcher=lambda: self.session
        )
        with mock.patch.object(claim.ClaimEvidence, "revalidate"):
            task = lifecycle.start(
                "left-index-finger",
                self.caller,
                self.evidence,
                lambda _update: None,
            )
            await asyncio.to_thread(started.wait)
            task.cancel()
            final = await task
            await lifecycle.stop()
        thread.join(timeout=2)
        self.assertFalse(task.cancelled())
        self.assertEqual(final.status, "enroll-failed")


if __name__ == "__main__":
    unittest.main()

