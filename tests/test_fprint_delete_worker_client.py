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
import t2_fprint_delete_worker_client as client
import t2_fprint_delete_worker_launcher as launcher
import t2_fprint_delete_worker_protocol as protocol
import t2_fprint_deletion_runtime as runtime
import t2_ipc_session as ipc
import t2_linux_account as account
import t2_polkit_grant as polkit


class Backend:
    pass


class FprintDeleteWorkerClientTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        subject = polkit.read_process_subject(os.getpid(), os.getuid())
        self.caller = dbus_identity.PinnedDBusCaller(
            ":1.51", subject, os.pidfd_open(os.getpid())
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
        self.endpoint = Path(self.temporary.name) / "delete.sock"
        self.client_socket, self.worker_socket = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET
        )
        self.session = launcher.DeleteWorkerConnection(
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

    async def test_returns_only_exact_reconciled_completion(self):
        expected = runtime.DeletionCompletion(
            "left-thumb", True, True, True, True
        )

        def worker():
            request, descriptor = protocol.receive_request(self.worker_socket)
            os.close(descriptor)
            self.assertEqual(request.finger_name, "left-thumb")
            protocol.send_completion(self.worker_socket, expected)

        thread = threading.Thread(target=worker)
        thread.start()
        lifecycle = client.DeletionWorkerClient(
            launcher=lambda: self.session
        )
        with mock.patch.object(claim.ClaimEvidence, "revalidate") as revalidate:
            result = await lifecycle.delete(
                "left-thumb", self.caller, self.evidence
            )
        thread.join(timeout=2)
        self.assertEqual(result, expected)
        self.assertEqual(revalidate.call_count, 2)

    async def test_cancellation_after_handoff_waits_for_reconciliation(self):
        started = threading.Event()
        release = threading.Event()
        expected = runtime.DeletionCompletion(
            "left-thumb", True, True, True, True
        )

        def worker():
            _request, descriptor = protocol.receive_request(self.worker_socket)
            os.close(descriptor)
            started.set()
            release.wait(timeout=5)
            protocol.send_completion(self.worker_socket, expected)

        thread = threading.Thread(target=worker)
        thread.start()
        lifecycle = client.DeletionWorkerClient(
            launcher=lambda: self.session
        )
        with mock.patch.object(claim.ClaimEvidence, "revalidate"):
            task = asyncio.create_task(
                lifecycle.delete("left-thumb", self.caller, self.evidence)
            )
            await asyncio.to_thread(started.wait)
            task.cancel()
            release.set()
            result = await task
        thread.join(timeout=2)
        self.assertFalse(task.cancelled())
        self.assertEqual(result, expected)

    async def test_cross_user_or_worker_failure_is_not_completion(self):
        lifecycle = client.DeletionWorkerClient(
            launcher=lambda: self.session
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
        with self.assertRaises(client.FprintDeleteWorkerClientError):
            await lifecycle.delete("left-thumb", self.caller, wrong)

        def worker():
            _request, descriptor = protocol.receive_request(self.worker_socket)
            os.close(descriptor)
            protocol.send_failure(self.worker_socket)

        thread = threading.Thread(target=worker)
        thread.start()
        with mock.patch.object(claim.ClaimEvidence, "revalidate"):
            with self.assertRaises(client.FprintDeleteWorkerClientError):
                await lifecycle.delete(
                    "left-thumb", self.caller, self.evidence
                )
        thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
