# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import os
import socket
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))

import t2_fprint_delete_worker as worker
import t2_fprint_delete_worker_protocol as protocol
import t2_fprint_deletion_runtime as runtime
import t2_ipc_session as ipc
import t2_linux_account as account
import t2_polkit_grant as polkit
import t2_user_broker as broker


def request():
    subject = polkit.read_process_subject(os.getpid(), os.getuid())
    return protocol.DeleteRequest(
        "left-thumb",
        subject,
        account.AccountEvidence(subject.uid, "a" * 64),
        ipc.SessionEvidence(
            "pidfd-session", "session-1", "wayland", "user", True, 1
        ),
    )


class Authorization:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class FprintDeleteWorkerTests(unittest.TestCase):
    def run_worker(self, connection, **overrides):
        result = []

        def target():
            try:
                result.append(worker.serve_once(connection, **overrides))
            except BaseException as error:
                result.append(error)

        thread = threading.Thread(target=target)
        thread.start()
        return thread, result

    def send_request(self, connection):
        descriptor = os.pidfd_open(os.getpid())
        try:
            protocol.send_request(connection, request(), descriptor)
        finally:
            os.close(descriptor)

    def test_success_hands_exact_claim_to_delete_one_broker(self):
        authorization = Authorization()
        expected = runtime.DeletionCompletion(
            "left-thumb", True, True, True, True
        )
        observed = {}

        def authorization_factory(peer, **arguments):
            self.assertEqual(peer.subject, request().caller)
            self.assertEqual(arguments["expected_account"], request().account)
            self.assertEqual(arguments["expected_session"], request().session)
            return authorization

        class Deletion:
            def __init__(self, finger_name, fallback):
                observed["finger_name"] = finger_name
                observed["fallback"] = fallback

            def __call__(self, _authority, _live):
                return expected

        def broker_runner(_connection, **arguments):
            observed.update(arguments)
            value = arguments["consumer"](
                SimpleNamespace(), SimpleNamespace()
            )
            return broker.BrokerResult(SimpleNamespace(), True, value)

        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        thread, result = self.run_worker(
            right,
            authorization_factory=authorization_factory,
            broker_runner=broker_runner,
            deletion_consumer_factory=Deletion,
        )
        self.send_request(left)
        self.assertEqual(protocol.receive_completion(left), expected)
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result, [expected])
        self.assertEqual(observed["operation"], "delete-one")
        self.assertTrue(observed["modification_allowed"])
        self.assertFalse(observed["collect_activation_authority"])
        self.assertTrue(observed["fallback"])
        self.assertTrue(authorization.closed)

    def test_authorization_failure_emits_only_generic_failure(self):
        def fail(_peer, **_arguments):
            raise ipc.IPCSessionError("private reason")

        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        thread, result = self.run_worker(
            right, authorization_factory=fail
        )
        self.send_request(left)
        with self.assertRaises(protocol.FprintDeleteWorkerFailed):
            protocol.receive_completion(left)
        thread.join(timeout=5)
        self.assertIsInstance(result[0], worker.FprintDeleteWorkerError)

    def test_completed_mutation_never_falls_back_to_failure_packet(self):
        authorization = Authorization()
        expected = runtime.DeletionCompletion(
            "left-thumb", True, True, True, True
        )

        def authorization_factory(_peer, **_arguments):
            return authorization

        class Deletion:
            def __init__(self, _finger_name, _fallback):
                pass

            def __call__(self, _authority, _live):
                return expected

        def broker_runner(_connection, **arguments):
            value = arguments["consumer"](
                SimpleNamespace(), SimpleNamespace()
            )
            return broker.BrokerResult(SimpleNamespace(), True, value)

        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        with mock.patch.object(
            protocol,
            "send_completion",
            side_effect=protocol.FprintDeleteWorkerProtocolError("closed"),
        ), mock.patch.object(protocol, "send_failure") as send_failure:
            thread, result = self.run_worker(
                right,
                authorization_factory=authorization_factory,
                broker_runner=broker_runner,
                deletion_consumer_factory=Deletion,
            )
            self.send_request(left)
            thread.join(timeout=5)
        send_failure.assert_not_called()
        self.assertIsInstance(result[0], worker.FprintDeleteWorkerError)
        self.assertTrue(authorization.closed)


if __name__ == "__main__":
    unittest.main()
