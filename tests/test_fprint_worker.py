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

import t2_enrollment_coordinator as coordinator
import t2_enrollment_protocol as enrollment_protocol
import t2_fprint_worker as worker
import t2_fprint_worker_protocol as protocol
import t2_ipc_session as ipc
import t2_linux_account as account
import t2_polkit_grant as polkit
import t2_user_broker as broker


def request():
    subject = polkit.read_process_subject(os.getpid(), os.getuid())
    return protocol.StartRequest(
        "left-thumb",
        subject,
        account.AccountEvidence(subject.uid, "a" * 64),
        ipc.SessionEvidence(
            "pidfd-session", "session-1", "wayland", "user", True, 1
        ),
    )


def transition(action, *, progress=None):
    return enrollment_protocol.EnrollmentTransition(
        action,
        enrollment_protocol.EnrollmentState.ACTIVE,
        progress_percent=progress,
    )


class Authorization:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class Binder:
    def __init__(self, alias):
        self.alias = alias
        self.bound = False

    def verify_password_fallback(self):
        return True

    def bind(self, context):
        self.bound = len(context) == 16


class FprintWorkerTests(unittest.TestCase):
    def start_request(self, connection):
        descriptor = os.pidfd_open(os.getpid())
        try:
            protocol.send_start(connection, request(), descriptor)
        finally:
            os.close(descriptor)

    def run_worker(self, right, **overrides):
        result = []

        def target():
            try:
                result.append(worker.serve_once(right, **overrides))
            except BaseException as error:
                result.append(error)

        thread = threading.Thread(target=target)
        thread.start()
        return thread, result

    def dependencies(self, operation):
        authorization = Authorization()
        selected = SimpleNamespace(
            unlock_mode="host-encrypted-credential",
            special_bag_alias=-501,
        )
        authority = SimpleNamespace(selected=selected)

        def authorization_factory(peer, **arguments):
            self.assertEqual(peer.subject, request().caller)
            self.assertEqual(arguments["expected_account"], request().account)
            self.assertEqual(arguments["expected_session"], request().session)
            return authorization

        def broker_runner(_connection, **arguments):
            self.assertIs(arguments["authorization_manager"], authorization)
            value = arguments["consumer"](authority, SimpleNamespace())
            return broker.BrokerResult(SimpleNamespace(), True, value)

        class Enrollment:
            def __init__(self, _finger, _bind, cancel, feedback, fallback):
                self.cancel = cancel
                self.feedback = feedback
                if fallback is not True:
                    raise AssertionError("fallback not verified")

            def __call__(self, _authority, _live):
                return operation(self.cancel, self.feedback)

        return {
            "authorization_factory": authorization_factory,
            "binder_factory": Binder,
            "broker_runner": broker_runner,
            "enrollment_consumer_factory": Enrollment,
        }, authorization

    def test_success_streams_initial_progress_and_terminal(self):
        def operation(_cancel, feedback):
            feedback(
                transition(
                    enrollment_protocol.EnrollmentAction.PROGRESS,
                    progress=25,
                )
            )
            return coordinator.EnrollmentCoordinatorResult(
                "identity-observed", True, True, True
            )

        dependencies, authorization = self.dependencies(operation)
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        thread, result = self.run_worker(right, **dependencies)
        self.start_request(left)
        updates = [protocol.receive_update(left) for _ in range(3)]
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(
            [update.status for update in updates],
            [None, "enroll-stage-passed", "enroll-completed"],
        )
        self.assertIsInstance(result[0], coordinator.EnrollmentCoordinatorResult)
        self.assertTrue(authorization.closed)

    def test_cancel_packet_drives_cooperative_reconciled_failure(self):
        entered = threading.Event()

        def operation(cancel, _feedback):
            entered.set()
            while not cancel():
                pass
            return coordinator.EnrollmentCoordinatorResult(
                "cancelled", True, False, True
            )

        dependencies, _authorization = self.dependencies(operation)
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        thread, result = self.run_worker(right, **dependencies)
        self.start_request(left)
        initial = protocol.receive_update(left)
        self.assertIsNone(initial.status)
        self.assertTrue(entered.wait(timeout=2))
        protocol.send_cancel(left)
        terminal = protocol.receive_update(left)
        thread.join(timeout=5)
        self.assertEqual(terminal.status, "enroll-failed")
        self.assertIsInstance(result[0], coordinator.EnrollmentCoordinatorResult)

    def test_authorization_or_broker_failure_emits_terminal_unknown(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)

        def fail(_peer, **_arguments):
            raise ipc.IPCSessionError("denied")

        thread, result = self.run_worker(right, authorization_factory=fail)
        self.start_request(left)
        terminal = protocol.receive_update(left)
        thread.join(timeout=5)
        self.assertEqual(terminal.status, "enroll-unknown-error")
        self.assertIsInstance(result[0], worker.FprintWorkerError)

    def test_mapping_without_worker_credential_never_constructs_binder(self):
        authorization = Authorization()
        authority = SimpleNamespace(
            selected=SimpleNamespace(
                unlock_mode="manual-password",
                special_bag_alias=-501,
            )
        )

        def authorization_factory(peer, **_arguments):
            return authorization

        def broker_runner(_connection, **arguments):
            arguments["consumer"](authority, SimpleNamespace())

        binder_factory = mock.Mock()
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        thread, result = self.run_worker(
            right,
            authorization_factory=authorization_factory,
            binder_factory=binder_factory,
            broker_runner=broker_runner,
        )
        self.start_request(left)
        terminal = protocol.receive_update(left)
        thread.join(timeout=5)
        self.assertEqual(terminal.status, "enroll-unknown-error")
        binder_factory.assert_not_called()
        self.assertTrue(authorization.closed)
        self.assertIsInstance(result[0], worker.FprintWorkerError)

    def test_typed_capacity_refusal_emits_data_full(self):
        def operation(_cancel, _feedback):
            raise broker.UserBrokerError("consumer failed") from (
                worker.t2_fprint_enrollment_consumer.FprintEnrollmentDataFullError(
                    "capacity exhausted"
                )
            )

        dependencies, authorization = self.dependencies(operation)
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        thread, result = self.run_worker(right, **dependencies)
        self.start_request(left)
        updates = [protocol.receive_update(left) for _ in range(2)]
        thread.join(timeout=5)
        self.assertEqual(
            [update.status for update in updates],
            [None, "enroll-data-full"],
        )
        self.assertTrue(updates[-1].done)
        self.assertTrue(authorization.closed)
        self.assertIsInstance(result[0], worker.FprintWorkerError)


if __name__ == "__main__":
    unittest.main()
