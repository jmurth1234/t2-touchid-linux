# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import os
import socket
import sys
import unittest
from pathlib import Path
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_user_broker_protocol as protocol
import t2_user_broker_socket_activation as activation
import t2_user_policy as policy


class Backend:
    def __init__(self, descriptors):
        self.value = descriptors
        self.calls = 0

    def descriptors(self):
        self.calls += 1
        return self.value


def duplicate_descriptor(connection: socket.socket) -> int:
    descriptor = os.dup(connection.fileno())
    os.set_inheritable(descriptor, True)
    return descriptor


class UserBrokerSocketActivationTests(unittest.TestCase):
    def setUp(self):
        self.root = mock.patch.object(activation, "ROOT_UID", os.geteuid())
        self.root.start()

    def tearDown(self):
        self.root.stop()

    def sockets(self, kind=socket.SOCK_SEQPACKET):
        left, right = socket.socketpair(socket.AF_UNIX, kind)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        return left, right

    def test_acquires_one_connected_seqpacket_and_owns_descriptor(self):
        left, _right = self.sockets()
        descriptor = duplicate_descriptor(left)
        backend = Backend(((descriptor, "connection"),))
        connection = activation.acquire_connected_socket(backend=backend)
        self.addCleanup(connection.close)
        self.assertEqual(backend.calls, 1)
        self.assertFalse(os.get_inheritable(connection.fileno()))
        self.assertEqual(
            connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE),
            socket.SOCK_SEQPACKET,
        )

    def test_rejects_wrong_count_name_type_or_listening_socket(self):
        cases = []
        left, _right = self.sockets()
        cases.append(Backend(tuple()))
        cases.append(
            Backend(
                (
                    (duplicate_descriptor(left), "connection"),
                    (duplicate_descriptor(left), "connection"),
                )
            )
        )
        cases.append(
            Backend(((duplicate_descriptor(left), "wrong-name"),))
        )
        stream, _peer = self.sockets(socket.SOCK_STREAM)
        cases.append(
            Backend(((duplicate_descriptor(stream), "connection"),))
        )
        listening = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(listening.close)
        listening.bind("\0t2-touchid-test-activation")
        listening.listen(1)
        cases.append(
            Backend(((duplicate_descriptor(listening), "connection"),))
        )
        for backend in cases:
            with self.subTest(count=len(backend.value)), self.assertRaises(
                activation.UserBrokerSocketActivationError
            ):
                activation.acquire_connected_socket(backend=backend)
            for descriptor, _name in backend.value:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def test_root_is_required_before_descriptor_collection(self):
        backend = Backend(tuple())
        with mock.patch.object(activation, "ROOT_UID", os.geteuid() + 1):
            with self.assertRaisesRegex(
                activation.UserBrokerSocketActivationError, "requires root"
            ):
                activation.acquire_connected_socket(backend=backend)
        self.assertEqual(backend.calls, 0)

    def test_run_once_passes_only_trusted_switches_and_closes_connection(self):
        left, _right = self.sockets()
        descriptor = duplicate_descriptor(left)
        backend = Backend(((descriptor, "connection"),))
        calls = []
        response = protocol.PreflightResponse(
            "verify",
            "operation-policy-denied",
            policy.OPERATION_POLICIES["verify"].action,
            False,
            False,
            False,
            "alias-absent",
            False,
            False,
        )

        def dispatcher(connection, **arguments):
            calls.append((connection.fileno(), arguments))
            return response

        self.assertIs(
            activation.run_once(
                modification_allowed=False,
                allow_user_interaction=True,
                backend=backend,
                dispatcher=dispatcher,
            ),
            response,
        )
        self.assertEqual(
            calls[0][1],
            {
                "modification_allowed": False,
                "allow_user_interaction": True,
            },
        )
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_invalid_dispatch_result_or_switch_fails_closed(self):
        for modification, interaction in ((1, False), (False, 0)):
            with self.subTest(
                modification=modification, interaction=interaction
            ), self.assertRaises(
                activation.UserBrokerSocketActivationError
            ):
                activation.run_once(
                    modification_allowed=modification,
                    allow_user_interaction=interaction,
                    backend=Backend(tuple()),
                )

        left, _right = self.sockets()
        backend = Backend(
            ((duplicate_descriptor(left), "connection"),)
        )
        with self.assertRaisesRegex(
            activation.UserBrokerSocketActivationError, "invalid response"
        ):
            activation.run_once(
                modification_allowed=False,
                allow_user_interaction=False,
                backend=backend,
                dispatcher=lambda connection, **arguments: object(),
            )


if __name__ == "__main__":
    unittest.main()
