# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import socket
import sys
import threading
import unittest
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_user_broker_client as client
import t2_user_broker_inventory as inventory
import t2_user_broker_protocol as protocol
import t2_user_policy as policy


def preflight(operation="verify"):
    return protocol.PreflightResponse(
        operation,
        "operation-policy-denied",
        policy.OPERATION_POLICIES[operation].action,
        False,
        False,
        False,
        "alias-absent",
        False,
        False,
    )


def identity_response():
    public = inventory.parse_public_inventory(
        {
            "schema_version": 1,
            "identity_count": 1,
            "identities": [
                {"slot": 1, "name": "Finger 1", "live": True}
            ],
            "local_live_reconciled": True,
            "selection_scope": "current-reconciled-list",
            "fprintd_listing_is_compatibility_alias": True,
            "identifiers_redacted": True,
        }
    )
    return protocol.InventoryResponse(
        "authorized",
        policy.OPERATION_POLICIES["inventory"].action,
        True,
        False,
        False,
        "ready",
        False,
        True,
        public,
    )


class UserBrokerClientTests(unittest.TestCase):
    def sockets(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        return left, right

    def exchange(self, request, response):
        left, right = self.sockets()
        protocol.send_response(right, response)
        received = client.exchange(left, request)
        sent = protocol.receive_request(right)
        return received, sent

    def test_preflight_exchange_binds_operation(self):
        request = protocol.BrokerRequest("preflight", "verify")
        response, sent = self.exchange(request, preflight())
        self.assertEqual(response, preflight())
        self.assertEqual(sent, request)

    def test_identity_exchange_binds_command_shape(self):
        request = protocol.BrokerRequest("identities", "inventory")
        response, sent = self.exchange(request, identity_response())
        self.assertEqual(response, identity_response())
        self.assertEqual(sent, request)

    def test_cross_command_or_operation_response_is_rejected(self):
        cases = (
            (
                protocol.BrokerRequest("preflight", "verify"),
                preflight("inventory"),
            ),
            (
                protocol.BrokerRequest("preflight", "inventory"),
                identity_response(),
            ),
            (
                protocol.BrokerRequest("identities", "inventory"),
                preflight("inventory"),
            ),
        )
        for request, response in cases:
            with self.subTest(request=request), self.assertRaises(
                client.UserBrokerClientError
            ):
                self.exchange(request, response)

    def test_invalid_request_or_transport_fails_without_fallback(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        with self.assertRaises(client.UserBrokerClientError):
            client.exchange(
                left, protocol.BrokerRequest("preflight", "verify")
            )

        left, right = self.sockets()
        protocol.send_response(right, preflight())
        with self.assertRaises(client.UserBrokerClientError):
            client.exchange(
                left, protocol.BrokerRequest("identities", "enroll")
            )

    def test_clean_peer_close_has_a_distinct_fail_closed_result(self):
        left, right = self.sockets()
        received = []

        def close_after_request():
            received.append(protocol.receive_request(right))
            right.close()

        server = threading.Thread(target=close_after_request)
        server.start()
        with self.assertRaises(client.UserBrokerClientPeerClosed):
            client.exchange(
                left, protocol.BrokerRequest("identities", "inventory")
            )
        server.join(timeout=2)
        self.assertFalse(server.is_alive())
        self.assertEqual(
            received,
            [protocol.BrokerRequest("identities", "inventory")],
        )


if __name__ == "__main__":
    unittest.main()
