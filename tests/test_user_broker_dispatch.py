# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import socket
import sys
import unittest
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_user_broker_dispatch as dispatch
import t2_user_broker_inventory as inventory
import t2_user_broker_protocol as protocol
import t2_user_policy as policy


def policy_decision(state="authorized"):
    operation = policy.OPERATION_POLICIES["inventory"]
    authorized = state == "authorized"
    return policy.UserPolicyDecision(
        state,
        "inventory",
        operation.action,
        authorized,
        state == "activation-authorization-required",
        False,
        "ready" if authorized else "alias-absent",
        False,
        None,
        None,
    )


def public_inventory():
    return inventory.parse_public_inventory(
        {
            "schema_version": 1,
            "identity_count": 2,
            "identities": [
                {"slot": 1, "name": "Finger 1", "live": True},
                {
                    "slot": 2,
                    "name": "Linux enrolled finger",
                    "live": True,
                },
            ],
            "local_live_reconciled": True,
            "selection_scope": "current-reconciled-list",
            "fprintd_listing_is_compatibility_alias": True,
            "identifiers_redacted": True,
        }
    )


class UserBrokerDispatchTests(unittest.TestCase):
    def sockets(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        return left, right

    def test_dispatches_preflight_as_one_packet(self):
        left, right = self.sockets()
        request = protocol.BrokerRequest("preflight", "verify")
        right.send(protocol.encode_request(request))
        calls = []

        def runner(connection, received, **arguments):
            calls.append((connection, received, arguments))
            return protocol.PreflightResponse(
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

        response = dispatch.serve_once(
            left,
            modification_allowed=True,
            allow_user_interaction=False,
            preflight_runner=runner,
            inventory_runner=lambda *args, **kwargs: self.fail(
                "inventory runner must not execute"
            ),
        )
        self.assertEqual(
            protocol.decode_response(right.recv(protocol.MAX_RESPONSE_BYTES)),
            response,
        )
        self.assertEqual(calls[0][0], left)
        self.assertEqual(calls[0][1], request)
        self.assertTrue(calls[0][2]["modification_allowed"])
        self.assertFalse(calls[0][2]["allow_user_interaction"])

    def test_dispatches_identity_inventory_without_modification_input(self):
        left, right = self.sockets()
        request = protocol.BrokerRequest("identities", "inventory")
        right.send(protocol.encode_request(request))
        calls = []

        def runner(connection, **arguments):
            calls.append((connection, arguments))
            return inventory.BrokerInventoryResult(
                policy_decision(), True, public_inventory()
            )

        response = dispatch.serve_once(
            left,
            modification_allowed=True,
            allow_user_interaction=False,
            preflight_runner=lambda *args, **kwargs: self.fail(
                "preflight runner must not execute"
            ),
            inventory_runner=runner,
        )
        received = protocol.decode_response(
            right.recv(protocol.MAX_RESPONSE_BYTES)
        )
        self.assertEqual(received, response)
        self.assertIsInstance(received, protocol.InventoryResponse)
        self.assertEqual(received.inventory.identity_count, 2)
        self.assertEqual(calls, [(left, {"allow_user_interaction": False})])

    def test_rejects_malformed_packet_or_runner_result_without_fallback(self):
        left, right = self.sockets()
        right.send(b'{"command":"identities","operation":"enroll",'
                   b'"schema_version":1}')
        with self.assertRaises(dispatch.UserBrokerDispatchError):
            dispatch.serve_once(
                left,
                modification_allowed=False,
                allow_user_interaction=False,
                preflight_runner=lambda *args, **kwargs: self.fail(
                    "runner must not execute"
                ),
                inventory_runner=lambda *args, **kwargs: self.fail(
                    "runner must not execute"
                ),
            )

        left, right = self.sockets()
        right.send(
            protocol.encode_request(
                protocol.BrokerRequest("preflight", "verify")
            )
        )
        with self.assertRaisesRegex(
            dispatch.UserBrokerDispatchError, "malformed"
        ):
            dispatch.serve_once(
                left,
                modification_allowed=False,
                allow_user_interaction=False,
                preflight_runner=lambda *args, **kwargs: object(),
            )

    def test_policy_switches_require_exact_booleans(self):
        for modification, interaction in ((1, False), (False, 0)):
            with self.subTest(
                modification=modification, interaction=interaction
            ), self.assertRaises(dispatch.UserBrokerDispatchError):
                dispatch.serve_once(
                    object(),
                    modification_allowed=modification,
                    allow_user_interaction=interaction,
                )


if __name__ == "__main__":
    unittest.main()
