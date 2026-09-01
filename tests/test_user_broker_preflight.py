# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import json
import socket
import sys
import unittest
import uuid
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_user_broker as broker
import t2_user_broker_preflight as preflight
import t2_user_broker_protocol as protocol
import t2_user_mapping as mapping
import t2_user_policy as policy
import t2_user_readiness as readiness


def identifier(number: int) -> str:
    return str(uuid.UUID(int=number))


def mapped():
    document = {
        "schema_version": 1,
        "mappings": [
            {
                "linux_uid": 1000,
                "linux_account_generation": "a" * 64,
                "apple_uid": 501,
                "account_uuid": identifier(1),
                "bag_uuid": identifier(2),
                "keybag_path": "/var/lib/t2-touchid/users/1000/user.kb",
                "keybag_sha256": "b" * 64,
                "unlock_mode": "password-on-demand",
                "capabilities": ["enroll", "verify"],
                "enabled": True,
            }
        ],
    }
    result = mapping.parse(json.dumps(document, sort_keys=True).encode())
    return result, result.mappings[0]


def persistent():
    return readiness.PersistentEvidence(
        "a" * 64,
        "b" * 64,
        501,
        identifier(1),
        identifier(2),
        True,
    )


def decision(operation="enroll", state="authorized"):
    operation_policy = policy.OPERATION_POLICIES[operation]
    authorized = state == "authorized"
    return policy.UserPolicyDecision(
        state,
        operation,
        operation_policy.action,
        authorized,
        state == "activation-authorization-required",
        False,
        "ready" if authorized else "alias-absent",
        False,
        None,
        None,
    )


class Live:
    runtime_generation = identifier(20)


class UserBrokerPreflightTests(unittest.TestCase):
    def test_ready_preflight_runs_only_read_only_consumer(self):
        current, selected = mapped()
        current_decision = decision()
        calls = []

        def runner(connection, **arguments):
            calls.append((connection, arguments))
            authority = broker.BrokerAuthority(
                current,
                selected,
                persistent(),
                readiness.AliasEvidence(
                    True, -501, identifier(2), 0, identifier(1)
                ),
                current_decision,
                identifier(30),
                identifier(21),
                identifier(20),
                "operate",
            )
            value = arguments["consumer"](authority, Live())
            return broker.BrokerResult(current_decision, True, value)

        request = protocol.BrokerRequest("preflight", "enroll")
        response = preflight.run(
            object(),
            request,
            modification_allowed=True,
            allow_user_interaction=False,
            broker_runner=runner,
        )
        self.assertEqual(response.state, "authorized")
        self.assertTrue(response.ready_handoff_proved)
        self.assertEqual(len(calls), 1)
        arguments = calls[0][1]
        self.assertEqual(arguments["operation"], "enroll")
        self.assertTrue(arguments["modification_allowed"])
        self.assertFalse(arguments["allow_user_interaction"])
        self.assertFalse(arguments["collect_activation_authority"])
        rendered = json.dumps(response.public(), sort_keys=True)
        self.assertNotIn(identifier(1), rendered)
        self.assertNotIn("501", rendered)

    def test_activation_required_is_reported_without_private_result(self):
        current_decision = decision(
            state="activation-authorization-required"
        )

        def runner(connection, **arguments):
            return broker.BrokerResult(current_decision, False, None)

        response = preflight.run(
            object(),
            protocol.BrokerRequest("preflight", "enroll"),
            modification_allowed=True,
            allow_user_interaction=True,
            broker_runner=runner,
        )
        self.assertTrue(response.activation_required)
        self.assertFalse(response.activation_permitted)
        self.assertFalse(response.ready_handoff_proved)

    def test_malformed_request_policy_result_and_broker_failure_are_clean(self):
        with self.assertRaises(preflight.UserBrokerPreflightError):
            preflight.run(
                object(),
                protocol.BrokerRequest("start", "enroll"),
                modification_allowed=True,
                allow_user_interaction=False,
            )
        with self.assertRaises(preflight.UserBrokerPreflightError):
            preflight.run(
                object(),
                protocol.BrokerRequest("preflight", "enroll"),
                modification_allowed=1,
                allow_user_interaction=False,
            )
        with self.assertRaisesRegex(
            preflight.UserBrokerPreflightError, "malformed"
        ):
            preflight.run(
                object(),
                protocol.BrokerRequest("preflight", "enroll"),
                modification_allowed=True,
                allow_user_interaction=False,
                broker_runner=lambda connection, **arguments: object(),
            )
        with self.assertRaisesRegex(
            preflight.UserBrokerPreflightError, "transaction failed"
        ):
            preflight.run(
                object(),
                protocol.BrokerRequest("preflight", "enroll"),
                modification_allowed=True,
                allow_user_interaction=False,
                broker_runner=lambda connection, **arguments: (_ for _ in ()).throw(
                    broker.UserBrokerError("private failure")
                ),
            )

    def test_claimed_consumer_handoff_requires_typed_read_only_proof(self):
        current_decision = decision()
        with self.assertRaisesRegex(
            preflight.UserBrokerPreflightError, "proof"
        ):
            preflight.run(
                object(),
                protocol.BrokerRequest("preflight", "enroll"),
                modification_allowed=True,
                allow_user_interaction=False,
                broker_runner=lambda connection, **arguments: broker.BrokerResult(
                    current_decision, True, {"untrusted": True}
                ),
            )

    def test_serve_once_joins_seqpacket_framing_to_preflight(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        current_decision = decision(
            operation="verify", state="operation-policy-denied"
        )

        def runner(connection, **arguments):
            self.assertIs(connection, left)
            return broker.BrokerResult(current_decision, False, None)

        right.send(
            protocol.encode_request(
                protocol.BrokerRequest("preflight", "verify")
            )
        )
        response = preflight.serve_once(
            left,
            modification_allowed=False,
            allow_user_interaction=False,
            broker_runner=runner,
        )
        received = protocol.decode_response(
            right.recv(protocol.MAX_RESPONSE_BYTES)
        )
        self.assertEqual(received, response)
        self.assertFalse(received.ready_handoff_proved)


if __name__ == "__main__":
    unittest.main()
