# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import array
import json
import os
import socket
import sys
import unittest
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_user_broker as broker
import t2_user_broker_protocol as protocol
import t2_user_policy as policy


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


class UserBrokerProtocolTests(unittest.TestCase):
    def test_every_named_operation_has_one_canonical_identifier_free_request(self):
        for operation in policy.OPERATION_POLICIES:
            with self.subTest(operation=operation):
                request = protocol.BrokerRequest("preflight", operation)
                encoded = protocol.encode_request(request)
                self.assertEqual(protocol.decode_request(encoded), request)
                self.assertEqual(
                    encoded,
                    json.dumps(
                        request.public(),
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("ascii"),
                )
                for forbidden in (
                    b"apple",
                    b"uuid",
                    b"keybag",
                    b"target",
                    b"handle",
                    b"user_id",
                ):
                    self.assertNotIn(forbidden, encoded.lower())

    def test_request_rejects_unknown_duplicate_numeric_and_noncanonical_data(self):
        valid = protocol.BrokerRequest("preflight", "enroll").public()
        malformed = (
            b"",
            b"\xff",
            b"null",
            b'{"schema_version":1,"command":"preflight"}',
            b'{"command":"preflight","operation":3,"schema_version":1}',
            b'{"command":"preflight","operation":"enroll",'
            b'"schema_version":true}',
            b'{"command":"preflight","operation":"raw-sep",'
            b'"schema_version":1}',
            b'{"apple_uid":501,"command":"preflight",'
            b'"operation":"enroll","schema_version":1}',
            b'{"command":"preflight","operation":"enroll",'
            b'"operation":"verify","schema_version":1}',
            b'{ "command":"preflight","operation":"enroll",'
            b'"schema_version":1}',
            json.dumps(valid, sort_keys=False).encode("ascii"),
            protocol.encode_request(
                protocol.BrokerRequest("preflight", "enroll")
            )
            + b"\n",
            b"x" * (protocol.MAX_REQUEST_BYTES + 1),
        )
        canonical = protocol.encode_request(
            protocol.BrokerRequest("preflight", "enroll")
        )
        for value in malformed:
            if value == canonical:
                continue
            with self.subTest(value=value[:40]):
                with self.assertRaises(protocol.UserBrokerProtocolError):
                    protocol.decode_request(value)

    def test_response_round_trip_is_redacted_and_coherent(self):
        request = protocol.BrokerRequest("preflight", "enroll")
        result = broker.BrokerResult(decision(), True, {"private": "secret"})
        response = protocol.response_from_result(request, result)
        encoded = protocol.encode_response(response)
        self.assertEqual(protocol.decode_response(encoded), response)
        public = json.loads(encoded)
        self.assertTrue(public["ready_handoff_proved"])
        self.assertFalse(public["t2_mutation_performed"])
        self.assertTrue(public["identifiers_redacted"])
        self.assertNotIn(b"private", encoded)
        self.assertNotIn(b"secret", encoded)

        denied = broker.BrokerResult(
            decision(state="activation-authorization-required"),
            False,
            None,
        )
        denied_response = protocol.response_from_result(request, denied)
        self.assertFalse(denied_response.ready_handoff_proved)
        self.assertTrue(denied_response.activation_required)

    def test_response_rejects_false_handoff_and_identifier_fields(self):
        invalid = protocol.PreflightResponse(
            "enroll",
            "operation-policy-denied",
            policy.OPERATION_POLICIES["enroll"].action,
            False,
            False,
            False,
            "ready",
            False,
            True,
        )
        with self.assertRaises(protocol.UserBrokerProtocolError):
            protocol.encode_response(invalid)

        missing_proof = protocol.PreflightResponse(
            "enroll",
            "authorized",
            policy.OPERATION_POLICIES["enroll"].action,
            True,
            False,
            False,
            "ready",
            False,
            False,
        )
        with self.assertRaises(protocol.UserBrokerProtocolError):
            protocol.encode_response(missing_proof)

        contradictory_activation = protocol.PreflightResponse(
            "enroll",
            "operation-policy-denied",
            policy.OPERATION_POLICIES["enroll"].action,
            False,
            True,
            False,
            None,
            False,
            False,
        )
        with self.assertRaises(protocol.UserBrokerProtocolError):
            protocol.encode_response(contradictory_activation)

        valid = protocol.PreflightResponse(
            "enroll",
            "authorized",
            policy.OPERATION_POLICIES["enroll"].action,
            True,
            False,
            False,
            "ready",
            False,
            True,
        ).public()
        valid["apple_uid"] = 501
        encoded = json.dumps(
            valid, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        with self.assertRaises(protocol.UserBrokerProtocolError):
            protocol.decode_response(encoded)

    def test_seqpacket_receive_and_send_preserve_one_message(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        request = protocol.BrokerRequest("preflight", "inventory")
        right.send(protocol.encode_request(request))
        self.assertEqual(protocol.receive_request(left), request)

        response = protocol.PreflightResponse(
            "inventory",
            "authorized",
            policy.OPERATION_POLICIES["inventory"].action,
            True,
            False,
            False,
            "ready",
            False,
            True,
        )
        protocol.send_response(left, response)
        self.assertEqual(
            protocol.decode_response(right.recv(protocol.MAX_RESPONSE_BYTES)),
            response,
        )

    def test_socket_boundary_rejects_stream_truncation_and_file_descriptors(self):
        stream_left, stream_right = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_STREAM
        )
        self.addCleanup(stream_left.close)
        self.addCleanup(stream_right.close)
        with self.assertRaises(protocol.UserBrokerProtocolError):
            protocol.receive_request(stream_left)

        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        right.send(b"x" * (protocol.MAX_REQUEST_BYTES + 1))
        with self.assertRaisesRegex(
            protocol.UserBrokerProtocolError, "truncated"
        ):
            protocol.receive_request(left)

        descriptor, write_descriptor = os.pipe()
        try:
            right.sendmsg(
                [
                    protocol.encode_request(
                        protocol.BrokerRequest("preflight", "verify")
                    )
                ],
                [
                    (
                        socket.SOL_SOCKET,
                        socket.SCM_RIGHTS,
                        array.array("i", [descriptor]),
                    )
                ],
            )
            with self.assertRaisesRegex(
                protocol.UserBrokerProtocolError, "ancillary"
            ):
                protocol.receive_request(left)
        finally:
            os.close(descriptor)
            os.close(write_descriptor)


if __name__ == "__main__":
    unittest.main()
