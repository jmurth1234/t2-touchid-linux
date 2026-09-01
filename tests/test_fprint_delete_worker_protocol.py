# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import os
import socket
import sys
import unittest
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))

import t2_fprint_delete_worker_protocol as protocol
import t2_fprint_deletion_runtime as runtime
import t2_fprint_worker_protocol as enrollment_protocol
import t2_ipc_session as ipc
import t2_linux_account as account
import t2_polkit_grant as polkit


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


class FprintDeleteWorkerProtocolTests(unittest.TestCase):
    def socket_pair(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        return left, right

    def test_request_round_trip_transfers_one_live_pidfd(self):
        left, right = self.socket_pair()
        descriptor = os.pidfd_open(os.getpid())
        self.addCleanup(os.close, descriptor)
        protocol.send_request(left, request(), descriptor)
        received, transferred = protocol.receive_request(right)
        self.addCleanup(os.close, transferred)
        self.assertEqual(received, request())
        self.assertEqual(
            os.readlink(f"/proc/self/fd/{transferred}"),
            "anon_inode:[pidfd]",
        )

    def test_request_is_not_accepted_by_enrollment_protocol_or_vice_versa(self):
        encoded = protocol.encode_request(request())
        with self.assertRaises(enrollment_protocol.FprintWorkerProtocolError):
            enrollment_protocol.decode_start(encoded)
        enrollment = enrollment_protocol.StartRequest(
            request().finger_name,
            request().caller,
            request().account,
            request().session,
        )
        with self.assertRaises(protocol.FprintDeleteWorkerProtocolError):
            protocol.decode_request(enrollment_protocol.encode_start(enrollment))

    def test_completion_is_exact_and_failure_is_distinct(self):
        left, right = self.socket_pair()
        value = runtime.DeletionCompletion(
            "left-thumb", True, True, True, True
        )
        protocol.send_completion(left, value)
        self.assertEqual(protocol.receive_completion(right), value)
        protocol.send_failure(left)
        with self.assertRaises(protocol.FprintDeleteWorkerFailed):
            protocol.receive_completion(right)
        encoded = protocol.encode_completion(value).lower()
        for forbidden in (
            b"uuid",
            b"apple",
            b"keybag",
            b"password",
            b"credential",
        ):
            self.assertNotIn(forbidden, encoded)

    def test_malformed_or_unreconciled_completion_fails_closed(self):
        cases = (
            b"{}",
            (
                b'{"deleted":false,"finger_name":"left-thumb",'
                b'"message":"delete-completed","mutation_performed":false,'
                b'"post_reboot_pending":false,"reconciled":false,'
                b'"schema_version":1}'
            ),
        )
        for data in cases:
            with self.subTest(data=data), self.assertRaises(
                protocol.FprintDeleteWorkerProtocolError
            ):
                protocol.decode_completion(data)


if __name__ == "__main__":
    unittest.main()
