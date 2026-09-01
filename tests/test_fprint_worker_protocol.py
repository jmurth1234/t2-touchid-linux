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

import t2_fprint_enrollment_runtime as runtime
import t2_fprint_worker_protocol as protocol
import t2_ipc_session as ipc
import t2_linux_account as account
import t2_polkit_grant as polkit


def request() -> protocol.StartRequest:
    subject = polkit.read_process_subject(os.getpid(), os.getuid())
    return protocol.StartRequest(
        "left-thumb",
        subject,
        account.AccountEvidence(subject.uid, "a" * 64),
        ipc.SessionEvidence(
            "pidfd-session",
            "session-1",
            "wayland",
            "user",
            True,
            1,
        ),
    )


class FprintWorkerProtocolTests(unittest.TestCase):
    def socket_pair(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        return left, right

    def test_start_round_trip_transfers_exactly_one_live_pidfd(self):
        left, right = self.socket_pair()
        original = os.pidfd_open(os.getpid())
        self.addCleanup(os.close, original)
        protocol.send_start(left, request(), original)
        received, descriptor = protocol.receive_start(right)
        self.addCleanup(os.close, descriptor)
        self.assertEqual(received, request())
        self.assertEqual(
            os.readlink(f"/proc/self/fd/{descriptor}"), "anon_inode:[pidfd]"
        )
        packet = protocol.encode_start(received)
        self.assertEqual(protocol.decode_start(packet), received)
        self.assertEqual(
            packet,
            json.dumps(
                received.public(), sort_keys=True, separators=(",", ":")
            ).encode("ascii"),
        )

    def test_start_rejects_noncanonical_name_root_or_changed_subject(self):
        current = request()
        invalid = (
            protocol.StartRequest(
                "Finger 1", current.caller, current.account, current.session
            ),
            protocol.StartRequest(
                current.finger_name,
                polkit.ProcessSubject(current.caller.pid, 0, current.caller.start_time_ticks),
                account.AccountEvidence(0, "a" * 64),
                current.session,
            ),
            protocol.StartRequest(
                current.finger_name,
                current.caller,
                account.AccountEvidence(current.caller.uid, "b" * 64),
                ipc.SessionEvidence(
                    "pidfd-session", "session-1", "wayland", "user", True, 0
                ),
            ),
        )
        for value in invalid:
            with self.subTest(value=value.finger_name), self.assertRaises(
                protocol.FprintWorkerProtocolError
            ):
                protocol.encode_start(value)

        packet = request().public()
        packet["caller"]["start_time_ticks"] += 1
        encoded = json.dumps(
            packet, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        left, right = self.socket_pair()
        descriptor = os.pidfd_open(os.getpid())
        try:
            left.sendmsg(
                [encoded],
                [
                    (
                        socket.SOL_SOCKET,
                        socket.SCM_RIGHTS,
                        array.array("i", [descriptor]),
                    )
                ],
            )
            with self.assertRaises(protocol.FprintWorkerProtocolError):
                protocol.receive_start(right)
        finally:
            os.close(descriptor)

    def test_start_requires_one_pidfd_and_rejects_stream_or_extra_fds(self):
        stream_left, _stream_right = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_STREAM
        )
        self.addCleanup(stream_left.close)
        self.addCleanup(_stream_right.close)
        with self.assertRaises(protocol.FprintWorkerProtocolError):
            protocol.receive_start(stream_left)

        for descriptor_count in (0, 2):
            left, right = self.socket_pair()
            descriptors = [os.pidfd_open(os.getpid()) for _ in range(descriptor_count)]
            try:
                ancillary = (
                    [
                        (
                            socket.SOL_SOCKET,
                            socket.SCM_RIGHTS,
                            array.array("i", descriptors),
                        )
                    ]
                    if descriptors
                    else []
                )
                left.sendmsg([protocol.encode_start(request())], ancillary)
                with self.assertRaises(protocol.FprintWorkerProtocolError):
                    protocol.receive_start(right)
            finally:
                for descriptor in descriptors:
                    os.close(descriptor)

    def test_cancel_and_updates_are_canonical_and_identifier_free(self):
        left, right = self.socket_pair()
        protocol.send_cancel(left)
        protocol.receive_cancel(right)

        updates = (
            runtime.EnrollmentUpdate(None, False, False, True),
            runtime.EnrollmentUpdate(
                "enroll-stage-passed", False, True, False
            ),
            runtime.EnrollmentUpdate(
                "enroll-completed", True, False, False
            ),
        )
        for update in updates:
            protocol.send_update(right, update)
            self.assertEqual(protocol.receive_update(left), update)
            encoded = protocol.encode_update(update)
            for forbidden in (
                b"apple",
                b"uuid",
                b"keybag",
                b"identity",
                b"password",
                b"credential",
            ):
                self.assertNotIn(forbidden, encoded.lower())

    def test_updates_reject_contradictory_or_unknown_state(self):
        invalid = (
            runtime.EnrollmentUpdate("made-up", False, False, True),
            runtime.EnrollmentUpdate("enroll-completed", False, False, False),
            runtime.EnrollmentUpdate(None, True, False, False),
            runtime.EnrollmentUpdate(None, False, True, True),
            runtime.EnrollmentUpdate("enroll-failed", True, True, False),
        )
        for update in invalid:
            with self.subTest(update=update), self.assertRaises(
                protocol.FprintWorkerProtocolError
            ):
                protocol.encode_update(update)

    def test_peer_close_is_distinct(self):
        for receiver in (protocol.receive_start, protocol.receive_cancel, protocol.receive_update):
            with self.subTest(receiver=receiver.__name__):
                left, right = self.socket_pair()
                right.close()
                with self.assertRaises(protocol.FprintWorkerPeerClosed):
                    receiver(left)


if __name__ == "__main__":
    unittest.main()

