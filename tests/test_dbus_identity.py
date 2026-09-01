# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import asyncio
import fcntl
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

from dbus_next import Message, MessageType, Variant


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_dbus_identity as identity


class FakeBus:
    def __init__(self, reply):
        self.reply = reply
        self.calls = []

    async def call(self, message):
        self.calls.append(message)
        return self.reply


def reply(*, uid=None, pid=None, process_fd=True):
    descriptor = os.pidfd_open(os.getpid()) if process_fd else -1
    credentials = {
        "UnixUserID": Variant("u", os.getuid() if uid is None else uid),
        "ProcessID": Variant("u", os.getpid() if pid is None else pid),
    }
    descriptors = []
    if process_fd:
        credentials["ProcessFD"] = Variant("h", 0)
        descriptors.append(descriptor)
    return Message(
        message_type=MessageType.METHOD_RETURN,
        reply_serial=1,
        signature="a{sv}",
        body=[credentials],
        unix_fds=descriptors,
    )


class DBusIdentityTests(unittest.IsolatedAsyncioTestCase):
    async def test_collects_and_owns_kernel_pinned_process(self):
        message = reply()
        received_descriptor = message.unix_fds[0]
        bus = FakeBus(message)
        caller = await identity.collect(bus, ":1.42")
        try:
            self.assertEqual(caller.subject.pid, os.getpid())
            self.assertEqual(caller.subject.uid, os.getuid())
            self.assertEqual(caller.verify(), caller.subject)
            self.assertEqual(bus.calls[0].member, "GetConnectionCredentials")
            self.assertEqual(bus.calls[0].body, [":1.42"])
            self.assertNotIn(str(os.getpid()), str(caller.redacted()))
        finally:
            pinned_descriptor = caller.pidfd
            caller.close()
        with self.assertRaises(OSError):
            fcntl.fcntl(received_descriptor, fcntl.F_GETFD)
        with self.assertRaises(OSError):
            fcntl.fcntl(pinned_descriptor, fcntl.F_GETFD)

    async def test_root_identity_is_pinned_but_not_granted_mutation_here(self):
        # The parser supports root callers needed by PAM verification. This
        # collector creates no mapping, session, or PolicyKit authority.
        message = reply(uid=0)
        bus = FakeBus(message)
        with mock.patch.object(
            identity.t2_polkit_grant,
            "read_process_subject",
            return_value=identity.t2_polkit_grant.ProcessSubject(
                os.getpid(), 0, 1
            ),
        ):
            caller = await identity.collect(bus, ":1.9")
        try:
            self.assertEqual(caller.subject.uid, 0)
        finally:
            caller.close()

    async def test_missing_fd_wrong_pid_and_malformed_sender_fail_closed(self):
        cases = (
            (FakeBus(reply(process_fd=False)), ":1.2"),
            (FakeBus(reply(pid=os.getpid() + 1)), ":1.3"),
        )
        for bus, sender in cases:
            with self.subTest(sender=sender), self.assertRaises(
                identity.DBusIdentityError
            ):
                await identity.collect(bus, sender)
            descriptors = getattr(bus.reply, "unix_fds", [])
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    fcntl.fcntl(descriptor, fcntl.F_GETFD)

        malformed = FakeBus(reply())
        descriptor = malformed.reply.unix_fds[0]
        try:
            with self.assertRaises(identity.DBusIdentityError):
                await identity.collect(malformed, "org.example.Client")
        finally:
            os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
