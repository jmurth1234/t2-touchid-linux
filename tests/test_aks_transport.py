# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_aks_observer
import t2_aks_transport as transport


class CommandRunner:
    def __init__(self):
        self.replies = []
        self.commands = []

    def __call__(self, command):
        self.commands.append(command)
        if not self.replies:
            raise AssertionError("no reply")
        return self.replies.pop(0)


class PasswordRunner:
    def __init__(self, completed=None):
        self.completed = completed or subprocess.CompletedProcess(
            [], 0, "status=0 response_length=16\n", ""
        )
        self.command = None
        self.view = None

    def __call__(self, command, password):
        self.command = command
        self.view = password
        return self.completed


class AKSActivationTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.runner = CommandRunner()
        self.observer = t2_aks_observer.AKSAliasObserver(
            tool=Path("/test/t2-aks-tool"),
            runtime_root=Path(self.temp.name),
            runtime_generation=str(uuid.UUID(int=10)),
            runner=self.runner,
        )

    def tearDown(self):
        self.temp.cleanup()

    def make(self, password_runner=None):
        return transport.AKSActivationTransport(
            self.observer,
            **({"password_runner": password_runner} if password_runner else {}),
        )

    def test_load_requires_exact_success_reply_and_policy_path(self):
        self.runner.replies.append(
            subprocess.CompletedProcess(
                [], 0, "status=0 handle=9 response_length=8\n", ""
            )
        )
        result = self.make().load_keybag(
            "/var/lib/t2-touchid/users/1000/user.kb"
        )
        self.assertEqual(result, 9)
        self.assertEqual(
            self.runner.commands[0][1:],
            [
                "load-keybag",
                "/var/lib/t2-touchid/users/1000/user.kb",
                "1",
            ],
        )
        for path in (
            "/var/lib/t2-touchid/user.kb",
            "/var/lib/t2-touchid/users/../user.kb",
            "/var/lib/t2-touchid/users/1000/nested/user.kb",
            "/var/lib/t2-touchid/users/not-a-uid/user.kb",
            "/var/lib/t2-touchid/users/0/user.kb",
            "/var/lib/t2-touchid/users/01000/user.kb",
            "/var/lib/t2-touchid/users/1000//user.kb",
            "relative/user.kb",
        ):
            with self.subTest(path=path):
                with self.assertRaises(transport.AKSActivationTransportError):
                    self.make().load_keybag(path)

    def test_load_rejects_nonzero_malformed_or_oversized_reply(self):
        replies = (
            subprocess.CompletedProcess([], 1, "status=0 handle=9 response_length=8", ""),
            subprocess.CompletedProcess([], 0, "status=0 handle=0 response_length=8", ""),
            subprocess.CompletedProcess([], 0, "status=0 handle=9 response_length=20000", ""),
            subprocess.CompletedProcess([], 0, "extra\nstatus=0 handle=9 response_length=8", ""),
        )
        for completed in replies:
            with self.subTest(output=completed.stdout):
                self.runner.replies.append(completed)
                with self.assertRaises(transport.AKSActivationTransportError):
                    self.make().load_keybag(
                        "/var/lib/t2-touchid/users/1000/user.kb"
                    )

    def test_bind_returns_typed_status_and_checks_exit_consistency(self):
        self.runner.replies.extend(
            [
                subprocess.CompletedProcess([], 0, "status=0 response_length=4\n", ""),
                subprocess.CompletedProcess([], 1, "status=0x5 response_length=4\n", ""),
            ]
        )
        instance = self.make()
        self.assertEqual(instance.bind_alias(9, -501), 0)
        self.assertEqual(instance.bind_alias(9, -501), 5)
        self.assertEqual(
            self.runner.commands[0][1:],
            ["set-system-keybag", "1", "9", "-501"],
        )
        self.runner.replies.append(
            subprocess.CompletedProcess([], 1, "status=0 response_length=4", "")
        )
        with self.assertRaises(transport.AKSActivationTransportError):
            instance.bind_alias(9, -501)

    def test_unlock_uses_writable_memoryview_and_password_runner(self):
        password_runner = PasswordRunner()
        instance = self.make(password_runner)
        secret = bytearray(b"secret")
        view = memoryview(secret)
        self.assertEqual(instance.unlock_alias(-501, view), 0)
        self.assertIs(password_runner.view, view)
        self.assertEqual(
            password_runner.command[1:],
            ["unlock-keybag-stdin", "1", "-501"],
        )
        with self.assertRaises(transport.AKSActivationTransportError):
            instance.unlock_alias(-501, memoryview(b"readonly"))
        with self.assertRaises(transport.AKSActivationTransportError):
            instance.unlock_alias(-501, memoryview(bytearray(1024)))

    def test_status_parser_rejects_malformed_runner_results(self):
        password_runner = PasswordRunner(
            subprocess.CompletedProcess([], 0, "status=0 response_length=0", "")
        )
        with self.assertRaises(transport.AKSActivationTransportError):
            self.make(password_runner).unlock_alias(
                -501, memoryview(bytearray(b"x"))
            )
        bad_runner = lambda command, password: "not completed"
        with self.assertRaises(transport.AKSActivationTransportError):
            self.make(bad_runner).unlock_alias(
                -501, memoryview(bytearray(b"x"))
            )

    def test_requires_concrete_observer(self):
        with self.assertRaises(transport.AKSActivationTransportError):
            transport.AKSActivationTransport(object())


if __name__ == "__main__":
    unittest.main()
