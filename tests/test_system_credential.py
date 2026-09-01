# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))

import t2_acm_device
import t2_system_credential as credential


class SystemCredentialTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.credentials_root = self.root / "credentials"
        self.credentials_root.mkdir(mode=0o700)
        self.directory = self.credentials_root / "worker.service"
        self.directory.mkdir(mode=0o700)
        self.secret = self.directory / credential.CREDENTIAL_NAME
        self.secret.write_bytes(b"test-secret\n")
        self.secret.chmod(0o400)
        self.state = self.root / "keybag.env"
        self.state.write_text(
            "T2_KEYBAG_SESSION=1\n"
            "T2_KEYBAG_HANDLE=42\n"
            "T2_KEYBAG_SPECIAL=-501\n",
            encoding="ascii",
        )
        self.state.chmod(0o600)
        self.tool = self.root / "t2-aks-tool"
        self.tool.write_bytes(b"tool")
        self.tool.chmod(0o700)
        self.calls = []

    def tearDown(self):
        self.temporary.cleanup()

    def runner(self, command, **arguments):
        self.calls.append((command, bytes(arguments["input"]), arguments))
        return SimpleNamespace(returncode=0)

    def patches(self):
        return (
            mock.patch.object(credential, "CREDENTIAL_ROOT", self.credentials_root),
            mock.patch.object(credential, "KEYBAG_STATE", self.state),
            mock.patch.object(credential, "AKS_TOOL", self.tool),
        )

    def test_proves_fallback_then_binds_context_without_secret_in_argv(self):
        with self.patches()[0], self.patches()[1], self.patches()[2]:
            binder = credential.CredentialPasswordBinder(
                -501,
                environment={"CREDENTIALS_DIRECTORY": str(self.directory)},
                runner=self.runner,
            )
            self.assertTrue(binder.verify_password_fallback())
            binder.bind(bytes(range(16)))
        self.assertEqual(
            self.calls[0][0],
            [str(self.tool), "verify-password-only-stdin", "1", "42"],
        )
        self.assertEqual(self.calls[0][1], b"test-secret\n")
        self.assertEqual(
            self.calls[1][0],
            [str(self.tool), "verify-password-acm-stdin", "1", "-501"],
        )
        self.assertEqual(self.calls[1][1], bytes(range(16)) + b"test-secret\n")
        for command, _payload, arguments in self.calls:
            self.assertNotIn("test-secret", " ".join(command))
            self.assertIs(arguments["stdout"], subprocess.DEVNULL)
            self.assertIs(arguments["stderr"], subprocess.DEVNULL)
        self.assertNotIn("test-secret", repr(binder))

    def test_rejects_public_or_malformed_credential_and_stale_alias(self):
        cases = ("public", "malformed", "stale")
        for case in cases:
            with self.subTest(case=case):
                self.secret.chmod(0o600)
                self.secret.write_bytes(b"test-secret\n")
                self.secret.chmod(0o400)
                self.state.write_text(
                    "T2_KEYBAG_SESSION=1\n"
                    "T2_KEYBAG_HANDLE=42\n"
                    f"T2_KEYBAG_SPECIAL={-502 if case == 'stale' else -501}\n",
                    encoding="ascii",
                )
                self.state.chmod(0o600)
                if case == "public":
                    self.secret.chmod(0o444)
                elif case == "malformed":
                    self.secret.chmod(0o600)
                    self.secret.write_bytes(b"\0bad")
                    self.secret.chmod(0o400)
                with self.patches()[0], self.patches()[1], self.patches()[2]:
                    if case == "stale":
                        with self.assertRaises(credential.SystemCredentialError):
                            credential.CredentialPasswordBinder(
                                -501,
                                environment={
                                    "CREDENTIALS_DIRECTORY": str(self.directory)
                                },
                                runner=self.runner,
                            )
                    else:
                        binder = credential.CredentialPasswordBinder(
                            -501,
                            environment={
                                "CREDENTIALS_DIRECTORY": str(self.directory)
                            },
                            runner=self.runner,
                        )
                        with self.assertRaises(credential.SystemCredentialError):
                            binder.verify_password_fallback()

    def test_binding_translates_credential_failure_to_acm_error(self):
        def fail(*_arguments, **_keywords):
            return SimpleNamespace(returncode=1)

        with self.patches()[0], self.patches()[1], self.patches()[2]:
            binder = credential.CredentialPasswordBinder(
                -501,
                environment={"CREDENTIALS_DIRECTORY": str(self.directory)},
                runner=fail,
            )
            with self.assertRaises(t2_acm_device.ACMDeviceError):
                binder.bind(bytes(16))

    def test_rejects_multiple_credential_lines(self):
        self.secret.chmod(0o600)
        self.secret.write_bytes(b"test-secret\nsecond-line\n")
        self.secret.chmod(0o400)
        with self.patches()[0], self.patches()[1], self.patches()[2]:
            binder = credential.CredentialPasswordBinder(
                -501,
                environment={"CREDENTIALS_DIRECTORY": str(self.directory)},
                runner=self.runner,
            )
            with self.assertRaises(credential.SystemCredentialError):
                binder.verify_password_fallback()


if __name__ == "__main__":
    unittest.main()
