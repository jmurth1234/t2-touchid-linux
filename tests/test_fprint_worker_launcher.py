# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import os
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))

import t2_fprint_worker as worker
import t2_fprint_worker_launcher as launcher


class FprintWorkerLauncherTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.worker_root = self.root / "workers"
        self.worker_root.mkdir(mode=0o700)
        self.systemd_run = self.root / "systemd-run"
        self.worker = self.root / "worker"
        self.credential = self.root / "credential"
        for path in (self.systemd_run, self.worker):
            path.write_bytes(b"executable")
            path.chmod(0o700)
        self.credential.write_bytes(b"encrypted")
        self.credential.chmod(0o600)
        self.commands = []
        self.peer_pid = None

    def tearDown(self):
        self.temporary.cleanup()

    def patches(self):
        return (
            mock.patch.object(launcher, "ROOT_UID", os.geteuid()),
            mock.patch.object(worker, "WORKER_ROOT", self.worker_root),
            mock.patch.object(launcher, "SYSTEMD_RUN", self.systemd_run),
            mock.patch.object(launcher, "WORKER", self.worker),
            mock.patch.object(
                launcher, "ENCRYPTED_CREDENTIAL", self.credential
            ),
        )

    def runner(self, command, **arguments):
        self.commands.append((command, arguments))
        endpoint = Path(command[-1])

        def connect():
            self.peer_pid = os.getpid()
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            connection.connect(str(endpoint))
            connection.recv(1)
            connection.close()

        threading.Thread(target=connect, daemon=True).start()
        return SimpleNamespace(returncode=0)

    def test_launches_hardened_credential_worker_and_cleans_socket(self):
        patches = self.patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            session = launcher.launch(
                runner=self.runner,
                unit_resolver=lambda pid: (
                    session_unit(self.commands[0][0])
                    if pid == self.peer_pid
                    else "wrong.service"
                ),
            )
            endpoint = session.endpoint
            self.assertTrue(endpoint.exists())
            self.assertEqual(endpoint.stat().st_mode & 0o777, 0o600)
            command, arguments = self.commands[0]
            rendered = " ".join(command)
            self.assertIn("LoadCredentialEncrypted=", rendered)
            self.assertIn("DeviceAllow=/dev/t2-aks rw", rendered)
            self.assertIn("ProtectSystem=strict", rendered)
            self.assertIn(
                "CapabilityBoundingSet=CAP_DAC_READ_SEARCH", rendered
            )
            self.assertIn("NoNewPrivileges=yes", rendered)
            self.assertIn("RestrictNamespaces=yes", rendered)
            self.assertIn("SystemCallFilter=@system-service", rendered)
            for forbidden in (
                "left-thumb",
                "right-index",
                "apple_uid",
                "linux_uid",
                "password=",
                "keybag",
            ):
                self.assertNotIn(forbidden, rendered.lower())
            self.assertIs(arguments["stdin"], launcher.subprocess.DEVNULL)
            session.connection.send(b"x")
            session.close()
            self.assertFalse(endpoint.exists())
            self.assertNotIn(str(endpoint), repr(session))

    def test_nonzero_launcher_or_wrong_peer_unit_fails_and_cleans(self):
        patches = self.patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            with self.assertRaises(launcher.FprintWorkerLauncherError):
                launcher.launch(
                    runner=self.runner,
                    unit_resolver=lambda _pid: "wrong.service",
                )
            self.assertEqual(list(self.worker_root.iterdir()), [])

    def test_public_runtime_directory_fails_before_runner(self):
        self.worker_root.chmod(0o755)
        patches = self.patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            runner = mock.Mock()
            with self.assertRaises(launcher.FprintWorkerLauncherError):
                launcher.launch(runner=runner)
            runner.assert_not_called()


def session_unit(command):
    return next(item.split("=", 1)[1] for item in command if item.startswith("--unit="))


if __name__ == "__main__":
    unittest.main()
