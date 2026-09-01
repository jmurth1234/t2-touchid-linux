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

import t2_fprint_delete_worker as worker
import t2_fprint_delete_worker_launcher as launcher


def session_unit(command):
    return next(
        item.split("=", 1)[1]
        for item in command
        if item.startswith("--unit=")
    )


class FprintDeleteWorkerLauncherTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.worker_root = self.root / "workers"
        self.worker_root.mkdir(mode=0o700)
        self.systemd_run = self.root / "systemd-run"
        self.worker = self.root / "worker"
        for path in (self.systemd_run, self.worker):
            path.write_bytes(b"executable")
            path.chmod(0o700)
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
        )

    def runner(self, command, **arguments):
        self.commands.append((command, arguments))
        endpoint = Path(command[-1])

        def connect():
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            connection.connect(str(endpoint))
            self.peer_pid = os.getpid()
            connection.recv(1)
            connection.close()

        threading.Thread(target=connect, daemon=True).start()
        return SimpleNamespace(returncode=0)

    def test_launches_hardened_credential_free_worker(self):
        patches = self.patches()
        with patches[0], patches[1], patches[2], patches[3]:
            session = launcher.launch(
                runner=self.runner,
                unit_resolver=lambda pid: (
                    session_unit(self.commands[0][0])
                    if pid == self.peer_pid
                    else "wrong.service"
                ),
            )
            endpoint = session.endpoint
            command, arguments = self.commands[0]
            rendered = " ".join(command)
            self.assertNotIn("LoadCredential", rendered)
            self.assertIn("DeviceAllow=/dev/t2-aks rw", rendered)
            self.assertIn("ProtectSystem=strict", rendered)
            self.assertIn(
                "ReadWritePaths=/run/t2-touchid /var/lib/t2-touchid",
                rendered,
            )
            for forbidden in (
                "left-thumb",
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

    def test_wrong_peer_unit_fails_and_removes_socket(self):
        patches = self.patches()
        with patches[0], patches[1], patches[2], patches[3]:
            with self.assertRaises(
                launcher.FprintDeleteWorkerLauncherError
            ):
                launcher.launch(
                    runner=self.runner,
                    unit_resolver=lambda _pid: "wrong.service",
                )
            self.assertEqual(list(self.worker_root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
