# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "src"
sys.path.insert(0, str(SOURCE))


def load_entrypoint():
    path = SOURCE / "t2-touchid-user-broker.py"
    specification = importlib.util.spec_from_file_location(
        "t2_touchid_user_broker_command", path
    )
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class UserBrokerServiceAssetTests(unittest.TestCase):
    def test_candidate_units_are_seqpacket_accept_once_and_not_enableable(self):
        socket_unit = (
            ROOT
            / "systemd/research/t2-touchid-user-broker.socket"
        ).read_text(encoding="utf-8")
        service_unit = (
            ROOT
            / "systemd/research/t2-touchid-user-broker@.service"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "ListenSequentialPacket=/run/t2-touchid/user-broker.sock",
            socket_unit,
        )
        for required in (
            "Accept=yes",
            "FileDescriptorName=connection",
            "SocketMode=0666",
            "MaxConnectionsPerSource=2",
            "TriggerLimitBurst=20",
        ):
            self.assertIn(required, socket_unit)
        self.assertNotIn("[Install]", socket_unit)
        self.assertNotIn("[Install]", service_unit)
        self.assertNotIn("ListenStream=", socket_unit)

    def test_service_is_root_read_only_and_sandboxed(self):
        service = (
            ROOT
            / "systemd/research/t2-touchid-user-broker@.service"
        ).read_text(encoding="utf-8")
        for required in (
            "User=root",
            "Group=root",
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "ProtectHome=read-only",
            "RestrictAddressFamilies=AF_UNIX AF_INET6",
            "CapabilityBoundingSet=CAP_DAC_READ_SEARCH",
            "DevicePolicy=closed",
            "DeviceAllow=/dev/t2-aks rw",
            "ReadWritePaths=/run/t2-touchid /var/lib/t2-touchid",
        ):
            self.assertIn(required, service)
        self.assertNotIn("EnvironmentFile=", service)
        self.assertNotIn("ExecStartPre=", service)

    def test_installer_does_not_install_start_or_enable_candidate_units(self):
        install = (ROOT / "install.sh").read_text(encoding="utf-8")
        uninstall = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
        for text in (install, uninstall):
            self.assertNotIn("systemd/research", text)
            self.assertNotIn("t2-touchid-user-broker.socket", text)
            self.assertNotIn("t2-touchid-user-broker@.service", text)
        self.assertNotIn(
            '"$source_dir/src/t2-touchid-user-broker.py" '
            "/usr/local/sbin/t2-touchid-user-broker\n",
            install,
        )

    def test_entrypoint_has_fixed_read_only_policy_and_generic_failure(self):
        module = load_entrypoint()
        runner = mock.Mock(return_value=object())
        with mock.patch.object(
            module.t2_user_broker_socket_activation,
            "run_once",
            runner,
        ):
            self.assertEqual(module.main(), 0)
        runner.assert_called_once_with(
            modification_allowed=False,
            allow_user_interaction=True,
        )

        error = module.t2_user_broker_socket_activation
        with mock.patch.object(
            error,
            "run_once",
            side_effect=error.UserBrokerSocketActivationError("private"),
        ), mock.patch.object(module.sys, "stderr") as stderr:
            self.assertEqual(module.main(), 1)
        rendered = "".join(
            str(call) for call in stderr.method_calls
        )
        self.assertNotIn("private", rendered)


if __name__ == "__main__":
    unittest.main()
