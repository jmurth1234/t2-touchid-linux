# SPDX-License-Identifier: GPL-2.0-only
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class BiometricPortRefreshAssetTests(unittest.TestCase):
    def test_installer_and_uninstaller_own_service_and_helper(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        uninstaller = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
        for asset in (
            "t2-biometric-port-refresh.service",
            "t2-biometric-port-refresh",
            "t2-bridge-network-prepare",
        ):
            self.assertIn(asset, installer)
            self.assertIn(asset, uninstaller)
        self.assertTrue(
            (ROOT / "systemd/system/t2-bridge-network.service").is_file()
        )
        self.assertIn("t2-bridge-network.service", uninstaller)

    def test_network_preparation_precedes_port_discovery(self):
        service = (
            ROOT / "systemd/system/t2-biometric-port-refresh.service"
        ).read_text(encoding="utf-8")
        network = (ROOT / "systemd/system/t2-bridge-network.service").read_text(
            encoding="utf-8"
        )

        self.assertIn("Requires=t2-bridge-network.service", service)
        self.assertIn("After=t2-bridge-network.service", service)
        self.assertIn("Before=network-online.target", network)

    def test_port_discovery_finishes_before_transport_attempt(self):
        transport = (ROOT / "systemd/system/t2-sep-transport.service").read_text(
            encoding="utf-8"
        )

        self.assertIn("After=local-fs.target t2-biometric-port-refresh.service", transport)
        self.assertIn("ExecStartPre=/usr/bin/sleep 5", transport)
        self.assertLess(
            transport.index("ExecStartPre=/usr/bin/sleep 5"),
            transport.index("ExecStart=/usr/local/sbin/t2-sep-transport-load"),
        )

    def test_network_helper_is_private_and_configuration_driven(self):
        helper = (ROOT / "src/t2-bridge-network-prepare.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("T2_TOUCHID_INTERFACE", helper)
        self.assertIn("T2_TOUCHID_HOST", helper)
        self.assertIn('driver == cdc_ncm', helper)
        self.assertIn('nmcli device set "$interface" managed no', helper)
        self.assertIn("ipaddress.IPv6Address", helper)
        self.assertIn("value.is_link_local", helper)
        self.assertIn("network-manager-detached", helper)
        self.assertIn("restore_network_manager", helper)
        self.assertIn("bind_unbound_ibridge", helper)
        self.assertIn("idVendor", helper)
        self.assertIn("idProduct", helper)
        self.assertIn("05ac", helper)
        self.assertIn("8233", helper)
        self.assertIn("/sys/bus/usb/drivers/cdc_ncm/bind", helper)
        self.assertIn("(( ${#candidates[@]} == 1 ))", helper)
        self.assertIn('printf \'%s\\n\' "$interface" >"$nm_marker"', helper)
        self.assertLess(helper.index("case ${1:-prepare}"), helper.index("[[ -r $config_file ]]"))
        self.assertNotIn("enp2s0f1u1", helper)
        self.assertNotIn("fe80::c908", helper)

    def test_network_service_allows_only_usb_driver_binding_under_sysfs(self):
        service = (
            ROOT / "systemd/system/t2-bridge-network.service"
        ).read_text(encoding="utf-8")

        self.assertIn("ProtectKernelTunables=yes", service)
        self.assertIn("ReadWritePaths=/sys/bus/usb/drivers", service)


if __name__ == "__main__":
    unittest.main()
