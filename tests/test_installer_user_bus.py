# SPDX-License-Identifier: GPL-2.0-only
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class InstallerUserBusTests(unittest.TestCase):
    def test_user_daemon_reload_is_bound_to_the_real_desktop_bus(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn('target_uid=$(id -u -- "$target_user")', installer)
        self.assertIn('target_runtime_dir=/run/user/$target_uid', installer)
        self.assertIn('[[ -S $target_runtime_dir/bus ]]', installer)
        self.assertIn('runuser -u "$target_user" -- env', installer)
        self.assertIn('XDG_RUNTIME_DIR="$target_runtime_dir"', installer)
        self.assertIn(
            'DBUS_SESSION_BUS_ADDRESS="unix:path=$target_runtime_dir/bus"',
            installer,
        )
        self.assertNotIn(
            'systemctl --machine="$target_user@.host" --user daemon-reload',
            installer,
        )

    def test_uninstaller_uses_the_same_bounded_user_bus(self):
        uninstaller = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
        self.assertIn('target_uid=$(id -u -- "$target_user"', uninstaller)
        self.assertIn('target_runtime_dir=/run/user/$target_uid', uninstaller)
        self.assertIn('[[ $target_uid =~ ^[0-9]+$', uninstaller)
        self.assertIn('runuser -u "$target_user" -- env', uninstaller)
        self.assertIn('XDG_RUNTIME_DIR="$target_runtime_dir"', uninstaller)
        self.assertIn(
            'DBUS_SESSION_BUS_ADDRESS="unix:path=$target_runtime_dir/bus"',
            uninstaller,
        )


if __name__ == "__main__":
    unittest.main()
